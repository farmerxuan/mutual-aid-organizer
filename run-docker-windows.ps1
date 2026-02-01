<#
run-docker-windows.ps1

Interactive helper for Windows users to create a .env and start the app with Docker Compose.
Run this from the project root (where this script lives):
  .\run-docker-windows.ps1
#>

Set-StrictMode -Version Latest

$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $root

Write-Host "This helper will create or update a .env file and run Docker Compose (build + start)."

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "Docker CLI not found. Please install Docker Desktop and try again."; exit 1
}

$envPath = Join-Path $root '.env'
$create = $true
if (Test-Path $envPath) {
    $resp = Read-Host "A .env file already exists. Overwrite? (y/N)"
    if ($resp -notin @('y','Y')) { Write-Host ".env exists; leaving it unchanged."; $create = $false }
}

if ($create) {
    $admin = Read-Host "Admin username (default: admin)"
    if ([string]::IsNullOrWhiteSpace($admin)) { $admin = 'admin' }

    Write-Host "Enter admin password (input will be hidden)"
    $secure = Read-Host -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

    $sk = Read-Host "SECRET_KEY (leave empty to auto-generate)"
    if ([string]::IsNullOrWhiteSpace($sk)) {
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $bytes = New-Object 'Byte[]' 32
        $rng.GetBytes($bytes)
        $sk = [Convert]::ToBase64String($bytes)
        Write-Host "Generated SECRET_KEY (persist this value if you want to reuse it):"
        Write-Host $sk
    }

    $lines = @()
    $lines += "ADMIN_USER=$admin"
    $lines += "ADMIN_PASS=$plain"
    $lines += "SECRET_KEY=$sk"
    $lines | Out-File -FilePath $envPath -Encoding ASCII -Force
    Write-Host "Wrote .env to $envPath"
}

Write-Host "Building and starting containers (this may take a few minutes)..."
docker compose up -d --build
if ($LASTEXITCODE -ne 0) { Write-Error "docker compose failed with exit code $LASTEXITCODE"; exit $LASTEXITCODE }

Write-Host "Application started at http://localhost:5000"
Write-Host "To view logs: docker compose logs -f"
Write-Host "To stop: docker compose down"
