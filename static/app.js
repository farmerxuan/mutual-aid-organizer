function getAuth(){
  const a = sessionStorage.getItem('auth');
  return a || '';
}
function getAuthUsername(){
  const a = sessionStorage.getItem('auth_user');
  return a || '';
}
function getAuthRole(){
  const r = sessionStorage.getItem('auth_role');
  return r || '';
}
function loginPrompt(){
  const modal = new bootstrap.Modal(document.getElementById('loginModal'));
  modal.show();
}
function setCredentials(username, password){
  // Prefer server-side session login
  fetch('/api/login', {method:'POST', credentials: 'same-origin', headers: {'Content-Type':'application/json'}, body: JSON.stringify({username: username, password: password})})
    .then(async res => {
      if(!res.ok){ const t = await res.text(); showToast('Login failed: '+t,'danger'); return; }
      const j = await res.json();
      sessionStorage.setItem('auth_user', j.username || username);
      sessionStorage.setItem('auth_role', j.role || 'volunteer');
      // keep basic auth as fallback
      const header = 'Basic ' + btoa(username+':'+password);
      sessionStorage.setItem('auth', header);
      updateNavbar();
      showSidebar();
      showToast('Logged in as ' + j.username,'success');
      // Redirect based on role: admin/coordinator -> admin UI, volunteers -> volunteer UI
      const role = (j.role || 'volunteer');
      if(role === 'admin' || role === 'coordinator'){
        window.location.href = '/ui/admin';
        return;
      }
      if(role === 'volunteer'){
        window.location.href = '/ui/volunteer';
        return;
      }
    }).catch(e=>{ showToast('Login error','danger'); });
}
function logout(){
  fetch('/api/logout', {method:'POST', credentials: 'same-origin'}).finally(()=>{
    sessionStorage.removeItem('auth');
    sessionStorage.removeItem('auth_user');
    sessionStorage.removeItem('auth_role');
    updateNavbar();
    hideSidebar();
    showToast('Logged out', 'info');
    window.location.href = '/';
  });
}
function updateNavbar(){
  const user = getAuthUsername();
  const btn = document.getElementById('credentialsBtn');
  const logoutBtn = document.getElementById('logoutBtn');
  if(user){
    btn.textContent = 'Logged in: ' + user;
    btn.classList.remove('btn-outline-light');
    btn.classList.add('btn-success');
    if(logoutBtn) logoutBtn.style.display = 'inline-block';
  } else {
    btn.textContent = 'Log In';
    btn.classList.add('btn-outline-light');
    btn.classList.remove('btn-success');
    if(logoutBtn) logoutBtn.style.display = 'none';
  }
}

function showSidebar(){
  const sidebar = document.getElementById('sidebar');
  const mainContent = document.getElementById('mainContent');
  const role = getAuthRole();
  if(sidebar){
    sidebar.classList.add('show');
    mainContent.classList.add('with-sidebar');
    // Disable admin link unless user is admin
    const adminLink = document.getElementById('adminLink');
    const usersLink = document.getElementById('usersLink');
    const logsLink = document.getElementById('logsLink');
    if(adminLink){
      if(role === 'admin'){
        adminLink.classList.remove('disabled');
        adminLink.style.pointerEvents = 'auto';
      } else {
        adminLink.classList.add('disabled');
        adminLink.style.pointerEvents = 'none';
      }
    }
    if(usersLink){
      if(role === 'admin'){
        usersLink.classList.remove('disabled');
        usersLink.style.pointerEvents = 'auto';
      } else {
        usersLink.classList.add('disabled');
        usersLink.style.pointerEvents = 'none';
      }
    }
    if(logsLink){
      if(role === 'admin'){
        logsLink.classList.remove('disabled');
        logsLink.style.pointerEvents = 'auto';
      } else {
        logsLink.classList.add('disabled');
        logsLink.style.pointerEvents = 'none';
      }
    }
  }
}

function hideSidebar(){
  const sidebar = document.getElementById('sidebar');
  const mainContent = document.getElementById('mainContent');
  if(sidebar){
    sidebar.classList.remove('show');
    mainContent.classList.remove('with-sidebar');
  }
}
async function apiGet(path){
  const auth = getAuth();
  const headers = {};
  if(auth) headers['Authorization'] = auth;
  return fetch(path, {headers: headers, credentials: 'same-origin'});
}
async function apiPost(path, body){
  const auth = getAuth();
  const headers = {'Content-Type':'application/json'};
  if(auth) headers['Authorization'] = auth;
  return fetch(path, {method:'POST', headers: headers, credentials: 'same-origin', body: JSON.stringify(body)});
}

document.addEventListener('DOMContentLoaded', ()=>{
  updateNavbar();
  const user = getAuthUsername();
  if(user){
    showSidebar();
  } else {
    hideSidebar();
  }
  const loginForm = document.getElementById('loginForm');
  if(loginForm){
    loginForm.addEventListener('submit', (e)=>{
      e.preventDefault();
      const u = document.getElementById('loginUsername').value;
      const p = document.getElementById('loginPassword').value;
      if(u && p){
        setCredentials(u, p);
        loginForm.reset();
        const modal = bootstrap.Modal.getInstance(document.getElementById('loginModal'));
        if(modal) modal.hide();
      }
    });
  }
});

// wire intake form
document.addEventListener('DOMContentLoaded', ()=>{
  const f = document.getElementById('intakeForm');
  if(!f) return;
  f.addEventListener('submit', async (e)=>{
    e.preventDefault();
    // simple validation
    const phone = f.elements['phone'].value || '';
      const phoneCountry = f.elements['phone_country'] ? f.elements['phone_country'].value : 'US';
      const digits = phone.replace(/\D/g,'');
      if(!digits){ showToast('Phone is required', 'danger'); f.elements['phone'].classList.add('is-invalid'); return; }
      if(!validatePhoneWithCountry(digits, phoneCountry)){
        showToast('Phone does not match selected country format', 'danger');
        f.elements['phone'].classList.add('is-invalid');
        return;
      }
    f.elements['phone'].classList.remove('is-invalid');

    const obj = {
      name: f.elements['name'].value || '',
      phone: phone,
      address: f.elements['address'].value || '',
      notes: f.elements['notes'].value || '',
      status: f.elements['status'].value || 'scheduled',
      items: collectItems()
    };
    const r = await apiPost('/intake', obj);
    if(r.status===201){ const j=await r.json(); showToast('Created: '+j.anon_id,'success'); f.reset(); clearItems(); } else { const t=await r.text(); showToast('Error: '+t,'danger'); }
  });
});

// Attach formatting to phone fields on pages
document.addEventListener('DOMContentLoaded', ()=>{
  // intake
  attachPhoneFormatting('phone-input','phone-country','US');
  // volunteer
  attachPhoneFormatting('vol-phone','vol-phone-country','US');
  // admin
  attachPhoneFormatting('admin-phone','admin-phone-country','US');
});

function attachPhoneFormatting(inputId, countrySelectId, defaultCountry){
  const input = document.getElementById(inputId);
  const countrySel = document.getElementById(countrySelectId);
  if(!input) return;
  const formatNow = ()=>{
    try{
      const digits = (input.value||'').trim();
      const country = (countrySel && countrySel.value) || defaultCountry;
      if(window.libphonenumber && digits){
        const parse = window.libphonenumber.parsePhoneNumberFromString(digits, country);
        if(parse){
          // prefer national formatting when editing
          input.value = parse.formatInternational();
        }
      }
    }catch(e){ /* ignore formatting errors */ }
  };
  input.addEventListener('blur', formatNow);
  if(countrySel) countrySel.addEventListener('change', formatNow);
}

 window.lookup = async function(anon){
   const r = await apiPost('/volunteer/lookup',{anon_id:anon});
   if(!r.ok){ alert('not allowed'); return; }
   const j = await r.json();
   alert(JSON.stringify(j.pii,null,2));
 }
// Items management
function addItem(kind){
  const input = document.getElementById(kind+'-input');
  const val = (input.value||'').trim();
  if(!val) return;
  const list = document.getElementById(kind+'-list');
  const el = document.createElement('div');
  el.className = 'd-flex align-items-center mb-1';
  el.innerHTML = `<div class="flex-grow-1">${escapeHtml(val)}</div><button class="btn btn-sm btn-outline-danger ms-2" type="button">Remove</button>`;
  el.querySelector('button').addEventListener('click', ()=> el.remove());
  list.appendChild(el);
  input.value='';
}
function clearItems(){ ['food','nonfood','custom'].forEach(k=>{ document.getElementById(k+'-list').innerHTML=''; }); }
function collectItems(){
  const result = { food:[], nonfood:[], custom:[] };
  ['food','nonfood','custom'].forEach(k=>{
    const list = document.getElementById(k+'-list');
    if(!list) return;
    for(const child of list.children){
      result[k].push(child.firstElementChild.innerText);
    }
  });
  return result;
}

function escapeHtml(s){ return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// Toast helper
function showToast(message, variant='info'){
  const id = 't'+Date.now();
  const container = document.getElementById('toast-container');
  const div = document.createElement('div');
  div.innerHTML = `<div id="${id}" class="toast align-items-center text-bg-${variant} border-0 mb-2" role="alert" aria-live="assertive" aria-atomic="true"><div class="d-flex"><div class="toast-body">${escapeHtml(message)}</div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button></div></div>`;
  container.appendChild(div);
  const toastEl = document.getElementById(id);
  const bsToast = bootstrap.Toast.getOrCreateInstance(toastEl, {delay: 5000});
  bsToast.show();
}

// Modal helper to show structured results
function showResultModal(title, htmlContent){
  const label = document.getElementById('resultModalLabel');
  const body = document.getElementById('resultModalBody');
  if(label) label.innerText = title || 'Result';
  if(body) body.innerHTML = htmlContent || '';
  const el = document.getElementById('resultModal');
  if(!el) return;
  const modal = new bootstrap.Modal(el);
  modal.show();
}

function validatePhoneWithCountry(digits, country){
  // Prefer libphonenumber-js if available for robust validation
  try{
    if(window.libphonenumber){
      // digits may be numeric-only; try to parse using country
      const maybe = window.libphonenumber.parsePhoneNumberFromString(digits, country);
      return maybe ? maybe.isValid() : false;
    }
  }catch(e){ /* fall back to heuristics */ }

  // Fallback heuristics
  country = (country||'').toUpperCase();
  if(country==='US' || country==='CA'){
    if(digits.length===10) return true;
    if(digits.length===11 && digits.startsWith('1')) return true;
    return false;
  }
  if(country==='GB'){
    if(digits.length===10) return true;
    if(digits.length===11 && digits.startsWith('0')) return true;
    if(digits.length===12 && digits.startsWith('44')) return true;
    return false;
  }
  if(country==='AU'){
    if(digits.length===9 || digits.length===10) return true;
    if(digits.length===11 && digits.startsWith('61')) return true;
    return false;
  }
  return digits.length>=7 && digits.length<=15;
}

async function searchByPhone(context){
  // context: 'volunteer' or 'admin'
  const countryEl = document.getElementById(context==='admin' ? 'admin-phone-country' : 'vol-phone-country');
  const phoneEl = document.getElementById(context==='admin' ? 'admin-phone' : 'vol-phone');
  if(!phoneEl) return;
  const country = countryEl ? countryEl.value : 'US';
  const phone = (phoneEl.value||'').trim();
  const digits = phone.replace(/\D/g,'');
  if(!digits){ showToast('Enter a phone to search','warning'); return; }
  if(!validatePhoneWithCountry(digits, country)){ showToast('Phone does not match selected country format','danger'); phoneEl.classList.add('is-invalid'); return; }
  phoneEl.classList.remove('is-invalid');
  const r = await apiPost('/lookup/phone', {phone: phone});
  if(!r.ok){ showToast('Search failed','danger'); return; }
  const j = await r.json();
  if(!j.found){ showToast('No record found','info'); return; }
  // show summary; include PII if available
  let html = `<p><strong>Anon ID:</strong> ${escapeHtml(j.anon_id)}</p><p><strong>Status:</strong> ${escapeHtml(j.status || '')}</p>`;
  if(j.items) html += `<p><strong>Items:</strong><pre>${escapeHtml(JSON.stringify(j.items, null, 2))}</pre></p>`;
  if(j.pii) html += `<p><strong>PII:</strong><pre>${escapeHtml(JSON.stringify(j.pii, null, 2))}</pre></p>`;
  showResultModal('Search Result', html);
}

async function viewExportLogs(){
  const r = await apiGet('/admin/export-logs');
  if(!r.ok){ showResultModal('Error','<p>Failed to fetch logs (auth required)</p>'); return; }
  const logs = await r.json();
  if(!logs || !logs.length) { showResultModal('Export Logs','<p>No export logs found.</p>'); return; }
  let table = '<table class="table table-sm"><thead><tr><th>ID</th><th>User</th><th>Action</th><th>Rows</th><th>When</th></tr></thead><tbody>';
  logs.forEach(l=>{ table += `<tr><td>${escapeHtml(String(l.id))}</td><td>${escapeHtml(l.username||'')}</td><td>${escapeHtml(l.action||'')}</td><td>${escapeHtml(String(l.rows||0))}</td><td>${escapeHtml(l.created_at||'')}</td></tr>`; });
  table += '</tbody></table>';
  showResultModal('Export Logs', table);
}

// Export identifying CSV flow: show confirm modal, then POST confirm and download
document.addEventListener('DOMContentLoaded', ()=>{
  const btn = document.getElementById('export-identifying-btn');
  if(btn){
    btn.addEventListener('click', ()=>{
      const em = new bootstrap.Modal(document.getElementById('exportConfirmModal'));
      em.show();
    });
  }
  const confirmBtn = document.getElementById('confirmExportBtn');
  if(confirmBtn){
    confirmBtn.addEventListener('click', async ()=>{
      // disable button to avoid double-click
      confirmBtn.disabled = true;
      const emEl = document.getElementById('exportConfirmModal');
      const em = bootstrap.Modal.getInstance(emEl);
      try{
        const auth = getAuth();
        const res = await fetch('/export/identifying', {method:'POST', headers: {'Authorization': auth, 'Content-Type':'application/json'}, body: JSON.stringify({confirm:true})});
        if(!res.ok){ const t = await res.text(); showResultModal('Error', `<pre>${escapeHtml(t)}</pre>`); return; }
        const csv = await res.text();
        // create download
        const blob = new Blob([csv], {type:'text/csv'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a'); a.href = url; a.download = 'identifying_export.csv'; a.click();
        showToast('Identifying CSV downloaded and export logged','success');
      }catch(e){ showResultModal('Error', `<pre>${escapeHtml(String(e))}</pre>`); }
      finally{ confirmBtn.disabled = false; if(em) em.hide(); }
    });
  }
});

