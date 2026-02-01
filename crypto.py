import os
import json
import re
import hashlib
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def get_key() -> bytes:
    # Expect SECRET_KEY as hex or base64 in env
    k = os.environ.get('SECRET_KEY')
    if not k:
        raise RuntimeError('SECRET_KEY not set')
    # try hex
    try:
        return bytes.fromhex(k)
    except Exception:
        try:
            return b64decode(k)
        except Exception:
            raise RuntimeError('SECRET_KEY must be hex or base64')


def encrypt_pii(pii: dict) -> bytes:
    key = get_key()
    aes = AESGCM(key)
    nonce = os.urandom(12)
    data = json.dumps(pii, separators=(',', ':')).encode()
    ct = aes.encrypt(nonce, data, None)
    return nonce + ct


def decrypt_pii(blob: bytes) -> dict:
    key = get_key()
    aes = AESGCM(key)
    nonce = blob[:12]
    ct = blob[12:]
    pt = aes.decrypt(nonce, ct, None)
    return json.loads(pt.decode())


def normalize_phone(phone: str) -> str:
    if not phone:
        return ''
    digits = re.sub(r"\D", "", phone)
    # naive: return last 10 digits if longer
    if len(digits) > 10:
        digits = digits[-10:]
    return digits


def phone_hash(norm_phone: str) -> str:
    return hashlib.sha256(norm_phone.encode()).hexdigest()
