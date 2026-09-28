import base64, hashlib
from cryptography.fernet import Fernet

def _key(password: str) -> bytes:
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)

def encrypt_bytes(data: bytes, password: str) -> bytes:
    return Fernet(_key(password)).encrypt(data)

def decrypt_bytes(token: bytes, password: str) -> bytes:
    return Fernet(_key(password)).decrypt(token)
