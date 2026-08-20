"""Crypto helpers. One real weakness; one look-alike that is FINE."""
import hashlib
from Crypto.Cipher import AES

# BUG (CWE-327/CWE-916): MD5 for password hashing. Fast, unsalted, broken.
def hash_password(pw: str) -> str:
    return hashlib.md5(pw.encode()).hexdigest()

# BUG (CWE-327/CWE-329): AES-ECB with a hardcoded, reused IV-equivalent.
_KEY = b"0123456789abcdef"
def encrypt_blob(data: bytes) -> bytes:
    cipher = AES.new(_KEY, AES.MODE_ECB)
    pad = 16 - (len(data) % 16)
    return cipher.encrypt(data + bytes([pad]) * pad)
