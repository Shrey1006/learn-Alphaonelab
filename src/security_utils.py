import base64
import hashlib
import hmac as _hmac
import json
import os

import js
from pyodide.ffi import to_js

from http_utils import capture_exception


def new_id() -> str:
    """Generate a random UUID v4 using os.urandom."""
    b = bytearray(os.urandom(16))
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    h = b.hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def _derive_key(secret: str) -> bytes:
    """Derive a 32-byte key from an arbitrary secret string via SHA-256."""
    return hashlib.sha256(secret.encode("utf-8")).digest()


def _derive_aes_key_bytes(secret: str) -> bytes:
    """Derive a 32-byte AES-256 key via PBKDF2-SHA256 with a fixed domain salt."""
    salt = hashlib.sha256(b"aol-edu-aes-salt-v1" + secret.encode()).digest()
    return hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 100_000)


async def _import_aes_key(key_bytes: bytes) -> object:
    """Import raw bytes as a Web Crypto AES-GCM CryptoKey."""
    key_buf = to_js(key_bytes, create_pyproxies=False)
    algo = to_js({"name": "AES-GCM"}, dict_converter=js.Object.fromEntries)
    usages = to_js(["encrypt", "decrypt"])
    return await js.crypto.subtle.importKey("raw", key_buf, algo, False, usages)


async def encrypt_aes(plaintext: str, secret: str) -> str:
    """
    AES-256-GCM encryption using js.crypto.subtle (Web Crypto API).
    Returns "v1:" + base64(iv || ciphertext+tag).
    """
    if not plaintext:
        return ""
    try:
        key_bytes = _derive_aes_key_bytes(secret)
        crypto_key = await _import_aes_key(key_bytes)

        iv_array = js.Uint8Array.new(12)
        js.crypto.getRandomValues(iv_array)
        iv = bytes(iv_array)

        algo = to_js({"name": "AES-GCM", "iv": iv_array}, dict_converter=js.Object.fromEntries)
        data = to_js(plaintext.encode("utf-8"))
        ct_buf = await js.crypto.subtle.encrypt(algo, crypto_key, data)
        ct = bytes(js.Uint8Array.new(ct_buf))
        return "v1:" + base64.b64encode(iv + ct).decode("ascii")
    except Exception as exc:
        capture_exception(exc, where="encrypt_aes")
        raise RuntimeError(f"AES-256-GCM encryption failed: {exc}") from exc


async def decrypt_aes(ciphertext: str, secret: str) -> str:
    """AES-256-GCM decryption. Handles both v1 and legacy XOR ciphertext."""
    if not ciphertext:
        return ""
    if not ciphertext.startswith("v1:"):
        return _decrypt_xor(ciphertext, secret)
    try:
        raw = base64.b64decode(ciphertext[3:])
        iv, ct = raw[:12], raw[12:]
    except Exception as exc:
        capture_exception(exc, where="decrypt_aes.decode")
        return "[decryption error]"
    try:
        key_bytes = _derive_aes_key_bytes(secret)
        crypto_key = await _import_aes_key(key_bytes)
        iv_array = to_js(iv)
        algo = to_js({"name": "AES-GCM", "iv": iv_array}, dict_converter=js.Object.fromEntries)
        data = to_js(ct)
        pt_buf = await js.crypto.subtle.decrypt(algo, crypto_key, data)
        return bytes(js.Uint8Array.new(pt_buf)).decode("utf-8")
    except Exception as exc:
        capture_exception(exc, where="decrypt_aes.auth")
        return "[decryption error]"


def _encrypt_xor(plaintext: str, secret: str) -> str:
    """Legacy XOR stream cipher kept for backward compatibility only."""
    if not plaintext:
        return ""
    key = _derive_key(secret)
    data = plaintext.encode("utf-8")
    ks = (key * (len(data) // len(key) + 1))[: len(data)]
    return base64.b64encode(bytes(a ^ b for a, b in zip(data, ks))).decode("ascii")


def _decrypt_xor(ciphertext: str, secret: str) -> str:
    """Legacy XOR stream cipher decryption kept for backward compatibility."""
    if not ciphertext:
        return ""
    try:
        key = _derive_key(secret)
        raw = base64.b64decode(ciphertext)
        ks = (key * (len(raw) // len(key) + 1))[: len(raw)]
        return bytes(a ^ b for a, b in zip(raw, ks)).decode("utf-8")
    except Exception:
        return "[decryption error]"


def blind_index(value: str, secret: str) -> str:
    """HMAC-SHA256 deterministic hash used as a blind index."""
    return _hmac.new(
        secret.encode("utf-8"), value.lower().encode("utf-8"), hashlib.sha256
    ).hexdigest()


_PEPPER = b"edu-platform-cf-pepper-2024"
_PBKDF2_IT = 100_000


def _user_salt(username: str) -> bytes:
    """Per-user PBKDF2 salt = SHA-256(pepper || username)."""
    return hashlib.sha256(_PEPPER + username.encode("utf-8")).digest()


def hash_password(password: str, username: str) -> str:
    """PBKDF2-SHA256 with per-user derived salt."""
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), _user_salt(username), _PBKDF2_IT
    )
    return base64.b64encode(dk).decode("ascii")


def verify_password(password: str, stored: str, username: str) -> bool:
    return hash_password(password, username) == stored


def create_token(uid: str, username: str, role: str, secret: str) -> str:
    payload = base64.b64encode(
        json.dumps({"id": uid, "username": username, "role": role}).encode()
    ).decode("ascii")
    sig = _hmac.new(
        secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"{payload}.{sig}"


def verify_token(raw: str, secret: str):
    """Return decoded payload dict or None if invalid/missing."""
    if not raw:
        return None
    try:
        token = raw.removeprefix("Bearer ").strip()
        dot = token.rfind(".")
        if dot == -1:
            return None
        payload, sig = token[:dot], token[dot + 1:]
        exp = _hmac.new(
            secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not _hmac.compare_digest(sig, exp):
            return None
        padding = (4 - len(payload) % 4) % 4
        return json.loads(base64.b64decode(payload + "=" * padding).decode("utf-8"))
    except Exception:
        return None
