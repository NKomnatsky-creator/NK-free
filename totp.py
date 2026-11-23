"""TOTP (RFC 6238) на стандартной библиотеке — без внешних зависимостей."""

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from urllib.parse import quote, urlencode

DIGITS = 6
PERIOD = 30


def generate_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode('ascii').rstrip('=')


def _hotp(secret: str, counter: int) -> str:
    padded = secret + '=' * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded.upper(), casefold=True)
    digest = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** DIGITS)).zfill(DIGITS)


def verify_totp(secret: str, code: str, window: int = 1, now: float = None) -> bool:
    if not secret or not code:
        return False
    code = str(code)
    if not code.isascii() or not code.isdigit() or len(code) != DIGITS:
        return False
    counter = int((time.time() if now is None else now) // PERIOD)
    for delta in range(-window, window + 1):
        if hmac.compare_digest(_hotp(secret, counter + delta), code):
            return True
    return False


def provisioning_uri(secret: str, account: str, issuer: str = 'NK Secure') -> str:
    label = quote(f'{issuer}:{account}', safe='')
    params = urlencode({
        'secret': secret,
        'issuer': issuer,
        'algorithm': 'SHA1',
        'digits': DIGITS,
        'period': PERIOD,
    })
    return f'otpauth://totp/{label}?{params}'


def generate_recovery_codes(count: int = 8) -> list:
    # 128 бит энтропии на код: короткие 32-битные коды легко подобрать при утечке БД.
    return [f'{secrets.token_hex(8)}-{secrets.token_hex(8)}' for _ in range(count)]


def hash_recovery_code(code: str) -> str:
    return hashlib.sha256(''.join(ch for ch in str(code) if ch.isalnum()).encode()).hexdigest()
