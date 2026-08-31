"""Time-based one-time passwords (RFC 6238), compatible with Google Authenticator.

The whole point of this file: the passphrase may be remembered by the machine,
but the six-digit code cannot be. It exists only on a phone, so every unlock
needs a human present. That is what stops an agent — or anything else with
access to this laptop — from opening the vault on its own.
"""
from __future__ import annotations
import base64, hmac, hashlib, os, struct, time, urllib.parse

DIGITS = 6
PERIOD = 30


def new_secret() -> str:
    """160 bits, base32 — what Google Authenticator expects."""
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def code_at(secret_b32: str, when: float | None = None, offset: int = 0) -> str:
    pad = "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(secret_b32.upper() + pad)
    counter = int((when or time.time()) // PERIOD) + offset
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    val = (struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** DIGITS)
    return str(val).zfill(DIGITS)


def verify(secret_b32: str, code: str, drift: int = 1) -> bool:
    """Accept one step either side, for clock skew between phone and laptop.
    Compared in constant time so a wrong code leaks nothing by timing."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit():
        return False
    return any(hmac.compare_digest(code_at(secret_b32, offset=o), code)
               for o in range(-drift, drift + 1))


def provisioning_uri(secret_b32: str, account: str, issuer: str = "Handshake") -> str:
    q = urllib.parse.urlencode({
        "secret": secret_b32, "issuer": issuer,
        "algorithm": "SHA1", "digits": DIGITS, "period": PERIOD,
    })
    label = urllib.parse.quote(f"{issuer}:{account}")
    return f"otpauth://totp/{label}?{q}"


def qr_ascii(uri: str) -> str:
    """Rendered locally. The secret never leaves this machine — no QR service,
    no image upload, nothing over the network."""
    import qrcode, io
    q = qrcode.QRCode(border=1)
    q.add_data(uri)
    q.make(fit=True)
    buf = io.StringIO()
    q.print_ascii(out=buf, invert=True)
    return buf.getvalue()
