"""Envelope encryption for the vault.

The shape, and why:

    passphrase --scrypt--> KEK          (derived on use, never stored)
    KEK --AES-GCM--> wraps each secret's own DEK
    DEK --AES-GCM--> encrypts one secret

Every secret gets its own key, so one leaked plaintext tells an attacker nothing
about the others. Only wrapped DEKs and ciphertext are ever written down, which
is what lets the vault live in Cloudflare D1 without Cloudflare — or anyone
holding the D1 token — being able to read it.

scrypt rather than Argon2id purely because it is in the standard library:
argon2-cffi needs a compiler on a fresh machine, and a recovery tool that cannot
be installed on a freshly wiped laptop is worse than useless. The parameters
below are deliberately expensive.

AES-GCM is authenticated, so tampering with stored ciphertext is detected rather
than silently returning wrong bytes.
"""
from __future__ import annotations
import hashlib, hmac, os, base64, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ~256 MB and around a second per attempt on a modern laptop. That is barely
# noticeable when you unlock once a session, and brutal for anyone guessing.
SCRYPT_N = 2 ** 18
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32

b64e = lambda b: base64.b64encode(b).decode()
b64d = lambda s: base64.b64decode(s.encode())


def derive_kek(passphrase: str, salt: bytes) -> bytes:
    """Passphrase -> key-encrypting key. Intentionally slow."""
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt,
                          n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=KEY_LEN,
                          maxmem=SCRYPT_N * SCRYPT_R * 256)


def seal(key: bytes, plaintext: bytes, aad: bytes = b"") -> str:
    """AES-256-GCM. `aad` binds the ciphertext to its context — a secret's
    record cannot be copied over another one's without the tag failing."""
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return b64e(nonce + ct)


def unseal(key: bytes, blob: str, aad: bytes = b"") -> bytes:
    raw = b64d(blob)
    return AESGCM(key).decrypt(raw[:12], raw[12:], aad)


def new_dek() -> bytes:
    return os.urandom(KEY_LEN)


def wrap_dek(kek: bytes, dek: bytes, name: str) -> str:
    """The secret's name is authenticated, so a wrapped key cannot be moved
    from one secret to another."""
    return seal(kek, dek, aad=name.encode())


def unwrap_dek(kek: bytes, wrapped: str, name: str) -> bytes:
    return unseal(kek, wrapped, aad=name.encode())


def verifier(kek: bytes, salt: bytes) -> str:
    """A value that proves a passphrase is right WITHOUT storing the key.

    It is an HMAC of a fixed label under the KEK. Anyone reading it learns
    nothing usable: reversing it means breaking HMAC-SHA256, and guessing means
    paying the scrypt cost per attempt.
    """
    return hmac.new(kek, b"handshake-verifier-v1" + salt, hashlib.sha256).hexdigest()


def check_passphrase(passphrase: str, salt: bytes, expected: str) -> bytes | None:
    kek = derive_kek(passphrase, salt)
    return kek if hmac.compare_digest(verifier(kek, salt), expected) else None


# ── Recovery ────────────────────────────────────────────────────────────────
# Shamir over GF(256): the KEK is split into shares, any `threshold` of which
# reconstruct it. Fewer than the threshold reveal nothing at all — that is a
# property of the maths, not of keeping the shares secret.
def _gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi: a ^= 0x1B
        b >>= 1
    return p


def _gf_pow(a: int, n: int) -> int:
    r = 1
    for _ in range(n): r = _gf_mul(r, a)
    return r


def _gf_inv(a: int) -> int:
    return _gf_pow(a, 254)


def split_secret(secret: bytes, shares: int, threshold: int) -> list[str]:
    if not 2 <= threshold <= shares <= 255:
        raise ValueError("need 2 <= threshold <= shares <= 255")
    out = [bytearray() for _ in range(shares)]
    for byte in secret:
        coeffs = [byte] + list(os.urandom(threshold - 1))
        for i in range(shares):
            x = i + 1
            y = 0
            for power, c in enumerate(coeffs):
                y ^= _gf_mul(c, _gf_pow(x, power))
            out[i].append(y)
    return [f"{i+1}-{b64e(bytes(s))}" for i, s in enumerate(out)]


def combine_shares(shares: list[str]) -> bytes:
    pts = []
    for s in shares:
        idx, data = s.split("-", 1)
        pts.append((int(idx), b64d(data)))
    length = len(pts[0][1])
    out = bytearray()
    for pos in range(length):
        total = 0
        for i, (xi, yi) in enumerate(pts):
            num, den = 1, 1
            for j, (xj, _) in enumerate(pts):
                if i == j: continue
                num = _gf_mul(num, xj)
                den = _gf_mul(den, xi ^ xj)
            total ^= _gf_mul(yi[pos], _gf_mul(num, _gf_inv(den)))
        out.append(total)
    return bytes(out)
