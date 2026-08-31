# Security policy

## Reporting a vulnerability

Use [private vulnerability
reporting](https://github.com/zeroai-tech/handshake/security/advisories/new).
Please do not open a public issue for anything that would let someone read a
vault they do not own.

Include what you need to demonstrate the problem and a rough impact assessment.
You will get a first response within 72 hours. If a fix is warranted, we will
agree a disclosure date with you and credit you in the advisory unless you would
rather we did not.

## Scope

**In scope** — anything that lets an attacker read plaintext without both
factors, or that silently weakens a stated guarantee:

- Recovering a secret from ciphertext, a database dump, or an export
- Using a wrapped DEK against a secret it was not wrapped for
- Bypassing TOTP, or opening a session without a passphrase
- Forging, replaying, or extending a session token
- Spending a session token from a different network than it was issued to
- Making the KDF cheaper than the stated parameters
- Plaintext, keys, or passphrases written anywhere on disk
- A crash or error message that leaks a secret's value

**Out of scope** — real, but not something this tool claims to solve:

- Root or an equivalent on an unlocked machine. Nothing in userspace survives it.
- A weak passphrase. The KDF makes guessing expensive, not impossible.
- An agent misusing a credential you deliberately gave it. Handshake bounds and
  records that; it cannot prevent it.
- Denial of service by someone holding your backend token. They can delete the
  vault. They cannot read it. That is why recovery shares exist.
- Losing every recovery share and forgetting the passphrase. There is no back
  door, and adding one would be the vulnerability.

## What is guaranteed

The [threat model table](README.md#threat-model) in the README is the
specification. If Handshake behaves differently from that table, it is a bug,
and a security bug — report it under this policy.

## Cryptography

| Purpose | Construction |
|---|---|
| Key derivation | scrypt, N=2¹⁸, r=8, p=1, 32-byte output, 16-byte random salt |
| Encryption | AES-256-GCM, 96-bit random nonce per operation |
| Key wrapping | AES-256-GCM with the secret's name as AAD |
| Passphrase check | HMAC-SHA256 over a fixed label and the salt |
| Second factor | TOTP (RFC 6238), SHA-1, 6 digits, 30s, ±1 step, constant-time compare |
| Recovery | Shamir over GF(256), 2-of-3 |
| Session token | 256 bits from `secrets.token_urlsafe`; only SHA-256 stored |
| Session binding | Expiry, plus same /24 (IPv4) or /64 (IPv6) as the unlock |

No custom primitives. AES-GCM comes from [`cryptography`](https://cryptography.io);
scrypt, HMAC and SHA-256 from the Python standard library. The Shamir and TOTP
implementations are ours and are the most valuable things to review — they are
in `hsvault/crypto.py` and `hsvault/totp.py`, roughly 200 lines together.

Handshake has **not** had a third-party audit. Judge it accordingly.

## Supported versions

The latest release on `main`. There are no long-term support branches yet.
