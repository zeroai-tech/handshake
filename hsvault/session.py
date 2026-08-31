"""Unlock sessions.

Three things must all hold for a session to be usable:

  1. The caller presents the session token. It is printed once at unlock and
     never written to disk in usable form — only its SHA-256 is stored. An
     agent that did not perform the unlock in this conversation does not have
     it, so opening a new chat forces a fresh unlock even on the same machine.
  2. It has not expired.
  3. The public IP still matches the one it was issued to.

Losing any one of those ends the session. That is deliberate: the intent is
that closing this instance and opening another means proving who you are again.
"""
from __future__ import annotations
import hashlib, json, os, secrets, time, urllib.request
from pathlib import Path

STATE = Path(os.environ.get("HANDSHAKE_HOME", Path.home() / ".handshake"))
SESSION_FILE = STATE / "session.json"
DEFAULT_TTL = 30 * 60


def _h(tok: str) -> str:
    return hashlib.sha256(tok.encode()).hexdigest()


def public_ip(timeout: int = 6) -> str | None:
    """Best effort. If it cannot be determined the session is simply not
    IP-bound, rather than refusing to work on a train."""
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                ip = r.read().decode().strip()
                if ip and len(ip) < 46:
                    return ip
        except Exception:
            continue
    return None


def begin(kek: bytes, ttl: int = DEFAULT_TTL, bind_ip: bool = True) -> str:
    """Open a session and return its token — shown once, to the human."""
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)
    # The KEK is kept only for this session's lifetime, encrypted under the
    # token itself. Without the token the file is inert, so a stolen laptop
    # yields nothing unless the thief also has the token from the transcript.
    from .crypto import seal
    tk = hashlib.sha256(("session-key:" + token).encode()).digest()
    rec = {
        "token_hash": _h(token),
        "kek": seal(tk, kek, aad=b"handshake-session"),
        "expires_at": int(time.time()) + ttl,
        "ip": public_ip() if bind_ip else None,
        "started_at": int(time.time()),
    }
    SESSION_FILE.write_text(json.dumps(rec))
    SESSION_FILE.chmod(0o600)
    return token


def resolve(token: str) -> tuple[bytes | None, str]:
    """Return (kek, reason). kek is None when the session cannot be used."""
    if not token:
        return None, "no session token — run: handshake unlock"
    try:
        rec = json.loads(SESSION_FILE.read_text())
    except Exception:
        return None, "no open session — run: handshake unlock"
    if not secrets.compare_digest(rec.get("token_hash", ""), _h(token)):
        return None, "that session token is not valid here — run: handshake unlock"
    if time.time() > rec.get("expires_at", 0):
        return None, "session expired — run: handshake unlock"
    if rec.get("ip"):
        now = public_ip()
        if now and now != rec["ip"]:
            return None, f"network changed since unlock ({rec['ip']} -> {now}) — run: handshake unlock"
    from .crypto import unseal
    tk = hashlib.sha256(("session-key:" + token).encode()).digest()
    try:
        return unseal(tk, rec["kek"], aad=b"handshake-session"), "ok"
    except Exception:
        return None, "session record is corrupt — run: handshake unlock"


def end() -> bool:
    try:
        SESSION_FILE.unlink()
        return True
    except FileNotFoundError:
        return False


def status() -> dict:
    try:
        rec = json.loads(SESSION_FILE.read_text())
    except Exception:
        return {"open": False}
    left = int(rec.get("expires_at", 0) - time.time())
    return {"open": left > 0, "seconds_left": max(0, left), "ip": rec.get("ip")}
