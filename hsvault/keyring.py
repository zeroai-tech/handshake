"""Optional OS password storage, enabled by the CLI only with key-file protection.

macOS uses native Keychain APIs; Linux uses Secret Service with stdin.
There is no Windows implementation. Password caching is not protection
against malicious software running as the same user.
"""
from __future__ import annotations
import shutil, subprocess, sys

SERVICE = "handshake-vault"


def _run(cmd: list[str], stdin: str | None = None) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=20)
        return p.returncode, (p.stdout or "").strip()
    except (OSError, subprocess.SubprocessError):
        return 1, ""


def available() -> str | None:
    if sys.platform == "darwin" and shutil.which("security"):
        return "macos"
    if shutil.which("secret-tool"):
        return "secret-service"
    return None


def get(account: str) -> str | None:
    kind = available()
    if kind == "macos":
        from .macos_keychain import perform
        try: return perform('get', SERVICE, account)
        except (OSError, ValueError): return None
    if kind == "secret-service":
        rc, out = _run(["secret-tool", "lookup", "service", SERVICE, "account", account])
        return out or None if rc == 0 else None
    return None


def set(account: str, value: str) -> bool:
    kind = available()
    if kind == "macos":
        from .macos_keychain import perform
        try: return perform('set', SERVICE, account, value)
        except (OSError, ValueError): return False
    if kind == "secret-service":
        rc, _ = _run(["secret-tool", "store", "--label=Handshake vault passphrase",
                      "service", SERVICE, "account", account], stdin=value)
        return rc == 0
    return False


def clear(account: str) -> bool:
    kind = available()
    if kind == "macos":
        from .macos_keychain import perform
        try: return perform('clear', SERVICE, account)
        except (OSError, ValueError): return False
    if kind == "secret-service":
        rc, _ = _run(["secret-tool", "clear", "service", SERVICE, "account", account])
        return rc == 0
    return False
