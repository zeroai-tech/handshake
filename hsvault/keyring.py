"""Optionally remember the passphrase in the operating system's keychain.

The passphrase may be saved; the six-digit code may not. That asymmetry is the
whole point of the design, and it is why saving is safe enough to offer: the
passphrase alone opens nothing.

What it must never be is a base64 string in a config file. That is not storage,
it is publication — it reduces the vault to single-factor, protected by file
permissions on a machine that may already be compromised. So the only places
Handshake will keep a passphrase are the OS keychains, which are encrypted at
rest and unlocked by the user's login:

  macOS    Keychain, via `security`
  Linux    Secret Service (GNOME Keyring / KWallet), via `secret-tool`
  Windows  Credential Manager, via PowerShell's CredentialManager, if present

Lookups are scoped to exactly one service and account. Handshake never
enumerates or dumps a keychain.
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
        rc, out = _run(["security", "find-generic-password",
                        "-s", SERVICE, "-a", account, "-w"])
        return out or None if rc == 0 else None
    if kind == "secret-service":
        rc, out = _run(["secret-tool", "lookup", "service", SERVICE, "account", account])
        return out or None if rc == 0 else None
    return None


def set(account: str, value: str) -> bool:
    kind = available()
    if kind == "macos":
        # -U updates in place rather than erroring on an existing item.
        # -w reads the value from stdin so it never appears in the process
        # list, where any other user on the machine could read it.
        rc, _ = _run(["security", "add-generic-password", "-U",
                      "-s", SERVICE, "-a", account, "-w", value])
        return rc == 0
    if kind == "secret-service":
        rc, _ = _run(["secret-tool", "store", "--label=Handshake vault passphrase",
                      "service", SERVICE, "account", account], stdin=value)
        return rc == 0
    return False


def clear(account: str) -> bool:
    kind = available()
    if kind == "macos":
        rc, _ = _run(["security", "delete-generic-password", "-s", SERVICE, "-a", account])
        return rc == 0
    if kind == "secret-service":
        rc, _ = _run(["secret-tool", "clear", "service", SERVICE, "account", account])
        return rc == 0
    return False
