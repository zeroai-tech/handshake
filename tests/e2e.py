"""End-to-end test of the real CLI through a pty.

Everything else is unit-tested. This exercises the thing a user actually
touches: init, unlock, put, get, run, export/import, passwd, and the session
rules — including the ones that must FAIL.
"""
import os, pty, re, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
HOME = tempfile.mkdtemp(prefix="handshake-e2e-")
# Prefer the repo's venv when it exists (local dev); fall back to whatever
# interpreter is running us (CI, or a system-wide install).
_venv = ROOT / ".venv" / "bin" / "python"
PY_ = str(_venv) if _venv.exists() else sys.executable
ENV = {**os.environ, "HANDSHAKE_HOME": HOME, "HANDSHAKE_BACKEND": "sqlite",
       "HANDSHAKE_SQLITE_PATH": os.path.join(HOME, "vault.db"), "PYTHONUNBUFFERED": "1"}

PASS = "correct horse battery staple"
ok = fail = 0


def check(label, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1; print(f"  ok    {label}")
    else:
        fail += 1; print(f"  FAIL  {label}  {extra}")


def interact(args, script, timeout=90):
    """Run the CLI on a pty, feeding lines when prompts appear."""
    pid, fd = pty.fork()
    if pid == 0:
        os.environ.update(ENV)
        os.execv(PY_, [PY_, str(ROOT / "handshake.py"), *args])
    out, deadline, pending = "", time.time() + timeout, list(script)
    os.set_blocking(fd, False)
    while time.time() < deadline:
        try:
            chunk = os.read(fd, 65536).decode(errors="replace")
            if not chunk:
                break
            out += chunk
        except BlockingIOError:
            time.sleep(0.05)
        except OSError:
            break
        while pending and callable(pending[0]) is False and pending[0][0] in out:
            _, reply = pending.pop(0)
            os.write(fd, (reply(out) if callable(reply) else reply).encode() + b"\n")
            time.sleep(0.2)
        if not pending and os.waitpid(pid, os.WNOHANG)[0]:
            try:
                out += os.read(fd, 65536).decode(errors="replace")
            except (BlockingIOError, OSError):
                pass
            break
    try: os.close(fd)
    except OSError: pass
    try: os.waitpid(pid, 0)
    except ChildProcessError: pass
    return out


def run(args, **kw):
    return subprocess.run([PY_, str(ROOT / "handshake.py"), *args],
                          capture_output=True, text=True, env=ENV, timeout=90, **kw)


print("\n  Handshake end-to-end\n")

# ── init ────────────────────────────────────────────────────────────────────
secret_box = {}


def grab_totp(buf):
    m = re.search(r"type this key in by hand:\s*\n\s*\n\s*([A-Z2-7]{16,})", buf)
    if not m:
        return "000000"
    secret_box["s"] = m.group(1)
    from hsvault import totp
    return totp.code_at(m.group(1), time.time())


out = interact(["init", "--account", "e2e"], [
    ("Choose a passphrase", PASS),
    ("Repeat it", PASS),
    ("6-digit code", grab_totp),
])
check("init creates the vault", "Vault created" in out, out[-400:])
check("init prints recovery shares", out.count("share ") >= 3)
check("init prints where the vault lives", "WHERE THE VAULT LIVES" in out)
shares = re.findall(r"share \d:\s+(\d+-[A-Za-z0-9+/=]+)", out)
check("three shares captured", len(shares) == 3, str(len(shares)))
S = secret_box.get("s")
check("totp secret captured", bool(S))

# Everything after this needs a working vault. Without one the remaining
# checks all fail for the same reason and bury the real cause, so stop here.
if not S or "Vault created" not in out:
    print("\n  init failed — the rest of the suite cannot run.")
    print("  Last output from init:\n")
    print("\n".join("    " + l for l in out.strip().splitlines()[-25:]))
    sys.exit(1)

# ── init is not repeatable without --force ──────────────────────────────────
out = interact(["init"], [("Choose a passphrase", PASS)])
check("second init refuses", "already exists" in out, out[-200:])

from hsvault import totp  # noqa: E402

# ── unlock: wrong passphrase, then wrong code, then correct ─────────────────
out = interact(["unlock"], [("Passphrase", "not the passphrase")])
check("wrong passphrase rejected", "Wrong passphrase" in out, out[-200:])

out = interact(["unlock"], [("Passphrase", PASS), ("6-digit code", "000000")])
check("wrong 2FA code rejected", "not valid" in out, out[-200:])

out = interact(["unlock", "--ttl", "600"], [
    ("Passphrase", PASS),
    ("6-digit code", lambda _: totp.code_at(S, time.time())),
])
m = re.search(r"\n\s{4}([A-Za-z0-9_\-]{40,})\s*\n", out)
TOK = m.group(1) if m else ""
check("unlock issues a session token", bool(TOK), out[-300:])

# ── secrets ─────────────────────────────────────────────────────────────────
r = run(["put", "prod/api-key", "--value", "sk-live-123", "--note", "billing",
         "--category", "prod", "-s", TOK])
check("put stores a secret", "stored prod/api-key" in r.stdout, r.stdout + r.stderr)

r = run(["get", "prod/api-key", "--reason", "e2e test", "-s", TOK])
check("get returns the exact value", r.stdout.strip() == "sk-live-123", repr(r.stdout))

r = run(["get", "prod/api-key", "-n", "-s", TOK])
check("get -n omits the newline", r.stdout == "sk-live-123", repr(r.stdout))

r = run(["list", "-s", TOK])
check("list shows the name", "prod/api-key" in r.stdout)
check("list never shows the value", "sk-live-123" not in r.stdout, r.stdout)

r = run(["get", "nope", "-s", TOK])
check("missing secret is an error", r.returncode != 0 and "No secret" in r.stdout)

# ── session rules that must FAIL ────────────────────────────────────────────
r = run(["get", "prod/api-key"])
check("no token is refused", r.returncode != 0 and "session" in r.stdout.lower(), r.stdout)

r = run(["get", "prod/api-key", "-s", "not-a-real-token"])
check("forged token is refused", r.returncode != 0, r.stdout)
check("forged token leaks nothing", "sk-live-123" not in r.stdout)

# ── run: credentials into a child process only ──────────────────────────────
r = run(["run", "-s", TOK, "-e", "MY_KEY=prod/api-key", "--",
         "/bin/sh", "-c", "echo got:$MY_KEY"])
check("run injects into the child env", "got:sk-live-123" in r.stdout, r.stdout + r.stderr)
check("run does not leak into this process", os.environ.get("MY_KEY") is None)

# ── audit trail ─────────────────────────────────────────────────────────────
r = run(["log", "--limit", "50", "-s", TOK])
check("audit recorded the read reason", "e2e test" in r.stdout, r.stdout[-400:])
check("audit recorded the failed unlock", "bad passphrase" in r.stdout)
check("audit never contains the value", "sk-live-123" not in r.stdout)

# ── bulk import from a .env file ────────────────────────────────────────────
envfile = os.path.join(HOME, "sample.env")
Path(envfile).write_text(
    "# a comment\n"
    "OPENAI_API_KEY=sk-env-aaa\n"
    "export QUOTED_KEY=\"has spaces here\"\n"
    "SINGLE='single quoted'\n"
    "EMPTY=\n"
    "malformed line without equals\n")
r = run(["import-env", envfile, "--prefix", "dev/", "--category", "dev", "-s", TOK])
check("import-env adds each key", "3 added" in r.stdout, r.stdout + r.stderr)
check("import-env applies the prefix", "dev/OPENAI_API_KEY" in r.stdout)
check("import-env skips comments and junk", "malformed" not in r.stdout)

r = run(["get", "dev/OPENAI_API_KEY", "-s", TOK])
check("imported value is exact", r.stdout.strip() == "sk-env-aaa", repr(r.stdout))
r = run(["get", "dev/QUOTED_KEY", "-s", TOK])
check("import-env strips double quotes", r.stdout.strip() == "has spaces here", repr(r.stdout))
r = run(["get", "dev/SINGLE", "-s", TOK])
check("import-env strips single quotes", r.stdout.strip() == "single quoted", repr(r.stdout))

r = run(["import-env", envfile, "--prefix", "dev/", "--skip-existing", "-s", TOK])
check("import-env --skip-existing is idempotent", "3 skipped" in r.stdout, r.stdout)

# ── export / import between backends ────────────────────────────────────────
exp = os.path.join(HOME, "vault.json")
r = run(["export", "--out", exp, "-s", TOK])
check("export writes a file", os.path.exists(exp), r.stdout)
body = Path(exp).read_text()
check("export is still encrypted", "sk-live-123" not in body)
check("export is owner-only", oct(os.stat(exp).st_mode & 0o777) == "0o600")

ENV2 = {**ENV, "HANDSHAKE_SQLITE_PATH": os.path.join(HOME, "vault2.db")}
r = subprocess.run([PY_, str(ROOT / "handshake.py"), "import", exp],
                   capture_output=True, text=True, env=ENV2, timeout=60)
check("import into a second backend", "imported 4 secret" in r.stdout, r.stdout + r.stderr)

# ── recovery shares actually work ───────────────────────────────────────────
out = interact(["recover"], [("Paste two recovery shares", shares[0] + "\n" + shares[2] + "\n")])
check("two shares rebuild the vault", "Recovered" in out, out[-300:])

# ── lock ────────────────────────────────────────────────────────────────────
run(["lock"])
r = run(["get", "prod/api-key", "-s", TOK])
check("lock ends the session", r.returncode != 0, r.stdout)

print(f"\n  {ok} passed, {fail} failed\n")
sys.exit(1 if fail else 0)
