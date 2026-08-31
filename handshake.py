#!/usr/bin/env python3
"""Handshake — a credential vault for people who work with AI agents.

The problem it exists for: agent CLIs run with your shell's environment. Every
API key you have exported is readable by every tool you run, and a `.env` file
is one `cat` away from any process that can execute code on your behalf. The
usual answer — a cloud secret manager — replaces the file with an always-valid
token sitting in the same environment, which is not obviously better.

Handshake's answer is to make the *open state* deliberate, brief, and visible:

  · Credentials live encrypted in a database you control. Whoever hosts it
    cannot read them, and neither can anyone who steals the hosting token.
  · Opening the vault takes a passphrase and a code from your phone. The
    passphrase can be remembered; the code cannot, so a human is always in the
    loop at least once per session.
  · An unlock produces a token that expires and is bound to your public IP.
    Agents spend that token; they cannot create one.
  · Every read is logged with a stated reason, so afterwards you can answer
    "what did that agent actually touch?"

The rule the whole design serves: an agent can USE a credential, but only a
person can UNLOCK the vault.
"""
from __future__ import annotations
import argparse, getpass, json, os, subprocess, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hsvault import crypto, keyring, session, store, totp
from hsvault.backends import BACKENDS, DESCRIPTIONS, PROMPTS

KEYRING_ACCOUNT = "passphrase"


def _die(msg: str, code: int = 1):
    print(f"  {msg}")
    sys.exit(code)


def _db():
    try:
        return store.backend()
    except RuntimeError as e:
        _die(str(e))


def _vault():
    return _db().get_vault()


def _ip():
    return session.status().get("ip")


def _passphrase(prompt="Passphrase: ") -> str:
    """Prompt, unless the OS keychain is holding it for us."""
    saved = keyring.get(KEYRING_ACCOUNT)
    if saved:
        return saved
    return getpass.getpass("  " + prompt)


def _ask(prompt: str, secret: bool = False, default: str = "") -> str:
    v = (getpass.getpass(f"  {prompt}: ") if secret else input(f"  {prompt}: ")).strip()
    return v or default


# ── setup ───────────────────────────────────────────────────────────────────
def _choose_backend() -> str:
    print("\n  Where should the vault live?\n")
    for i, b in enumerate(BACKENDS, 1):
        print(f"    {i}. {b:<9} {DESCRIPTIONS[b]}")
    print()
    while True:
        pick = input(f"  Choose 1-{len(BACKENDS)} [2]: ").strip() or "2"
        if pick.isdigit() and 1 <= int(pick) <= len(BACKENDS):
            return BACKENDS[int(pick) - 1]
        print("  Not one of the options.")


def _collect(name: str) -> dict:
    out = {}
    for key, prompt, is_secret in PROMPTS[name]:
        out[key] = _ask(prompt, is_secret)
    return {k: v for k, v in out.items() if v}


def cmd_connect(a):
    """Point this machine at a vault — new or existing.

    Writes only the vault's address and the credential needed to reach it.
    That grants no ability to read anything: the contents stay encrypted under
    a key this file never contains.
    """
    name = a.backend or _choose_backend()
    if name not in BACKENDS:
        _die(f"Unknown backend {name!r}. Choose from: {', '.join(BACKENDS)}")
    cfg = store.load_config()
    cfg["backend"] = name
    cfg[name] = {**cfg.get(name, {}), **_collect(name)}
    store.save_config(cfg)
    try:
        db = store.backend(refresh=True)
        db.ensure_schema()
        print(f"\n  Connected — {db.health()}")
    except RuntimeError as e:
        print(f"\n  Saved, but the vault did not answer:\n    {e}\n")
        if name == "supabase":
            print("  If the tables are missing, run: handshake setup-sql\n")
        sys.exit(1)
    print(f"  Next: handshake {'unlock' if _vault() else 'init'}\n")


def cmd_setup_sql(a):
    from hsvault.backends.supabase import SETUP_SQL
    print(SETUP_SQL)


def cmd_init(a):
    db = _db()
    try:
        db.ensure_schema()
    except RuntimeError as e:
        _die(f"{e}\n\n  Configure storage first: handshake connect")
    if db.get_vault() and not a.force:
        _die("A vault already exists here. --force destroys it and everything in it.")

    print("\n  Setting up Handshake.\n")
    print("  The passphrase is the one thing that is never stored anywhere,")
    print("  by anyone. Choose something long that you will not lose.\n")
    p1 = getpass.getpass("  Choose a passphrase (a sentence is ideal): ")
    if len(p1) < 12:
        _die("Too short. Twelve characters minimum, and longer is much better.")
    if p1 != getpass.getpass("  Repeat it: "):
        _die("Those did not match.")

    salt = os.urandom(16)
    print("\n  Deriving key (deliberately slow)…")
    kek = crypto.derive_kek(p1, salt)

    # Two-factor is not a setting. The vault cannot be created without it,
    # because "I'll turn it on later" is how it never gets turned on.
    tsec = totp.new_secret()
    uri = totp.provisioning_uri(tsec, a.account or "handshake")
    print("\n  Scan this with your authenticator app")
    print("  (Google Authenticator, 1Password, Aegis, Raivo — any TOTP app):\n")
    print(totp.qr_ascii(uri))
    print(f"  If the QR will not scan, type this key in by hand:\n\n    {tsec}\n")

    code = input("  Enter the 6-digit code to prove it is set up: ").strip()
    if not totp.verify(tsec, code):
        _die("That code did not verify — nothing was created. Try again.")

    db.put_vault(salt=crypto.b64e(salt), verifier=crypto.verifier(kek, salt),
                 totp_enc=crypto.seal(kek, tsec.encode(), aad=b"totp"),
                 created_at=int(time.time()))

    shares = crypto.split_secret(kek, 3, 2)
    print("\n  ── RECOVERY SHARES ──────────────────────────────────────────")
    print("  Any TWO of these three rebuild the vault if you forget the")
    print("  passphrase or lose your phone. Any ONE alone is useless —")
    print("  that is arithmetic, not a promise about how you store them.")
    print("  They are generated once and kept nowhere. Print them.\n")
    for i, s in enumerate(shares, 1):
        print(f"    share {i}:  {s}\n")
    print("  ── WHERE THE VAULT LIVES ────────────────────────────────────")
    print("  The shares rebuild the key, not the address. On a fresh")
    print("  machine you need both. Recreate this with: handshake connect\n")
    name = store.backend_name()
    for k, v in store.backend_config(name).items():
        print(f"    {k:<12}: {v}")
    print(f"    backend     : {name}\n")
    print("  ─────────────────────────────────────────────────────────────")
    db.log(int(time.time()), "init", None, session.public_ip(), True, None)
    print("\n  Vault created. Next: handshake unlock\n")


# ── sessions ────────────────────────────────────────────────────────────────
def cmd_unlock(a):
    db = _db()
    v = db.get_vault()
    if not v:
        _die("No vault here yet — run: handshake init")
    salt = crypto.b64d(v["salt"])
    pw = _passphrase()
    kek = crypto.check_passphrase(pw, salt, v["verifier"])
    if not kek:
        db.log(int(time.time()), "unlock", None, session.public_ip(), False, "bad passphrase")
        _die("Wrong passphrase.")

    tsec = crypto.unseal(kek, v["totp_enc"], aad=b"totp").decode()
    code = a.code or input("  6-digit code from your authenticator: ").strip()
    if not totp.verify(tsec, code):
        db.log(int(time.time()), "unlock", None, session.public_ip(), False, "bad 2FA code")
        _die("That code is not valid.")

    if a.remember:
        if keyring.set(KEYRING_ACCOUNT, pw):
            print("\n  Passphrase saved to your OS keychain. The 6-digit code is")
            print("  still required every time — that is what keeps this safe.")
        else:
            print("\n  No OS keychain available here; passphrase not saved.")

    tok = session.begin(kek, ttl=a.ttl, bind_ip=not a.no_ip_bind)
    ip = session.status().get("ip")
    db.log(int(time.time()), "unlock", None, ip, True, None)
    print(f"\n  Unlocked for {a.ttl // 60} minutes" + (f", bound to {ip}" if ip else ""))
    print("  Session token — give this to your agent; it is not stored readably:\n")
    print(f"    {tok}\n")


def _kek_or_die(a) -> bytes:
    kek, why = session.resolve(a.session or os.environ.get("HANDSHAKE_SESSION", ""))
    if not kek:
        _die(why)
    return kek


def cmd_lock(a):
    print("  locked" if session.end() else "  no open session")


def cmd_forget(a):
    print("  passphrase removed from the keychain" if keyring.clear(KEYRING_ACCOUNT)
          else "  nothing was saved")


#: Every dialect's way of saying "that table isn't there yet".
_NO_TABLE = ("no such table", "does not exist", "undefined_table", "42P01")


def _missing_schema(e: Exception) -> bool:
    msg = str(e).lower()
    return any(m in msg for m in _NO_TABLE)


def cmd_status(a):
    s = session.status()
    try:
        db = store.backend()
        name = store.backend_name()
        try:
            v = db.get_vault()
            print(f"  storage    : {db.health()}")
            print(f"  vault      : {'ready' if v else 'not initialised'}")
        except RuntimeError as e:
            # Reachable but empty is the normal state before `init`, and it
            # must not look like a failure.
            if _missing_schema(e):
                print(f"  storage    : {name} · reachable, no tables yet")
                print("  vault      : not initialised — run: handshake init")
            else:
                raise
    except RuntimeError as e:
        print(f"  storage    : not configured\n               {e}")
    open_ = s.get("open")
    print(f"  session    : {'open, ' + str(s['seconds_left'] // 60) + ' min left' if open_ else 'locked'}")
    if s.get("ip"):
        print(f"  bound to   : {s['ip']}")
    if keyring.get(KEYRING_ACCOUNT):
        print("  passphrase : saved in OS keychain (2FA still required)")


# ── secrets ─────────────────────────────────────────────────────────────────
def _read(db, kek: bytes, name: str) -> str:
    r = db.get_secret(name)
    if not r:
        db.log(int(time.time()), "get", name, _ip(), False, "not found")
        _die(f"No secret named {name}")
    dek = crypto.unwrap_dek(kek, r["wrapped_dek"], name)
    return crypto.unseal(dek, r["ciphertext"], aad=name.encode()).decode()


def cmd_put(a):
    kek, db = _kek_or_die(a), _db()
    value = a.value if a.value is not None else getpass.getpass("  Value: ")
    if value == "-":
        value = sys.stdin.read().rstrip("\n")
    dek = crypto.new_dek()
    db.put_secret(a.name, crypto.wrap_dek(kek, dek, a.name),
                  crypto.seal(dek, value.encode(), aad=a.name.encode()),
                  a.note, a.category, int(time.time()))
    db.log(int(time.time()), "put", a.name, _ip(), True, None)
    print(f"  stored {a.name}")


def cmd_get(a):
    kek, db = _kek_or_die(a), _db()
    val = _read(db, kek, a.name)
    db.log(int(time.time()), "get", a.name, _ip(), True, a.reason)
    # No trailing newline with -n, so `$(handshake get X)` is exact.
    print(val, end="" if a.no_newline else "\n")


def cmd_list(a):
    _kek_or_die(a)
    db = _db()
    rows = db.list_secrets()
    db.log(int(time.time()), "list", None, _ip(), True, None)
    rows.sort(key=lambda r: ((r.get("category") or "~"), r["name"]))
    cat = object()
    for r in rows:
        if r.get("category") != cat:
            cat = r.get("category")
            print(f"\n  {cat or 'uncategorised'}")
        print(f"    {r['name']:<40} {r.get('note') or ''}")
    print(f"\n  {len(rows)} secret(s)\n")


def cmd_rm(a):
    _kek_or_die(a)
    db = _db()
    if not a.yes:
        if input(f"  Delete {a.name}? This cannot be undone. [y/N] ").strip().lower() != "y":
            _die("cancelled", 0)
    existed = db.delete_secret(a.name)
    db.log(int(time.time()), "rm", a.name, _ip(), existed, None)
    print(f"  removed {a.name}" if existed else f"  no secret named {a.name}")


def cmd_log(a):
    _kek_or_die(a)
    for r in _db().recent_log(a.limit):
        ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(int(r["at"])))
        mark = "ok  " if r["ok"] else "FAIL"
        print(f"  {ts}  {mark}  {r['action']:<7} {(r.get('name') or ''):<32}"
              f" {(r.get('ip') or ''):<16} {r.get('detail') or ''}")


# ── running a command with credentials in its environment ───────────────────
def cmd_run(a):
    """Put secrets in a child process's environment and nowhere else.

    This is the point of the tool in daily use. Instead of exporting keys in
    your shell profile — where every process you ever launch can read them —
    they exist only inside the one command that needs them, for as long as it
    runs, and the read is recorded.

        handshake run -s TOK -e OPENAI_API_KEY -- claude

    Use NAME=secret when the variable is named differently from the secret:

        handshake run -s TOK -e OPENAI_API_KEY=work/openai -- codex
    """
    if not a.argv:
        _die("Nothing to run. Put the command after --, e.g.\n"
             "    handshake run -e OPENAI_API_KEY -- claude")
    kek, db = _kek_or_die(a), _db()
    env = dict(os.environ)
    names = []
    for spec in a.env:
        var, _, secret = spec.partition("=")
        secret = secret or var
        env[var] = _read(db, kek, secret)
        names.append(secret)
    for secret in names:
        db.log(int(time.time()), "run", secret, _ip(), True, a.reason or " ".join(a.argv[:2]))
    print(f"  injecting {len(names)} credential(s) into: {' '.join(a.argv)}", file=sys.stderr)
    try:
        # exec-style: no shell, so nothing lands in shell history and the
        # values never touch a command line other arguments could expose.
        sys.exit(subprocess.call(a.argv, env=env))
    except FileNotFoundError:
        _die(f"command not found: {a.argv[0]}")


# ── moving a vault between backends ─────────────────────────────────────────
def cmd_export(a):
    """Dump the vault as encrypted JSON.

    Nothing here is decrypted — the export is exactly the ciphertext the
    database holds, so this file is as safe as the vault itself and useless
    without the passphrase. It exists so you can move from SQLite to D1, or
    from Supabase to Postgres, without ever having plaintext on disk.
    """
    _kek_or_die(a)
    db = _db()
    v = db.get_vault()
    if not v:
        _die("No vault to export.")
    rows = []
    for meta in db.list_secrets():
        rows.append(db.get_secret(meta["name"]))
    blob = {"format": "handshake-export-v1", "vault": v, "secrets": rows}
    out = json.dumps(blob, indent=2, default=str)
    if a.out:
        p = Path(a.out).expanduser()
        p.write_text(out)
        p.chmod(0o600)
        print(f"  exported {len(rows)} secret(s) (still encrypted) to {p}")
    else:
        print(out)
    db.log(int(time.time()), "export", None, _ip(), True, f"{len(rows)} secrets")


def cmd_import(a):
    """Load an export into the currently configured backend."""
    blob = json.loads(Path(a.file).expanduser().read_text())
    if blob.get("format") != "handshake-export-v1":
        _die("Not a Handshake export.")
    db = _db()
    db.ensure_schema()
    existing = db.get_vault()
    if existing and not a.force:
        _die("This backend already holds a vault. --force overwrites it.\n"
             "  Both vaults' passphrases differ; importing replaces the key material.")
    v = blob["vault"]
    db.put_vault(v["salt"], v["verifier"], v["totp_enc"],
                 int(v["created_at"]), int(v.get("version", 1)))
    for r in blob["secrets"]:
        db.put_secret(r["name"], r["wrapped_dek"], r["ciphertext"],
                      r.get("note"), r.get("category"), int(r["updated_at"]))
    db.log(int(time.time()), "import", None, session.public_ip(), True,
           f"{len(blob['secrets'])} secrets")
    print(f"  imported {len(blob['secrets'])} secret(s) into {db.health()}")
    print("  Unlock with the passphrase and authenticator from the SOURCE vault.")


# ── recovery ────────────────────────────────────────────────────────────────
def cmd_recover(a):
    db = _db()
    v = db.get_vault()
    if not v:
        _die("No vault to recover.")
    print("  Paste two recovery shares (blank line to finish):")
    shares = []
    while True:
        line = input("    ").strip()
        if not line:
            break
        shares.append(line)
    if len(shares) < 2:
        _die("Two shares are required.")
    try:
        kek = crypto.combine_shares(shares)
    except Exception:
        _die("Those do not look like shares.")
    if crypto.verifier(kek, crypto.b64d(v["salt"])) != v["verifier"]:
        db.log(int(time.time()), "recover", None, session.public_ip(), False, None)
        _die("Those shares do not rebuild this vault.")
    tok = session.begin(kek, ttl=a.ttl, bind_ip=False)
    db.log(int(time.time()), "recover", None, session.public_ip(), True, None)
    print(f"\n  Recovered. Session token:\n\n    {tok}\n")
    print("  Set a new passphrase now:  handshake passwd --session <token>\n")


def cmd_passwd(a):
    kek, db = _kek_or_die(a), _db()
    v = db.get_vault()
    p1 = getpass.getpass("  New passphrase: ")
    if len(p1) < 12:
        _die("Too short. Twelve characters minimum.")
    if p1 != getpass.getpass("  Repeat: "):
        _die("Those did not match.")
    salt = os.urandom(16)
    print("  Deriving key…")
    new_kek = crypto.derive_kek(p1, salt)
    # Only the wrapped DEKs change. The ciphertext of every secret is untouched,
    # so this is fast and cannot corrupt a value even if it fails midway.
    rows = db.list_secrets()
    for meta in rows:
        r = db.get_secret(meta["name"])
        dek = crypto.unwrap_dek(kek, r["wrapped_dek"], r["name"])
        db.put_secret(r["name"], crypto.wrap_dek(new_kek, dek, r["name"]),
                      r["ciphertext"], r.get("note"), r.get("category"),
                      int(r["updated_at"]))
    tsec = crypto.unseal(kek, v["totp_enc"], aad=b"totp")
    db.put_vault(crypto.b64e(salt), crypto.verifier(new_kek, salt),
                 crypto.seal(new_kek, tsec, aad=b"totp"),
                 int(v["created_at"]), int(v.get("version", 1)))
    keyring.clear(KEYRING_ACCOUNT)
    session.end()
    db.log(int(time.time()), "passwd", None, _ip(), True, f"{len(rows)} re-wrapped")
    print(f"  Passphrase changed, {len(rows)} secret(s) re-wrapped, session ended.")
    print("  Your authenticator code is unchanged.")


# ── argument parsing ────────────────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        prog="handshake",
        description="An encrypted credential vault. Agents can use a credential; "
                    "only a person can unlock the vault.")
    p.add_argument("--version", action="version", version="handshake 1.0.0")
    sub = p.add_subparsers(dest="cmd", required=True)

    def with_session(sp):
        sp.add_argument("-s", "--session", help="token from `handshake unlock`")
        return sp

    c = sub.add_parser("connect", help="choose and configure where the vault lives")
    c.add_argument("--backend", choices=BACKENDS)
    c.set_defaults(fn=cmd_connect)

    sub.add_parser("setup-sql", help="print the SQL to create Supabase/Postgres tables"
                   ).set_defaults(fn=cmd_setup_sql)

    i = sub.add_parser("init", help="create the vault (2FA is mandatory)")
    i.add_argument("--account", help="label shown in your authenticator app")
    i.add_argument("--force", action="store_true", help="destroy an existing vault")
    i.set_defaults(fn=cmd_init)

    u = sub.add_parser("unlock", help="open a session (passphrase + 2FA)")
    u.add_argument("--code", help="6-digit code (otherwise prompted)")
    u.add_argument("--ttl", type=int, default=session.DEFAULT_TTL, help="seconds (default 1800)")
    u.add_argument("--no-ip-bind", action="store_true", help="do not pin to this public IP")
    u.add_argument("--remember", action="store_true", help="save the passphrase to the OS keychain")
    u.set_defaults(fn=cmd_unlock)

    g = with_session(sub.add_parser("get", help="read one secret"))
    g.add_argument("name")
    g.add_argument("--reason", help="recorded permanently in the audit log")
    g.add_argument("-n", "--no-newline", action="store_true")
    g.set_defaults(fn=cmd_get)

    pu = with_session(sub.add_parser("put", help="store one secret"))
    pu.add_argument("name")
    pu.add_argument("--value", help="value, or - to read stdin (otherwise prompted)")
    pu.add_argument("--note"); pu.add_argument("--category")
    pu.set_defaults(fn=cmd_put)

    with_session(sub.add_parser("list", help="list names and notes, never values")
                 ).set_defaults(fn=cmd_list)

    r = with_session(sub.add_parser("rm", help="delete a secret"))
    r.add_argument("name"); r.add_argument("-y", "--yes", action="store_true")
    r.set_defaults(fn=cmd_rm)

    lg = with_session(sub.add_parser("log", help="who read what, when, from where"))
    lg.add_argument("--limit", type=int, default=40)
    lg.set_defaults(fn=cmd_log)

    rn = with_session(sub.add_parser(
        "run", help="run a command with secrets in its environment"))
    rn.add_argument("-e", "--env", action="append", default=[], metavar="VAR[=secret]",
                    help="repeatable; VAR alone means the secret is named VAR")
    rn.add_argument("--reason")
    rn.add_argument("argv", nargs=argparse.REMAINDER, help="-- then the command")
    rn.set_defaults(fn=cmd_run)

    ex = with_session(sub.add_parser("export", help="dump the vault, still encrypted"))
    ex.add_argument("--out", help="file to write (otherwise stdout)")
    ex.set_defaults(fn=cmd_export)

    im = sub.add_parser("import", help="load an export into this backend")
    im.add_argument("file"); im.add_argument("--force", action="store_true")
    im.set_defaults(fn=cmd_import)

    sub.add_parser("lock", help="end the session now").set_defaults(fn=cmd_lock)
    sub.add_parser("status", help="where is the vault, is it open?").set_defaults(fn=cmd_status)
    sub.add_parser("forget", help="remove the saved passphrase from the keychain"
                   ).set_defaults(fn=cmd_forget)

    rc = sub.add_parser("recover", help="rebuild access from two recovery shares")
    rc.add_argument("--ttl", type=int, default=session.DEFAULT_TTL)
    rc.set_defaults(fn=cmd_recover)

    with_session(sub.add_parser("passwd", help="change the passphrase")
                 ).set_defaults(fn=cmd_passwd)
    return p


def main():
    a = build_parser().parse_args()
    if getattr(a, "argv", None) and a.argv and a.argv[0] == "--":
        a.argv = a.argv[1:]
    try:
        a.fn(a)
    except KeyboardInterrupt:
        print("\n  cancelled")
        sys.exit(130)
    except RuntimeError as e:
        _die(str(e))


if __name__ == "__main__":
    main()
