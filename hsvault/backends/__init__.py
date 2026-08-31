"""Backend registry and configuration.

Config lives at ~/.handshake/config.json (override with HANDSHAKE_HOME) and
holds only the *address* of the vault plus the credential needed to reach it.
Never a key, never a passphrase, never a secret's plaintext.

    {
      "backend": "d1",
      "d1":       {"account_id": "...", "database_id": "...", "api_token": "..."},
      "supabase": {"url": "https://xxx.supabase.co", "service_key": "..."},
      "postgres": {"dsn": "postgresql://..."},
      "sqlite":   {"path": "~/.handshake/vault.db"}
    }

Environment variables override the file, which is what makes Handshake usable
in CI and in containers without writing anything to disk.
"""
from __future__ import annotations
import json, os
from pathlib import Path

HOME = Path(os.environ.get("HANDSHAKE_HOME", Path.home() / ".handshake"))
CONF = HOME / "config.json"

BACKENDS = ("sqlite", "d1", "supabase", "postgres")

#: Per-backend env overrides: config key -> environment variable.
ENV = {
    "d1": {"account_id": "CLOUDFLARE_ACCOUNT_ID",
           "database_id": "HANDSHAKE_D1_DATABASE_ID",
           "api_token": "HANDSHAKE_D1_API_TOKEN"},
    "supabase": {"url": "HANDSHAKE_SUPABASE_URL",
                 "service_key": "HANDSHAKE_SUPABASE_SERVICE_KEY"},
    "postgres": {"dsn": "HANDSHAKE_POSTGRES_DSN"},
    "sqlite": {"path": "HANDSHAKE_SQLITE_PATH"},
}


def load_config() -> dict:
    try:
        return json.loads(CONF.read_text())
    except Exception:
        return {}


def save_config(cfg: dict) -> None:
    HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    CONF.write_text(json.dumps(cfg, indent=2))
    CONF.chmod(0o600)


def _migrate(cfg: dict) -> dict:
    """Accept the pre-1.0 flat layout, which had D1 keys at the top level.

    Old configs keep working untouched; they are simply read as D1.
    """
    if "backend" not in cfg and {"account_id", "database_id"} <= set(cfg):
        return {"backend": "d1", "d1": {k: cfg[k] for k in
                ("account_id", "database_id", "api_token") if k in cfg}}
    return cfg


def backend_name(cfg: dict | None = None) -> str:
    cfg = _migrate(cfg if cfg is not None else load_config())
    return os.environ.get("HANDSHAKE_BACKEND") or cfg.get("backend") or "sqlite"


def backend_config(name: str, cfg: dict | None = None) -> dict:
    cfg = _migrate(cfg if cfg is not None else load_config())
    section = dict(cfg.get(name) or {})
    for key, var in ENV.get(name, {}).items():
        if os.environ.get(var):
            section[key] = os.environ[var]
    return section


def get_backend(cfg: dict | None = None):
    """Build the configured backend. Raises with an actionable message."""
    name = backend_name(cfg)
    if name not in BACKENDS:
        raise RuntimeError(f"Unknown backend {name!r}. Choose one of: {', '.join(BACKENDS)}")
    conf = backend_config(name, cfg)
    if name == "sqlite":
        from .sqlite import SqliteBackend
        return SqliteBackend(conf)
    if name == "d1":
        from .d1 import D1Backend
        return D1Backend(conf)
    if name == "supabase":
        from .supabase import SupabaseBackend
        return SupabaseBackend(conf)
    from .postgres import PostgresBackend
    return PostgresBackend(conf)


#: What each backend needs from `handshake connect`, and how to ask for it.
#: (key, prompt, secret?)
PROMPTS = {
    "sqlite": [("path", "Path to the vault file [~/.handshake/vault.db]", False)],
    "d1": [("account_id", "Cloudflare account id", False),
           ("database_id", "D1 database id", False),
           ("api_token", "D1 API token (needs D1:Edit)", True)],
    "supabase": [("url", "Supabase project URL (https://xxx.supabase.co)", False),
                 ("service_key", "Supabase service-role key (NOT the anon key)", True)],
    "postgres": [("dsn", "Postgres DSN (postgresql://user:pass@host/db)", True)],
}

DESCRIPTIONS = {
    "sqlite": "local file · zero setup · only as safe as this disk",
    "d1": "Cloudflare D1 · HTTP, no driver · free tier is plenty",
    "supabase": "Supabase · HTTP via PostgREST · needs the service-role key",
    "postgres": "any Postgres (Neon/RDS/self-hosted) · needs a driver installed",
}
