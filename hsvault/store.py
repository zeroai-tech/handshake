"""Storage facade.

Everything above this line in the call stack talks to a vault; everything below
it talks to a specific database. Swapping Cloudflare D1 for Supabase changes
which object `backend()` returns and nothing else.
"""
from __future__ import annotations
import time
from .backends import (BACKENDS, CONF, DESCRIPTIONS, HOME, PROMPTS,   # noqa: F401
                       backend_config, backend_name, get_backend,
                       load_config, save_config)

_cached = None


def backend(refresh: bool = False):
    global _cached
    if _cached is None or refresh:
        _cached = get_backend()
    return _cached


def ensure_schema() -> None:
    backend().ensure_schema()


def log(action: str, name: str | None, ok: bool,
        ip: str | None = None, detail: str | None = None) -> None:
    backend().log(int(time.time()), action, name, ip, ok, detail)


# Legacy aliases, kept so an older config or script does not break.
config = load_config
