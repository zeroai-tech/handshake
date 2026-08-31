"""A vault in a local SQLite file.

The zero-setup option: no account, no network, no token. Good for trying the
tool, for air-gapped machines, and for a laptop that is backed up anyway.

The trade-off is honest and worth stating plainly: this file is only as durable
as the disk it sits on. If the point of your vault is to survive the machine
being wiped, use a remote backend instead.
"""
from __future__ import annotations
import sqlite3
from pathlib import Path
from ._sql import SqlBackend
from .base import SQL_SCHEMA_SQLITE


class SqliteBackend(SqlBackend):
    name = "sqlite"
    placeholder = "?"
    schema = SQL_SCHEMA_SQLITE

    def __init__(self, cfg: dict):
        self.path = Path(cfg.get("path") or Path.home() / ".handshake" / "vault.db").expanduser()

    def _connect(self):
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        c = sqlite3.connect(self.path, timeout=15)
        c.row_factory = sqlite3.Row
        return c

    def _exec(self, sql, params=None):
        # Driver exceptions are normalised to RuntimeError so callers can
        # handle "no tables yet" the same way whatever the backend is.
        try:
            with self._connect() as c:
                cur = c.execute(sql, params or [])
                rows = [dict(r) for r in cur.fetchall()] if cur.description else []
        except sqlite3.Error as e:
            raise RuntimeError(f"sqlite: {e}") from None
        # Owner-only, from the moment the file first exists.
        try:
            self.path.chmod(0o600)
        except OSError:
            pass
        return rows

    def health(self) -> str:
        n = self.count_secrets()
        return f"sqlite · {self.path} · {n} secret(s)"
