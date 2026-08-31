"""A vault in any Postgres: Supabase's direct connection, Neon, RDS, or the
database already running on your own box.

Needs a driver — `pip install 'handshake-vault[postgres]'` — because there is
no Postgres wire protocol in the standard library. If installing one is a
problem on the machine you are recovering, use the D1 or Supabase backends,
which are HTTP and need nothing.
"""
from __future__ import annotations
from ._sql import SqlBackend
from .base import SQL_SCHEMA_POSTGRES


class PostgresBackend(SqlBackend):
    name = "postgres"
    placeholder = "%s"
    schema = SQL_SCHEMA_POSTGRES

    def __init__(self, cfg: dict):
        self.dsn = cfg.get("dsn") or ""
        if not self.dsn:
            raise RuntimeError("Postgres backend needs a dsn — run: handshake connect")
        try:
            import psycopg                      # noqa: F401
            self._driver = "psycopg"
        except ImportError:
            try:
                import psycopg2                 # noqa: F401
                self._driver = "psycopg2"
            except ImportError:
                raise RuntimeError(
                    "No Postgres driver. Install one:\n"
                    "    pip install 'handshake-vault[postgres]'\n"
                    "or use the d1/supabase backend, which need no driver.") from None

    def _connect(self):
        if self._driver == "psycopg":
            import psycopg
            return psycopg.connect(self.dsn, connect_timeout=15)
        import psycopg2
        return psycopg2.connect(self.dsn, connect_timeout=15)

    def _exec(self, sql, params=None):
        # As with the other backends, driver errors surface as RuntimeError.
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, params or [])
                    if cur.description:
                        cols = [d[0] for d in cur.description]
                        return [dict(zip(cols, r)) for r in cur.fetchall()]
                conn.commit()
            return []
        except RuntimeError:
            raise
        except Exception as e:
            raise RuntimeError(f"postgres: {e}") from None

    @staticmethod
    def _bool(v: bool):
        return bool(v)                  # Postgres `ok` column is BOOLEAN

    def health(self) -> str:
        n = self.count_secrets()
        # Never echo the DSN: it contains the password.
        host = self.dsn.split("@")[-1].split("/")[0] if "@" in self.dsn else "postgres"
        return f"postgres · {host} · {n} secret(s)"
