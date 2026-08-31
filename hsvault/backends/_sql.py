"""The half of a backend that is identical for every SQL database.

SQLite, Cloudflare D1 and Postgres differ in how you send a statement and how
you spell a placeholder. They do not differ in what the vault asks of them, so
that part is written once, here, and each backend supplies `_exec`.
"""
from __future__ import annotations
from .base import VAULT_ID

V, S, L = "handshake_vault", "handshake_secrets", "handshake_access_log"


class SqlBackend:
    #: "?" for SQLite/D1, "%s" for Postgres.
    placeholder = "?"
    schema: list[str] = []

    def _exec(self, sql: str, params: list | None = None) -> list[dict]:
        raise NotImplementedError

    def _q(self, sql: str) -> str:
        """Statements are written with `?`; Postgres wants `%s`."""
        return sql if self.placeholder == "?" else sql.replace("?", self.placeholder)

    def x(self, sql: str, params: list | None = None) -> list[dict]:
        return self._exec(self._q(sql), params or [])

    # ── lifecycle ───────────────────────────────────────────────────────────
    def ensure_schema(self) -> None:
        for ddl in self.schema:
            self.x(ddl)

    # ── vault ───────────────────────────────────────────────────────────────
    def get_vault(self) -> dict | None:
        rows = self.x(f"SELECT * FROM {V} WHERE id = ?", [VAULT_ID])
        return rows[0] if rows else None

    def put_vault(self, salt, verifier, totp_enc, created_at, version=1) -> None:
        # Written as delete+insert rather than an upsert because the three
        # dialects spell upsert differently and this is a once-per-vault path.
        self.x(f"DELETE FROM {V} WHERE id = ?", [VAULT_ID])
        self.x(f"INSERT INTO {V} (id,salt,verifier,totp_enc,created_at,version)"
               f" VALUES (?,?,?,?,?,?)",
               [VAULT_ID, salt, verifier, totp_enc, created_at, version])

    # ── secrets ─────────────────────────────────────────────────────────────
    def get_secret(self, name: str) -> dict | None:
        rows = self.x(f"SELECT * FROM {S} WHERE name = ?", [name])
        return rows[0] if rows else None

    def put_secret(self, name, wrapped_dek, ciphertext, note, category, updated_at) -> None:
        self.x(f"DELETE FROM {S} WHERE name = ?", [name])
        self.x(f"INSERT INTO {S} (name,wrapped_dek,ciphertext,note,category,updated_at)"
               f" VALUES (?,?,?,?,?,?)",
               [name, wrapped_dek, ciphertext, note, category, updated_at])

    def list_secrets(self) -> list[dict]:
        # Ciphertext is deliberately excluded: listing must never be a way to
        # pull the encrypted material out in bulk.
        return self.x(f"SELECT name,note,category,updated_at FROM {S} ORDER BY name")

    def delete_secret(self, name: str) -> bool:
        existed = self.get_secret(name) is not None
        self.x(f"DELETE FROM {S} WHERE name = ?", [name])
        return existed

    def count_secrets(self) -> int:
        rows = self.x(f"SELECT COUNT(*) AS n FROM {S}")
        return int(rows[0]["n"]) if rows else 0

    # ── audit ───────────────────────────────────────────────────────────────
    def log(self, at, action, name, ip, ok, detail) -> None:
        try:
            self.x(f"INSERT INTO {L} (at,action,name,ip,ok,detail) VALUES (?,?,?,?,?,?)",
                   [at, action, name, ip, self._bool(ok), detail])
        except Exception as e:
            # Loud, never fatal. A vault that refuses to work because logging
            # broke is a vault you cannot use in an incident.
            print(f"  ! audit write failed: {e}")

    @staticmethod
    def _bool(v: bool):
        return 1 if v else 0

    def recent_log(self, limit: int) -> list[dict]:
        return self.x(f"SELECT at,action,name,ip,ok,detail FROM {L}"
                      f" ORDER BY at DESC, id DESC LIMIT ?", [int(limit)])
