"""What a storage backend has to provide.

Deliberately a *repository* interface, not a "run this SQL" interface. Two
reasons:

  1. Not every usable backend speaks SQL over the wire. Supabase's PostgREST
     is a REST API; forcing SQL through it would mean shipping a SQL parser or
     requiring a Postgres driver nobody asked for.
  2. A narrow interface is auditable. There are eleven methods here, and a
     reviewer can check every one of them for whether it could leak plaintext.
     A `query(sql)` hole cannot be audited at all.

Backends store ciphertext. A backend is never given a key, a passphrase, or a
plaintext secret, and no method below returns one. If you are writing a new
backend and find yourself wanting the plaintext, something has gone wrong.
"""
from __future__ import annotations
from typing import Protocol, Any


class Backend(Protocol):
    """Storage for an encrypted vault.

    Implementations live in this package and are registered in __init__.py.
    """

    name: str

    # ── lifecycle ───────────────────────────────────────────────────────────
    def ensure_schema(self) -> None:
        """Create tables if absent. Must be safe to call repeatedly."""

    def health(self) -> str:
        """Human-readable one-liner: reachable? which database? Used by
        `handshake status` and `handshake connect` so a misconfiguration is
        obvious immediately rather than at the first read."""

    # ── the vault record (exactly one row) ──────────────────────────────────
    def get_vault(self) -> dict | None:
        """Row with: salt, verifier, totp_enc, created_at, version. None if
        the vault has not been created."""

    def put_vault(self, salt: str, verifier: str, totp_enc: str,
                  created_at: int, version: int = 1) -> None: ...

    # ── secrets ─────────────────────────────────────────────────────────────
    def get_secret(self, name: str) -> dict | None:
        """Row with: name, wrapped_dek, ciphertext, note, category, updated_at."""

    def put_secret(self, name: str, wrapped_dek: str, ciphertext: str,
                   note: str | None, category: str | None, updated_at: int) -> None: ...

    def list_secrets(self) -> list[dict]:
        """Metadata only — name, note, category, updated_at. Never ciphertext,
        so `handshake list` cannot become an exfiltration path."""

    def delete_secret(self, name: str) -> bool: ...

    def count_secrets(self) -> int: ...

    # ── audit ───────────────────────────────────────────────────────────────
    def log(self, at: int, action: str, name: str | None, ip: str | None,
            ok: bool, detail: str | None) -> None:
        """Append-only. Must not raise: a failed audit write should be loud,
        never fatal."""

    def recent_log(self, limit: int) -> list[dict]: ...


# Shared DDL, for the backends that do speak SQL. Kept here so the three SQL
# backends cannot drift apart in ways that break cross-backend export/import.
#
# `?` placeholders are rewritten per-dialect by the backend.
SQL_SCHEMA_SQLITE = [
    """CREATE TABLE IF NOT EXISTS handshake_vault (
         id TEXT PRIMARY KEY, salt TEXT NOT NULL, verifier TEXT NOT NULL,
         totp_enc TEXT NOT NULL, created_at INTEGER NOT NULL,
         version INTEGER NOT NULL DEFAULT 1)""",
    """CREATE TABLE IF NOT EXISTS handshake_secrets (
         name TEXT PRIMARY KEY, wrapped_dek TEXT NOT NULL, ciphertext TEXT NOT NULL,
         note TEXT, category TEXT, updated_at INTEGER NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS handshake_access_log (
         id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, action TEXT NOT NULL,
         name TEXT, ip TEXT, ok INTEGER NOT NULL, detail TEXT)""",
    "CREATE INDEX IF NOT EXISTS idx_handshake_log_at ON handshake_access_log(at)",
]

SQL_SCHEMA_POSTGRES = [
    """CREATE TABLE IF NOT EXISTS handshake_vault (
         id TEXT PRIMARY KEY, salt TEXT NOT NULL, verifier TEXT NOT NULL,
         totp_enc TEXT NOT NULL, created_at BIGINT NOT NULL,
         version INTEGER NOT NULL DEFAULT 1)""",
    """CREATE TABLE IF NOT EXISTS handshake_secrets (
         name TEXT PRIMARY KEY, wrapped_dek TEXT NOT NULL, ciphertext TEXT NOT NULL,
         note TEXT, category TEXT, updated_at BIGINT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS handshake_access_log (
         id BIGSERIAL PRIMARY KEY, at BIGINT NOT NULL, action TEXT NOT NULL,
         name TEXT, ip TEXT, ok BOOLEAN NOT NULL, detail TEXT)""",
    "CREATE INDEX IF NOT EXISTS idx_handshake_log_at ON handshake_access_log(at)",
]

VAULT_ID = "default"
