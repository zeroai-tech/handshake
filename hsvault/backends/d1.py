"""A vault in Cloudflare D1, reached over the HTTP API.

Chosen as the reference remote backend because it needs nothing installed: no
driver, no compiler, no connection pooler. A freshly wiped laptop with Python
and network access can reach it, which is exactly the situation a credential
vault exists for.

Cloudflare stores ciphertext. Someone who steals the D1 token can delete the
vault or read encrypted blobs; they cannot decrypt one.
"""
from __future__ import annotations
import json, urllib.error, urllib.request
from ._sql import SqlBackend
from .base import SQL_SCHEMA_SQLITE

API = "https://api.cloudflare.com/client/v4"


class D1Backend(SqlBackend):
    name = "d1"
    placeholder = "?"
    schema = SQL_SCHEMA_SQLITE          # D1 is SQLite underneath

    REQUIRED = ("account_id", "database_id", "api_token")

    def __init__(self, cfg: dict):
        missing = [k for k in self.REQUIRED if not cfg.get(k)]
        if missing:
            raise RuntimeError(
                "D1 backend needs " + ", ".join(missing) + " — run: handshake connect")
        self.account = cfg["account_id"]
        self.database = cfg["database_id"]
        self.token = cfg["api_token"]

    def _exec(self, sql, params=None):
        body = json.dumps({"sql": sql, "params": params or []}).encode()
        req = urllib.request.Request(
            f"{API}/accounts/{self.account}/d1/database/{self.database}/query",
            data=body,
            headers={"Authorization": f"Bearer {self.token}",
                     "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                out = json.loads(r.read())
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:300]
            # 403 here is nearly always the wrong token rather than a real
            # permission problem, so say so instead of just reporting the code.
            hint = " — check the token has D1:Edit on this account" if e.code in (401, 403) else ""
            raise RuntimeError(f"D1 HTTP {e.code}{hint}: {detail}") from None
        except urllib.error.URLError as e:
            raise RuntimeError(f"D1 unreachable: {e.reason}") from None
        if not out.get("success"):
            raise RuntimeError("D1: " + "; ".join(
                e.get("message", "?") for e in out.get("errors", [])))
        res = out.get("result") or [{}]
        return res[0].get("results") or []

    def health(self) -> str:
        n = self.count_secrets()
        return f"cloudflare-d1 · database {self.database[:8]}… · {n} secret(s)"
