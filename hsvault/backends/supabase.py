"""A vault in Supabase, over PostgREST.

Supabase is Postgres, so the `postgres` backend also works against it and is
the better choice if you already have a driver installed. This backend exists
for the case that matters most to a recovery tool: a machine with nothing on it
but Python and a network connection. PostgREST is plain HTTPS, so it works
there, and it also works from behind the kind of network that blocks port 5432.

Two things to understand before using it.

**Use the service-role key, not the anon key.** The vault tables must not be
readable by your application's public key. The service-role key is a secret in
its own right — it is the one credential that cannot live inside the vault it
opens, which is true of every backend's connection credential.

**Turn Row Level Security on.** The setup SQL below enables RLS and adds no
policies, which denies every anon/authenticated request while leaving
service-role (which bypasses RLS by design) working. Without this, anyone
holding your project's public anon key can list your ciphertext. They still
cannot decrypt it, but there is no reason to hand it out.

PostgREST cannot execute DDL, so the tables are created once by pasting the
printed SQL into the Supabase SQL editor. That is a deliberate trade: the
alternative is asking for a credential powerful enough to reshape your
database, which a credential vault has no business holding.
"""
from __future__ import annotations
import json, urllib.error, urllib.parse, urllib.request
from .base import VAULT_ID

V, S, L = "handshake_vault", "handshake_secrets", "handshake_access_log"

SETUP_SQL = """\
-- Handshake: run once in the Supabase SQL editor.
create table if not exists handshake_vault (
  id text primary key, salt text not null, verifier text not null,
  totp_enc text not null, created_at bigint not null, version int not null default 1);

create table if not exists handshake_secrets (
  name text primary key, wrapped_dek text not null, ciphertext text not null,
  note text, category text, updated_at bigint not null);

create table if not exists handshake_access_log (
  id bigserial primary key, at bigint not null, action text not null,
  name text, ip text, ok boolean not null, detail text);

create index if not exists idx_handshake_log_at on handshake_access_log(at);

-- RLS on, no policies: anon and authenticated are denied everything.
-- service_role bypasses RLS, so Handshake keeps working and your app's
-- public key cannot read the vault.
alter table handshake_vault      enable row level security;
alter table handshake_secrets    enable row level security;
alter table handshake_access_log enable row level security;
"""


class SupabaseBackend:
    name = "supabase"

    def __init__(self, cfg: dict):
        url = (cfg.get("url") or "").rstrip("/")
        key = cfg.get("service_key") or ""
        if not (url and key):
            raise RuntimeError("Supabase backend needs url + service_key — run: handshake connect")
        if not url.startswith("https://"):
            raise RuntimeError("Supabase url must be https://")
        self.base = f"{url}/rest/v1"
        self.key = key

    # ── transport ───────────────────────────────────────────────────────────
    def _req(self, method: str, path: str, body=None, prefer: str | None = None):
        headers = {
            "apikey": self.key,
            "Authorization": f"Bearer {self.key}",
            "Content-Type": "application/json",
        }
        if prefer:
            headers["Prefer"] = prefer
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read()
                rng = r.headers.get("Content-Range", "")
                payload = json.loads(raw) if raw else []
                return payload, rng
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:300]
            if e.code == 404 or "does not exist" in detail:
                raise RuntimeError(
                    "Handshake's tables are missing from this project.\n"
                    "Run `handshake setup-sql`, paste the output into the\n"
                    "Supabase SQL editor, then try again.") from None
            if e.code in (401, 403):
                raise RuntimeError(
                    f"Supabase rejected the key (HTTP {e.code}). This backend needs the\n"
                    f"service-role key, not the anon key: {detail}") from None
            raise RuntimeError(f"Supabase HTTP {e.code}: {detail}") from None
        except urllib.error.URLError as e:
            raise RuntimeError(f"Supabase unreachable: {e.reason}") from None

    @staticmethod
    def _eq(**kw) -> str:
        return "&".join(f"{k}=eq.{urllib.parse.quote(str(v), safe='')}" for k, v in kw.items())

    # ── lifecycle ───────────────────────────────────────────────────────────
    def ensure_schema(self) -> None:
        # PostgREST cannot run DDL. Prove the tables exist and give a precise
        # instruction if they do not, rather than failing later mid-write.
        self._req("GET", f"/{V}?select=id&limit=1")

    def health(self) -> str:
        host = urllib.parse.urlparse(self.base).netloc
        return f"supabase · {host} · {self.count_secrets()} secret(s)"

    # ── vault ───────────────────────────────────────────────────────────────
    def get_vault(self) -> dict | None:
        rows, _ = self._req("GET", f"/{V}?{self._eq(id=VAULT_ID)}&select=*")
        return rows[0] if rows else None

    def put_vault(self, salt, verifier, totp_enc, created_at, version=1) -> None:
        self._req("POST", f"/{V}", [{
            "id": VAULT_ID, "salt": salt, "verifier": verifier, "totp_enc": totp_enc,
            "created_at": created_at, "version": version}],
            prefer="resolution=merge-duplicates,return=minimal")

    # ── secrets ─────────────────────────────────────────────────────────────
    def get_secret(self, name: str) -> dict | None:
        rows, _ = self._req("GET", f"/{S}?{self._eq(name=name)}&select=*")
        return rows[0] if rows else None

    def put_secret(self, name, wrapped_dek, ciphertext, note, category, updated_at) -> None:
        self._req("POST", f"/{S}", [{
            "name": name, "wrapped_dek": wrapped_dek, "ciphertext": ciphertext,
            "note": note, "category": category, "updated_at": updated_at}],
            prefer="resolution=merge-duplicates,return=minimal")

    def list_secrets(self) -> list[dict]:
        rows, _ = self._req("GET", f"/{S}?select=name,note,category,updated_at&order=name")
        return rows

    def delete_secret(self, name: str) -> bool:
        existed = self.get_secret(name) is not None
        self._req("DELETE", f"/{S}?{self._eq(name=name)}", prefer="return=minimal")
        return existed

    def count_secrets(self) -> int:
        _, rng = self._req("GET", f"/{S}?select=name&limit=1", prefer="count=exact")
        try:
            return int(rng.split("/")[-1])
        except (ValueError, AttributeError):
            return 0

    # ── audit ───────────────────────────────────────────────────────────────
    def log(self, at, action, name, ip, ok, detail) -> None:
        try:
            self._req("POST", f"/{L}", [{
                "at": at, "action": action, "name": name, "ip": ip,
                "ok": bool(ok), "detail": detail}], prefer="return=minimal")
        except Exception as e:
            print(f"  ! audit write failed: {e}")

    def recent_log(self, limit: int) -> list[dict]:
        rows, _ = self._req(
            "GET", f"/{L}?select=at,action,name,ip,ok,detail&order=at.desc&limit={int(limit)}")
        return rows
