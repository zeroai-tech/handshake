# Handshake

**An encrypted credential vault for people who work with AI agents.**

An agent can *use* a credential. Only a person can *unlock* the vault.

```bash
handshake unlock                                  # passphrase + code from your phone
handshake run -e OPENAI_API_KEY -- claude         # key exists only inside that process
handshake log                                     # what was read, when, and why
```

---

## Why this exists

Agent CLIs inherit your shell environment. That is the whole problem in one
sentence.

When you run Claude Code, Codex, Gemini CLI, Aider, or any tool that executes
code on your behalf, it starts with a copy of everything you have exported. Your
`OPENAI_API_KEY` is there. So is the AWS key you exported in 2023 and forgot, the
production database URL, and the Stripe secret. A `.env` file is no better: it is
one `cat` away from any process allowed to read your project directory, which is
exactly the permission you granted when you let an agent edit your code.

The usual fix is a cloud secret manager. It solves a real problem — durability,
rotation, team access — but for this particular threat it mostly moves the
credential. You now hold a long-lived token that fetches every secret, and that
token sits in the same environment, readable by the same processes.

Handshake takes a narrower position: **the open state should be deliberate,
brief, and visible.**

- Credentials sit encrypted in a database you control. The host cannot read
  them. Neither can anyone who steals the token used to reach the host.
- Opening the vault needs a passphrase **and** a code from your phone. The
  passphrase can be remembered by your OS keychain; the six-digit code cannot be
  remembered by anything, which is precisely the point — a human is in the loop
  at least once per session.
- Unlocking produces a session token that expires and is pinned to your public
  IP. Agents spend that token. They cannot mint one.
- Every read is appended to a log with the reason the caller gave. Afterwards
  you can answer the question that actually matters: *what did that agent
  touch?*

It was built in one sitting because the author was about to wipe a laptop that
held the only copy of every credential for a working company. That deadline
shaped two decisions worth naming: recovery is taken as seriously as encryption,
and the tool must run on a machine with nothing installed on it.

---

## Threat model

Security tools that do not say what they *don't* protect against are marketing.
Here is the honest table.

| Someone who has | Can they read your secrets? |
|---|---|
| Your database (D1/Supabase/Postgres dump) | **No.** Ciphertext only. The key was never sent there. |
| The hosting API token | **No.** They can delete or corrupt the vault; they cannot decrypt it. |
| Your laptop, powered off | **No.** No plaintext at rest, no key file. |
| Your laptop, while a session is open | **Yes**, if they also have the session token. It is in the terminal that opened it. |
| Your passphrase, and nothing else | **No.** They still need a code from your phone. |
| Your phone, and nothing else | **No.** They still need the passphrase. |
| Your passphrase **and** your phone | **Yes.** That is what being you means. |
| Two of your three recovery shares | **Yes.** Store them apart, in different places. |
| One recovery share | **No** — mathematically, not merely in practice. |
| Root on your machine while unlocked | **Yes.** Nothing in userspace survives this. Not a solvable problem here. |

**What Handshake does not do.** It does not stop a malicious agent from
exfiltrating a credential you deliberately handed it — once a secret is in a
process's environment, that process has it. What it does is make the window
short, the scope explicit, and the access recorded, so the damage is bounded and
the forensics exist. Treat `handshake run -e ONE_KEY` as the norm and
`--session` sprayed across a long chat as the thing to avoid.

It also does not protect against you choosing "password123". The KDF is tuned to
make guessing expensive, not free.

---

## How it is built

### Key hierarchy

```
passphrase ──scrypt(N=2^18, r=8, p=1)──▶ KEK          derived on use, stored nowhere
                                          │
                                          ├─AES-256-GCM─▶ wraps DEK₁ ─▶ encrypts secret 1
                                          ├─AES-256-GCM─▶ wraps DEK₂ ─▶ encrypts secret 2
                                          └─AES-256-GCM─▶ wraps DEK₃ ─▶ encrypts secret 3
```

Envelope encryption, one data key per secret. Compromising a single plaintext
tells an attacker nothing about the others, and changing your passphrase
re-wraps *n* small keys instead of re-encrypting *n* secrets — so `passwd` is
fast and cannot corrupt a value even if it dies halfway.

**Each secret's name is bound in as AES-GCM additional authenticated data.** A
wrapped key lifted from `staging/db` and pasted over `prod/db` fails to
authenticate rather than quietly decrypting. There is a test for this, because
it is the kind of thing that silently stops being true during a refactor.

**scrypt at N=2¹⁸** costs about 0.9 seconds and ~256 MB per attempt on a current
laptop. That is unnoticeable when you unlock once a session, and it caps an
offline attacker at roughly four thousand guesses an hour per core. scrypt
rather than Argon2id for one reason: it is in Python's standard library.
`argon2-cffi` wants a compiler, and a recovery tool that cannot be installed on a
freshly wiped machine is worse than no recovery tool. That is a real trade —
Argon2id is the better primitive — and it is made deliberately.

**The passphrase is verified without being stored.** The vault holds
`HMAC-SHA256(KEK, "handshake-verifier-v1" || salt)`. Reversing it means breaking
HMAC; guessing it means paying the scrypt cost per attempt.

### Sessions

`unlock` prints a token exactly once. What is written to disk is its SHA-256,
plus the KEK sealed under `SHA-256("session-key:" || token)`. Without the token
the session file is inert — a stolen laptop yields nothing unless the thief also
has the token out of your terminal scrollback.

Three conditions must all hold for a session to be spendable: the token matches,
it has not expired (30 minutes by default), and your public IP is unchanged.
Fail any one and you authenticate again. The IP binding is best-effort by
design: if the public IP cannot be determined, the session is simply not
IP-bound rather than refusing to work on a train.

### Recovery

`init` prints three Shamir shares over GF(256) with a threshold of two. Any two
rebuild the KEK; any one reveals *nothing* — not "not much", nothing, as a
property of the polynomial. They are generated once and stored nowhere.

The shares rebuild the **key**, not the **address**. On a wiped machine you need
both, so `init` prints the backend connection details on the same card. Print
it. That card is the entire disaster-recovery plan.

### Audit log

Append-only: timestamp, action, secret name, IP, success, and the reason the
caller supplied. `list` deliberately returns metadata only and never ciphertext,
so listing cannot be turned into bulk extraction.

---

## Storage backends

The vault is portable across all four. `handshake export` emits the ciphertext
as-is — no key needed, nothing decrypted — and `handshake import` loads it
elsewhere.

| Backend | Setup | Needs a driver? | Use it when |
|---|---|---|---|
| `sqlite` | none | no | Trying it out; air-gapped; the disk is already backed up |
| `d1` | Cloudflare account | no (HTTPS) | **Recommended.** Free tier is ample; reachable from a bare machine |
| `supabase` | paste one SQL block | no (PostgREST) | You already run Supabase |
| `postgres` | a database | yes (`psycopg`) | Neon, RDS, self-hosted, or Supabase's direct connection |

```bash
handshake connect                 # interactive picker
handshake connect --backend d1    # or name it
```

Two notes that matter.

**Supabase:** use the **service-role key**, not the anon key, and run
`handshake setup-sql` to get DDL that enables Row Level Security with no
policies. That denies anon and authenticated everything while service-role
(which bypasses RLS by design) keeps working. Without it, anyone holding your
project's public anon key can list your ciphertext. They still cannot decrypt
it, but there is no reason to publish it.

**Every backend's connection credential is the one secret that cannot live in
the vault it opens.** That is not a flaw in this design; it is true of every
system of this shape. Keep it on the recovery card.

---

## Install

Requires Python 3.10+ and `cryptography`.

```bash
git clone https://github.com/zeroai-tech/handshake.git
cd handshake
python3 -m venv .venv && ./.venv/bin/pip install -e .
ln -s "$PWD/bin/handshake" /usr/local/bin/handshake     # optional
```

Then:

```bash
handshake connect     # where should the vault live?
handshake init        # passphrase, scan the QR, save the recovery card
handshake unlock      # start a session
```

`init` will not create anything until you have proved 2FA works by entering a
live code. Two-factor is not a setting you can forget to enable.

---

## Daily use

```bash
handshake put prod/openai --category prod --note "billing account"
handshake list -s $TOK
handshake get prod/openai --reason "deploying the worker" -s $TOK
handshake rm old/key -s $TOK
handshake log --limit 50 -s $TOK
handshake lock
```

Prefer `run` over `get` wherever you can — it never puts the value in your shell
history, your scrollback, or your environment:

```bash
handshake run -s $TOK -e OPENAI_API_KEY -e ANTHROPIC_API_KEY -- claude
handshake run -s $TOK -e DATABASE_URL=prod/postgres -- ./migrate.sh
```

Save the passphrase if you want; the code is still required every time:

```bash
handshake unlock --remember     # OS keychain — never a file, never base64
handshake forget                # undo
```

---

## Using it with an agent

`bin/handshake-mcp.mjs` is an MCP server exposing `status`, `list`, `get`, `put`
and `log`.

**It has no unlock tool.** Not disabled, not permission-gated — absent. There is
no way to pass a passphrase or a code through it. An agent can spend a session
you opened; it can never open one. That asymmetry is the security model, so it
is enforced by what the interface does not contain rather than by a check
someone can be talked out of.

Claude Code:

```bash
claude mcp add handshake --scope user -- node /path/to/handshake/bin/handshake-mcp.mjs
```

Anything else that speaks MCP over stdio works the same way. For agents that
don't, `handshake run` covers the same ground with no integration at all.

A workflow that keeps the blast radius small:

1. You run `handshake unlock` in a terminal and paste the token into the chat.
2. The agent calls `handshake_get` with a stated reason when it needs something.
3. You run `handshake lock` when the task is done, or let the TTL do it.
4. `handshake log` afterwards shows exactly what was touched.

---

## Development

```bash
./.venv/bin/python tests/test_vault.py     # unit: crypto, Shamir, TOTP, backends
./.venv/bin/python tests/e2e.py            # full CLI through a pty, incl. failure paths
```

The e2e suite asserts the negatives as hard as the positives: a forged token is
refused, a wrong code is refused, `list` never emits a value, an export contains
no plaintext, and a lock actually ends the session.

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). If you are
adding a backend, note that the interface in `hsvault/backends/base.py` is a
repository, not a SQL passthrough. That is intentional: eleven methods can be
audited for leaks; `query(sql)` cannot.

---

## Security reporting

Please use [GitHub's private vulnerability
reporting](https://github.com/zeroai-tech/handshake/security/advisories/new)
rather than a public issue. See [SECURITY.md](SECURITY.md).

Handshake has not had a third-party audit. The cryptography is standard
constructions from `cryptography` and the Python standard library, assembled
conservatively, and the assembly is what would benefit from review. Read
`hsvault/crypto.py` — it is about 140 lines and it is all there.

---

## Licence

Apache 2.0. See [LICENSE](LICENSE).

Built at [ZeroAI](https://zeroaitech.tech) and released for anyone who has the
same problem.
