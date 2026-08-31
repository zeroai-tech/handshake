# Handshake

**An encrypted credential vault for people who work with AI agents.**

An agent can *use* a credential. Only a person can *unlock* the vault.

```bash
curl -fsSL https://raw.githubusercontent.com/zeroai-tech/handshake/main/install.sh | bash
handshake setup
```

Then, from anywhere:

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
- Unlocking produces a session token that expires and is pinned to your
  network. Agents spend that token. They cannot mint one.
- Every read is appended to a log with the reason the caller gave. Afterwards
  you can answer the question that actually matters: *what did that agent
  touch?*

It was built in one sitting because the author was about to wipe a laptop that
held the only copy of every credential for a working company. That deadline
shaped two decisions worth naming: recovery is taken as seriously as encryption,
and the tool must run on a machine with nothing installed on it.

---

## Install

One command. It installs into `~/.handshake/app`, keeps its own Python
environment so nothing touches your system, puts `handshake` on your `PATH`,
and registers itself with any agent CLI you have.

```bash
curl -fsSL https://raw.githubusercontent.com/zeroai-tech/handshake/main/install.sh | bash
```

Re-run it any time to update.

<details>
<summary>Prefer to install by hand?</summary>

```bash
git clone https://github.com/zeroai-tech/handshake.git ~/.handshake/app
cd ~/.handshake/app
python3 -m venv .venv && ./.venv/bin/pip install -e .
ln -s ~/.handshake/app/bin/handshake ~/.local/bin/handshake
handshake agents          # register with your agent CLIs
```
</details>

## Set it up

```bash
handshake setup
```

That is the whole thing. It takes about a minute and walks through three steps:

1. **Where the vault lives.** Pick a backend from the list. If you are not
   sure, choose Cloudflare D1 — the free tier is ample and it survives your
   laptop. SQLite is fine for trying it out.
2. **Create the vault.** You choose a passphrase, then a QR code appears in
   your terminal. Scan it with Google Authenticator, 1Password, Aegis, Raivo —
   any TOTP app. Type the 6-digit code back. **Nothing is created until that
   code checks out**, so you cannot end up with a vault whose 2FA does not work.
3. **Wire up your agents.** It finds Claude Code, Codex, Gemini CLI, Cursor and
   Windsurf and registers the MCP server with whichever are present.

Then it prints a **recovery card**: three recovery shares plus the address of
your vault. Photograph it or print it before you close the window — the shares
are generated once and stored nowhere, by anyone, including us.

> **The shares are not a backup code — they are the vault.** Any two of them
> rebuild your master key with no passphrase and no authenticator. Get them off
> the machine (a photo, paper, a printer) and keep the three apart. Never paste
> that screen anywhere: not into a chat or an AI assistant, not a note in your
> password manager, not a support ticket. Anywhere it lands, someone owns your
> vault. Setup makes you confirm you have saved them before it continues.
>
> If they ever do leak and the vault is still empty or small, the fix is quick:
> `handshake init --force` mints a fresh key and fresh shares.

> **Why can't this be fully automated?** Because the point of the tool is that
> a machine cannot open your vault alone. The passphrase has to come out of
> your head and the code has to come off your phone. If a script could do it,
> so could anything else running on your machine.

## Adding credentials

`put` adds a new credential, and updates one that already exists — the same
command either way, so re-running is always safe.

```bash
handshake unlock                                    # start a session first
export HANDSHAKE_SESSION=<the token it prints>      # saves typing -s every time

handshake put openai/api-key                        # prompts, so it stays out of history
handshake put openai/api-key --value sk-...         # or pass it directly
handshake put db/prod-url --category prod --note "read replica"
cat key.pem | handshake put ssh/deploy-key --value -   # a whole file
```

**Names are yours to choose.** A `category/name` shape (`prod/stripe`,
`dev/openai`) keeps `handshake list` readable once you have thirty of them, but
nothing enforces it.

**Bring a whole `.env` file in at once:**

```bash
handshake import-env .env
handshake import-env .env.production --prefix prod/ --category prod
handshake import-env .env --skip-existing            # only add what is missing
```

It ignores comments and blank lines, handles `export FOO=bar`, and strips
quotes the way a shell would. Once it is in the vault, delete the file.

**Bringing in an existing vault** from another backend — see
[Storage backends](#storage-backends) — is `handshake export` then
`handshake import`.

## Everyday use

```bash
handshake list                          # names and notes, never values
handshake get openai/api-key            # print one value
handshake get openai/api-key --reason "deploying the worker"
handshake rm old/key                    # asks first; -y to skip
handshake log                           # who read what, when, and why
handshake status                        # is anything open?
handshake lock                          # close the session now
```

Prefer `run` over `get` whenever you are launching something. The value goes
into that one process and nowhere else — not your shell history, not your
scrollback, not your environment:

```bash
handshake run -e OPENAI_API_KEY -- claude
handshake run -e OPENAI_API_KEY -e ANTHROPIC_API_KEY -- aider
handshake run -e DATABASE_URL=prod/postgres -- ./migrate.sh
```

Use `VAR=secret-name` when the environment variable is not named the same as
the secret.

## Sessions

A session lasts 30 minutes by default, then everything locks again.

```bash
handshake unlock --ttl 7200      # two hours instead
handshake unlock --remember      # save the passphrase to your OS keychain
handshake forget                 # stop saving it
```

`--remember` puts the passphrase in the macOS Keychain or your Linux secret
service — never in a file, never encoded in a config. **The 6-digit code is
still required every time**, which is what makes saving the passphrase safe:
on its own it opens nothing.

## Housekeeping

```bash
handshake passwd                 # change the passphrase; secrets are untouched
handshake recover                # lost the passphrase or the phone? use two shares
handshake export --out backup.json   # encrypted backup, safe to store anywhere
handshake agents                 # re-register with agent CLIs after installing one
```

`passwd` re-wraps the small per-secret keys rather than re-encrypting your
data, so it is quick and cannot corrupt a value even if it is interrupted. Your
authenticator code is unchanged by it.

## Using it with an agent

`bin/handshake-mcp.mjs` is an MCP server exposing `status`, `list`, `get`, `put`
and `log`.

**It has no unlock tool.** Not disabled, not permission-gated — absent. There is
no way to pass a passphrase or a code through it. An agent can spend a session
you opened; it can never open one. That asymmetry is the security model, so it
is enforced by what the interface does not contain rather than by a check
someone can be talked out of.

`handshake setup` registers it automatically with Claude Code, Codex, Gemini
CLI, Cursor and Windsurf. Run `handshake agents` again after installing a new
one. Anything else that speaks MCP over stdio can point at
`~/.handshake/app/bin/handshake-mcp.mjs`; for agents that speak no MCP at all,
`handshake run` covers the same ground with no integration whatsoever.

A workflow that keeps the blast radius small:

1. You run `handshake unlock` in a terminal and paste the token into the chat.
2. The agent calls `handshake_get` with a stated reason when it needs something.
3. You run `handshake lock` when the task is done, or let the TTL do it.
4. `handshake log` afterwards shows exactly what was touched.

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
| A session token, used from another network | **No.** The binding refuses it. |
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
it has not expired (30 minutes by default), and you are still on the same
network. Fail any one and you authenticate again.

"Same network" means the same /24, or the same /64 on IPv6 — not the same
address. Large egress pools hand out a different address per connection, and
CGNAT, corporate proxies, mobile carriers and CI runners all do it; comparing
exact addresses logs people out while they sit perfectly still. We found this
the honest way, by watching a macOS CI runner move from `…117.183` to `…117.182`
between two calls and kill its own session. The prefix keeps the property that
matters — a token replayed from another network is refused — without the false
positives. `handshake unlock --strict-ip` restores exact matching if you are on
a fixed address and want it.

The binding is best-effort in one further respect: if the public IP cannot be
determined at all, the session is simply not network-bound rather than refusing
to work on a train.

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

