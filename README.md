# Handshake

An encrypted credential vault with a small, local setup interface and a CLI for trusted tools. Built by ZeroAI Technologies.

## Start

```bash
curl -fsSL https://raw.githubusercontent.com/zeroai-tech/handshake/main/install.sh | bash
handshake gui
```

The interface opens in your browser, served only on this device. It guides you through local or cloud storage, a passphrase, an optional separate security key file (recommended), authenticator enrollment, recovery shares, and selected tool connections. No analytics or external UI assets are loaded. Use **Quit Handshake** to stop the local server and end its session.

On macOS the installer creates `~/Applications/Handshake.app` for double-click launching. From a checkout, run `python scripts/create-launcher.py` to create it.

Existing vaults open locked. Changing an existing vault's passphrase upgrades its key envelope without rewriting credentials, and preserves its original recovery shares. Opening the interface alone does not migrate your vault.

## Protection and recovery

Use a long, unique passphrase. For protection against someone who knows that passphrase and obtains a database copy, enable the separate security key file and keep it on another device or USB drive, with a separate backup. Keeping it beside the database weakens this protection.

The authenticator code verifies the application's unlock flow. **It is not an independent encryption factor:** someone with a password-only vault and its passphrase can decrypt the data outside the application. A separate key file adds independent random material to the encryption key.

Save the three recovery shares in separate safe locations. Any two grant full vault access, bypassing the passphrase, authenticator, and key file. Never give them to an AI assistant. Recovery shares rebuild a key; they cannot rebuild a deleted database. Keep an encrypted database export off-device too. Recovery cards for remote storage also contain its connection settings and must be treated as sensitive.

The interface supports storing credentials, listing names, locking, encrypted backups, password changes, recovery, access history, and optional agent connections. Credential values do not appear in the list.

## CLI

```bash
handshake keyfile --out /path/on/separate-device/handshake-key.json
handshake init --key-file /path/on/separate-device/handshake-key.json
handshake unlock --key-file /path/on/separate-device/handshake-key.json
handshake put work/openai --value -       # provide the value on stdin
handshake list
handshake run -e OPENAI_API_KEY=work/openai -- your-command
handshake export --out encrypted-backup.json
handshake passwd --key-file /path/on/separate-device/handshake-key.json
handshake lock
handshake --help
```

Unlock produces a bearer session token. Follow the command's instructions to set `HANDSHAKE_SESSION` in your shell. An authorized token grants access to the whole vault; give it only to trusted tools. The MCP bridge has no unlock tool, passes tokens through subprocess environment variables, and supplies new credential values on stdin rather than command-line arguments. It requires Node.js.

Use `handshake agents` to register CLI integrations, or choose individual integrations in the interface. Supported integrations include Claude Code, Codex, Gemini CLI, Cursor and Windsurf. Registration alone does not unlock a vault.

## Storage

SQLite works without an account. Cloudflare D1, Supabase and Postgres are also supported. Storage credentials are saved locally with restrictive permissions; they grant database access and should be protected. Supabase requires the repository's setup SQL. Postgres requires the optional dependency:

```bash
python -m pip install '.[postgres]'
```

Use `handshake setup --help` for terminal storage configuration. Remote storage contains encrypted credential values, but names, notes, categories and access logs are visible to its operator. Encryption does not prevent deletion or modification of the database.

## Threat model

| Situation | Limit or protection |
|---|---|
| Database or encrypted backup stolen | Values are encrypted; guessing the passphrase remains possible. Separate key-file mode additionally needs that file. |
| Passphrase and password-only database stolen | The phone-code check cannot prevent offline decryption. |
| Two recovery shares stolen | Full vault access, given the database. |
| Token deliberately given to a tool | Whole-vault access for normal application calls until expiry or lock. |
| A process running as your user | Can inspect local files, process memory and environment, or alter application code. Handshake is not a security boundary against it. |
| Tool retains a credential or key | Locking cannot revoke material already copied or invalidate a provider's API key. Rotate that credential at its provider. |
| Network changes | Best-effort public-IP binding rejects detected changes. Lookup failures do not lock you out. This is not strong identity verification. |
| Storage deleted | Restore an encrypted database backup; recovery shares alone are insufficient. |

The session timer governs cooperative application access. The session file and bearer token together can expose the master key to a same-user process. Do not describe the timer or authenticator as protection against a malicious local agent. Audit logs are best-effort and can be altered by someone controlling storage.

## Development

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python tests/test_vault.py
.venv/bin/python tests/test_hardening.py
.venv/bin/python tests/test_gui.py
.venv/bin/python tests/e2e.py
node tests/verify_gui.cjs /absolute/path/to/playwright
```

Browser tests use an isolated temporary vault and disable keychain changes. See [SECURITY.md](SECURITY.md) for cryptographic details and reporting. This project has not undergone an independent security audit.
