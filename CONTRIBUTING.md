# Contributing

## Before a pull request

```bash
python3 -m venv .venv && ./.venv/bin/pip install -e '.[dev]'
./.venv/bin/python tests/test_vault.py
./.venv/bin/python tests/e2e.py
```

Both must pass. The e2e suite drives the real CLI through a pty, including the
paths that must fail — a forged token, a wrong code, a locked session. If you
change behaviour, change those assertions deliberately rather than deleting
them.

## Rules that are not negotiable

These are the invariants the tool exists to provide. A change that breaks one
will be declined regardless of what else it does.

1. **No plaintext at rest.** Not in the config, not in a cache, not in a
   temporary file, not base64'd anywhere.
2. **No unlock path that skips 2FA.** Including "just for CI", "just for
   testing", and "behind a flag".
3. **No unlock capability in the MCP server.** An agent spends sessions; a
   human creates them. Enforced by absence, not by a check.
4. **No secret in the audit log.** Names, reasons and IPs. Never values.
5. **No test backdoor in shipping code.** Tests drive the real interface.
6. **The KDF cost does not go down** without a written argument in the PR.

## Adding a backend

Implement the `Backend` protocol in `hsvault/backends/base.py` and register it
in `hsvault/backends/__init__.py`. If your database speaks SQL, inherit
`SqlBackend` from `_sql.py` and supply `_exec` plus a placeholder style — that is
usually about forty lines.

The interface is a repository, not a SQL passthrough, on purpose: eleven narrow
methods can be reviewed for whether any of them can leak plaintext. A generic
`query(sql)` cannot be reviewed at all.

Your backend is only ever handed ciphertext. If you find yourself wanting the
key or the plaintext, something has gone wrong upstream.

Add your backend to the table in the README, and to `test_vault.py` if it can be
tested without credentials.

## Style

Match the surrounding code. Comments explain *why*, not *what* — the code
already says what. Prefer the standard library; every dependency is one more
thing that has to install on a freshly wiped laptop during a recovery, which is
the situation this tool exists for.
