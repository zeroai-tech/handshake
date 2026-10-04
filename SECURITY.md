# Security policy

Report vulnerabilities using [GitHub private vulnerability reporting](https://github.com/zeroai-tech/handshake/security/advisories/new). Do not include real credentials, passphrases, key files, or recovery shares. Supply a minimal reproduction using a disposable vault.

## Cryptography

Passphrases are derived with scrypt (N=2^18, r=8, p=1, 16-byte random salt, 32-byte output). In key-file mode, HKDF-SHA256 combines this output with an independent random 32-byte key file. AES-256-GCM wraps a stable random vault master key. Each credential has a fresh random data key; credential-name authenticated data binds its wrapped key and ciphertext to its name. Nonces are random 96-bit values.

Version 2 stores an encrypted master-key envelope in the existing metadata row. Passphrase changes update that row atomically and preserve the master key, credential ciphertext, and recovery shares. Legacy vaults remain readable; upgrading wraps their existing key rather than rewriting each credential. Individual SQL credential and metadata replacements use atomic upserts.

TOTP uses six-digit SHA-1 codes, 30-second intervals and a one-step clock tolerance. Its seed is encrypted under the vault key. This checks the application's unlock procedure, **not independent offline encryption protection**. Passphrase plus a password-only database is sufficient for offline decryption. Separate key-file protection requires keeping that file away from an attacker who has the database and passphrase.

Recovery uses two-of-three Shamir shares over GF(256). Any two recover the master key. Recovery bypasses all normal unlock factors and cannot replace an encrypted database backup. Original shares remain valid after passphrase rotation or recovery enrollment; rotate stored provider credentials if shares were compromised.

## Local interface

The UI server binds only to 127.0.0.1 on an ephemeral port. Mutations require an exact Host, exact Origin, JSON content type and a random launch capability. That capability is carried in the URL fragment, not request logs. UI assets are local, responses are uncached, and a content security policy prevents framing and external scripts. Quit ends the interface's session and shuts down its server.

This limits drive-by website requests; it cannot protect against malicious code running as the same OS user. Browser extensions, developer tools, local processes and root may inspect the interface's inputs or memory. Use a trusted device and browser.

## Sessions and storage

Bearer session tokens authorize access to the entire vault. Expiry, explicit lock and best-effort IP checks govern ordinary application access. These checks cannot revoke a credential or key already copied by a tool. A local process with both the session file and token can recover its key and keep it beyond expiry. Use OS isolation when running untrusted software.

Cloud storage operators can see credential names, notes, categories and logs, and can delete or modify data. Logs are best-effort, not tamper-proof evidence. Backend credentials are sensitive even though credential values are encrypted. Keep independent backups and test recovery on a disposable copy.

macOS passphrase storage uses native Keychain APIs, avoiding secrets in process arguments. Linux Secret Service receives passwords on stdin. Remembering a passphrase is offered only with separate key-file protection; no Windows password-cache implementation is currently provided. File permissions are restrictive on Unix; Windows protection depends on the user's directory ACLs.

This release is tested but has not had an independent security audit. Please report incorrect cryptographic behavior, data-loss paths, cross-origin authorization failures, accidental secret exposure, or discrepancies from this documented threat model.
