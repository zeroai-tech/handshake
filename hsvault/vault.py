"""Versioned vault envelopes shared by the CLI and local setup interface.

The master key is stable. Changing a passphrase only replaces its encrypted
envelope; credential records and recovery shares remain valid. Legacy v1 vaults
are read without migration and upgraded only by an explicit passphrase change.
TOTP is an interactive check, not an independent encryption factor. Optional
random key files add separate key material; keep them off the vault device.
"""
from __future__ import annotations
import hashlib, hmac, json, os, time
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag
from . import crypto, totp


def bundle(record: dict) -> dict | None:
    if int(record.get('version', 1)) < 2:
        return None
    value = json.loads(record['totp_enc'])
    if value.get('format') != 'handshake-envelope-v2':
        raise ValueError('Unsupported vault format. Update Handshake before continuing.')
    return value


def new_keyfile() -> str:
    return json.dumps({'format': 'handshake-keyfile-v1', 'key': crypto.b64e(os.urandom(32))}, indent=2)


def parse_keyfile(content: str) -> bytes:
    try:
        data = json.loads(content)
        key = crypto.b64d(data['key'])
        if data['format'] != 'handshake-keyfile-v1' or len(key) != 32:
            raise ValueError()
        return key
    except (ValueError, KeyError, TypeError):
        raise ValueError('Choose a valid Handshake security key file.') from None


def read_keyfile(file: str | None) -> bytes | None:
    if not file:
        return None
    p = Path(file).expanduser()
    if p.stat().st_size > 4096:
        raise ValueError('Invalid security key file.')
    return parse_keyfile(p.read_text())


def factor_id(keyfile: bytes) -> str:
    return hashlib.sha256(b'handshake-factor-id-v1:' + keyfile).hexdigest()


def unlock_key(passphrase: str, salt: bytes, keyfile: bytes | None = None) -> bytes:
    key = crypto.derive_kek(passphrase, salt)
    if keyfile is None:
        return key
    if len(keyfile) != 32:
        raise ValueError('Invalid security key file.')
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=b'handshake-keyfile-unlock-v2').derive(key + keyfile)


def wrap(master: bytes, passphrase: str, tsec: str, created_at: int | None = None,
         keyfile: bytes | None = None, recovery: dict | None = None) -> dict:
    if len(passphrase) < 12:
        raise ValueError('Use a passphrase of at least 12 characters.')
    salt = os.urandom(16)
    key = unlock_key(passphrase, salt, keyfile)
    recovery = recovery or {'salt': crypto.b64e(os.urandom(16))}
    rsalt = crypto.b64d(recovery['salt'])
    envelope = {
        'format': 'handshake-envelope-v2',
        'master': crypto.seal(key, master, aad=b'handshake-master-v2'),
        'totp': crypto.seal(master, tsec.encode(), aad=b'totp'),
        'factor_id': factor_id(keyfile) if keyfile else None,
        'recovery': {'salt': recovery['salt'], 'verifier': crypto.verifier(master, rsalt)},
    }
    return {'salt': crypto.b64e(salt), 'verifier': crypto.verifier(key, salt),
            'totp_enc': json.dumps(envelope), 'created_at': created_at or int(time.time()), 'version': 2}


def create(passphrase: str, tsec: str, keyfile: bytes | None = None) -> tuple[dict, bytes, list[str]]:
    master = os.urandom(32)
    return wrap(master, passphrase, tsec, keyfile=keyfile), master, crypto.split_secret(master, 3, 2)


def open_key(record: dict, passphrase: str, keyfile: bytes | None = None) -> bytes:
    data = bundle(record)
    if data and data.get('factor_id'):
        if keyfile is None or not hmac.compare_digest(data['factor_id'], factor_id(keyfile)):
            raise ValueError('This vault needs its original security key file.')
    else:
        keyfile = None
    salt = crypto.b64d(record['salt'])
    key = unlock_key(passphrase, salt, keyfile)
    if not hmac.compare_digest(crypto.verifier(key, salt), record['verifier']):
        raise ValueError('Wrong passphrase.')
    try: master = crypto.unseal(key, data['master'], aad=b'handshake-master-v2') if data else key
    except InvalidTag: raise ValueError('The vault envelope failed authentication. Restore a verified backup.') from None
    return master


def check_code(record: dict, master: bytes, code: str) -> None:
    data = bundle(record)
    try: tsec = crypto.unseal(master, data['totp'] if data else record['totp_enc'], aad=b'totp').decode()
    except InvalidTag: raise ValueError('The authenticator record failed verification. Restore a verified backup.') from None
    if not totp.verify(tsec, code):
        raise ValueError('That authenticator code is not valid.')


def authenticate(record: dict, passphrase: str, code: str, keyfile: bytes | None = None) -> bytes:
    master = open_key(record, passphrase, keyfile)
    check_code(record, master, code)
    return master


def rotate(record: dict, master: bytes, passphrase: str, keyfile: bytes | None = None,
           new_totp: str | None = None) -> dict:
    data = bundle(record)
    if data and data.get('factor_id') and (keyfile is None or factor_id(keyfile) != data['factor_id']):
        raise ValueError('Keep the original security key file when changing this passphrase.')
    tsec = new_totp or crypto.unseal(master, data['totp'] if data else record['totp_enc'], aad=b'totp').decode()
    return wrap(master, passphrase, tsec, int(record['created_at']), keyfile,
                data.get('recovery') if data else None)


def recover(record: dict, shares: list[str]) -> bytes:
    master = crypto.combine_shares(shares)
    data = bundle(record)
    recovery = data['recovery'] if data else record
    expected = crypto.verifier(master, crypto.b64d(recovery['salt']))
    if not hmac.compare_digest(expected, recovery['verifier']):
        raise ValueError('Those recovery shares do not match this vault.')
    return master


def save(db, record: dict) -> None:
    db.put_vault(record['salt'], record['verifier'], record['totp_enc'], int(record['created_at']), int(record['version']))
