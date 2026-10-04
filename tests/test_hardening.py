"""Data-loss, stable recovery and independent key-material regressions."""
import os, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ['HANDSHAKE_HOME'] = tempfile.mkdtemp(prefix='handshake-hardening-')
from hsvault import crypto, vault, session, keyring, totp
from hsvault.backends.sqlite import SqliteBackend

class Hardening(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = SqliteBackend({'path': str(Path(self.temp.name) / 'vault.db')}); self.db.ensure_schema()
    def tearDown(self): self.temp.cleanup()
    def test_failed_secret_update_keeps_original(self):
        self.db.put_secret('demo', 'old', 'cipher', None, None, 1); old = self.db.get_secret('demo')
        original = self.db._exec
        def fail(sql, params=None):
            if sql.startswith('INSERT INTO handshake_secrets'): raise RuntimeError('injected failure')
            return original(sql, params)
        with patch.object(self.db, '_exec', side_effect=fail):
            with self.assertRaises(RuntimeError): self.db.put_secret('demo', 'new', 'new', None, None, 2)
        self.assertEqual(self.db.get_secret('demo'), old)
    def test_failed_vault_update_keeps_original(self):
        self.db.put_vault('salt', 'verifier', 'totp', 1); old = self.db.get_vault()
        original = self.db._exec
        def fail(sql, params=None):
            if sql.startswith('INSERT INTO handshake_vault'): raise RuntimeError('injected failure')
            return original(sql, params)
        with patch.object(self.db, '_exec', side_effect=fail):
            with self.assertRaises(RuntimeError): self.db.put_vault('new', 'new', 'new', 1)
        self.assertEqual(self.db.get_vault(), old)
    def test_rotation_keeps_secret_and_recovery(self):
        factor = vault.parse_keyfile(vault.new_keyfile()); code = totp.new_secret()
        record, master, shares = vault.create('original passphrase only', code, factor)
        vault.save(self.db, record); dek = crypto.new_dek()
        self.db.put_secret('demo', crypto.wrap_dek(master, dek, 'demo'), crypto.seal(dek, b'fixture', aad=b'demo'), None, None, 1)
        old = self.db.get_secret('demo'); updated = vault.rotate(record, master, 'replacement passphrase only', factor); vault.save(self.db, updated)
        self.assertEqual(self.db.get_secret('demo'), old)
        self.assertEqual(vault.recover(updated, shares[:2]), master)
        self.assertEqual(vault.authenticate(updated, 'replacement passphrase only', totp.code_at(code), factor), master)
        with self.assertRaises(ValueError): vault.authenticate(updated, 'original passphrase only', totp.code_at(code), factor)
    def test_password_alone_cannot_decrypt_keyfile_envelope(self):
        factor = vault.parse_keyfile(vault.new_keyfile()); code = totp.new_secret()
        record, master, _ = vault.create('known fixture passphrase', code, factor)
        key = crypto.derive_kek('known fixture passphrase', crypto.b64d(record['salt']))
        with self.assertRaises(Exception): crypto.unseal(key, vault.bundle(record)['master'], aad=b'handshake-master-v2')
        with self.assertRaises(ValueError): vault.authenticate(record, 'known fixture passphrase', totp.code_at(code))
        with self.assertRaises(ValueError): vault.authenticate(record, 'known fixture passphrase', totp.code_at(code), os.urandom(32))
    def test_legacy_upgrade_preserves_original_shares(self):
        salt = os.urandom(16); master = crypto.derive_kek('legacy fixture passphrase', salt)
        code = totp.new_secret(); shares = crypto.split_secret(master, 3, 2)
        record = {'salt': crypto.b64e(salt), 'verifier': crypto.verifier(master, salt), 'totp_enc': crypto.seal(master, code.encode(), aad=b'totp'), 'created_at': 1, 'version': 1}
        self.assertEqual(vault.authenticate(record, 'legacy fixture passphrase', totp.code_at(code)), master)
        updated = vault.rotate(record, master, 'new fixture passphrase')
        self.assertEqual(vault.recover(updated, shares[:2]), master)
        self.assertEqual(vault.authenticate(updated, 'new fixture passphrase', totp.code_at(code)), master)
    def test_compressed_ipv6(self):
        self.assertTrue(session.same_network('2001:db8::1', '2001:db8::2'))
        self.assertFalse(session.same_network('2001:db8:1::1', '2001:db8:2::1'))
    def test_duplicate_share_rejected(self):
        shares = crypto.split_secret(os.urandom(32), 3, 2)
        with self.assertRaises(ValueError): crypto.combine_shares([shares[0], shares[0]])
    def test_macos_password_never_enters_subprocess(self):
        with patch.object(keyring, 'available', return_value='macos'), patch('hsvault.macos_keychain.perform', return_value=True) as native, patch.object(keyring, '_run') as process:
            self.assertTrue(keyring.set('fixture', 'private fixture password'))
            native.assert_called_once_with('set', keyring.SERVICE, 'fixture', 'private fixture password'); process.assert_not_called()

if __name__ == '__main__': unittest.main(verbosity=2)
