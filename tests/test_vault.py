"""Tests for the parts where being wrong is expensive.

Run: python3 -m pytest tests/ -q     (or: python3 tests/test_vault.py)
"""
import os, sys, tempfile, time, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["HANDSHAKE_HOME"] = tempfile.mkdtemp(prefix="handshake-test-")

from hsvault import crypto, totp                      # noqa: E402
from hsvault.backends.sqlite import SqliteBackend     # noqa: E402
from hsvault.session import same_network as sn        # noqa: E402


class Crypto(unittest.TestCase):
    def test_roundtrip(self):
        k = os.urandom(32)
        self.assertEqual(crypto.unseal(k, crypto.seal(k, b"hello")), b"hello")

    def test_wrong_key_fails_loudly(self):
        blob = crypto.seal(os.urandom(32), b"secret")
        with self.assertRaises(Exception):
            crypto.unseal(os.urandom(32), blob)

    def test_tampering_is_detected(self):
        """AES-GCM must reject edited ciphertext rather than return garbage."""
        k = os.urandom(32)
        blob = bytearray(crypto.b64d(crypto.seal(k, b"balance=100")))
        blob[-3] ^= 0x01
        with self.assertRaises(Exception):
            crypto.unseal(k, crypto.b64e(bytes(blob)))

    def test_dek_cannot_move_between_secrets(self):
        """The whole point of binding the name in as AAD."""
        kek, dek = os.urandom(32), crypto.new_dek()
        wrapped = crypto.wrap_dek(kek, dek, "prod/db")
        self.assertEqual(crypto.unwrap_dek(kek, wrapped, "prod/db"), dek)
        with self.assertRaises(Exception):
            crypto.unwrap_dek(kek, wrapped, "staging/db")

    def test_verifier_accepts_only_the_right_passphrase(self):
        salt = os.urandom(16)
        kek = crypto.derive_kek("correct horse battery staple", salt)
        v = crypto.verifier(kek, salt)
        self.assertIsNotNone(crypto.check_passphrase("correct horse battery staple", salt, v))
        self.assertIsNone(crypto.check_passphrase("wrong horse battery staple", salt, v))

    def test_same_plaintext_encrypts_differently(self):
        """Random nonce per seal: equal values must not look equal at rest."""
        k = os.urandom(32)
        self.assertNotEqual(crypto.seal(k, b"same"), crypto.seal(k, b"same"))

    def test_kdf_is_actually_slow(self):
        """A fast KDF here would make offline guessing cheap. Guard the cost."""
        t = time.time()
        crypto.derive_kek("x" * 20, os.urandom(16))
        self.assertGreater(time.time() - t, 0.25, "scrypt parameters were weakened")


class Shamir(unittest.TestCase):
    def test_any_two_of_three_rebuild(self):
        secret = os.urandom(32)
        s = crypto.split_secret(secret, 3, 2)
        for pair in ((0, 1), (0, 2), (1, 2)):
            self.assertEqual(crypto.combine_shares([s[i] for i in pair]), secret)

    def test_one_share_reveals_nothing(self):
        secret = b"A" * 32
        s = crypto.split_secret(secret, 3, 2)
        self.assertNotEqual(crypto.combine_shares([s[0], s[0]]), secret)

    def test_wrong_shares_do_not_silently_succeed(self):
        a = crypto.split_secret(os.urandom(32), 3, 2)
        b = crypto.split_secret(os.urandom(32), 3, 2)
        self.assertNotEqual(crypto.combine_shares([a[0], b[1]]), crypto.combine_shares(a[:2]))


class Totp(unittest.TestCase):
    def test_current_code_verifies(self):
        s = totp.new_secret()
        self.assertTrue(totp.verify(s, totp.code_at(s, time.time())))

    def test_wrong_code_rejected(self):
        s = totp.new_secret()
        bad = "000000" if totp.code_at(s, time.time()) != "000000" else "111111"
        self.assertFalse(totp.verify(s, bad))

    def test_clock_drift_tolerated_but_bounded(self):
        s = totp.new_secret()
        self.assertTrue(totp.verify(s, totp.code_at(s, time.time() - 30)))
        self.assertFalse(totp.verify(s, totp.code_at(s, time.time() - 3000)))


class Backend(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = SqliteBackend({"path": os.path.join(self.dir, "v.db")})
        self.db.ensure_schema()

    def test_schema_is_idempotent(self):
        self.db.ensure_schema()
        self.db.ensure_schema()

    def test_vault_roundtrip(self):
        self.assertIsNone(self.db.get_vault())
        self.db.put_vault("s", "v", "t", 1700000000)
        self.assertEqual(self.db.get_vault()["verifier"], "v")

    def test_secret_crud(self):
        self.db.put_secret("a/b", "wd", "ct", "note", "cat", 123)
        self.assertEqual(self.db.get_secret("a/b")["ciphertext"], "ct")
        self.assertEqual(self.db.count_secrets(), 1)
        self.db.put_secret("a/b", "wd2", "ct2", None, None, 124)   # replace
        self.assertEqual(self.db.count_secrets(), 1)
        self.assertEqual(self.db.get_secret("a/b")["ciphertext"], "ct2")
        self.assertTrue(self.db.delete_secret("a/b"))
        self.assertFalse(self.db.delete_secret("a/b"))

    def test_list_never_returns_ciphertext(self):
        """A listing must not become a way to pull encrypted material in bulk."""
        self.db.put_secret("x", "wd", "SENSITIVE", None, None, 1)
        for row in self.db.list_secrets():
            self.assertNotIn("ciphertext", row)
            self.assertNotIn("wrapped_dek", row)

    def test_audit_log_appends(self):
        self.db.log(1, "get", "x", "1.2.3.4", True, "why")
        self.db.log(2, "get", "y", None, False, None)
        rows = self.db.recent_log(10)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["name"], "y")          # newest first

    def test_vault_file_is_owner_only(self):
        self.assertEqual(oct(os.stat(self.db.path).st_mode & 0o777), "0o600")


class NetworkBinding(unittest.TestCase):
    """A session is pinned to a network, not to an address.

    Regression guard: CI caught a macOS runner egressing from a NAT pool
    (…117.183 then …117.182 seconds apart), which under exact matching killed
    a live session. Corporate proxies, CGNAT and mobile carriers all do this.
    """

    def test_same_pool_is_tolerated(self):
        self.assertTrue(sn("13.105.117.183", "13.105.117.182"))

    def test_strict_mode_rejects_the_same_pool(self):
        self.assertFalse(sn("13.105.117.183", "13.105.117.182", strict=True))

    def test_different_network_is_refused(self):
        self.assertFalse(sn("13.105.117.183", "203.0.113.9"))

    def test_adjacent_subnet_is_refused(self):
        self.assertFalse(sn("13.105.117.183", "13.105.118.1"))

    def test_ipv6_compares_the_64(self):
        self.assertTrue(sn("2001:db8:1:2::5", "2001:db8:1:2::9"))
        self.assertFalse(sn("2001:db8:1:2::5", "2001:db8:9:9::5"))

    def test_protocol_flip_is_refused(self):
        self.assertFalse(sn("13.105.117.183", "2001:db8::1"))

    def test_unknown_address_does_not_lock_you_out(self):
        """Better to keep working than to strand someone whose IP lookup failed."""
        self.assertTrue(sn("13.105.117.183", None))
        self.assertTrue(sn(None, "13.105.117.183"))


class ConfigMigration(unittest.TestCase):
    def test_pre_1_0_flat_config_still_reads_as_d1(self):
        """Existing installs must not break on upgrade."""
        from hsvault.backends import _migrate
        old = {"account_id": "acc", "database_id": "db", "api_token": "tok"}
        new = _migrate(old)
        self.assertEqual(new["backend"], "d1")
        self.assertEqual(new["d1"]["database_id"], "db")

    def test_new_config_passes_through(self):
        from hsvault.backends import _migrate
        cfg = {"backend": "sqlite", "sqlite": {"path": "/x"}}
        self.assertEqual(_migrate(cfg), cfg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
