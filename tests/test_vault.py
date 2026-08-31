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


class QrRendering(unittest.TestCase):
    """The QR is how 2FA gets enrolled. If it will not scan, setup stalls."""

    URI = "otpauth://totp/Handshake:demo?secret=JBSWY3DPEHPK3PXP&issuer=Handshake"

    def test_colour_render_is_dark_on_light(self):
        """A QR must be dark modules on a light field or scanners refuse it."""
        out = totp.qr_ascii(self.URI, color=True)
        self.assertIn("48;5;15", out)               # white background present
        self.assertIn("48;5;16", out)               # black modules present
        self.assertTrue(out.rstrip().endswith("\033[0m"))

    def test_modules_are_two_cells_wide(self):
        """Terminal cells are ~2:1, so one cell per module renders a stretched
        code that many phones will not read."""
        plain = totp.qr_ascii(self.URI, color=False)
        rows = [r for r in plain.splitlines() if r.strip()]
        width = len(rows[0]) - 2                    # minus the leading indent
        self.assertEqual(width % 2, 0)
        self.assertEqual(width // 2, len(rows))     # square in modules

    def test_quiet_zone_is_present(self):
        """Without a margin, scanners cannot find the code's edges.

        The border row must be entirely light modules. In the no-colour
        rendering a light module is a filled block, so a uniform first row is
        what a correct quiet zone looks like there.
        """
        rows = [r[2:] for r in totp.qr_ascii(self.URI, color=False).splitlines()]
        self.assertTrue(rows[0])
        self.assertEqual(set(rows[0]), {"\u2588"}, "top border is not a clean quiet zone")
        self.assertEqual(set(rows[-1]), {"\u2588"}, "bottom border is not a clean quiet zone")
        self.assertEqual(rows[len(rows) // 2][:2], "\u2588\u2588", "no left margin")

    def test_no_colour_when_not_a_tty(self):
        """Piped output must not be full of escape codes."""
        self.assertNotIn("\033[", totp.qr_ascii(self.URI, color=False))

    def test_png_is_a_valid_png(self):
        import tempfile, struct
        path = os.path.join(tempfile.mkdtemp(), "qr.png")
        self.assertTrue(totp.qr_png(self.URI, path))
        with open(path, "rb") as f:
            raw = f.read()
        self.assertEqual(raw[:8], b"\x89PNG\r\n\x1a\n")
        w, h = struct.unpack(">II", raw[16:24])
        self.assertEqual(w, h)                      # square
        self.assertGreater(w, 100)
        # IEND is a full chunk: 4-byte length, tag, then CRC.
        self.assertEqual(raw[-12:], b"\x00\x00\x00\x00IEND\xae\x42\x60\x82")

    def test_missing_secret_does_not_crash_rendering(self):
        self.assertIsInstance(totp.qr_ascii("otpauth://totp/x", color=False), str)


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
