import os, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROBE = "import handshake; print(handshake.KEYRING_ACCOUNT)"

def account(home=None):
    env = dict(os.environ); env.pop("HANDSHAKE_HOME", None)
    if home: env["HANDSHAKE_HOME"] = home
    return subprocess.run([sys.executable, "-c", PROBE], cwd=ROOT, env=env, capture_output=True, text=True, check=True).stdout.strip()

class KeychainScope(unittest.TestCase):
    def test_default_vault_keeps_its_saved_passphrase(self):
        self.assertEqual(account(), "passphrase")
    def test_other_vault_never_shares_the_default_entry(self):
        with tempfile.TemporaryDirectory() as d:
            a = account(d)
            self.assertNotEqual(a, "passphrase")
            self.assertIn(str(Path(d).resolve()), a)

if __name__ == "__main__": unittest.main()
