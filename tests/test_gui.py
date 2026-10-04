"""Real HTTP boundary and controller tests; all storage and keys are fixtures."""
import json, os, sys, tempfile, threading, unittest, urllib.request, urllib.error
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ['HANDSHAKE_HOME'] = tempfile.mkdtemp(prefix='handshake-gui-test-')
from hsvault import session, totp, vault
from hsvault.gui import Controller, GuiServer
from hsvault.backends.sqlite import SqliteBackend

class Gui(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.folder = Path(self.temp.name)
        self.patches = [patch('hsvault.gui.store.load_config', return_value={}), patch('hsvault.gui.store.save_config'),
                        patch.dict(os.environ, {'HANDSHAKE_BACKEND':'sqlite', 'HANDSHAKE_SQLITE_PATH':str(self.folder/'vault.db')}),
                        patch.object(session, 'STATE', self.folder), patch.object(session, 'SESSION_FILE', self.folder/'session.json'),
                        patch.object(session, 'public_ip', return_value=None), patch('hsvault.keyring.clear', return_value=True)]
        for p in self.patches: p.start()
        self.db = SqliteBackend({'path':str(self.folder/'vault.db')}); self.db.ensure_schema()
        self.controller = Controller(); self.controller.db = self.db
        self.server = GuiServer(self.controller)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        for p in reversed(self.patches): p.stop()
        self.temp.cleanup()
    def request(self, action, body=None, overrides=None):
        headers={'Origin':self.server.origin,'X-Handshake-Token':self.server.capability,'Content-Type':'application/json'}
        headers.update(overrides or {})
        request = urllib.request.Request(self.server.origin+'/api/'+action, data=json.dumps(body or {}).encode(), headers=headers)
        try:
            with urllib.request.urlopen(request) as response: return response.status, json.load(response)
        except urllib.error.HTTPError as e: return e.code, json.load(e)
    def enroll(self):
        self.assertEqual(self.request('storage', {'backend':'sqlite'})[0],200)
        result = self.request('enroll', {'passphrase':'fixture passphrase only','confirm':'fixture passphrase only','use_keyfile':True})
        self.assertEqual(result[0],200); self.factor=result[1]['keyfile']; self.tsec=self.controller.pending['tsec']
        self.shares=self.request('verify',{'code':totp.code_at(self.tsec)})[1]['shares']
        self.assertEqual(self.request('commit',{'saved':True,'keyfile_saved':True})[0],200)
    def test_cross_origin_and_untrusted_requests_refused(self):
        for headers in [{'Origin':'https://attacker.example'},{'Origin':'null'},{'Origin':''},{'X-Handshake-Token':'invalid'},{'Host':'attacker.example'},{'Content-Type':'text/plain'}]:
            self.assertEqual(self.request('state', overrides=headers)[0],403)
        self.assertIsNone(self.db.get_vault())
    def test_static_pages_do_not_expose_capability_or_state(self):
        with urllib.request.urlopen(self.server.origin) as response:
            text=response.read().decode(); self.assertNotIn(self.server.capability,text)
            self.assertEqual(response.headers['Cache-Control'],'no-store'); self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])
    def test_setup_does_not_commit_before_verification_and_recovery_acknowledgment(self):
        self.request('enroll',{'passphrase':'fixture passphrase only','confirm':'fixture passphrase only'})
        self.assertEqual(self.request('commit',{'saved':True,'keyfile_saved':True})[0],400)
        self.assertIsNone(self.db.get_vault())
        self.assertEqual(self.request('verify',{'code':'not-a-code'})[0],400)
        self.assertIsNone(self.db.get_vault())
    def test_complete_setup_lock_unlock_backup_rotation_and_recovery(self):
        self.enroll()
        secret='private fixture credential'
        self.assertEqual(self.request('put',{'name':'demo','value':secret})[0],200)
        self.assertNotIn(secret,json.dumps(self.request('list')[1]))
        backup=self.request('export')[1]; self.assertNotIn(secret,json.dumps(backup)); original=self.db.get_secret('demo')
        self.request('lock'); self.assertEqual(self.request('list')[0],400)
        self.assertEqual(self.request('unlock',{'passphrase':'fixture passphrase only','code':totp.code_at(self.tsec)})[0],400)
        self.assertEqual(self.request('unlock',{'passphrase':'fixture passphrase only','code':totp.code_at(self.tsec),'keyfile':self.factor})[0],200)
        self.assertEqual(self.request('passwd',{'passphrase':'replacement passphrase only','confirm':'replacement passphrase only','keyfile':self.factor})[0],200)
        self.assertEqual(self.db.get_secret('demo'),original)
        master=vault.recover(self.db.get_vault(),self.shares[:2])
        self.assertEqual(self.request('recover',{'shares':self.shares[:2]})[0],200)
        self.assertEqual(self.request('enroll',{'passphrase':'recovered passphrase only','confirm':'recovered passphrase only','use_keyfile':True})[0],200)
        newfactor=self.controller.pending['keytext']; newcode=self.controller.pending['tsec']
        self.assertEqual(self.request('verify',{'code':totp.code_at(newcode)})[0],200)
        self.assertEqual(self.request('commit',{'saved':True,'keyfile_saved':True})[0],200)
        self.assertEqual(self.db.get_secret('demo'),original)
        self.assertEqual(vault.authenticate(self.db.get_vault(),'recovered passphrase only',totp.code_at(newcode),vault.parse_keyfile(newfactor)),master)
        self.assertEqual(vault.recover(self.db.get_vault(),self.shares[:2]),master)
    def test_unverified_setup_cancellation_leaves_no_vault(self):
        self.request('enroll',{'passphrase':'fixture passphrase only','confirm':'fixture passphrase only'})
        self.request('cancel'); self.assertIsNone(self.controller.pending); self.assertIsNone(self.db.get_vault())

if __name__=='__main__': unittest.main(verbosity=2)
