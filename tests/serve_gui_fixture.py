"""Isolated browser fixture; never reads the user's configuration or keychain."""
import json, os, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
folder = tempfile.TemporaryDirectory(prefix='handshake-browser-')
os.environ.update({'HANDSHAKE_HOME':folder.name,'HANDSHAKE_BACKEND':'sqlite','HANDSHAKE_SQLITE_PATH':str(Path(folder.name)/'vault.db')})
from hsvault import session, keyring
from hsvault.gui import GuiServer
from hsvault.backends.sqlite import SqliteBackend
session.public_ip = lambda *args, **kwargs: None
keyring.clear = lambda *args, **kwargs: True
SqliteBackend({'path':str(Path(folder.name)/'vault.db')}).ensure_schema()
server = GuiServer()
print(json.dumps({'url':server.origin+'/#'+server.capability,'home':folder.name}),flush=True)
try: server.serve_forever()
finally: server.server_close(); folder.cleanup()
