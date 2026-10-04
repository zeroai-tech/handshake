"""Local, capability-protected setup UI. No secrets are sent to a web service.

The random launch capability, exact Host/Origin checks and JSON-only writes keep
unrelated browser pages from operating this loopback server. These checks do
not claim to protect against malicious code already running as the same user.
"""
from __future__ import annotations
import base64, json, os, secrets, threading, time, webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from . import crypto, session, store, totp, vault
from .backends import BACKENDS, ENV, HOME, get_backend

ASSETS = Path(__file__).parent / 'gui_assets'
AGENTS = ('Claude Code', 'Codex', 'Gemini CLI', 'Cursor', 'Windsurf')

def qr_image(uri):
    import qrcode
    qr = qrcode.QRCode(border=0, error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(uri); qr.make(fit=True)
    return 'data:image/png;base64,' + base64.b64encode(totp._png_bytes(qr.get_matrix())).decode()

class Controller:
    def __init__(self):
        self.pending = None
        self.token = None
        self.failures = 0
        self.blocked_until = 0
        self.db = None
        cfg = store.load_config()
        configured = cfg.get('backend') or cfg.get('account_id') or os.environ.get('HANDSHAKE_BACKEND') or (HOME / 'vault.db').exists()
        if configured: self.db = get_backend()

    def record(self):
        if self.db is None: return None
        try: return self.db.get_vault()
        except RuntimeError: raise ValueError('Cannot reach the vault. Check storage settings or your network.') from None

    def state(self):
        record = self.record()
        data = vault.bundle(record) if record else None
        current = session.status()
        if not current.get('open'): self.token = None
        return {'configured': self.db is not None, 'exists': record is not None,
                'backend': self.db.name if self.db else None,
                'unlocked': bool(self.token), 'seconds_left': current.get('seconds_left', 0) if self.token else 0,
                'keyfile': bool(data and data.get('factor_id')), 'legacy': bool(record and not data),
                'agents': self.detect_agents()}

    @staticmethod
    def detect_agents():
        import shutil
        home = Path.home()
        paths = {'Codex': '.codex', 'Gemini CLI': '.gemini', 'Cursor': '.cursor', 'Windsurf': '.codeium/windsurf'}
        found = [name for name, folder in paths.items() if (home / folder).is_dir()]
        if shutil.which('claude'): found.insert(0, 'Claude Code')
        return found

    def key(self):
        key, reason = session.resolve(self.token or '')
        if key is None:
            self.token = None
            raise ValueError('Your session has ended. Unlock the vault again.')
        return key

    @staticmethod
    def factor(body):
        text = body.get('keyfile')
        return vault.parse_keyfile(text) if text else None

    def enrollment(self):
        pending = self.pending
        if not pending or time.monotonic() - pending['started'] > 900:
            self.pending = None
            raise ValueError('Setup expired. Start again; your vault has not been changed.')
        return pending

    def handle(self, action, body):
        if action == 'state': return self.state()
        if action == 'storage':
            try: existing = self.record()
            except ValueError: existing = None
            if existing and body.get('switch') is not True: raise ValueError('An existing vault is connected. Confirm switching storage first.')
            name = body.get('backend', 'sqlite')
            if name not in BACKENDS: raise ValueError('Choose a supported storage option.')
            config = body.get('config', {})
            if not isinstance(config, dict): raise ValueError('Invalid storage settings.')
            config = {key: str(config[key]).strip() for key in ENV[name] if config.get(key)}
            if name == 'sqlite': config.setdefault('path', str(HOME / 'vault.db'))
            cfg = store.load_config(); cfg.update({'backend': name, name: config})
            candidate = get_backend(cfg)
            try: candidate.ensure_schema(); candidate.get_vault()
            except RuntimeError: raise ValueError('Could not connect. Check the settings; for Supabase, create the vault tables first.') from None
            if self.token: session.end()
            store.save_config(cfg); self.db = candidate; self.pending = None; self.token = None
            return self.state()
        if action == 'enroll':
            if not self.db: raise ValueError('Choose storage first.')
            recovering = self.pending and 'recovery_master' in self.pending
            previous = self.enrollment()['previous'] if recovering else None
            current = self.record()
            if current and not recovering: raise ValueError('A vault already exists. Unlock it instead.')
            if recovering and current != previous: raise ValueError('The vault changed. Start recovery again.')
            if not recovering and self.db.count_secrets(): raise ValueError('This storage contains incomplete vault data. Restore its original backup before creating a new vault.')
            password = body.get('passphrase', '')
            if password != body.get('confirm'): raise ValueError('The passphrases do not match.')
            keytext = vault.new_keyfile() if body.get('use_keyfile', True) else None
            factor = vault.parse_keyfile(keytext) if keytext else None
            tsec = totp.new_secret()
            if recovering:
                master = self.pending['recovery_master']
                data = vault.bundle(previous)
                record = vault.wrap(master, password, tsec, int(previous['created_at']), factor, data.get('recovery') if data else None)
                shares = crypto.split_secret(master, 3, 2)
            else: record, master, shares = vault.create(password, tsec, factor)
            self.pending = {'record': record, 'master': master, 'shares': shares,
                            'tsec': tsec, 'started': time.monotonic(), 'verified': False,
                            'keytext': keytext, 'previous': previous}
            uri = totp.provisioning_uri(tsec, body.get('account') or 'My vault')
            return {'qr': qr_image(uri), 'manual_key': tsec, 'keyfile': keytext}
        if action == 'verify':
            pending = self.enrollment()
            if not totp.verify(pending['tsec'], str(body.get('code', ''))): raise ValueError('That code did not match. Try the newest code on your phone.')
            pending['verified'] = True
            return {'shares': pending['shares'], 'connection': store.load_config()}
        if action == 'commit':
            pending = self.enrollment()
            if not pending['verified'] or body.get('saved') is not True:
                raise ValueError('Verify your authenticator and save the recovery shares first.')
            if pending['keytext'] and body.get('keyfile_saved') is not True:
                raise ValueError('Save the security key file before continuing.')
            current = self.record()
            if current != pending['previous']: raise ValueError('The vault changed. Start setup or recovery again.')
            vault.save(self.db, pending['record'])
            self.token = session.begin(pending['master'])
            self.pending = None
            self.db.log(int(time.time()), 'init', None, session.status().get('ip'), True, 'guided setup')
            return self.state()
        if action == 'cancel':
            self.pending = None
            return self.state()
        if action == 'unlock':
            if time.monotonic() < self.blocked_until: raise ValueError('Too many attempts. Wait one minute before trying again.')
            record = self.record()
            if not record: raise ValueError('Create a vault first.')
            try:
                master = vault.authenticate(record, str(body.get('passphrase', '')), str(body.get('code', '')), self.factor(body))
            except ValueError:
                self.failures += 1
                if self.failures >= 5: self.blocked_until = time.monotonic() + 60; self.failures = 0
                self.db.log(int(time.time()), 'unlock', None, None, False, 'authentication failed')
                raise ValueError('Could not unlock. Check the passphrase, phone code and security key file.') from None
            ttl = int(body.get('ttl', 1800))
            if ttl not in (600, 1800, 3600): raise ValueError('Choose a 10, 30 or 60 minute session.')
            self.token = session.begin(master, ttl=ttl)
            self.failures = 0
            self.db.log(int(time.time()), 'unlock', None, session.status().get('ip'), True, 'local interface')
            return self.state()
        if action == 'lock':
            if self.token: session.end()
            self.token = None; self.pending = None
            return self.state()
        if action == 'recover':
            record = self.record()
            if not record: raise ValueError('Connect your existing vault first.')
            shares = body.get('shares', [])
            if not isinstance(shares, list) or len(shares) != 2: raise ValueError('Enter two different recovery shares.')
            master = vault.recover(record, shares)
            self.pending = {'recovery_master': master, 'previous': record, 'started': time.monotonic()}
            return {'recovery': True}
        if action == 'agents':
            import handshake
            home = Path.home()
            registry = {
                'Claude Code': handshake._register_claude_code,
                'Codex': handshake._register_codex,
                'Gemini CLI': lambda: handshake._register_json_agent('Gemini CLI', home / '.gemini/settings.json', 'mcpServers'),
                'Cursor': lambda: handshake._register_json_agent('Cursor', home / '.cursor/mcp.json', 'mcpServers'),
                'Windsurf': lambda: handshake._register_json_agent('Windsurf', home / '.codeium/windsurf/mcp_config.json', 'mcpServers'),
            }
            selected = body.get('agents', [])
            if not isinstance(selected, list) or any(name not in registry for name in selected): raise ValueError('Choose an agent from the list.')
            done, failed = [], []
            for name in selected:
                try:
                    if registry[name](): done.append(name)
                    else: failed.append(name)
                except (OSError, RuntimeError): failed.append(name)
            return {'done': done, 'failed': failed}
        master = self.key()
        if action == 'new-keyfile': return {'keyfile': vault.new_keyfile()}
        if action == 'list': return {'items': self.db.list_secrets()}
        if action == 'put':
            name = str(body.get('name', '')).strip(); value = body.get('value')
            if not name or len(name) > 128 or not isinstance(value, str) or not value or len(value) > 32768:
                raise ValueError('Enter a credential name and value (up to 32 KB).')
            if self.db.get_secret(name) and body.get('replace') is not True: raise ValueError('That name already exists. Confirm replacement to update it.')
            dek = crypto.new_dek()
            self.db.put_secret(name, crypto.wrap_dek(master, dek, name), crypto.seal(dek, value.encode(), aad=name.encode()),
                               str(body.get('note', ''))[:500] or None, str(body.get('category', ''))[:100] or None, int(time.time()))
            self.db.log(int(time.time()), 'put', name, session.status().get('ip'), True, 'local interface')
            return {'items': self.db.list_secrets()}
        if action == 'export':
            records = [self.db.get_secret(item['name']) for item in self.db.list_secrets()]
            result = {'format': 'handshake-export-v1', 'vault': self.record(), 'secrets': records}
            self.db.log(int(time.time()), 'export', None, session.status().get('ip'), True, 'encrypted backup')
            return result
        if action == 'passwd':
            password = body.get('passphrase', '')
            if password != body.get('confirm'): raise ValueError('The passphrases do not match.')
            updated = vault.rotate(self.record(), master, password, self.factor(body))
            vault.save(self.db, updated)
            import handshake
            from . import keyring
            keyring.clear(handshake.KEYRING_ACCOUNT)
            session.end(); self.token = None
            return self.state()
        if action == 'token': return {'token': self.token}
        if action == 'log': return {'items': self.db.recent_log(50)}
        raise ValueError('Unknown action.')


class GuiServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, controller=None, port=0):
        self.controller = controller or Controller()
        self.capability = secrets.token_urlsafe(32)
        self.operation_lock = threading.Lock()
        super().__init__(('127.0.0.1', port), Handler)
        self.origin = f'http://127.0.0.1:{self.server_port}'

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def reply(self, status, content, mime='application/json'):
        if mime == 'application/json': content = json.dumps(content).encode()
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(content)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.end_headers(); self.wfile.write(content)
    def do_GET(self):
        if self.headers.get('Host') != self.server.origin.removeprefix('http://'):
            return self.reply(403, {'error': 'Invalid host.'})
        paths = {'/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                 '/style.css': ('style.css', 'text/css; charset=utf-8'), '/logo.svg': ('logo.svg', 'image/svg+xml')}
        if self.path not in paths: return self.reply(404, {'error': 'Not found.'})
        name, mime = paths[self.path]
        self.reply(200, (ASSETS / name).read_bytes(), mime)
    def do_POST(self):
        expected = self.server.origin
        if (self.headers.get('Host') != expected.removeprefix('http://') or self.headers.get('Origin') != expected
                or not secrets.compare_digest(self.headers.get('X-Handshake-Token', ''), self.server.capability)
                or self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/json'):
            return self.reply(403, {'error': 'This window is not authorized. Reopen Handshake.'})
        try:
            length = int(self.headers.get('Content-Length', 0))
            if not 0 < length <= 65536: return self.reply(413, {'error': 'Request is too large.'})
            if not self.path.startswith('/api/'): return self.reply(404, {'error': 'Not found.'})
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict): raise ValueError('Invalid request.')
            if self.path == '/api/quit':
                with self.server.operation_lock: self.server.controller.handle('lock', {})
                self.reply(200, {'closed': True})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return
            with self.server.operation_lock: result = self.server.controller.handle(self.path[5:], body)
            self.reply(200, result)
        except ValueError as error:
            self.reply(400, {'error': str(error) if not isinstance(error, json.JSONDecodeError) else 'Invalid request.'})
        except (KeyError, TypeError):
            self.reply(400, {'error': 'Check the entered details and try again.'})
        except (RuntimeError, OSError):
            self.reply(503, {'error': 'Could not complete the operation. Check your storage connection and try again.'})
        except Exception:
            self.reply(500, {'error': 'Could not verify the vault data. Restore a verified backup or reopen Handshake.'})
    def do_OPTIONS(self): self.reply(403, {'error': 'Cross-origin access is not allowed.'})

def launch(open_browser=True):
    server = GuiServer()
    address = server.origin + '/#' + server.capability
    # The fragment never travels in an HTTP request and request logging is off.
    if open_browser: webbrowser.open(address)
    else: print(address, flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally:
        if server.controller.token: session.end()
        server.controller.token = None; server.controller.pending = None
        server.server_close()
