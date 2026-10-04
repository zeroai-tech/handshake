"""Create an optional double-click macOS launcher for this installed checkout."""
import os, plistlib, shlex, sys
from pathlib import Path

if sys.platform != 'darwin':
    raise SystemExit('Use handshake gui on this platform.')
root = Path(__file__).resolve().parent.parent
app = Path(sys.argv[1]).expanduser() if len(sys.argv)>1 else Path.home()/'Applications/Handshake.app'
contents=app/'Contents'; executable=contents/'MacOS/Handshake'
executable.parent.mkdir(parents=True, exist_ok=True)
with (contents/'Info.plist').open('wb') as f:
    plistlib.dump({'CFBundleName':'Handshake','CFBundleIdentifier':'tech.zeroai.handshake','CFBundleExecutable':'Handshake','CFBundlePackageType':'APPL','CFBundleShortVersionString':'1.1.0'},f)
executable.write_text('#!/bin/sh\nexec '+shlex.quote(sys.executable)+' '+shlex.quote(str(root/'handshake.py'))+' gui\n')
executable.chmod(0o755)
print(app)
