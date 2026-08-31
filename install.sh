#!/usr/bin/env bash
# Handshake installer.
#
#   curl -fsSL https://raw.githubusercontent.com/zeroai-tech/handshake/main/install.sh | bash
#
# Installs into ~/.handshake/app, puts `handshake` on your PATH, and registers
# the MCP server with any agent CLI it finds. Safe to re-run: it updates.
set -euo pipefail

REPO="https://github.com/zeroai-tech/handshake.git"
APP="${HANDSHAKE_APP:-$HOME/.handshake/app}"
BIN="${HANDSHAKE_BIN:-$HOME/.local/bin}"

say()  { printf '  %s\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

printf '\n  Handshake — encrypted credential vault\n\n'

# ── requirements ────────────────────────────────────────────────────────────
command -v git >/dev/null || die "git is required."
PY=""
for c in python3.13 python3.12 python3.11 python3.10 python3; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info>=(3,10) else 1)' 2>/dev/null; then
    PY="$c"; break
  fi
done
[ -n "$PY" ] || die "Python 3.10+ is required. Install it, then re-run this."
ok "python: $($PY --version 2>&1)"

# ── fetch ───────────────────────────────────────────────────────────────────
if [ -d "$APP/.git" ]; then
  say "updating $APP"
  git -C "$APP" fetch --quiet origin main
  git -C "$APP" reset --quiet --hard origin/main
  ok "updated"
else
  say "installing to $APP"
  mkdir -p "$(dirname "$APP")"
  git clone --quiet --depth 1 "$REPO" "$APP"
  ok "cloned"
fi

# ── isolated environment ────────────────────────────────────────────────────
say "setting up its own environment (nothing touches your system python)"
"$PY" -m venv "$APP/.venv" 2>/dev/null || die "could not create a virtualenv"
"$APP/.venv/bin/pip" install --quiet --upgrade pip >/dev/null 2>&1 || true
"$APP/.venv/bin/pip" install --quiet -e "$APP" || die "dependency install failed"
ok "dependencies installed"

# ── PATH ────────────────────────────────────────────────────────────────────
mkdir -p "$BIN"
ln -sf "$APP/bin/handshake" "$BIN/handshake"
ok "handshake -> $BIN/handshake"

if ! command -v handshake >/dev/null 2>&1; then
  LINE="export PATH=\"$BIN:\$PATH\""
  for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
    [ -f "$rc" ] || continue
    grep -qF "$BIN" "$rc" 2>/dev/null || { printf '\n# Handshake\n%s\n' "$LINE" >> "$rc"; say "added $BIN to PATH in $rc"; }
  done
  warn "open a new terminal, or run:  $LINE"
fi

# ── agent CLIs ──────────────────────────────────────────────────────────────
"$APP/.venv/bin/python" "$APP/handshake.py" agents --quiet || true

printf '\n'
ok "installed"
printf '\n  Next — one command, about a minute:\n\n      handshake setup\n\n'
printf '  It asks for a passphrase, shows a QR code for your authenticator app,\n'
printf '  and prints a recovery card. Nothing is created until 2FA is proven.\n\n'
