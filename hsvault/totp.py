"""Time-based one-time passwords (RFC 6238), compatible with Google Authenticator.

The whole point of this file: the passphrase may be remembered by the machine,
but the six-digit code cannot be. It exists only on a phone, so every unlock
needs a human present. That is what stops an agent — or anything else with
access to this laptop — from opening the vault on its own.
"""
from __future__ import annotations
import base64, hmac, hashlib, os, struct, sys, time, urllib.parse

DIGITS = 6
PERIOD = 30


def new_secret() -> str:
    """160 bits, base32 — what Google Authenticator expects."""
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def code_at(secret_b32: str, when: float | None = None, offset: int = 0) -> str:
    pad = "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(secret_b32.upper() + pad)
    counter = int((when or time.time()) // PERIOD) + offset
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    val = (struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** DIGITS)
    return str(val).zfill(DIGITS)


def verify(secret_b32: str, code: str, drift: int = 1) -> bool:
    """Accept one step either side, for clock skew between phone and laptop.
    Compared in constant time so a wrong code leaks nothing by timing."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit():
        return False
    return any(hmac.compare_digest(code_at(secret_b32, offset=o), code)
               for o in range(-drift, drift + 1))


def provisioning_uri(secret_b32: str, account: str, issuer: str = "Handshake") -> str:
    q = urllib.parse.urlencode({
        "secret": secret_b32, "issuer": issuer,
        "algorithm": "SHA1", "digits": DIGITS, "period": PERIOD,
    })
    label = urllib.parse.quote(f"{issuer}:{account}")
    return f"otpauth://totp/{label}?{q}"


def qr_ascii(uri: str, color: bool | None = None, quiet: int = 3) -> str:
    """Render the enrolment QR so a phone camera will actually read it.

    Always local. The secret never leaves this machine — no QR web service, no
    image upload, nothing over the network. That rules out the convenient
    option of shelling out to an online generator, which would hand a stranger
    your second factor.

    Two details decide whether a phone can read a terminal QR at all:

    * **Contrast direction.** A QR must be dark modules on a light field.
      Drawing it with block characters gives light-on-dark in a dark-theme
      terminal — the inverse — and many scanners simply refuse it. So we paint
      real background colours instead of glyphs, which makes the result
      independent of the user's colour scheme.
    * **Aspect ratio.** Terminal cells are about twice as tall as they are
      wide, so one module per cell produces a stretched code. Each module is
      two cells wide, which squares it up.

    Falls back to block characters when colour is unavailable (piped output,
    NO_COLOR, a dumb terminal), and to manual entry if `qrcode` is missing —
    setup must never be blocked by a rendering problem.
    """
    try:
        import qrcode
    except ImportError:
        return ("  (QR rendering needs the `qrcode` package — "
                "use the manual key below)\n")

    q = qrcode.QRCode(
        border=quiet,
        # M tolerates ~15% damage. Worth the slightly larger code: terminal
        # captures are often photographed at an angle or slightly blurred.
        error_correction=qrcode.constants.ERROR_CORRECT_M,
    )
    q.add_data(uri)
    q.make(fit=True)
    matrix = q.get_matrix()

    if color is None:
        color = (os.environ.get("NO_COLOR") is None
                 and os.environ.get("TERM", "") != "dumb"
                 and sys.stdout.isatty())

    if color:
        # 48;5;15 = white background, 48;5;16 = black. Two spaces per module.
        light, dark, reset = "\033[48;5;15m", "\033[48;5;16m", "\033[0m"
        rows = []
        for row in matrix:
            line, current = [], None
            for cell in row:
                want = dark if cell else light
                if want != current:
                    line.append(want)
                    current = want
                line.append("  ")
            rows.append("  " + "".join(line) + reset)
        return "\n".join(rows) + "\n"

    # No colour available. Draw light modules as filled blocks and dark modules
    # as spaces — on a dark-background terminal that comes out the right way
    # round, which is the common case and what other terminal QR renderers do.
    # On a light background it is inverted and may not scan; that is precisely
    # why the coloured path above exists and is preferred.
    rows = []
    for row in matrix:
        rows.append("  " + "".join("  " if cell else "\u2588\u2588" for cell in row))
    return "\n".join(rows) + "\n"


def _png_bytes(rows: list[list[int]], scale: int = 8, quiet: int = 4) -> bytes:
    """Encode a black-and-white matrix as a PNG, using only the stdlib.

    `qrcode`'s own image writers need Pillow or pypng. Neither is worth adding
    to a tool whose whole point is installing on a freshly wiped machine, and a
    greyscale PNG is about thirty lines: a header, one IDAT of zlib-compressed
    scanlines, and an end marker, each with a CRC.
    """
    import struct, zlib

    n = len(rows)
    side = (n + quiet * 2) * scale
    white, black = b"\xff", b"\x00"

    raw = bytearray()
    blank = b"\x00" + white * side          # filter byte 0, then a white row
    for _ in range(quiet * scale):
        raw += blank
    for row in rows:
        line = bytearray()
        for _ in range(quiet * scale):
            line += white
        for cell in row:
            line += (black if cell else white) * scale
        for _ in range(quiet * scale):
            line += white
        for _ in range(scale):              # repeat vertically to square it
            raw += b"\x00" + line
    for _ in range(quiet * scale):
        raw += blank

    def chunk(tag: bytes, data: bytes) -> bytes:
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", side, side, 8, 0, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
            + chunk(b"IEND", b""))


def qr_png(uri: str, path) -> bool:
    """Also write the QR as a PNG, for when the terminal rendering will not scan.

    Generated locally like everything else — nothing is uploaded. Needs no
    imaging library; see `_png_bytes`.
    """
    try:
        import qrcode
        q = qrcode.QRCode(border=0, error_correction=qrcode.constants.ERROR_CORRECT_M)
        q.add_data(uri)
        q.make(fit=True)
        with open(path, "wb") as f:
            f.write(_png_bytes(q.get_matrix()))
        return True
    except Exception:
        return False
