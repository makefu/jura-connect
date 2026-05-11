"""Jura WiFi obfuscation cipher.

Direct port of ``joe_android_connector.src.connection.wifi.WifiCryptoUtil``
from the J.O.E. Android APK.

Wire framing for TCP messages:

    b'*'  <encoded_payload>  b'\\r\\n'

``<encoded_payload>`` begins with the random key byte (or the escape
sequence ``0x1B <key^0x80>`` when the key value is one of the reserved
sync bytes). Every encoded byte that falls into the reserved set is
emitted as ``0x1B <byte^0x80>``. The same escape rules apply on receive.

The per-nibble permutation in :func:`_a` is self-inverse — encoding twice
returns the original input — so the same function powers both encode
and decode.
"""

from __future__ import annotations

import secrets

__all__ = [
    "SBOX_A",
    "SBOX_B",
    "RESERVED",
    "encode_payload",
    "decode_payload",
    "wrap_frame",
    "unwrap_frame",
    "encode",
    "decode",
]

# Permutation tables (4-bit). Lifted verbatim from WifiCryptoUtil.
SBOX_A: tuple[int, ...] = (1, 0, 3, 2, 15, 14, 8, 10, 6, 13, 7, 12, 11, 9, 5, 4)
SBOX_B: tuple[int, ...] = (9, 12, 6, 11, 10, 15, 2, 14, 13, 0, 4, 3, 1, 8, 7, 5)

# Bytes that must be escaped (XOR 0x80, prefixed with 0x1B).
# 0x00 NUL, 0x0A LF, 0x0D CR, 0x26 '&', 0x1B ESC
RESERVED: frozenset[int] = frozenset({0x00, 0x0A, 0x0D, 0x26, 0x1B})

_ESCAPE = 0x1B
_ESCAPE_XOR = 0x80


def _a(nibble: int, pos: int, key_hi: int, key_full: int) -> int:
    """The per-nibble permutation. Self-inverse for the SBOX_A/SBOX_B pair."""
    # Stage 1
    iB = (nibble + pos + key_hi) & 0xFF
    iB %= 16

    i11 = (pos >> 4) & 0xFF

    # Stage 2 -- inner SBOX_B lookup
    inner_idx = ((i11 + (SBOX_A[iB] + key_full)) - pos - key_hi) & 0xFF
    inner_idx %= 16

    # Stage 3 -- outer SBOX_A lookup
    outer_idx = ((SBOX_B[inner_idx] + key_hi + pos - key_full) - i11) & 0xFF
    outer_idx %= 16

    result = (SBOX_A[outer_idx] - pos - key_hi) & 0xFF
    return result % 16


def _key_random() -> int:
    """Pick a random key byte, skipping reserved low nibbles."""
    while True:
        k = secrets.randbelow(0x100)
        low = k & 0x0F
        # APK rejects low nibbles 0x0E and 0x0F
        if low not in (0x0E, 0x0F):
            return k


def encode_payload(payload: bytes, key: int | None = None) -> bytes:
    """Encode the inner payload (does not include the leading sync ``*``).

    Returns a byte string starting with the key (or its escape pair)
    followed by the encoded payload bytes with reserved bytes escaped.
    """
    if key is None:
        key = _key_random()
    else:
        key &= 0xFF

    out = bytearray()
    if key in RESERVED:
        out.append(_ESCAPE)
        out.append(key ^ _ESCAPE_XOR)
    else:
        out.append(key)

    key_hi = (key >> 4) & 0x0F
    pos = 0
    for b in payload:
        hi = (b >> 4) & 0x0F
        lo = b & 0x0F
        eh = _a(hi, pos, key_hi, key) & 0x0F
        el = _a(lo, pos + 1, key_hi, key) & 0x0F
        enc = ((eh << 4) | el) & 0xFF
        pos += 2
        if enc in RESERVED:
            out.append(_ESCAPE)
            out.append(enc ^ _ESCAPE_XOR)
        else:
            out.append(enc)
    return bytes(out)


def decode_payload(buf: bytes) -> bytes:
    """Decode the inner payload (does not include the leading sync ``*``).

    The first byte (or escape pair) carries the key, the remainder is
    the encoded data terminated wherever the caller already trimmed.
    """
    if not buf:
        return b""
    i = 0
    if buf[i] == _ESCAPE:
        i += 1
        key = buf[i] ^ _ESCAPE_XOR
        i += 1
    else:
        key = buf[i]
        i += 1
    key_hi = (key >> 4) & 0x0F

    out = bytearray()
    pos = 0
    n = len(buf)
    while i < n:
        b = buf[i]
        i += 1
        if b == _ESCAPE:
            if i >= n:
                break
            b = buf[i] ^ _ESCAPE_XOR
            i += 1
        hi = (b >> 4) & 0x0F
        lo = b & 0x0F
        dh = _a(hi, pos, key_hi, key) & 0x0F
        dl = _a(lo, pos + 1, key_hi, key) & 0x0F
        out.append(((dh << 4) | dl) & 0xFF)
        pos += 2
    return bytes(out)


# Reasonable upper bound on a single message; matches APK MSS / receive buffer.
MAX_FRAME = 1500


def wrap_frame(payload: bytes, key: int | None = None) -> bytes:
    """Encode and wrap a single frame ready to be written to the TCP socket.

    Output format::

        b'*' <encoded_payload> b'\\r\\n'
    """
    return b"*" + encode_payload(payload, key) + b"\r\n"


def unwrap_frame(raw: bytes) -> bytes:
    """Decode one received frame.

    ``raw`` is the bytes between the leading ``*`` (which the caller is
    expected to strip) and the terminating CR/LF, with the encoded key
    byte still at index 0.
    """
    # Strip optional leading '*' for robustness.
    if raw and raw[0] == 0x2A:
        raw = raw[1:]
    # Strip trailing CR/LF.
    while raw and raw[-1] in (0x0D, 0x0A):
        raw = raw[:-1]
    return decode_payload(raw)


# Convenience aliases that match the naming in the APK doc.
encode = encode_payload
decode = decode_payload
