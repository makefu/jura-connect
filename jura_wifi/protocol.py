"""Shared framing primitives for both client and simulator.

A "frame" on the wire is exactly:

    b'*' <encoded_body> b'\\r\\n'

``<encoded_body>`` always starts with a *key byte* (or the escape pair
``0x1B <key^0x80>`` when the key value clashes with the reserved set).
The body bytes after the key are obfuscated by
:func:`jura_wifi.crypto.encode_payload`; reserved bytes inside the body
are re-escaped with the same ``0x1B`` rule.

The same primitives back both ends of the protocol: the client uses them
to talk to a real coffee machine, and :mod:`jura_wifi.simulator` uses
them to *be* a coffee machine in tests.
"""

from __future__ import annotations

import socket

from . import crypto

SYNC = 0x2A  # b'*'
LINEBREAK = b"\r\n"


def wrap(payload: bytes, *, key: int | None = None) -> bytes:
    """Encode ``payload`` and produce a framed wire message."""
    return b"*" + crypto.encode_payload(payload, key=key) + LINEBREAK


def unwrap(raw: bytes) -> bytes:
    """Decode one received frame body (between ``*`` and ``\\r\\n``)."""
    # Strip leading sync if still present.
    if raw and raw[0] == SYNC:
        raw = raw[1:]
    while raw and raw[-1] in (0x0D, 0x0A):
        raw = raw[:-1]
    return crypto.decode_payload(raw)


class FrameReader:
    """Buffered, frame-by-frame reader over any blocking socket-like object.

    Used by both the client and the simulator. Holds a ``bytearray`` of
    in-flight bytes so partial reads are accumulated until a complete
    ``* … \\r\\n`` frame is in the buffer.
    """

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._buf = bytearray()

    def clear(self) -> None:
        self._buf.clear()

    def _pump(self) -> None:
        chunk = self._sock.recv(4096)
        if not chunk:
            raise ConnectionError("peer closed the connection")
        self._buf.extend(chunk)

    def next_frame(self, *, timeout: float | None = None) -> bytes:
        """Block until one full frame is available, then return the *decoded* body.

        Any leading garbage before the next ``*`` is silently discarded.
        """
        old = self._sock.gettimeout()
        try:
            if timeout is not None:
                self._sock.settimeout(timeout)
            while True:
                star = self._buf.find(SYNC)
                if star >= 0:
                    crlf = self._buf.find(LINEBREAK, star + 1)
                    if crlf >= 0:
                        body = bytes(self._buf[star + 1 : crlf])
                        del self._buf[: crlf + len(LINEBREAK)]
                        return crypto.decode_payload(body)
                self._pump()
        finally:
            self._sock.settimeout(old)


def send_frame(sock: socket.socket, payload: bytes, *, key: int | None = None) -> None:
    """Encode and write one frame to ``sock``."""
    sock.sendall(wrap(payload, key=key))
