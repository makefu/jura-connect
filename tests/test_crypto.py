"""Tests for the WiFi obfuscation cipher.

The cipher is its own inverse, so any client-side encode must round-trip
through the simulator (which uses the same module). These tests exercise
that invariant directly without any network in the loop.
"""

from __future__ import annotations

import secrets

import pytest

from jura_connect import crypto


def _valid_key(k: int) -> bool:
    # Mirror the J.O.E. rejection of low nibbles 0xE / 0xF.
    return (k & 0x0F) not in (0x0E, 0x0F)


@pytest.mark.parametrize("key", [k for k in range(256) if _valid_key(k)])
def test_roundtrip_all_keys_short_message(key: int) -> None:
    msg = b"@HP:,4A75726174657374,"
    enc = crypto.encode_payload(msg, key=key)
    assert crypto.decode_payload(enc) == msg


@pytest.mark.parametrize("key", [0x00, 0x0A, 0x0D, 0x1B, 0x26])
def test_roundtrip_for_keys_in_reserved_set(key: int) -> None:
    """Keys equal to a reserved byte must be escaped as ``0x1B <key^0x80>``."""
    msg = b"@HU?\r"
    enc = crypto.encode_payload(msg, key=key)
    # Reserved keys must be emitted as the escape pair.
    assert enc[0] == 0x1B
    assert enc[1] == (key ^ 0x80)
    assert crypto.decode_payload(enc) == msg


def test_reserved_bytes_inside_payload_are_escaped() -> None:
    # 0x26 ('&') is reserved; the encoder must emit 0x1B 0xa6 for it.
    msg = bytes([0x26]) * 8
    enc = crypto.encode_payload(msg, key=0x42)
    # Every encoded byte must NOT be one of the reserved values.
    for b in enc:
        assert b not in crypto.RESERVED, f"reserved byte 0x{b:02X} leaked through"
    assert crypto.decode_payload(enc) == msg


def test_roundtrip_random_messages() -> None:
    rng = secrets.SystemRandom(0xC0FFEE)
    for _ in range(500):
        key = rng.randint(0, 0x100 - 1)
        if not _valid_key(key):
            continue
        n = rng.randint(0, 80)
        msg = bytes(rng.randint(0, 255) for _ in range(n))
        assert crypto.decode_payload(crypto.encode_payload(msg, key=key)) == msg


def test_wrap_unwrap_includes_sync_and_crlf() -> None:
    payload = b"@HB"
    frame = crypto.wrap_frame(payload, key=0x42)
    assert frame.startswith(b"*")
    assert frame.endswith(b"\r\n")
    assert crypto.unwrap_frame(frame) == payload


def test_protocol_wrap_appends_inner_crlf() -> None:
    """``protocol.wrap`` must append ``\\r\\n`` to the cleartext body
    before encoding — TT237W rejects writes with ``@tm:00`` otherwise.

    Verified against the J.O.E. Android app's pcap on Kaffeebert:
    every payload it sends ends with ``\\r\\n`` inside the cipher body
    *and* the outer frame terminator.
    """
    from jura_connect import protocol

    frame = protocol.wrap(b"@TM:13,211E96", key=0x42)
    # Decode the inner body and check it ends with the inner CRLF.
    body = frame[1:-2]  # strip leading '*' and trailing outer CRLF
    decoded = crypto.decode_payload(body)
    assert decoded == b"@TM:13,211E96\r\n"

    # Idempotent: callers that already include the CRLF aren't doubled.
    frame2 = protocol.wrap(b"@TS:00\r\n", key=0x42)
    decoded2 = crypto.decode_payload(frame2[1:-2])
    assert decoded2 == b"@TS:00\r\n"


def test_protocol_unwrap_strips_inner_crlf() -> None:
    """``protocol.unwrap`` strips the inner CRLF so callers see clean
    payloads (the real dongle adds CRLF inside its replies too)."""
    from jura_connect import protocol

    frame = protocol.wrap(b"@tm:13", key=0x42)
    assert protocol.unwrap(frame) == b"@tm:13"
