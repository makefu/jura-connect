"""Tests for the broadcast-reply parser."""

from __future__ import annotations

import datetime

import pytest

from jura_connect.discovery import parse_reply


def _build_reply(
    *,
    fw: bytes = b"TT237W V06.11" + b" " * 3,  # 16 bytes
    name: bytes = b"Kaffeebert" + b" " * 22,  # 32 bytes
    hw_id: bytes = b"S8-EB" + b" " * 11,  # 16 bytes
    article: int = 0x3B1B,
    machine: int = 0x0001,
    serial: int = 0x1234,
    prod_date_raw: int = 0x4F39,  # 2029-09-25 -- valid bit packing
    flags: int = 0b00010001,
    status_tail: bytes = b"\xab\xcd\xef",
) -> bytes:
    """Build a broadcast reply with the structure WifiFrog.H expects."""
    body = bytearray(b"\x00" * 110)
    total_len = 110 + len(status_tail)
    body[0:2] = total_len.to_bytes(2, "big")
    # Control word: bit15 set, bit14 clear, low 12 = 1523.
    control = (1 << 15) | 1523
    body[2:4] = control.to_bytes(2, "big")
    assert len(fw) == 16
    body[4:20] = fw
    assert len(name) == 32
    body[20:52] = name
    assert len(hw_id) == 16
    body[52:68] = hw_id
    body[68:70] = article.to_bytes(2, "big")
    body[70:72] = machine.to_bytes(2, "big")
    body[72:74] = serial.to_bytes(2, "big")
    body[74:76] = prod_date_raw.to_bytes(2, "big")
    body[76:78] = (0).to_bytes(2, "big")
    body[109] = flags
    return bytes(body) + status_tail


def test_parses_valid_broadcast() -> None:
    raw = _build_reply()
    m = parse_reply(raw, "192.168.1.42")
    assert m.address == "192.168.1.42"
    assert m.fw == "TT237W V06.11"
    assert m.name == "Kaffeebert"
    assert m.hw_id == "S8-EB"
    assert m.article_number == 0x3B1B
    assert m.serial_number == 0x1234
    assert m.status_hex == "ABCDEF"


def test_rejects_too_short_reply() -> None:
    with pytest.raises(ValueError):
        parse_reply(b"\x00" * 32, "1.2.3.4")


def test_rejects_bad_magic() -> None:
    raw = bytearray(_build_reply())
    # Corrupt the magic 1523 -> 1024
    raw[2:4] = ((1 << 15) | 1024).to_bytes(2, "big")
    with pytest.raises(ValueError):
        parse_reply(bytes(raw), "1.2.3.4")


def test_production_date_parses_or_returns_none() -> None:
    # prod_date_raw=0 -> month/day both zero -> None (handled gracefully).
    m = parse_reply(_build_reply(prod_date_raw=0), "1.2.3.4")
    assert m.production_date is None

    # Valid encoded date: ((2029-1990)<<9) | (9<<5) | 25 = 20217
    encoded = ((2029 - 1990) << 9) | (9 << 5) | 25
    m2 = parse_reply(_build_reply(prod_date_raw=encoded), "1.2.3.4")
    assert m2.production_date == datetime.date(2029, 9, 25)


def test_flag_helpers() -> None:
    m = parse_reply(_build_reply(flags=0b10010001), "1.2.3.4")  # bits 0,4,7
    assert m.standby is True
    assert m.ready is True  # bit 4
    assert m.busy is False  # bit 0 set -> S=False -> not busy
