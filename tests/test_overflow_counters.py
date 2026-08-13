"""Overflow product-counter bank (``@TR:33``) against the simulator.

No machine on hand declares this bank — EF545, EF1091 and EF1151 all
list ``@TR:32`` alone — so everything here is checked against the
simulator and against J.O.E.'s decoding, never against hardware. See
docs/PROTOCOL.md §5.5.
"""

from __future__ import annotations

from jura_connect.client import JuraClient, ProductCounters
from jura_connect.profile import load_profile


def _paired(sim, ef: str) -> JuraClient:
    host, port = sim.address
    c = JuraClient(
        host, port=port, conn_id="reader", auth_hash="", profile=load_profile(ef)
    )
    r = c.pair(timeout=2.0)
    assert r.state == "CORRECT"
    return c


# EF1147 declares @TR:32 + @TR:33 (+ the special-counter banks);
# EF1091 declares @TR:32 alone.
WITH_OVERFLOW = "EF1147"
WITHOUT_OVERFLOW = "EF1091"


def test_high_byte_lifts_a_count_past_65535(sim_factory) -> None:
    counters = [0xFFFF] * 64
    counters[0] = 0x0002  # total, low word
    counters[0x02] = 0x0001  # espresso, low word
    overflow = [0x00] * 64
    overflow[0] = 0x01  # total  = 0x00010002 = 65538
    overflow[0x02] = 0x02  # espresso = 0x00020001 = 131073
    sim = sim_factory(product_counters=counters, product_counter_overflow=overflow)

    c = _paired(sim, WITH_OVERFLOW)
    try:
        pc = c.read_product_counters(timeout_per_page=2.0)
    finally:
        c.close()

    assert pc.total == 65538
    assert pc.by_name["espresso"] == 131073
    assert pc.by_code["02"] == 131073


def test_neutral_high_bytes_and_unused_slots_are_left_alone(sim_factory) -> None:
    """0x00 and 0xFF carry no high word, and a slot the base table marks
    unused stays unused even if the overflow bank has a byte for it."""
    counters = [0xFFFF] * 64
    counters[0] = 10
    counters[0x02] = 78
    counters[0x03] = 595
    overflow = [0x00] * 64
    overflow[0x02] = 0x00  # "no overflow yet"
    overflow[0x03] = 0xFF  # not-configured sentinel
    overflow[0x04] = 0x03  # cappuccino is 0xFFFF in the base table
    sim = sim_factory(product_counters=counters, product_counter_overflow=overflow)

    c = _paired(sim, WITH_OVERFLOW)
    try:
        pc = c.read_product_counters(timeout_per_page=2.0)
    finally:
        c.close()

    assert pc.by_name["espresso"] == 78
    assert pc.by_name["coffee"] == 595
    assert "04" not in pc.by_code


def test_bank_declared_but_answered_with_tr00(sim_factory) -> None:
    """A machine may declare the bank in its XML and still answer the
    bare ``@tr:00`` J.O.E.'s matcher accepts. Decoding falls back to the
    base table instead of failing."""
    counters = [0xFFFF] * 64
    counters[0] = 3
    counters[0x02] = 3
    sim = sim_factory(product_counters=counters, product_counter_overflow=None)

    c = _paired(sim, WITH_OVERFLOW)
    try:
        pc = c.read_product_counters(timeout_per_page=2.0)
    finally:
        c.close()

    assert pc.total == 3
    assert pc.by_name["espresso"] == 3
    assert any(b"@TR:33" in cmd for cmd in sim.sent_commands)


def test_machine_without_the_bank_is_never_asked_for_it(sim_factory) -> None:
    """The S8 EB declares @TR:32 only — reading its counters must not
    cost 16 extra round-trips."""
    sim = sim_factory()

    c = _paired(sim, WITHOUT_OVERFLOW)
    try:
        pc = c.read_product_counters(timeout_per_page=2.0)
    finally:
        c.close()

    assert pc.by_name["2_coffee"] == 10
    assert not any(b"@TR:33" in cmd for cmd in sim.sent_commands)


def test_merge_is_decodable_without_a_socket() -> None:
    """The same merge, straight through from_slots — J.O.E. computes
    ``value + (high << 16)`` per slot (``StatisticStateEmit``)."""
    slots = [0xFFFF] * 64
    slots[0] = 0x0DAC
    slots[0x03] = 0x0005
    overflow = [0x00] * 64
    overflow[0x03] = 0x01
    pc = ProductCounters.from_slots(
        slots, profile=load_profile(WITH_OVERFLOW), overflow=overflow
    )
    assert pc.by_name["coffee"] == 65541
    assert pc.raw_slots[0x03] == 65541


def test_unknown_overflow_reply_does_not_lose_the_base_counts(sim_factory) -> None:
    """No machine here answers @TR:33, so a firmware that replies with a
    shape we don't know — here the bare bank echo a dongle emits for an
    unhandled @TR: command — must degrade to base counts, not raise."""
    counters = [0xFFFF] * 64
    counters[0] = 7
    counters[0x02] = 7
    sim = sim_factory(
        product_counters=counters,
        product_counter_overflow=None,
        overflow_bank_reply="@tr:3300",
    )

    c = _paired(sim, WITH_OVERFLOW)
    try:
        pc = c.read_product_counters(timeout_per_page=0.5)
    finally:
        c.close()

    assert pc.total == 7
    assert pc.by_name["espresso"] == 7


def test_bank_shorter_than_16_pages_keeps_what_was_read(sim_factory) -> None:
    """Bank sizes differ — J.O.E. asks for 16 pages of the product
    counter but only 4 of the special counter — so a machine that stops
    answering mid-bank yields the slots it did serve, not nothing."""
    counters = [0xFFFF] * 64
    counters[0] = 1
    counters[0x02] = 0x0003
    overflow = [0x00] * 16  # two pages' worth, then "@tr:00"
    overflow[0x02] = 0x01
    sim = sim_factory(product_counters=counters, product_counter_overflow=overflow)

    c = _paired(sim, WITH_OVERFLOW)
    try:
        pc = c.read_product_counters(timeout_per_page=2.0)
    finally:
        c.close()

    assert pc.by_name["espresso"] == 65539
