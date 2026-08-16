"""Every counter bank a machine XML can declare, against the simulator.

Ten banks live under ``<STATISTIC>``: the product counter (``@TR:32``)
and its overflow (``@TR:33``) — covered by ``test_overflow_counters.py``
— plus the special, barista and daily banks covered here.

None of these are on a machine available to this project: EF1091 (the
maintainer's S8 EB) declares ``@TR:32`` alone. The special banks are
J.O.E.-derived (``WifiCommandSpecialCounterStatistics``); the barista
and daily banks are **XML-derived only** — the app never reads them.
Everything here is therefore exercised against the simulator, never
against hardware. See docs/PROTOCOL.md §5.5.
"""

from __future__ import annotations

import pytest

from jura_connect.client import (
    COUNTER_BANK_SPECS,
    DAILY_BARISTA_COUNTER_BANK,
    DAILY_PRODUCT_COUNTER_BANK,
    BARISTA_COUNTER_BANK,
    CounterBank,
    JuraClient,
    SPECIAL_COUNTER_BANK,
)
from jura_connect.commands import run_named
from jura_connect.profile import iter_profiles, load_profile

# EF1143 is the only bundled profile that declares every bank; EF1147
# declares the special banks plus the daily *product* counter but no
# daily barista bank; EF1091 (S8 EB) declares @TR:32 alone.
ALL_BANKS = "EF1143"
SPECIAL_ONLY = "EF1147"
PRODUCT_ONLY = "EF1091"


def _paired(sim, ef: str) -> JuraClient:
    host, port = sim.address
    c = JuraClient(
        host, port=port, conn_id="reader", auth_hash="", profile=load_profile(ef)
    )
    r = c.pair(timeout=2.0)
    assert r.state == "CORRECT"
    return c


def _pages_requested(sim, bank: str) -> list[int]:
    """Page indices the client asked for on ``bank``, in order."""
    prefix = f"{bank},".encode()
    pages = []
    for cmd in sim.sent_commands:
        text = cmd.decode("ascii", "replace").rstrip("\r\n")
        if text.encode("ascii", "replace").startswith(prefix):
            pages.append(int(text.split(",", 1)[1], 16))
    return pages


# --------------------------------------------------------------------- #
# Bank table
# --------------------------------------------------------------------- #


def test_every_bundled_profile_declares_only_known_banks() -> None:
    """Pins the bank table: across all 89 bundled XMLs the declared
    ``<PRODUCTCOUNTER>`` / ``<DAILYCOUNTER>`` banks are exactly the ten
    commands the client knows how to read."""
    seen: dict[str, int] = {}
    profiles = 0
    for prof in iter_profiles():
        profiles += 1
        for bank in prof.counter_banks + prof.daily_counter_banks:
            assert bank in COUNTER_BANK_SPECS, f"{prof.code} declares {bank}"
            seen[bank] = seen.get(bank, 0) + 1
    assert profiles == 89
    assert seen == {
        "@TR:32": 89,
        "@TR:33": 34,
        "@TR:52": 14,
        "@TR:53": 4,
        "@TR:34": 4,
        "@TR:35": 3,
        "@TR:42": 37,
        "@TR:43": 4,
        "@TR:44": 4,
        "@TR:45": 4,
    }


def test_daily_banks_carry_their_reset_command() -> None:
    """Every ``<DAILYCOUNTER>`` in the corpus resets with ``@TF:05``."""
    with_daily = 0
    for prof in iter_profiles():
        if prof.daily_counter_banks:
            with_daily += 1
            assert prof.daily_counter_reset == "@TF:05"
        else:
            assert prof.daily_counter_reset is None
    assert with_daily == 37


def test_product_counter_banks_stay_out_of_the_daily_tuple() -> None:
    """``counter_banks`` keeps its documented meaning (PRODUCTCOUNTER
    only) — Home Assistant reads it."""
    prof = load_profile(ALL_BANKS)
    assert prof.counter_banks == (
        "@TR:32",
        "@TR:33",
        "@TR:34",
        "@TR:35",
        "@TR:52",
        "@TR:53",
    )
    assert prof.daily_counter_banks == ("@TR:42", "@TR:43", "@TR:44", "@TR:45")


# --------------------------------------------------------------------- #
# Pagination / bytes per value, one test per bank
# --------------------------------------------------------------------- #


def test_special_counter_reads_four_pages_of_u16(sim_factory) -> None:
    """J.O.E.'s ``WifiCommandSpecialCounterStatistics.j()`` walks
    ``IntRange(0, 3)`` — four pages, two bytes per value."""
    special = [0xFFFF] * 16
    special[0] = 1234  # total
    special[3] = 7  # sweet foam
    special[4] = 2  # cold brew, first of three slots
    special[5] = 3
    special[9] = 11  # strong cold brew
    sim = sim_factory(special_counters=special)

    c = _paired(sim, SPECIAL_ONLY)
    try:
        bank = c.read_counter_bank(SPECIAL_COUNTER_BANK, timeout_per_page=2.0)
    finally:
        c.close()

    assert bank is not None
    assert _pages_requested(sim, "@TR:52") == [0, 1, 2, 3]
    assert len(bank.raw_slots) == 16
    assert bank.total == 1234
    assert bank.by_code["03"] == 7
    assert bank.by_name["sweet_foam"] == 7
    assert bank.by_name["cold_brew"] == 5  # slots 4+5+6, 0xFFFF skipped
    assert bank.by_name["strong_cold_brew"] == 11


def test_special_counter_overflow_folds_in(sim_factory) -> None:
    special = [0xFFFF] * 16
    special[0] = 0x0002
    special[9] = 0x0001
    # 4 pages × 8 high bytes: the overflow bank is byte-per-slot, so it
    # covers twice as many slots per page as the u16 bank it belongs to.
    overflow = [0x00] * 32
    overflow[0] = 0x01  # total = 0x00010002
    overflow[9] = 0x02  # strong cold brew = 0x00020001
    sim = sim_factory(special_counters=special, special_counter_overflow=overflow)

    c = _paired(sim, SPECIAL_ONLY)
    try:
        bank = c.read_counter_bank(SPECIAL_COUNTER_BANK, timeout_per_page=2.0)
    finally:
        c.close()

    assert bank is not None
    assert _pages_requested(sim, "@TR:53") == [0, 1, 2, 3]
    assert bank.total == 65538
    assert bank.by_name["strong_cold_brew"] == 131073


def test_barista_counter_is_product_indexed(sim_factory) -> None:
    """The barista bank indexes the same product-code space as
    ``@TR:32``, so profile product names apply."""
    slots = [0xFFFF] * 64
    slots[0] = 42
    slots[0x02] = 5
    slots[0x03] = 9
    overflow = [0x00] * 128  # 16 pages × 8 high bytes
    overflow[0x03] = 0x01
    sim = sim_factory(barista_counters=slots, barista_counter_overflow=overflow)

    c = _paired(sim, ALL_BANKS)
    try:
        bank = c.read_counter_bank(BARISTA_COUNTER_BANK, timeout_per_page=2.0)
    finally:
        c.close()

    assert bank is not None
    assert _pages_requested(sim, "@TR:34") == list(range(16))
    assert _pages_requested(sim, "@TR:35") == list(range(16))
    assert bank.total == 42
    assert bank.by_code["02"] == 5
    assert bank.by_code["03"] == 65545
    assert bank.by_name["espresso"] == 5


def test_daily_product_counter_reads_like_the_product_bank(sim_factory) -> None:
    slots = [0xFFFF] * 64
    slots[0] = 6
    slots[0x02] = 2
    slots[0x03] = 4
    sim = sim_factory(daily_product_counters=slots)

    c = _paired(sim, ALL_BANKS)
    try:
        bank = c.read_counter_bank(DAILY_PRODUCT_COUNTER_BANK, timeout_per_page=2.0)
    finally:
        c.close()

    assert bank is not None
    assert _pages_requested(sim, "@TR:42") == list(range(16))
    assert bank.total == 6
    assert bank.by_name["espresso"] == 2
    assert bank.to_dict()["bank"] == "@TR:42"


def test_daily_barista_counter_folds_its_own_overflow(sim_factory) -> None:
    slots = [0xFFFF] * 64
    slots[0] = 0x0003
    slots[0x02] = 0x0002
    overflow = [0x00] * 128
    overflow[0x02] = 0x01
    sim = sim_factory(
        daily_barista_counters=slots, daily_barista_counter_overflow=overflow
    )

    c = _paired(sim, ALL_BANKS)
    try:
        bank = c.read_counter_bank(DAILY_BARISTA_COUNTER_BANK, timeout_per_page=2.0)
    finally:
        c.close()

    assert bank is not None
    assert bank.by_code["02"] == 65538
    assert _pages_requested(sim, "@TR:45") == list(range(16))


# --------------------------------------------------------------------- #
# Negative paths
# --------------------------------------------------------------------- #


def test_tr00_on_the_first_page_means_bank_not_implemented(sim_factory) -> None:
    """A machine may declare a bank in its XML and still answer the bare
    ``@tr:00`` J.O.E.'s matcher accepts."""
    sim = sim_factory(special_counters=None)

    c = _paired(sim, SPECIAL_ONLY)
    try:
        bank = c.read_counter_bank(SPECIAL_COUNTER_BANK, timeout_per_page=2.0)
    finally:
        c.close()

    assert bank is None
    assert _pages_requested(sim, "@TR:52") == [0]


def test_tr00_mid_bank_keeps_what_was_read(sim_factory) -> None:
    """Bank sizes are not uniform; a machine that stops answering
    mid-bank yields the slots it did serve."""
    slots = [0xFFFF] * 8  # two pages' worth, then @tr:00
    slots[0] = 3
    slots[0x02] = 3
    sim = sim_factory(daily_product_counters=slots)

    c = _paired(sim, ALL_BANKS)
    try:
        bank = c.read_counter_bank(DAILY_PRODUCT_COUNTER_BANK, timeout_per_page=2.0)
    finally:
        c.close()

    assert bank is not None
    assert bank.raw_slots == (3, 0xFFFF, 3, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)
    assert _pages_requested(sim, "@TR:42") == [0, 1, 2]


def test_bank_the_profile_does_not_declare_is_never_requested(sim_factory) -> None:
    """The S8 EB declares @TR:32 alone — no round-trip for the rest."""
    sim = sim_factory(
        special_counters=[1] * 16,
        barista_counters=[1] * 64,
        daily_product_counters=[1] * 64,
    )

    c = _paired(sim, PRODUCT_ONLY)
    try:
        assert c.read_counter_bank(SPECIAL_COUNTER_BANK, timeout_per_page=2.0) is None
        assert c.read_counter_bank(BARISTA_COUNTER_BANK, timeout_per_page=2.0) is None
        assert (
            c.read_counter_bank(DAILY_PRODUCT_COUNTER_BANK, timeout_per_page=2.0)
            is None
        )
    finally:
        c.close()

    for bank in ("@TR:52", "@TR:34", "@TR:42"):
        assert not any(bank.encode() in cmd for cmd in sim.sent_commands)


def test_daily_barista_bank_is_skipped_when_only_the_product_one_is_declared(
    sim_factory,
) -> None:
    """EF1147 declares ``@TR:42`` but no ``@TR:44``."""
    sim = sim_factory(daily_product_counters=[1] * 64, daily_barista_counters=[1] * 64)

    c = _paired(sim, SPECIAL_ONLY)
    try:
        assert (
            c.read_counter_bank(DAILY_PRODUCT_COUNTER_BANK, timeout_per_page=2.0)
            is not None
        )
        assert (
            c.read_counter_bank(DAILY_BARISTA_COUNTER_BANK, timeout_per_page=2.0)
            is None
        )
    finally:
        c.close()

    assert not any(b"@TR:44" in cmd for cmd in sim.sent_commands)


def test_declared_overflow_answered_with_tr00_keeps_base_counts(sim_factory) -> None:
    special = [0xFFFF] * 16
    special[0] = 5
    sim = sim_factory(special_counters=special, special_counter_overflow=None)

    c = _paired(sim, SPECIAL_ONLY)
    try:
        bank = c.read_counter_bank(SPECIAL_COUNTER_BANK, timeout_per_page=2.0)
    finally:
        c.close()

    assert bank is not None
    assert bank.total == 5
    assert any(b"@TR:53" in cmd for cmd in sim.sent_commands)


def test_without_a_profile_the_machine_decides(sim_factory) -> None:
    """No profile means no declaration to consult: the bank is asked for
    and the dongle's own ``@tr:00`` settles it."""
    special = [0xFFFF] * 16
    special[0] = 8
    sim = sim_factory(special_counters=special)
    host, port = sim.address
    c = JuraClient(host, port=port, conn_id="reader", auth_hash="")
    assert c.pair(timeout=2.0).state == "CORRECT"
    try:
        present = c.read_counter_bank(SPECIAL_COUNTER_BANK, timeout_per_page=2.0)
        absent = c.read_counter_bank(BARISTA_COUNTER_BANK, timeout_per_page=2.0)
    finally:
        c.close()

    assert present is not None
    assert present.total == 8
    # Nothing declared this read, so it is not a "declared" claim — but
    # the caller never opted into a probe either.
    assert present.source == "unprofiled"
    assert present.to_dict()["probed"] is False
    assert absent is None


# --------------------------------------------------------------------- #
# Probing a bank the XML does not declare (docs/PROTOCOL.md §5.5)
# --------------------------------------------------------------------- #


def _kaffeebert_special_counters() -> list[int]:
    """The S8 EB's own ``@TR:52`` table, from the 2026-08-16 capture.

    Verbatim pages (``docs/captures/2026-08-16-kaffeebert-s8eb.md`` §6)::

        @tr:52,00,FFFFFFFF0001000E
        @tr:52,01,FFFFFFFFFFFFFFFF
        @tr:52,02,0A65FFFFFFFFFFFF
        @tr:52,03,FFFFFFFFFFFFFFFF

    Note slot 0 — the bank's own total — reads the unused sentinel on
    this machine; only slots 2, 3 and 8 carry values.
    """
    slots = [0xFFFF] * 16
    slots[2] = 1
    slots[3] = 14  # sweet_foam
    slots[8] = 0x0A65  # 2661
    return slots


def test_undeclared_bank_stays_off_the_wire_without_probe(sim_factory) -> None:
    """Default behaviour is unchanged: the S8 EB serves ``@TR:52`` but
    does not declare it, and we still send nothing."""
    sim = sim_factory(special_counters=_kaffeebert_special_counters())

    c = _paired(sim, PRODUCT_ONLY)
    try:
        assert c.read_counter_bank(SPECIAL_COUNTER_BANK, timeout_per_page=2.0) is None
    finally:
        c.close()

    assert not any(b"@TR:52" in cmd for cmd in sim.sent_commands)


def test_probe_reads_the_bank_the_s8_eb_serves_undeclared(sim_factory) -> None:
    """Regression test for the real machine: EF1091 declares ``@TR:32``
    alone yet answers ``@TR:52,00..03`` with live counts."""
    sim = sim_factory(special_counters=_kaffeebert_special_counters())

    c = _paired(sim, PRODUCT_ONLY)
    try:
        bank = c.read_counter_bank(
            SPECIAL_COUNTER_BANK, timeout_per_page=2.0, probe=True
        )
    finally:
        c.close()

    assert bank is not None
    assert _pages_requested(sim, "@TR:52") == [0, 1, 2, 3]
    assert bank.by_code["02"] == 1
    assert bank.by_name["sweet_foam"] == 14
    assert bank.by_code["08"] == 2661
    assert bank.source == "probed"
    assert bank.to_dict()["probed"] is True
    assert bank.to_dict()["source"] == "probed"
    assert "probed" in bank.format()


def test_probe_on_a_bank_answering_tr00_is_still_not_implemented(sim_factory) -> None:
    """The other four banks the S8 EB rejects stay rejected: one page
    goes out, the bare ``@tr:00`` comes back, and the result is the same
    "nothing here" as the declared case."""
    sim = sim_factory(special_counters=_kaffeebert_special_counters())

    c = _paired(sim, PRODUCT_ONLY)
    try:
        for bank in (
            BARISTA_COUNTER_BANK,
            DAILY_PRODUCT_COUNTER_BANK,
            DAILY_BARISTA_COUNTER_BANK,
        ):
            assert (
                c.read_counter_bank(bank, timeout_per_page=2.0, probe=True) is None
            ), bank
    finally:
        c.close()

    for bank in ("@TR:34", "@TR:42", "@TR:44"):
        assert _pages_requested(sim, bank) == [0]


def test_a_declared_bank_is_never_marked_probed(sim_factory) -> None:
    """``probe=True`` on a machine whose XML declares the bank is an
    ordinary declared read — the stronger claim survives."""
    special = _kaffeebert_special_counters()
    special[0] = 99
    sim = sim_factory(special_counters=special)

    c = _paired(sim, SPECIAL_ONLY)
    try:
        bank = c.read_counter_bank(
            SPECIAL_COUNTER_BANK, timeout_per_page=2.0, probe=True
        )
    finally:
        c.close()

    assert bank is not None
    assert bank.total == 99
    assert bank.source == "declared"
    assert bank.to_dict()["probed"] is False
    assert "probed" not in bank.format()


def test_probe_covers_the_undeclared_overflow_of_a_probed_bank(sim_factory) -> None:
    """A probed bank's overflow is undeclared too, so probing has to
    reach it or counts past 65535 are silently truncated."""
    special = _kaffeebert_special_counters()
    special[0] = 2
    overflow = [0x00] * 32
    overflow[0] = 0x01  # total = 0x00010002
    sim = sim_factory(special_counters=special, special_counter_overflow=overflow)

    c = _paired(sim, PRODUCT_ONLY)
    try:
        bank = c.read_counter_bank(
            SPECIAL_COUNTER_BANK, timeout_per_page=2.0, probe=True
        )
    finally:
        c.close()

    assert bank is not None
    assert _pages_requested(sim, "@TR:53") == [0, 1, 2, 3]
    assert bank.total == 65538


def test_probe_never_reaches_a_bank_the_caller_did_not_ask_for(sim_factory) -> None:
    """Probing is per-read: asking for the special bank must not drag
    the barista or daily banks onto the wire."""
    sim = sim_factory(special_counters=_kaffeebert_special_counters())

    c = _paired(sim, PRODUCT_ONLY)
    try:
        c.read_counter_bank(SPECIAL_COUNTER_BANK, timeout_per_page=2.0, probe=True)
    finally:
        c.close()

    for bank in ("@TR:34", "@TR:35", "@TR:42", "@TR:43", "@TR:44", "@TR:45"):
        assert not any(bank.encode() in cmd for cmd in sim.sent_commands)


def test_reading_an_overflow_bank_directly_is_refused() -> None:
    """Overflow banks are folded into their base bank, never read alone."""
    c = JuraClient("127.0.0.1", port=1, conn_id="x", auth_hash="")
    with pytest.raises(ValueError, match="overflow"):
        c.read_counter_bank("@TR:33")
    with pytest.raises(ValueError, match="unknown counter bank"):
        c.read_counter_bank("@TR:99")


# --------------------------------------------------------------------- #
# Presentation
# --------------------------------------------------------------------- #


def test_counter_bank_format_and_to_dict_round_trip() -> None:
    slots = [0xFFFF] * 64
    slots[0] = 12
    slots[0x02] = 5
    slots[0x3F] = 1  # no product carries code 0x3F -> unnamed
    bank = CounterBank.from_slots(
        BARISTA_COUNTER_BANK, slots, profile=load_profile(ALL_BANKS)
    )
    text = bank.format()
    assert "@TR:34" in text
    assert "12" in text
    assert "(unnamed slots)" in text
    assert bank.to_dict() == {
        "bank": "@TR:34",
        "name": "barista_counter",
        "total": 12,
        "by_name": dict(bank.by_name),
        "by_code": dict(bank.by_code),
        "source": "declared",
        "probed": False,
    }


def test_bank_command_explains_an_undeclared_bank_and_points_at_probe(
    sim_factory,
) -> None:
    sim = sim_factory(special_counters=_kaffeebert_special_counters())

    c = _paired(sim, PRODUCT_ONLY)
    try:
        result = run_named(c, "special-counters", timeout=2.0)
    finally:
        c.close()

    text = result.format()
    assert "not declared" in text
    assert "EF1091" in text
    assert "--probe" in text
    assert not any(b"@TR:52" in cmd for cmd in sim.sent_commands)


def test_bank_command_with_probe_returns_the_undeclared_bank(sim_factory) -> None:
    sim = sim_factory(special_counters=_kaffeebert_special_counters())

    c = _paired(sim, PRODUCT_ONLY)
    try:
        result = run_named(c, "special-counters", timeout=2.0, probe=True)
    finally:
        c.close()

    assert isinstance(result.value, CounterBank)
    assert result.value.source == "probed"
    assert result.to_dict()["value"]["probed"] is True


def test_probe_changes_nothing_for_a_command_that_reads_no_bank(sim_factory) -> None:
    """``probe`` is a counter-bank option; every other command ignores
    it and puts exactly the same frames on the wire."""
    sim = sim_factory()

    c = _paired(sim, PRODUCT_ONLY)
    try:
        plain = run_named(c, "counters", timeout=2.0)
        probed = run_named(c, "counters", timeout=2.0, probe=True)
    finally:
        c.close()

    assert probed.to_dict() == plain.to_dict()
    assert not any(b"@TR:" in cmd for cmd in sim.sent_commands)


def test_counter_bank_rejects_an_unknown_source() -> None:
    """``source`` is a closed set — a typo must not reach ``to_dict``."""
    with pytest.raises(ValueError, match="source"):
        CounterBank.from_slots(BARISTA_COUNTER_BANK, [1, 2], source="guessed")
