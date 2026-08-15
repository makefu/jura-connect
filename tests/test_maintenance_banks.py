"""The ``@TG:43`` / ``@TG:C0`` field order is declared per machine.

Both banks list their fields as ``<TEXTITEM Type=…>`` children of a
``<BANK>`` element in the machine XML, and 21 of the 89 bundled
profiles disagree with the EF536/EF1091 baseline the library used to
hard-code — some drop ``FilterChange``, some carry only four fields,
some swap the rinse/clean tail. These tests pin the parsed order and
the decoded field names for the outliers.
"""

from __future__ import annotations

import pytest

from jura_connect.client import (
    DEFAULT_MAINTENANCE_COUNTER_FIELDS,
    DEFAULT_MAINTENANCE_PERCENT_FIELDS,
    JuraClient,
    MaintenanceCounters,
    MaintenancePercent,
)
from jura_connect.profile import iter_profiles, load_profile

# The live reply from Kaffeebert (S8 EB), see docs/PROTOCOL.md §5.3.
KAFFEEBERT_TG43 = "@tg:4300150001000801580E21005B"
KAFFEEBERT_VALUES = (0x0015, 0x0001, 0x0008, 0x0158, 0x0E21, 0x005B)

# Every field name the bundled XMLs declare for either bank.
KNOWN_FIELDS = {
    "cleaning",
    "filter_change",
    "descale",
    "cappu_rinse",
    "coffee_rinse",
    "cappu_clean",
}


def test_profiles_declare_the_baseline_bank_order() -> None:
    for code in ("EF536", "EF1091"):
        p = load_profile(code)
        assert p.maintenance_counter_fields == DEFAULT_MAINTENANCE_COUNTER_FIELDS
        assert p.maintenance_percent_fields == DEFAULT_MAINTENANCE_PERCENT_FIELDS


def test_profiles_declare_the_outlier_bank_orders() -> None:
    # Swapped tail: CoffeeRinse before CappuRinse.
    assert load_profile("EF1090").maintenance_counter_fields == (
        "cleaning",
        "filter_change",
        "descale",
        "coffee_rinse",
        "cappu_rinse",
        "cappu_clean",
    )
    # Four fields only — no cappuccino hardware.
    assert load_profile("EF529").maintenance_counter_fields == (
        "cleaning",
        "filter_change",
        "descale",
        "coffee_rinse",
    )
    # The one profile without FilterChange in either bank.
    assert load_profile("EF567_C").maintenance_counter_fields == (
        "cleaning",
        "descale",
        "cappu_rinse",
        "coffee_rinse",
        "cappu_clean",
    )
    assert load_profile("EF567_C").maintenance_percent_fields == (
        "cleaning",
        "descale",
    )


def test_every_bundled_profile_declares_known_bank_fields() -> None:
    """Walk all 89 profiles: both banks must parse into non-empty,
    duplicate-free lists of names the client knows how to label."""
    seen = 0
    for p in iter_profiles():
        seen += 1
        for fields in (p.maintenance_counter_fields, p.maintenance_percent_fields):
            assert fields, p.code
            assert set(fields) <= KNOWN_FIELDS, (p.code, fields)
            assert len(set(fields)) == len(fields), (p.code, fields)
        assert p.maintenance_counter_fields[0] == "cleaning", p.code
    assert seen == 89


def test_counters_parse_without_profile_is_unchanged() -> None:
    mc = MaintenanceCounters.parse(KAFFEEBERT_TG43)
    assert (
        mc.cleaning,
        mc.filter_change,
        mc.descale,
        mc.cappu_rinse,
        mc.coffee_rinse,
        mc.cappu_clean,
    ) == KAFFEEBERT_VALUES
    assert len(mc.raw) == 12
    assert mc.format() == (
        "cleaning=21 filter=1 descale=8 cappu_rinse=344 "
        "coffee_rinse=3617 cappu_clean=91"
    )
    assert mc.to_dict() == {
        "cleaning": 21,
        "filter_change": 1,
        "descale": 8,
        "cappu_rinse": 344,
        "coffee_rinse": 3617,
        "cappu_clean": 91,
        "raw_hex": "00150001000801580E21005B",
    }


def test_counters_parse_with_ef1091_matches_no_profile() -> None:
    profile = load_profile("EF1091")
    with_profile = MaintenanceCounters.parse(KAFFEEBERT_TG43, profile=profile)
    without = MaintenanceCounters.parse(KAFFEEBERT_TG43)
    assert with_profile == without


def test_counters_parse_with_swapped_tail_profile() -> None:
    mc = MaintenanceCounters.parse(KAFFEEBERT_TG43, profile=load_profile("EF1090"))
    assert mc.cleaning == 0x0015
    assert mc.filter_change == 0x0001
    assert mc.descale == 0x0008
    # The two that swap places relative to the baseline.
    assert mc.coffee_rinse == 0x0158
    assert mc.cappu_rinse == 0x0E21
    assert mc.cappu_clean == 0x005B
    assert mc.to_dict()["coffee_rinse"] == 0x0158


def test_counters_parse_four_field_profile() -> None:
    """EF529 declares four counters, so the machine answers 8 bytes."""
    reply = "@tg:430015000100080158"
    mc = MaintenanceCounters.parse(reply, profile=load_profile("EF529"))
    assert mc.cleaning == 0x0015
    assert mc.filter_change == 0x0001
    assert mc.descale == 0x0008
    assert mc.coffee_rinse == 0x0158
    assert mc.cappu_rinse is None
    assert mc.cappu_clean is None
    assert mc.format() == "cleaning=21 filter=1 descale=8 coffee_rinse=344"
    assert mc.to_dict() == {
        "cleaning": 21,
        "filter_change": 1,
        "descale": 8,
        "coffee_rinse": 344,
        "raw_hex": "0015000100080158",
    }


def test_counters_parse_rejects_an_empty_payload() -> None:
    with pytest.raises(ValueError, match="too short"):
        MaintenanceCounters.parse("@tg:43")


def test_percent_parse_without_profile_is_unchanged() -> None:
    mp = MaintenancePercent.parse("@tg:C050FF1E")
    assert (mp.cleaning, mp.filter_change, mp.descale) == (0x50, 0xFF, 0x1E)
    assert mp.format() == "cleaning=80 filter=255 descale=30"
    assert mp.to_dict() == {
        "cleaning": 80,
        "filter_change": 255,
        "descale": 30,
        "raw_hex": "50FF1E",
    }


def test_percent_parse_two_field_profile() -> None:
    mp = MaintenancePercent.parse("@tg:C0501E", profile=load_profile("EF567_C"))
    assert mp.cleaning == 0x50
    assert mp.descale == 0x1E
    assert mp.filter_change is None
    assert mp.format() == "cleaning=80 descale=30"


def _paired(sim, profile=None) -> JuraClient:
    host, port = sim.address
    c = JuraClient(host, port=port, conn_id="reader", auth_hash="", profile=profile)
    r = c.pair(timeout=2.0)
    assert r.state == "CORRECT"
    return c


def test_client_uses_its_profile_for_both_banks(sim_factory) -> None:
    """End-to-end through the simulator: a four-counter machine's reply
    must land on the names its XML declares."""
    sim = sim_factory(
        maint_counters=bytes.fromhex("0015000100080158"),
        maint_percent=bytes.fromhex("50FF1E"),
    )
    c = _paired(sim, profile=load_profile("EF529"))
    try:
        mc = c.read_maintenance_counter(timeout=2.0)
        mp = c.read_maintenance_percent(timeout=2.0)
    finally:
        c.close()
    assert mc.coffee_rinse == 0x0158
    assert mc.cappu_rinse is None
    assert mp.descale == 0x1E


def test_machine_info_carries_profile_aware_counters(sim_factory) -> None:
    sim = sim_factory(maint_counters=bytes.fromhex("00150001000801580E21005B"))
    c = _paired(sim, profile=load_profile("EF1090"))
    try:
        info = c.read_machine_info(timeout=3.0)
    finally:
        c.close()
    assert info.maintenance_counters.coffee_rinse == 0x0158
    assert info.maintenance_counters.cappu_rinse == 0x0E21
