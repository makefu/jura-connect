"""PMode (programmable-recipe) reads and writes.

Everything exercised here is **APK-derived and hardware-untested**: no
Jura machine that actually exposes PMode slots was available, so the
wire formats come from the J.O.E. APK's ``WifiCommandPModeProduct*`` /
``WifiCommandPModeSlotProduct*`` classes and the ``ch.toptronic.joe``
``AppProduct.d()`` blob builder. The simulator models both branches:
a machine that exposes slots, and the EF1091-style machine that
answers ``@tm:C2`` for everything.
"""

from __future__ import annotations

import pytest

from jura_connect.client import JuraClient, _settings_checksum
from jura_connect.commands import CommandError, DestructiveCommandError, run_named
from jura_connect.profile import PMODE_BLOB_BYTES, load_profile

# EF1143: Productprogramming="true", GRINDER_FREENESS (F17) on most
# products, and <CAPABILITIES IntakeF18="true"> in its MACHINEMANIFEST.
PMODE_MACHINE = "EF1143"
# EF529: Productprogramming="true" but no F17 anywhere and no
# MACHINEMANIFEST at all — the "empty tail" branch of the slot write.
NO_F17_MACHINE = "EF529"

#: EF1143 Espresso (code 0x02): F2 grinder_ratio=02, F3 strength=08,
#: F4 water 45 ml -> 0x09, F7 temperature=02, F17 freeness=04.
ESPRESSO_BLOB = "0202080900000200000000000000000004"


def _paired(sim, machine_type: str | None = None) -> JuraClient:
    host, port = sim.address
    c = JuraClient(
        host,
        port=port,
        conn_id="pmode-tests",
        auth_hash="",
        profile=None if machine_type is None else load_profile(machine_type),
    )
    r = c.pair(timeout=2.0)
    assert r.state == "CORRECT"
    return c


def _sent(sim) -> list[str]:
    return [f.decode("ascii", "replace").rstrip("\r\n") for f in sim.sent_commands]


# --------------------------------------------------------------------- #
# Profile: the PMode declarations the XML actually carries
# --------------------------------------------------------------------- #


def test_profile_parses_product_programming_flag() -> None:
    assert load_profile(PMODE_MACHINE).product_programming is True
    assert load_profile(NO_F17_MACHINE).product_programming is True
    # The S8 EB says so itself: Productprogramming="false".
    assert load_profile("EF1091").product_programming is False


def test_profile_has_pmode_tracks_product_programming() -> None:
    """No bundled XML carries a <PROGRAMMODE> element — the machine
    declares product programming on <MACHINESETTINGS> instead, so
    has_pmode must follow that attribute or it is dead forever."""
    assert load_profile(PMODE_MACHINE).has_pmode is True
    assert load_profile("EF1091").has_pmode is False


def test_profile_parses_declared_slot_count() -> None:
    # Only five profiles declare NumberOfSlotsForProductProgramming.
    assert load_profile("EF1119").pmode_slot_count == 6
    assert load_profile(PMODE_MACHINE).pmode_slot_count is None


def test_profile_parses_intake_f18_capability() -> None:
    assert load_profile(PMODE_MACHINE).intake_f18 is True
    assert load_profile(NO_F17_MACHINE).intake_f18 is False
    assert load_profile("EF1091").intake_f18 is False


def test_profile_parses_pmode_adjust_and_product_settings() -> None:
    p = load_profile(NO_F17_MACHINE)
    espresso = p.product_by_code[0x02]
    assert espresso.product_settings is True
    strength = espresso.param("coffee_strength")
    assert strength is not None
    # EF529 marks COFFEE_STRENGTH PModeAdjust="false".
    assert strength.pmode_adjust is False
    water = espresso.param("water_amount")
    assert water is not None
    assert water.pmode_adjust is None  # attribute absent = unconstrained


# --------------------------------------------------------------------- #
# Blob construction
# --------------------------------------------------------------------- #


def test_pmode_blob_is_17_bytes_with_freeness_at_byte_16() -> None:
    espresso = load_profile(PMODE_MACHINE).product_by_code[0x02]
    blob = espresso.build_pmode_hex()
    assert len(blob) == PMODE_BLOB_BYTES * 2 == 34
    assert blob == ESPRESSO_BLOB
    assert blob[:2] == "02"  # product code at byte 0
    assert blob[32:34] == "04"  # F17 grinder freeness at byte 16
    # Unlike the @TP: start blob, byte 8 is NOT forced to 0x01.
    assert blob[16:18] == "00"


def test_pmode_blob_without_grinder_freeness_leaves_byte_16_zero() -> None:
    hotwater = load_profile(PMODE_MACHINE).product_by_code[0x0D]
    blob = hotwater.build_pmode_hex()
    assert len(blob) == 34
    assert blob[32:34] == "00"
    # F4 water 220 ml -> 44 ticks -> 0x2C at byte 3; F7 temp at byte 6.
    assert blob[6:8] == "2C"
    assert blob[12:14] == "02"


def test_pmode_blob_applies_overrides() -> None:
    espresso = load_profile(PMODE_MACHINE).product_by_code[0x02]
    blob = espresso.build_pmode_hex({"water_amount": 60, "temperature": "normal"})
    assert blob[6:8] == "0C"  # 60 ml / 5
    assert blob[12:14] == "01"  # temperature "normal"


def test_pmode_blob_rejects_out_of_range_value_before_the_wire() -> None:
    espresso = load_profile(PMODE_MACHINE).product_by_code[0x02]
    with pytest.raises(ValueError, match="water_amount"):
        espresso.build_pmode_hex({"water_amount": 999})


def test_pmode_blob_rejects_unknown_parameter() -> None:
    espresso = load_profile(PMODE_MACHINE).product_by_code[0x02]
    with pytest.raises(ValueError, match="unknown recipe parameter"):
        espresso.build_pmode_hex({"nonsense": 1})


def test_pmode_blob_refuses_override_of_non_adjustable_parameter() -> None:
    """EF529 marks COFFEE_STRENGTH PModeAdjust="false" — J.O.E. hides
    that slider in product programming, so we refuse the override
    rather than writing a value the machine will not honour."""
    espresso = load_profile(NO_F17_MACHINE).product_by_code[0x02]
    with pytest.raises(ValueError, match="PModeAdjust"):
        espresso.build_pmode_hex({"coffee_strength": 4})
    # Without the override the parameter still lands in the blob.
    assert espresso.build_pmode_hex()[4:6] == "02"


# --------------------------------------------------------------------- #
# Wire format
# --------------------------------------------------------------------- #


def test_product_write_wire_format_and_checksum(sim_factory) -> None:
    sim = sim_factory(pmode_writable=True, pmode_products={})
    c = _paired(sim, PMODE_MACHINE)
    try:
        c.write_pmode_product("espresso", timeout=2.0)
    finally:
        c.close()
    body = f"41,{ESPRESSO_BLOB}"
    expected = f"@TM:{body}{_settings_checksum(body)}"
    assert expected in _sent(sim)


def test_slot_write_tail_carries_grinder_freeness(sim_factory) -> None:
    """WifiCommandPModeSlotProductWrite.Companion.a: a product with F17
    gets ``"00" + F17 + "00000000"`` appended to the 14-byte head."""
    sim = sim_factory(pmode_writable=True, pmode_products={})
    c = _paired(sim, PMODE_MACHINE)
    try:
        c.write_pmode_slot(3, "espresso", timeout=2.0)
    finally:
        c.close()
    head = ESPRESSO_BLOB[:28]
    body = f"42,03{head}000400000000"
    assert f"@TM:{body}{_settings_checksum(body)}" in _sent(sim)


def test_slot_write_tail_is_six_zero_bytes_with_intake_f18(sim_factory) -> None:
    """No F17 on the product but IntakeF18 on the machine -> the tail
    is six zero bytes rather than absent."""
    sim = sim_factory(pmode_writable=True, pmode_products={})
    c = _paired(sim, PMODE_MACHINE)
    try:
        c.write_pmode_slot(1, "hotwater_portion", timeout=2.0)
    finally:
        c.close()
    blob = load_profile(PMODE_MACHINE).product_by_code[0x0D].build_pmode_hex()
    body = f"42,01{blob[:28]}000000000000"
    assert f"@TM:{body}{_settings_checksum(body)}" in _sent(sim)


def test_slot_write_tail_absent_without_f17_or_intake_f18(sim_factory) -> None:
    sim = sim_factory(pmode_writable=True, pmode_products={})
    c = _paired(sim, NO_F17_MACHINE)
    try:
        c.write_pmode_slot(0, "espresso", timeout=2.0)
    finally:
        c.close()
    blob = load_profile(NO_F17_MACHINE).product_by_code[0x02].build_pmode_hex()
    body = f"42,00{blob[:28]}"
    assert f"@TM:{body}{_settings_checksum(body)}" in _sent(sim)


def test_writes_are_wrapped_in_lock_unlock(sim_factory) -> None:
    """PMODE-priority commands ride inside @TS:01 / @TS:00 exactly like
    the settings write; without it the machine ACKs and forgets."""
    sim = sim_factory(pmode_writable=True, pmode_products={})
    c = _paired(sim, PMODE_MACHINE)
    try:
        assert sim.config.screen_locked is False
        c.write_pmode_slot(2, "espresso", timeout=2.0)
        assert sim.config.screen_locked is False
    finally:
        c.close()
    sent = _sent(sim)
    write_at = next(i for i, s in enumerate(sent) if s.startswith("@TM:42,02"))
    assert "@TS:01" in sent[:write_at]
    assert "@TS:00" in sent[write_at:]


def test_verbatim_blob_escape_hatch_needs_no_profile(sim_factory) -> None:
    sim = sim_factory(pmode_writable=True, pmode_products={})
    c = _paired(sim)  # no profile at all
    try:
        c.write_pmode_product(ESPRESSO_BLOB, timeout=2.0)
    finally:
        c.close()
    body = f"41,{ESPRESSO_BLOB}"
    assert f"@TM:{body}{_settings_checksum(body)}" in _sent(sim)


# --------------------------------------------------------------------- #
# Round trips against a machine that exposes slots
# --------------------------------------------------------------------- #


def test_slot_write_then_read_returns_the_same_product(sim_factory) -> None:
    sim = sim_factory(
        pmode_writable=True,
        pmode_products={},
        pmode_slot_bytes=bytes.fromhex("04"),
    )
    c = _paired(sim, PMODE_MACHINE)
    try:
        c.write_pmode_slot(2, "espresso", {"water_amount": 60}, timeout=2.0)
        table = c.read_pmode_slots(timeout=2.0)
    finally:
        c.close()
    assert table.num_slots == 4
    by_index = {s.index: s for s in table.slots}
    assert set(by_index) == {2}
    written = (
        load_profile(PMODE_MACHINE)
        .product_by_code[0x02]
        .build_pmode_hex({"water_amount": 60})
    )
    assert by_index[2].product_code == 0x02
    # Only the 14-byte head + tail survive a slot write, so compare the head.
    assert by_index[2].raw_payload.startswith(written[:28])


def test_product_write_then_read_returns_the_same_blob(sim_factory) -> None:
    sim = sim_factory(pmode_writable=True, pmode_products={})
    c = _paired(sim, PMODE_MACHINE)
    try:
        c.write_pmode_product("espresso", {"temperature": "normal"}, timeout=2.0)
        got = c.read_pmode_product("espresso", timeout=2.0)
    finally:
        c.close()
    assert got is not None
    assert got.product_code == 0x02
    assert got.blob == load_profile(PMODE_MACHINE).product_by_code[
        0x02
    ].build_pmode_hex({"temperature": "normal"})
    # Decoded per-argument view, F-numbered like the APK's parser.
    assert got.arguments["F1"] == "02"
    assert got.arguments["F7"] == "01"
    assert got.arguments["F17"] == "04"
    assert "espresso" in got.format()
    assert got.to_dict()["product_code"] == "02"


def test_configured_slot_read_verifies_the_reply_checksum(sim_factory) -> None:
    """The decode path for a *populated* slot — never observed on
    hardware, now covered by simulation."""
    sim = sim_factory(
        pmode_slot_bytes=bytes.fromhex("02"),
        pmode_slots={1: 0x02},
    )
    c = _paired(sim, PMODE_MACHINE)
    try:
        table = c.read_pmode_slots(timeout=2.0)
    finally:
        c.close()
    assert table.num_slots == 2
    assert [s.index for s in table.slots] == [1]
    # Checksum stripped: the payload is product code + arguments only.
    assert len(table.slots[0].raw_payload) % 2 == 0
    assert table.slots[0].raw_payload.startswith("02")
    assert table.unsupported == (0,)


# --------------------------------------------------------------------- #
# Rejection tokens are "not supported", never success
# --------------------------------------------------------------------- #


def test_product_read_maps_c1_to_none(sim) -> None:
    """Default simulator = EF1091-style: no product programming."""
    c = _paired(sim, PMODE_MACHINE)
    try:
        assert c.read_pmode_product("espresso", timeout=2.0) is None
    finally:
        c.close()


def test_product_write_raises_on_c1(sim_factory) -> None:
    sim = sim_factory(pmode_writable=True, pmode_products=None)
    c = _paired(sim, PMODE_MACHINE)
    try:
        with pytest.raises(ValueError, match="not supported"):
            c.write_pmode_product("espresso", timeout=2.0)
    finally:
        c.close()


def test_slot_write_raises_on_c2(sim_factory) -> None:
    sim = sim_factory(pmode_writable=True, pmode_products=None)
    c = _paired(sim, PMODE_MACHINE)
    try:
        with pytest.raises(ValueError, match="not supported"):
            c.write_pmode_slot(0, "espresso", timeout=2.0)
    finally:
        c.close()


def test_write_raises_on_bare_rejection_token(sim_factory) -> None:
    """``@tm:00`` is the dongle's "write rejected" answer; it must not
    read as the success echo of argument 00."""
    sim = sim_factory(pmode_writable=True, pmode_products={}, pmode_reject_writes=True)
    c = _paired(sim, PMODE_MACHINE)
    try:
        with pytest.raises(ValueError, match="rejected"):
            c.write_pmode_product("espresso", timeout=2.0)
    finally:
        c.close()


def test_num_slots_read_maps_d0_to_zero(sim_factory) -> None:
    sim = sim_factory(pmode_slot_bytes=b"")
    c = _paired(sim, PMODE_MACHINE)
    try:
        table = c.read_pmode_slots(timeout=2.0)
    finally:
        c.close()
    assert table.num_slots == 0
    assert table.slots == ()


# --------------------------------------------------------------------- #
# Resilience: the real S8 EB resets the TCP session mid-table
# --------------------------------------------------------------------- #


def test_connection_reset_mid_table_marks_remaining_slots_unsupported(
    sim_factory,
) -> None:
    sim = sim_factory(
        pmode_slot_bytes=bytes.fromhex("08"),
        pmode_slots={0: 0x02, 1: 0x03},
        pmode_reset_after_slot=2,
    )
    c = _paired(sim, PMODE_MACHINE)
    try:
        table = c.read_pmode_slots(timeout=1.0)
    finally:
        c.close()
    assert table.num_slots == 8
    assert [s.index for s in table.slots] == [0, 1]
    # Everything from the reset onwards is reported, not raised.
    assert set(table.unsupported) == set(range(2, 8))


# --------------------------------------------------------------------- #
# Named commands + the destructive gate
# --------------------------------------------------------------------- #


def test_named_pmode_product_read(sim_factory) -> None:
    sim = sim_factory(pmode_writable=True, pmode_products={0x02: ESPRESSO_BLOB})
    c = _paired(sim, PMODE_MACHINE)
    try:
        result = run_named(c, "pmode-product", ["espresso"], timeout=2.0)
    finally:
        c.close()
    assert result.value is not None
    assert "espresso" in result.format()
    import json

    json.loads(json.dumps(result.to_dict()))


def test_named_pmode_product_reports_c1_instead_of_none(sim) -> None:
    """A machine without product programming must produce a readable
    explanation, not a bare ``None``."""
    c = _paired(sim, PMODE_MACHINE)
    try:
        result = run_named(c, "pmode-product", ["espresso"], timeout=2.0)
    finally:
        c.close()
    assert "@tm:C1" in result.format()
    assert "not supported" in result.format()


def test_named_pmode_set_product_needs_a_profile_for_a_name(sim_factory) -> None:
    sim = sim_factory(pmode_writable=True, pmode_products={})
    c = _paired(sim)  # no profile
    try:
        with pytest.raises(CommandError, match="machine profile"):
            run_named(
                c,
                "pmode-set-product",
                ["espresso"],
                timeout=2.0,
                allow_destructive=True,
            )
    finally:
        c.close()


def test_named_pmode_writes_are_gated(sim_factory) -> None:
    sim = sim_factory(pmode_writable=True, pmode_products={})
    c = _paired(sim, PMODE_MACHINE)
    try:
        for name, args in (
            ("pmode-set-product", ["espresso"]),
            ("pmode-set-slot", ["0", "espresso"]),
        ):
            with pytest.raises(DestructiveCommandError) as exc:
                run_named(c, name, args, timeout=1.0)
            assert "no undo" in str(exc.value)
    finally:
        c.close()


def test_named_pmode_writes_reach_the_wire_with_the_flag(sim_factory) -> None:
    sim = sim_factory(pmode_writable=True, pmode_products={})
    c = _paired(sim, PMODE_MACHINE)
    try:
        run_named(
            c,
            "pmode-set-slot",
            ["4", "espresso", "water=60"],
            timeout=2.0,
            allow_destructive=True,
        )
    finally:
        c.close()
    assert any(s.startswith("@TM:42,04") for s in _sent(sim))


def test_simulator_refuses_pmode_writes_by_default(sim_factory) -> None:
    """Guardrail mirror of DESTRUCTIVE_PREFIXES: the simulator only
    accepts a PMode write when a test asks for it explicitly."""
    sim = sim_factory(pmode_products={})
    c = _paired(sim, PMODE_MACHINE)
    try:
        reply = c.write_pmode_product("espresso", timeout=2.0)
    finally:
        c.close()
    assert reply.startswith("@an:error")
