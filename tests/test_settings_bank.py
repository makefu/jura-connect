"""Batch settings read (``@TM:00,FC``) and limit load (``@TM:60``).

Two machine-settings gaps closed here:

* the ``<MACHINESETTINGS><BANK Name="Setting">`` declaration every
  newer XML carries — one round trip for several settings instead of
  one ``@TM:<arg>`` per setting. **The reply layout is a guess** (no
  J.O.E. code path issues the command; see ``docs/PROTOCOL.md`` §5.7.1),
  so the high-level API must fall back to per-setting reads whenever
  the batch answer does not parse. That fallback is the behaviour these
  tests pin down.
* ``@TM:60,<product code><checksum>`` (``WifiCommandReadLimitLoad``),
  whose reply layout *is* APK-derived (``LimitLoadParser``): five
  min/max byte pairs for F4, F5, F6, F10, F11 scaled by each
  argument's XML ``Step``.

Everything here runs against :mod:`jura_connect.simulator`; nothing is
hardware-verified.
"""

from __future__ import annotations

import dataclasses

import pytest

from jura_connect import commands
from jura_connect.client import (
    JuraClient,
    ProductLimits,
    SettingsSnapshot,
    _settings_checksum,
)
from jura_connect.profile import SettingsBank, iter_profiles, load_profile

EF1091_BANK_ARGS = ("02", "08", "09", "13")


def _paired(sim, code: str | None = "EF1091") -> JuraClient:
    host, port = sim.address
    profile = load_profile(code) if code else None
    c = JuraClient(host, port=port, conn_id="settings", auth_hash="", profile=profile)
    result = c.pair(timeout=2.0)
    assert result.state == "CORRECT"
    return c


# --------------------------------------------------------------------- #
# Profile: the <BANK Name="Setting"> declaration
# --------------------------------------------------------------------- #


def test_ef1091_declares_the_settings_bank() -> None:
    bank = load_profile("EF1091").settings_bank
    assert bank is not None
    assert bank.name == "Setting"
    assert bank.command == "@TM:00,FC"
    assert bank.arguments == EF1091_BANK_ARGS


def test_settings_bank_shape_across_every_profile() -> None:
    """Walk all bundled XMLs: a settings bank is either absent or a
    well-shaped (command, argument-list) pair.

    57 of the 89 profiles declare one; the other 32 carry no
    ``<MACHINESETTINGS>`` block at all (the old T-protocol families such
    as the EF536 fallback baseline).
    """
    with_bank = 0
    total = 0
    for profile in iter_profiles():
        total += 1
        bank = profile.settings_bank
        if bank is None:
            assert profile.settings == (), (
                f"{profile.code}: settings without a bank declaration"
            )
            continue
        with_bank += 1
        assert bank.command == "@TM:00,FC", profile.code
        assert bank.arguments, profile.code
        for arg in bank.arguments:
            assert len(arg) == 2, f"{profile.code}: odd bank argument {arg!r}"
            int(arg, 16)  # raises if the CommandArgument is not hex
    assert total == 89
    assert with_bank == 57


def test_settings_bank_argument_list_is_boilerplate_not_per_machine() -> None:
    """The bank's ``CommandArgument`` is copied verbatim across the
    XMLs: several profiles list settings their own ``<MACHINESETTINGS>``
    never declares. The batch reader must therefore not assume every
    bank argument resolves to a :class:`SettingDef`.
    """
    mismatched = []
    for profile in iter_profiles():
        bank = profile.settings_bank
        if bank is None:
            continue
        assert bank.arguments == EF1091_BANK_ARGS, profile.code
        if any(profile.setting_by_arg(a) is None for a in bank.arguments):
            mismatched.append(profile.code)
    assert "EF1096" in mismatched
    assert "EF1091" not in mismatched
    assert len(mismatched) == 16


# --------------------------------------------------------------------- #
# Batch settings read
# --------------------------------------------------------------------- #


def test_batch_read_returns_every_bank_argument(sim) -> None:
    c = _paired(sim)
    try:
        values = c.read_settings_bank(timeout=2.0)
    finally:
        c.close()
    assert values == {"02": "10", "08": "00", "09": "02", "13": "211E"}


def test_batch_read_sends_the_xml_declared_command(sim) -> None:
    c = _paired(sim)
    try:
        c.read_settings_bank(timeout=2.0)
    finally:
        c.close()
    assert b"@TM:00,FC" in sim.sent_commands
    # No checksum by default: the XML's Command attribute is sent
    # verbatim, like every other <BANK Command="…"> we speak.
    assert b"@TM:00,FC" + _settings_checksum("00,FC").encode() not in sim.sent_commands


def test_batch_read_can_append_the_settings_checksum(sim_factory) -> None:
    """Opt-in variant for hardware probing: some firmwares may want the
    ``ByteOperations.d`` checksum every other ``@TM:<arg>,<val>`` frame
    carries. Which form the machine wants is untested."""
    sim = sim_factory(settings_bank_requires_checksum=True)
    c = _paired(sim)
    try:
        values = c.read_settings_bank(timeout=2.0, checksum=True)
    finally:
        c.close()
    assert values["09"] == "02"
    assert b"@TM:00,FC" + _settings_checksum("00,FC").encode() in sim.sent_commands


def test_batch_read_honours_a_different_bank_argument_list(sim_factory) -> None:
    """Nothing may hard-code ``02080913``: the reader follows whatever
    the profile's bank declares, and the reply is decoded in that
    order."""
    sim = sim_factory(settings_bank_arguments="0902")
    profile = dataclasses.replace(
        load_profile("EF1091"),
        settings_bank=SettingsBank(
            name="Setting", command="@TM:00,FC", arguments=("09", "02")
        ),
    )
    host, port = sim.address
    c = JuraClient(host, port=port, conn_id="settings", auth_hash="", profile=profile)
    assert c.pair(timeout=2.0).state == "CORRECT"
    try:
        values = c.read_settings_bank(timeout=2.0)
    finally:
        c.close()
    assert list(values.items()) == [("09", "02"), ("02", "10")]


def test_batch_read_raises_when_the_machine_rejects_the_bank(sim_factory) -> None:
    sim = sim_factory(settings_bank_arguments=None)
    c = _paired(sim)
    try:
        with pytest.raises(ValueError, match="rejected"):
            c.read_settings_bank(timeout=2.0)
    finally:
        c.close()


def test_batch_read_raises_on_a_checksum_mismatch(sim_factory) -> None:
    sim = sim_factory(settings_bank_corrupt_checksum=True)
    c = _paired(sim)
    try:
        with pytest.raises(ValueError, match="checksum"):
            c.read_settings_bank(timeout=2.0)
    finally:
        c.close()


def test_read_all_settings_uses_the_batch_for_the_bank_arguments(sim) -> None:
    c = _paired(sim)
    try:
        snap = c.read_all_settings(timeout=2.0)
    finally:
        c.close()
    assert isinstance(snap, SettingsSnapshot)
    assert snap.batch_used is True
    assert snap.batch_error is None
    by_name = {r.name: r for r in snap.readings}
    assert by_name["hardness"].raw == "10"
    assert by_name["hardness"].source == "batch"
    assert by_name["auto_off"].raw == "211E"
    assert by_name["auto_off"].item == "30min"
    assert by_name["language"].item == "english"
    # Settings outside the bank still come from single reads.
    assert by_name["display_brightness_setting"].source == "single"
    assert by_name["display_brightness_setting"].raw == "04"
    # One request for the bank + one per remaining catalogue setting.
    tm_reads = [c for c in sim.sent_commands if c.startswith(b"@TM:")]
    assert len(tm_reads) == 1 + (len(load_profile("EF1091").settings) - 4)


def test_read_all_settings_falls_back_to_single_reads(sim_factory) -> None:
    """A machine that answers the bare rejection token ``@tm:00`` must
    still yield the full, correct settings snapshot — just one request
    per setting."""
    sim = sim_factory(settings_bank_arguments=None)
    c = _paired(sim)
    try:
        snap = c.read_all_settings(timeout=2.0)
    finally:
        c.close()
    assert snap.batch_used is False
    assert snap.batch_error is not None
    by_name = {r.name: r for r in snap.readings}
    assert by_name["hardness"].raw == "10"
    assert by_name["units"].item == "ml"
    assert by_name["auto_off"].raw == "211E"
    assert all(r.source == "single" for r in snap.readings)
    assert len(snap.readings) == len(load_profile("EF1091").settings)


def test_read_all_settings_batch_and_fallback_agree(sim_factory) -> None:
    batched = sim_factory()
    single = sim_factory(settings_bank_arguments=None)
    c1, c2 = _paired(batched), _paired(single)
    try:
        a = c1.read_all_settings(timeout=2.0)
        b = c2.read_all_settings(timeout=2.0)
    finally:
        c1.close()
        c2.close()
    assert a.batch_used and not b.batch_used
    assert {(r.p_argument, r.raw) for r in a.readings} == {
        (r.p_argument, r.raw) for r in b.readings
    }


def test_settings_snapshot_format_and_to_dict(sim) -> None:
    c = _paired(sim)
    try:
        snap = c.read_all_settings(timeout=2.0)
    finally:
        c.close()
    text = snap.format()
    assert "hardness" in text
    assert "30min" in text
    payload = snap.to_dict()
    assert payload["batch_used"] is True
    entry = next(r for r in payload["readings"] if r["name"] == "language")
    assert entry == {
        "p_argument": "09",
        "name": "language",
        "raw": "02",
        "item": "english",
        "source": "batch",
    }


def test_read_all_settings_needs_a_profile(sim) -> None:
    c = _paired(sim, code=None)
    try:
        with pytest.raises(RuntimeError, match="MachineProfile"):
            c.read_all_settings(timeout=2.0)
    finally:
        c.close()


# --------------------------------------------------------------------- #
# Limit load (@TM:60)
# --------------------------------------------------------------------- #


def test_limit_load_decodes_live_ranges(sim) -> None:
    c = _paired(sim)
    try:
        limits = c.read_limit_load("cappuccino", timeout=2.0)
    finally:
        c.close()
    assert isinstance(limits, ProductLimits)
    assert limits.product_code == 0x04
    assert limits.product_name == "cappuccino"
    ranges = {limit.kind: (limit.minimum, limit.maximum) for limit in limits.limits}
    # F4 water: bytes 05..30 scaled by the XML Step of 5 -> 25..240 ml.
    assert ranges["water_amount"] == (25, 240)
    # F6 milk foam: Step 1 -> raw seconds.
    assert ranges["milk_foam_amount"] == (1, 45)
    # F5/F10/F11 come back as FFFF ("not applicable") and are dropped,
    # exactly as LimitLoadParser drops them.
    assert set(ranges) == {"water_amount", "milk_foam_amount"}


def test_limit_load_request_carries_the_settings_checksum(sim) -> None:
    c = _paired(sim)
    try:
        c.read_limit_load(0x04, timeout=2.0)
    finally:
        c.close()
    expected = f"@TM:60,04{_settings_checksum('60,04')}".encode()
    assert expected in sim.sent_commands


def test_limit_load_rejects_a_corrupt_reply_checksum(sim_factory) -> None:
    sim = sim_factory(limit_load_corrupt_checksum=True)
    c = _paired(sim)
    try:
        with pytest.raises(ValueError, match="checksum"):
            c.read_limit_load("cappuccino", timeout=2.0)
    finally:
        c.close()


def test_limit_load_rejects_a_product_code_mismatch(sim_factory) -> None:
    sim = sim_factory(limit_load_echo_wrong_code=True)
    c = _paired(sim)
    try:
        with pytest.raises(ValueError, match="product code"):
            c.read_limit_load("cappuccino", timeout=2.0)
    finally:
        c.close()


def test_limit_load_reports_an_unsupported_product(sim) -> None:
    """``@tm:C1`` is the APK's "machine does not support product
    programming" token."""
    c = _paired(sim)
    try:
        with pytest.raises(ValueError, match="does not support"):
            c.read_limit_load("espresso", timeout=2.0)
    finally:
        c.close()


def test_limit_load_rejects_a_truncated_reply(sim_factory) -> None:
    sim = sim_factory(limit_load={0x04: "0530FFFF"})
    c = _paired(sim)
    try:
        with pytest.raises(ValueError, match="too short"):
            c.read_limit_load("cappuccino", timeout=2.0)
    finally:
        c.close()


def test_limit_load_format_and_to_dict(sim) -> None:
    c = _paired(sim)
    try:
        limits = c.read_limit_load("cappuccino", timeout=2.0)
    finally:
        c.close()
    text = limits.format()
    assert "cappuccino" in text
    assert "25" in text and "240" in text
    payload = limits.to_dict()
    assert payload["product_code"] == "04"
    assert {
        "kind": "water_amount",
        "argument": 4,
        "minimum": 25,
        "maximum": 240,
        "step": 5,
    } in payload["limits"]


def test_limit_load_validates_a_brew_against_the_live_range(sim) -> None:
    """The point of the command: bound a brew by what the machine
    reports *now* rather than by the static XML range."""
    c = _paired(sim)
    try:
        limits = c.read_limit_load("cappuccino", timeout=2.0)
    finally:
        c.close()
    assert limits.allows("water_amount", 100) is True
    assert limits.allows("water_amount", 500) is False
    # Unknown / not-reported parameters are not constrained.
    assert limits.allows("milk_break", 20) is True


def test_limit_load_needs_a_profile(sim) -> None:
    c = _paired(sim, code=None)
    try:
        with pytest.raises(RuntimeError, match="MachineProfile"):
            c.read_limit_load("cappuccino", timeout=2.0)
    finally:
        c.close()


# --------------------------------------------------------------------- #
# Settings catalogue coverage
# --------------------------------------------------------------------- #


def test_time_format_and_brightness_settings_are_catalogued() -> None:
    """``@TM:1F`` (TimeFormat) and ``@TM:0A`` (display brightness) show
    up in the J.O.E. mock; both are plain ``<SWITCH>`` / ``<COMBOBOX>``
    entries and must parse wherever a machine declares them. EF1091 has
    no TimeFormat — EF1097 does."""
    ef1097 = load_profile("EF1097")
    time_format = ef1097.setting_by_arg("1F")
    assert time_format is not None
    assert time_format.kind == "switch"
    assert {i.name for i in time_format.items} >= {"am_pm"}

    brightness = load_profile("EF1091").setting_by_arg("0A")
    assert brightness is not None
    assert brightness.kind == "combobox"
    assert len(brightness.items) == 10


def test_switch_mask_is_parsed() -> None:
    """``Mask`` is not a slider-only attribute: the ESM switch carries
    ``Mask="01"``. It used to be dropped for every non-slider kind."""
    esm = load_profile("EF0000").setting_by_arg("07")
    assert esm is not None
    assert esm.kind == "switch"
    assert esm.mask == "01"


def test_named_commands_are_registered_and_read_only(sim) -> None:
    names = {s.name: s for s in commands.list_commands()}
    assert names["settings"].destructive is False
    assert names["limits"].destructive is False

    c = _paired(sim)
    try:
        settings = commands.run_named(c, "settings", timeout=2.0)
        limits = commands.run_named(c, "limits", ("cappuccino",), timeout=2.0)
    finally:
        c.close()
    assert isinstance(settings.value, SettingsSnapshot)
    assert "hardness" in settings.format()
    assert isinstance(limits.value, ProductLimits)
    assert "water_amount" in limits.format()


def test_named_commands_need_a_profile(sim) -> None:
    c = _paired(sim, code=None)
    try:
        with pytest.raises(commands.CommandError, match="MachineProfile"):
            commands.run_named(c, "settings", timeout=2.0)
        with pytest.raises(commands.CommandError, match="MachineProfile"):
            commands.run_named(c, "limits", ("cappuccino",), timeout=2.0)
    finally:
        c.close()


def test_only_four_element_kinds_exist_in_machinesettings() -> None:
    """Guard against a future XML introducing a settings widget the
    parser silently drops."""
    kinds = {s.kind for p in iter_profiles() for s in p.settings}
    assert kinds == {"switch", "combobox", "step_slider", "item_slider"}
