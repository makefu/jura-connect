"""Named-command registry tests, end-to-end via the simulator.

Each registered command is dispatched against the in-tree simulator
(no mocks), exercising the same code path the CLI takes.
"""

from __future__ import annotations

import pytest

from jura_connect import commands
from jura_connect.client import (
    JuraClient,
    MachineInfo,
    MachineStatus,
    MaintenanceCounters,
    MaintenancePercent,
)
from jura_connect.commands import CommandError, DestructiveCommandError, run_named


def _paired(sim) -> JuraClient:
    host, port = sim.address
    c = JuraClient(host, port=port, conn_id="cmd-tests", auth_hash="")
    r = c.pair(timeout=2.0)
    assert r.state == "CORRECT"
    return c


def test_list_commands_contains_safe_and_destructive_groups() -> None:
    specs = commands.list_commands()
    names = [s.name for s in specs]
    # Safe operations are present.
    for expected in [
        "info",
        "counters",
        "percent",
        "status",
        "lock",
        "unlock",
        "mem-read",
        "register-read",
        "raw",
    ]:
        assert expected in names
    # Destructive operations are present *and* flagged with a danger string.
    for expected in [
        "clean",
        "decalc",
        "filter-change",
        "cappu-clean",
        "cappu-rinse",
        "reset-counters",
        "restart",
        "power-off",
        "brew",
        "set-pin",
        "set-ssid",
        "set-password",
        "set-name",
    ]:
        assert expected in names, f"{expected!r} missing from registry"
        spec = commands.get_command(expected)
        assert spec.destructive, f"{expected!r} must be flagged destructive"
        assert spec.danger, f"{expected!r} must carry a danger explanation"
    # The read-only group must NOT be marked destructive.
    for safe in [
        "info",
        "counters",
        "percent",
        "status",
        "lock",
        "unlock",
        "mem-read",
        "register-read",
        "raw",
    ]:
        assert not commands.get_command(safe).destructive


def test_unknown_command_raises() -> None:
    with pytest.raises(CommandError, match="unknown command"):
        commands.get_command("not-a-real-command")


def test_wrong_argument_count_raises(sim) -> None:
    c = _paired(sim)
    try:
        with pytest.raises(CommandError, match="expected 1"):
            run_named(c, "mem-read", [], timeout=1.0)
        with pytest.raises(CommandError, match="expected 0"):
            run_named(c, "counters", ["extra-arg"], timeout=1.0)
    finally:
        c.close()


def test_info_returns_machine_info(sim) -> None:
    c = _paired(sim)
    try:
        result = run_named(c, "info", timeout=3.0)
    finally:
        c.close()
    assert isinstance(result.value, MachineInfo)
    assert "machine info" in result.format()
    assert "no_beans" in result.format()


def test_counters(sim) -> None:
    c = _paired(sim)
    try:
        result = run_named(c, "counters", timeout=2.0)
    finally:
        c.close()
    assert isinstance(result.value, MaintenanceCounters)
    assert result.value.cleaning == 0x0015
    assert "cleaning=21" in result.format()


def test_percent(sim) -> None:
    c = _paired(sim)
    try:
        result = run_named(c, "percent", timeout=2.0)
    finally:
        c.close()
    assert isinstance(result.value, MaintenancePercent)
    assert result.value.cleaning == 0x50


def test_status(sim) -> None:
    c = _paired(sim)
    try:
        result = run_named(c, "status", timeout=2.0)
    finally:
        c.close()
    assert isinstance(result.value, MachineStatus)
    # Simulator default frame activates bit 10 (no_beans) + bit 34
    # (cleaning_alert) under MSB-first decoding.
    assert "no_beans" in result.value.active_alerts
    assert "cleaning_alert" in result.value.active_alerts


def test_lock_unlock(sim) -> None:
    c = _paired(sim)
    try:
        lock = run_named(c, "lock", timeout=2.0)
        assert lock.value.startswith("@ts")  # type: ignore[union-attr]
        assert sim.config.screen_locked is True
        unlock = run_named(c, "unlock", timeout=2.0)
        assert unlock.value.startswith("@ts")  # type: ignore[union-attr]
        assert sim.config.screen_locked is False
    finally:
        c.close()


def test_mem_read_with_argument(sim) -> None:
    c = _paired(sim)
    try:
        result = run_named(c, "mem-read", ["50"], timeout=2.0)
    finally:
        c.close()
    # Simulator echoes the address back as the @tm: reply tail.
    assert isinstance(result.value, str)
    assert result.value.lower().startswith("@tm:50")


def test_register_read_with_argument(sim) -> None:
    c = _paired(sim)
    try:
        result = run_named(c, "register-read", ["32"], timeout=2.0)
    finally:
        c.close()
    assert isinstance(result.value, str)
    assert result.value.lower().startswith("@tr:32")


def test_raw_passthrough(sim) -> None:
    c = _paired(sim)
    try:
        result = run_named(c, "raw", ["@TG:43"], timeout=2.0)
    finally:
        c.close()
    assert isinstance(result.value, str)
    assert result.value.startswith("@tg:43")


def test_raw_rejects_non_at_prefix(sim) -> None:
    c = _paired(sim)
    try:
        with pytest.raises(CommandError, match="must start with '@'"):
            run_named(c, "raw", ["TG:43"], timeout=1.0)
    finally:
        c.close()


def test_command_spec_usage_string() -> None:
    assert commands.get_command("counters").usage() == "counters"
    assert commands.get_command("mem-read").usage() == "mem-read <addr>"


# --------------------------------------------------------------------- #
# to_dict() — JSON-serialisable representation
# --------------------------------------------------------------------- #


def test_counters_result_to_dict_round_trips_through_json(sim) -> None:
    import json as _json

    c = _paired(sim)
    try:
        result = run_named(c, "counters", timeout=2.0)
    finally:
        c.close()
    d = result.to_dict()
    assert d["name"] == "counters"
    assert d["value"]["cleaning"] == 0x0015
    assert d["value"]["raw_hex"].startswith("0015")
    # Whole thing must round-trip via json without TypeError.
    _json.loads(_json.dumps(d))


def test_status_result_to_dict(sim) -> None:
    c = _paired(sim)
    try:
        result = run_named(c, "status", timeout=2.0)
    finally:
        c.close()
    d = result.to_dict()
    assert d["name"] == "status"
    assert "no_beans" in d["value"]["active_alerts"]
    assert "cleaning_alert" in d["value"]["active_alerts"]
    assert d["value"]["bits_hex"] == "0020000020000000"


def test_info_result_to_dict_is_nested(sim) -> None:
    import json as _json

    c = _paired(sim)
    try:
        result = run_named(c, "info", timeout=3.0)
    finally:
        c.close()
    d = result.to_dict()
    assert d["name"] == "info"
    assert d["value"]["handshake_state"] == "CORRECT"
    assert d["value"]["maintenance_counters"]["cleaning"] == 0x0015
    assert d["value"]["status"]["active_alerts"]
    # Composite must remain JSON-serialisable.
    _json.loads(_json.dumps(d))


def test_brews_returns_product_counters(sim) -> None:
    from jura_connect.client import ProductCounters

    c = _paired(sim)
    try:
        result = run_named(c, "brews", timeout=3.0)
    finally:
        c.close()
    assert isinstance(result.value, ProductCounters)
    pc = result.value
    # Defaults straight out of the simulator (mirror Kaffeebert).
    assert pc.total == 3229
    assert pc.by_name["espresso"] == 78
    assert pc.by_name["coffee"] == 595
    assert pc.by_name["americano"] == 1019
    assert pc.by_name["lungo"] == 3
    assert pc.by_name["espresso_doppio"] == 20
    # Unused slots don't make it into the by_code map.
    assert "01" not in pc.by_code  # ristretto = 0xFFFF
    # JSON-serialisable.
    import json as _json

    _json.loads(_json.dumps(result.to_dict()))


def test_brews_format_includes_named_products(sim) -> None:
    c = _paired(sim)
    try:
        result = run_named(c, "brews", timeout=3.0)
    finally:
        c.close()
    text = result.format()
    assert "total brews : 3229" in text
    assert "espresso" in text
    assert "americano" in text
    assert "espresso_doppio" in text


def test_brews_uses_profile_to_name_machine_specific_products(sim) -> None:
    """With an EF1091 profile loaded, codes 0x2B/0x2C/0x31/0x36 are
    named (cortado, sweet_latte, 2_espressi, 2_coffee) rather than
    falling through to the EF536 baseline where they're unknown."""
    from jura_connect.client import JuraClient
    from jura_connect.profile import load_profile

    host, port = sim.address
    c = JuraClient(
        host,
        port=port,
        conn_id="profile-tests",
        auth_hash="",
        profile=load_profile("EF1091"),
    )
    r = c.pair(timeout=2.0)
    assert r.state == "CORRECT"
    try:
        result = run_named(c, "brews", timeout=3.0)
    finally:
        c.close()
    pc = result.value
    assert pc.by_name["cortado"] == 2  # 0x2B
    assert pc.by_name["sweet_latte"] == 1  # 0x2C
    assert pc.by_name["2_espressi"] == 1  # 0x31 — EF536 has this at 0x12
    assert pc.by_name["2_coffee"] == 10  # 0x36 — EF536 has this at 0x13
    # Without the profile these would all show up in by_code only.
    assert "cortado" in result.format()
    assert "0x2B" not in result.format()


def test_pmode_empty_when_machine_returns_c2(sim) -> None:
    """The default simulator config mirrors Kaffeebert: @TM:50 reports
    20 slots but @TM:42 returns C2 for everything. The format output
    must explain that, not pretend the slots are configured."""
    c = _paired(sim)
    try:
        result = run_named(c, "pmode", timeout=2.0)
    finally:
        c.close()
    pm = result.value
    assert pm.num_slots == 20
    assert pm.slots == ()
    assert "not supported by machine" in pm.format()
    # JSON-serialisable.
    import json as _json

    _json.loads(_json.dumps(result.to_dict()))


def test_pmode_with_configured_slots(sim_factory) -> None:
    """When the simulator exposes slot product codes, the parser
    populates ProgramModeSlots.slots accordingly."""
    sim = sim_factory(pmode_slots={0: 0x02, 1: 0x03, 5: 0x28})
    c = _paired(sim)
    try:
        result = run_named(c, "pmode", timeout=2.0)
    finally:
        c.close()
    pm = result.value
    assert pm.num_slots == 20
    assert len(pm.slots) == 3
    by_index = {s.index: s.product_code for s in pm.slots}
    assert by_index == {0: 0x02, 1: 0x03, 5: 0x28}
    # Every other slot is unsupported.
    assert set(pm.unsupported) == set(range(20)) - {0, 1, 5}


def test_status_categorisation_no_beans_is_info_not_error(sim) -> None:
    """The user explicitly flagged this: no_beans means 'bin running
    low', not 'machine is stuck'. It must NOT appear under .errors."""
    c = _paired(sim)
    try:
        result = run_named(c, "status", timeout=2.0)
    finally:
        c.close()
    st = result.value
    # Simulator default status frame has bit 10 (no_beans, info) +
    # bit 34 (cleaning_alert, process) set under MSB-first decoding.
    assert "no_beans" in st.info
    assert "no_beans" not in st.errors
    assert "cleaning_alert" in st.process
    assert "cleaning_alert" not in st.errors
    # The errors group should be empty for the default frame.
    assert st.errors == ()


def test_status_format_groups_severities(sim) -> None:
    c = _paired(sim)
    try:
        result = run_named(c, "status", timeout=2.0)
    finally:
        c.close()
    text = result.format()
    assert "errors  : (none)" in text
    assert "no_beans" in text


def test_kaffeebert_idle_frame_decodes_to_coffee_ready_energy_safe() -> None:
    """Regression test: the live frame captured from Kaffeebert at idle
    (`@TF:0004000008000000`) must decode to bit 13 (coffee_ready) +
    bit 36 (energy_safe) under MSB-first byte/bit indexing. Prior to
    v0.9.0 the LSB-first parser mis-decoded this as no_beans +
    cappu_rinse_alert."""
    st = MachineStatus.parse("@TF:0004000008000000")
    assert "coffee_ready" in st.active_alerts
    assert "energy_safe" in st.active_alerts
    assert "no_beans" not in st.active_alerts
    assert "cappu_rinse_alert" not in st.active_alerts


def test_string_result_to_dict_passthrough(sim) -> None:
    c = _paired(sim)
    try:
        result = run_named(c, "lock", timeout=2.0)
    finally:
        c.close()
    d = result.to_dict()
    assert d["name"] == "lock"
    assert isinstance(d["value"], str)
    assert d["value"].startswith("@ts")


# --------------------------------------------------------------------- #
# Destructive command gate
# --------------------------------------------------------------------- #


# (name, args) pairs covering every destructive command in the registry.
_DESTRUCTIVE_INVOCATIONS = [
    ("clean", []),
    ("decalc", []),
    ("filter-change", []),
    ("cappu-clean", []),
    ("cappu-rinse", []),
    ("reset-counters", []),
    ("restart", []),
    ("power-off", []),
    ("brew", ["01"]),
    ("set-pin", ["1234"]),
    ("set-ssid", ["mywifi"]),
    ("set-password", ["s3cret"]),
    ("set-name", ["Kaffeebert"]),
]


@pytest.mark.parametrize(("name", "args"), _DESTRUCTIVE_INVOCATIONS)
def test_destructive_command_blocked_without_flag(sim, name, args) -> None:
    """Every destructive command refuses without --allow-destructive-commands."""
    c = _paired(sim)
    try:
        with pytest.raises(DestructiveCommandError) as exc:
            run_named(c, name, args, timeout=1.0)
        # The message must name the command and tell the user how to override.
        msg = str(exc.value)
        assert name in msg
        assert "allow-destructive-commands" in msg or "allow_destructive" in msg
    finally:
        c.close()


@pytest.mark.parametrize(("name", "args"), _DESTRUCTIVE_INVOCATIONS)
def test_destructive_command_reaches_wire_with_flag(sim, name, args) -> None:
    """With the flag, the destructive command is sent. The simulator still
    refuses with @an:error — that's the proof it reached the wire."""
    c = _paired(sim)
    try:
        result = run_named(c, name, args, timeout=2.0, allow_destructive=True)
    finally:
        c.close()
    # Either we get @an:error (simulator's wire-level refusal) or, for
    # restart/power-off, the connection-closed sentinel.
    assert isinstance(result.value, str)
    assert (
        result.value.startswith("@an:error") or "connection closed" in result.value
    ), f"unexpected reply for {name!r}: {result.value!r}"


def test_raw_payload_destructive_prefix_blocked_without_flag(sim) -> None:
    """raw is non-destructive as a command, but its argument is inspected."""
    c = _paired(sim)
    try:
        with pytest.raises(DestructiveCommandError, match="@TG:24"):
            run_named(c, "raw", ["@TG:24"], timeout=1.0)
        with pytest.raises(DestructiveCommandError, match="@HW:"):
            run_named(c, "raw", ["@HW:01,1234"], timeout=1.0)
    finally:
        c.close()


def test_raw_payload_destructive_prefix_allowed_with_flag(sim) -> None:
    c = _paired(sim)
    try:
        result = run_named(c, "raw", ["@TG:24"], timeout=2.0, allow_destructive=True)
    finally:
        c.close()
    assert isinstance(result.value, str)
    assert result.value.startswith("@an:error")


def test_safe_raw_payload_is_not_gated(sim) -> None:
    """A non-destructive @ command via raw works without the flag."""
    c = _paired(sim)
    try:
        result = run_named(c, "raw", ["@TG:43"], timeout=2.0)
    finally:
        c.close()
    assert result.value.startswith("@tg:43")  # type: ignore[union-attr]


def test_set_pin_validates_numeric(sim) -> None:
    c = _paired(sim)
    try:
        with pytest.raises(CommandError, match="must be numeric"):
            run_named(c, "set-pin", ["abcd"], timeout=1.0, allow_destructive=True)
    finally:
        c.close()


def test_destructive_error_message_includes_danger_explanation(sim) -> None:
    """The message a user sees must explain WHAT can go wrong."""
    c = _paired(sim)
    try:
        with pytest.raises(DestructiveCommandError) as exc:
            run_named(c, "set-ssid", ["foo"], timeout=1.0)
    finally:
        c.close()
    msg = str(exc.value)
    # The danger field for set-ssid mentions both the action and recovery.
    assert "WiFi" in msg or "ssid" in msg.lower()
    assert "factory reset" in msg


# --------------------------------------------------------------------- #
# Settings (read + write via profile-driven @TM:<arg>)
# --------------------------------------------------------------------- #


def _paired_with_profile(sim, code: str = "EF1091") -> JuraClient:
    from jura_connect.profile import load_profile

    host, port = sim.address
    c = JuraClient(
        host,
        port=port,
        conn_id="cmd-tests",
        auth_hash="",
        profile=load_profile(code),
    )
    r = c.pair(timeout=2.0)
    assert r.state == "CORRECT"
    return c


def test_setting_read_resolves_against_profile(sim) -> None:
    c = _paired_with_profile(sim)
    try:
        result = run_named(c, "setting", ["hardness"], timeout=2.0)
    finally:
        c.close()
    # Simulator stores hardness=0x10 (16°dH) by default.
    assert "hardness" in str(result.value).lower()
    assert "16" in str(result.value)
    assert "0x10" in str(result.value)


def test_setting_read_via_substring(sim) -> None:
    c = _paired_with_profile(sim)
    try:
        # "bright" is a substring of "display_brightness_setting".
        result = run_named(c, "setting", ["bright"], timeout=2.0)
    finally:
        c.close()
    assert "0x04" in str(result.value)  # default brightness ITEM value


def test_setting_read_unknown_name_lists_known(sim) -> None:
    c = _paired_with_profile(sim)
    try:
        with pytest.raises(CommandError) as exc:
            run_named(c, "setting", ["definitely_not_a_real_setting"], timeout=1.0)
    finally:
        c.close()
    msg = str(exc.value)
    assert "EF1091" in msg
    assert "hardness" in msg  # at least one known setting is enumerated


def test_setting_read_refuses_without_profile(sim) -> None:
    """The 'setting' command needs a profile loaded; the bare client
    cannot enumerate the catalogue from thin air."""
    host, port = sim.address
    c = JuraClient(host, port=port, conn_id="cmd-tests", auth_hash="")
    c.pair(timeout=2.0)
    try:
        with pytest.raises(CommandError, match="MachineProfile"):
            run_named(c, "setting", ["hardness"], timeout=1.0)
    finally:
        c.close()


def test_setting_write_is_destructive(sim) -> None:
    c = _paired_with_profile(sim)
    try:
        # Two-arg call triggers the dynamic destructive gate.
        with pytest.raises(DestructiveCommandError) as exc:
            run_named(c, "setting", ["hardness", "20"], timeout=1.0)
    finally:
        c.close()
    msg = str(exc.value)
    assert "@TM:<arg>,<val>" in msg
    assert "--allow-destructive-commands" in msg


def test_setting_write_allowed_with_gate_persists_value(sim) -> None:
    c = _paired_with_profile(sim)
    try:
        # 20°dH should round-trip through hex 0x14.
        write_res = run_named(
            c, "setting", ["hardness", "20"], timeout=2.0, allow_destructive=True
        )
        assert "0x14" in str(write_res.value)
        # Now re-read and confirm the simulator stored the new value.
        read_res = run_named(c, "setting", ["hardness"], timeout=2.0)
    finally:
        c.close()
    assert "20" in str(read_res.value)
    assert "0x14" in str(read_res.value)


def test_setting_write_validates_step_slider_range(sim) -> None:
    c = _paired_with_profile(sim)
    try:
        # Hardness range is 1..30; 99 is out of bounds.
        with pytest.raises(CommandError, match="outside"):
            run_named(
                c,
                "setting",
                ["hardness", "99"],
                timeout=1.0,
                allow_destructive=True,
            )
    finally:
        c.close()


def test_setting_write_validates_combobox_unknown_item(sim) -> None:
    c = _paired_with_profile(sim)
    try:
        with pytest.raises(CommandError, match="Allowed"):
            run_named(
                c,
                "setting",
                ["language", "klingon"],
                timeout=1.0,
                allow_destructive=True,
            )
    finally:
        c.close()


def test_setting_write_accepts_item_name_for_combobox(sim) -> None:
    c = _paired_with_profile(sim)
    try:
        result = run_named(
            c,
            "setting",
            ["language", "french"],
            timeout=2.0,
            allow_destructive=True,
        )
        assert "0x03" in str(result.value)  # french=03 per EF1091 XML
        # And the simulator should now report French on read.
        read = run_named(c, "setting", ["language"], timeout=2.0)
    finally:
        c.close()
    assert "french" in str(read.value).lower()


def test_setting_write_accepts_switch_by_off(sim) -> None:
    c = _paired_with_profile(sim)
    try:
        # Frother Instructions: on=01, off=00.
        run_named(
            c,
            "setting",
            ["frother_instructions", "off"],
            timeout=2.0,
            allow_destructive=True,
        )
        read = run_named(c, "setting", ["frother_instructions"], timeout=2.0)
    finally:
        c.close()
    assert "off" in str(read.value).lower()


def test_setting_write_checksum_must_match(sim) -> None:
    """A raw write with a wrong checksum must be refused @an:error."""
    from jura_connect.client import _settings_checksum

    c = _paired_with_profile(sim)
    try:
        # Correct payload: @TM:02,14<csum>. We tamper with the csum.
        good = _settings_checksum("02,14")
        bad = "00" if good != "00" else "FF"
        bad_cmd = f"@TM:02,14{bad}"
        reply = c.request(bad_cmd, match=r"^@(tm|an)", timeout=2.0)
    finally:
        c.close()
    assert "error" in reply.lower()


def test_setting_read_strips_trailing_checksum(sim) -> None:
    """Regression for v0.9.0: hardness=13 (=0x0D) came back as 3581
    because the parser kept the trailing checksum byte as if it were
    part of the value. The reply for arg=02 is ``@tm:02,0DFD`` where
    ``0D`` is the value and ``FD`` is the ByteOperations.d checksum
    over ``"02,0D"``. The decoded read must surface 13 (not 3581)."""
    sim.config.settings["02"] = "0D"  # 13 °dH on the wire
    c = _paired_with_profile(sim)
    try:
        result = run_named(c, "setting", ["hardness"], timeout=2.0)
    finally:
        c.close()
    text = str(result.value)
    assert "hardness" in text.lower()
    assert " 13 " in text
    assert "0x0D" in text
    assert "3581" not in text


def test_setting_write_wraps_in_lock_unlock(sim) -> None:
    """Regression for v0.9.2: settings writes silently dropped on the
    real machine because we sent @TM:<arg>,<val><csum> bare; the J.O.E.
    APK wraps every PMODE-priority command in @TS:01...@TS:00. Without
    the wrapper Kaffeebert ACKs the write but the value doesn't change.

    The simulator tracks `screen_locked` based on @TS:01 / @TS:00, so
    we observe the wrap by toggling that flag and checking it returns
    to False after the write."""
    sim.config.settings["02"] = "08"
    c = _paired_with_profile(sim)
    try:
        # Pre-condition: screen not locked.
        assert sim.config.screen_locked is False
        result = run_named(
            c, "setting", ["hardness", "12"], timeout=3.0, allow_destructive=True
        )
        # Post-condition: lock got released. If the unlock were missed,
        # screen_locked would still be True here and the machine would
        # be stuck in remote-service mode.
        assert sim.config.screen_locked is False
        assert "0x0C" in str(result.value)  # 12 dec → 0x0C
        # Confirm the write actually went through (verify path).
        read = run_named(c, "setting", ["hardness"], timeout=2.0)
    finally:
        c.close()
    assert " 12 " in str(read.value)
    assert "0x0C" in str(read.value)


def test_setting_write_bank_arg_uses_bulk_format(sim) -> None:
    """Regression for v0.9.3: bank args (hardness/units/language/
    auto_off on EF1091) need the bulk ``@TM:00,FC,<block><csum>``
    form; the individual ``@TM:<arg>,<val>`` write was ACKed by the
    dongle as ``@tm:00`` but the machine ignored the value. End-to-
    end test: changing auto_off must (a) leave the other bank
    settings unchanged, (b) succeed verify-after-write."""
    sim.config.settings["02"] = "0D"  # hardness 13
    sim.config.settings["08"] = "00"  # units mL
    sim.config.settings["09"] = "02"  # language English
    sim.config.settings["13"] = "220168"  # auto_off 6h (3 bytes)
    c = _paired_with_profile(sim)
    try:
        # 30min via item name. Goes through bank write because arg 13
        # is in EF1091's <BANK CommandArgument="02080913">.
        result = run_named(
            c,
            "setting",
            ["auto_off", "30min"],
            timeout=3.0,
            allow_destructive=True,
        )
        assert "0x211E" in str(result.value)
    finally:
        c.close()
    # auto_off updated, others intact.
    assert sim.config.settings["13"] == "211E"
    assert sim.config.settings["02"] == "0D"
    assert sim.config.settings["08"] == "00"
    assert sim.config.settings["09"] == "02"


def test_setting_write_bank_handles_value_width_change(sim) -> None:
    """auto_off values are variable-length (0F=15min 1B; 211E=30min
    2B; 220168=6h 3B). The bulk-write block must carry the new
    value's actual width, and the dongle parses by leading byte."""
    sim.config.settings["13"] = "0F"  # 15min (1 byte)
    c = _paired_with_profile(sim)
    try:
        # Jump 15min → 6h (1B → 3B value).
        run_named(
            c,
            "setting",
            ["auto_off", "6h"],
            timeout=3.0,
            allow_destructive=True,
        )
    finally:
        c.close()
    assert sim.config.settings["13"] == "220168"


def test_setting_write_individual_arg_keeps_individual_format(sim) -> None:
    """Non-bank args (brightness 0A, milk_rinsing 04, frother 62)
    still use the individual ``@TM:<arg>,<val>`` write form. The
    dongle ACKs with ``@tm:<arg>`` not ``@tm:00``, and the simulator
    stores the new value directly."""
    sim.config.settings["0A"] = "01"  # 10% brightness
    c = _paired_with_profile(sim)
    try:
        run_named(
            c,
            "setting",
            ["brightness", "50"],  # ITEM Name="50" Value="05"
            timeout=3.0,
            allow_destructive=True,
        )
    finally:
        c.close()
    assert sim.config.settings["0A"] == "05"


def test_setting_read_detects_bad_checksum_from_wire(sim) -> None:
    """If the dongle ever returns a body whose trailing two chars don't
    match ByteOperations.d, read_setting raises ValueError so the
    user sees the problem rather than a silently-corrupt value."""
    # Spoofed reply: 0D is the value but the trailing 00 is a wrong csum.
    sim.config.settings["02"] = "0D"
    # Override the simulator's reply path by writing a value that ends
    # in a known-bad sequence isn't possible — instead drive the client
    # method directly with a fake reply via monkey-patching `request`.
    from jura_connect.client import JuraClient

    host, port = sim.address
    c = JuraClient(host, port=port, conn_id="cmd-tests", auth_hash="")
    c.pair(timeout=2.0)
    try:
        c.request = lambda *a, **kw: "@tm:02,0D00"  # type: ignore[method-assign]
        with pytest.raises(ValueError, match="checksum mismatch"):
            c.read_setting("02", timeout=1.0)
    finally:
        c.close()
