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
        "cancel",
    ]:
        assert expected in names
    # Destructive operations are present *and* flagged with a danger string.
    for expected in [
        "clean",
        "descale",
        "filter-change",
        "cappu-clean",
        "cappu-rinse",
        "skip-quality-step",
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
        "products",
        "cancel",
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


def test_hex_body_pads_odd_length_to_even() -> None:
    """Regression: the J8 (SAS / EF1069) WiFi dongle emits @TF: status
    frames of 15 hex nibbles — the 8-byte baseline frame with the final
    low nibble of byte 7 truncated. _hex_body must pad a trailing 0 so
    bytes.fromhex() succeeds; before this the first data fetch crashed
    with "fromhex() arg must contain an even number of hexadecimal
    digits". See makefu/jura-connect-hass#3."""
    from jura_connect.client import _hex_body

    # 15 nibbles -> padded to 16 -> 8 bytes, last byte's low nibble = 0.
    data = _hex_body("@TF:000400000000020", "@TF:")
    assert data == bytes.fromhex("0004000000000200")
    assert len(data) == 8


# Live @TF: frames captured from a J8 (SAS / EF1069) WiFi Connect dongle
# by DaftHonk via `jura-connect ... --watch`. These are 15 nibbles long
# and decode against the EF1069 profile, whose XML maps the byte-7 bits
# (54 ml_oz_status, 56 coffee_eye_cup_detected) absent from the EF536
# baseline codebook. See makefu/jura-connect-hass#3.
@pytest.mark.parametrize(
    "frame,expected",
    [
        ("@TF:000400000000020", {"coffee_ready", "ml_oz_status"}),
        ("@TF:400000000000020", {"fill_water", "ml_oz_status"}),
        (
            "@TF:000400000000028",
            {"coffee_ready", "ml_oz_status", "coffee_eye_cup_detected"},
        ),
    ],
)
def test_j8_odd_length_status_frame_decodes(frame: str, expected: set[str]) -> None:
    from jura_connect.profile import load_profile

    st = MachineStatus.parse(frame, profile=load_profile("EF1069"))
    assert set(st.active_alerts) == expected


def test_j8_no_water_tank_frame_is_an_error() -> None:
    """The 'water tank removed' J8 capture sets bit 1 (fill_water),
    which EF1069 types as a blocking alert -> it must land in errors,
    not info, so the integration reports the machine as stuck."""
    from jura_connect.profile import load_profile

    st = MachineStatus.parse("@TF:400000000000020", profile=load_profile("EF1069"))
    assert "fill_water" in st.errors
    assert "ml_oz_status" in st.info


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
    ("descale", []),
    ("filter-change", []),
    ("cappu-clean", []),
    ("cappu-rinse", []),
    # Both forms of the quality-assistant skip: one step and the app's
    # 32×F "skip everything" argument. Both stay gated.
    ("skip-quality-step", []),
    ("skip-quality-step", ["all"]),
    ("restart", []),
    ("reset-daily-counters", []),
    ("power-off", []),
    # A full 32-hex @TP: blob reaches the wire without a profile.
    ("brew", ["28000709000001000109000000000000"]),
    ("set-pin", ["1234"]),
    ("set-ssid", ["mywifi"]),
    ("set-password", ["s3cret"]),
    ("set-name", ["Kaffeebert"]),
    # A full 34-hex PMode blob reaches the wire without a profile, the
    # same escape hatch `brew` has. See tests/test_pmode.py for the
    # profile-driven paths.
    ("pmode-set-product", ["0202080900000200000000000000000004"]),
    ("pmode-set-slot", ["3", "0202080900000200000000000000000004"]),
    # Interactive maintenance processes: starting one, confirming the
    # step it parks on, and advancing to the next one all drive a real
    # cycle. See docs/PROTOCOL.md §5.11.
    ("process-start", ["cleaning"]),
    ("process-run", ["cleaning"]),
    ("process-accept", []),
    ("process-accept", ["@TG:04"]),
    ("process-next", []),
    # Same verbatim-blob escape hatch, so no profile is needed.
    ("coffee-timer", ["28000709000001000109000000000000", "30m"]),
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
    # restart/power-off, the connection-closed sentinel. Commands whose
    # runner returns a structured result (coffee-timer) render the same
    # reply through format().
    rendered = result.format()
    assert "@an:error" in rendered or "connection closed" in rendered, (
        f"unexpected reply for {name!r}: {rendered!r}"
    )


def test_cancel_runs_without_the_destructive_gate(sim) -> None:
    """``@TG:FF`` is J.O.E.'s WifiCommandCancelProductStep — the "abort
    this brew" verb, not a reset. It must work without the gate and get
    the machine's ``@tg:FF`` acknowledgement back."""
    c = _paired(sim)
    try:
        result = run_named(c, "cancel", timeout=2.0)
    finally:
        c.close()
    assert isinstance(result.value, str)
    assert result.value.lower().startswith("@tg:ff")


def test_cancel_prefix_is_not_in_the_destructive_set(sim) -> None:
    """The reclassification must also free the raw escape hatch, which
    gates on DESTRUCTIVE_PREFIXES rather than on the command name."""
    assert b"@TG:FF" not in commands.DESTRUCTIVE_PREFIXES
    c = _paired(sim)
    try:
        result = run_named(c, "raw", ["@TG:FF"], timeout=2.0)
    finally:
        c.close()
    assert result.value.lower().startswith("@tg:ff")  # type: ignore[union-attr]


def test_skip_quality_step_sends_both_wire_forms(sim) -> None:
    """Bare ``@TG:7E`` skips one quality-assistant step, the 32×F
    argument skips all of them. Both must reach the wire only with the
    gate, and the simulator refuses both."""
    c = _paired(sim)
    try:
        one = run_named(c, "skip-quality-step", timeout=2.0, allow_destructive=True)
        every = run_named(
            c, "skip-quality-step", ["all"], timeout=2.0, allow_destructive=True
        )
    finally:
        c.close()
    assert one.value == "@an:error"
    assert every.value == "@an:error"
    sent = [f.decode("ascii", errors="replace") for f in sim.sent_commands]
    assert "@TG:7E" in sent
    assert "@TG:7E," + "F" * 32 in sent


def test_skip_quality_step_rejects_unknown_scope(sim) -> None:
    c = _paired(sim)
    try:
        with pytest.raises(CommandError, match="scope"):
            run_named(
                c, "skip-quality-step", ["some"], timeout=1.0, allow_destructive=True
            )
    finally:
        c.close()


def test_skip_quality_step_danger_states_both_readings() -> None:
    """AGENTS.md records a real machine whose maintenance counters were
    zeroed by @TG:7E while the app calls it a quality-assistant skip.
    The danger string must not pick a side and hide the other."""
    danger = commands.get_command("skip-quality-step").danger or ""
    assert "quality" in danger.lower()
    assert "counter" in danger.lower()
    assert "irreversib" in danger.lower()


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


# ---- brew: recipe-blob building --------------------------------------


def test_brew_by_name_builds_blob_and_reaches_wire(sim) -> None:
    """Named product + profile -> 16-byte blob on the wire. The
    simulator's @an:error refusal is the proof of wire contact."""
    c = _paired_with_profile(sim)
    try:
        result = run_named(
            c,
            "brew",
            ["hotwater", "water=220"],
            timeout=2.0,
            allow_destructive=True,
        )
    finally:
        c.close()
    assert result.value.startswith("@an:error")  # type: ignore[union-attr]


def test_brew_full_blob_passthrough(sim) -> None:
    """A full recipe blob is sent verbatim, profile or not."""
    c = _paired(sim)
    try:
        result = run_named(
            c,
            "brew",
            ["28000709000001000109000000000000"],
            timeout=2.0,
            allow_destructive=True,
        )
    finally:
        c.close()
    assert result.value.startswith("@an:error")  # type: ignore[union-attr]


def test_brew_by_name_without_profile_is_refused_client_side(sim) -> None:
    c = _paired(sim)
    try:
        with pytest.raises(CommandError, match="machine profile"):
            run_named(c, "brew", ["espresso"], timeout=1.0, allow_destructive=True)
    finally:
        c.close()


def test_brew_validates_overrides_before_wire(sim) -> None:
    c = _paired_with_profile(sim)
    try:
        with pytest.raises(CommandError, match="outside"):
            run_named(
                c,
                "brew",
                ["hotwater", "water=9999"],
                timeout=1.0,
                allow_destructive=True,
            )
        with pytest.raises(CommandError, match="unknown parameter"):
            run_named(
                c,
                "brew",
                ["hotwater", "beans=42"],
                timeout=1.0,
                allow_destructive=True,
            )
        with pytest.raises(CommandError, match="param=value"):
            run_named(
                c,
                "brew",
                ["hotwater", "220"],
                timeout=1.0,
                allow_destructive=True,
            )
        with pytest.raises(CommandError, match="cannot be combined"):
            run_named(
                c,
                "brew",
                ["28000709000001000109000000000000", "water=220"],
                timeout=1.0,
                allow_destructive=True,
            )
    finally:
        c.close()


def test_brew_unknown_and_ambiguous_product_names(sim) -> None:
    c = _paired_with_profile(sim)
    try:
        with pytest.raises(CommandError, match="not known"):
            run_named(c, "brew", ["americano"], timeout=1.0, allow_destructive=True)
        # 'espresso' prefix-matches espresso, espresso_macchiato,
        # espresso_doppio… — but the exact name must win.
        result = run_named(c, "brew", ["espresso"], timeout=2.0, allow_destructive=True)
        assert result.value.startswith("@an:error")  # type: ignore[union-attr]
        with pytest.raises(CommandError, match="ambiguous"):
            run_named(c, "brew", ["esp"], timeout=1.0, allow_destructive=True)
    finally:
        c.close()


def test_client_brew_api_builds_and_sends(sim) -> None:
    """The library-level JuraClient.brew() mirrors the CLI path."""
    c = _paired_with_profile(sim)
    try:
        reply = c.brew("hotwater", ml=100, temperature="high")
    finally:
        c.close()
    assert reply.startswith("@an:error")  # simulator refuses @TP:


def test_brew_variadic_overrides_uncapped(sim) -> None:
    """The override arg is truly variadic — more than the old 5-cap
    param=value pairs parse fine (they just validate/refuse per-kind)."""
    spec = commands.get_command("brew")
    # One product + one real variadic override argument, not a fake cap.
    assert len(spec.arguments) == 2
    assert spec.arguments[1].variadic is True
    c = _paired_with_profile(sim)
    try:
        # Multiple overrides in one call reach the wire (validated first).
        result = run_named(
            c,
            "brew",
            ["espresso", "strength", "water=45"],
            timeout=1.0,
            allow_destructive=True,
        )
    except CommandError as exc:
        # 'strength' without '=' must be a clear param=value error, not a
        # silent drop or an arg-count error.
        assert "param=value" in str(exc)
    else:  # pragma: no cover - defensive
        result  # noqa: B018
    finally:
        c.close()


def test_brew_accept_semantics_tp_vs_tp00() -> None:
    """The machine returns bare `@tp` on accept but `@tp:00` when it
    rejects/ignores the blob (e.g. the old FF-padded layout). `@tp:00`
    must NOT count as accepted."""
    from jura_connect.client import _is_brew_accept

    assert _is_brew_accept("@tp") is True
    assert _is_brew_accept("@TP") is True
    assert _is_brew_accept("@tp:00") is False
    assert _is_brew_accept("@an:error") is False


def test_brew_short_hex_name_is_not_a_verbatim_blob(sim) -> None:
    """A short all-hex token ('dec', 'face') is a name, not a raw blob:
    only >= 32 hex chars are sent verbatim. Without a profile it must be
    refused client-side rather than shipped as a bare @TP: payload."""
    c = _paired(sim)  # no profile
    try:
        with pytest.raises(CommandError, match="machine profile"):
            run_named(c, "brew", ["face"], timeout=1.0, allow_destructive=True)
        # 30 hex chars (< 32) is still treated as a name/code, not a blob.
        with pytest.raises(CommandError, match="machine profile"):
            run_named(c, "brew", ["0D" * 15], timeout=1.0, allow_destructive=True)
    finally:
        c.close()


def test_brew_bypass_and_milk_overrides_reach_wire(sim) -> None:
    """Bypass, milk-foam and milk-break overrides are accepted via the
    CLI param=value keys, encoded onto the right blob byte, and reach
    the wire (NOT live-verified — see build_recipe_hex caveat).

    Asserts the blob byte through the CLI key->kind mapping the runner
    uses, then confirms the same invocation reaches the wire."""
    from jura_connect.commands import _BREW_KEY_TO_KIND
    from jura_connect.profile import load_profile

    prof = load_profile("EF538")
    # Cafe Barista (0x28) carries BYPASS (F10 -> byte 9); Latte
    # Macchiato (0x07) carries MILK_FOAM_AMOUNT (F6 -> byte 5) and
    # MILK_BREAK (F11 -> byte 10).
    barista = prof.product_by_code[0x28]
    latte = prof.product_by_code[0x07]
    assert barista.param("bypass") is not None
    assert latte.param("milk_foam_amount") is not None
    assert latte.param("milk_break") is not None

    def _blob_via_cli_keys(product, **cli_kwargs):
        overrides = {_BREW_KEY_TO_KIND[k]: v for k, v in cli_kwargs.items()}
        return product.build_recipe_hex(overrides)

    # bypass=30 ml -> 6 ticks (0x06) at byte 9.
    assert _blob_via_cli_keys(barista, bypass=30)[9 * 2 : 9 * 2 + 2] == "06"
    # milk (foam) = 30 s -> 0x1E at byte 5; milk_break = 45 s -> 0x2D at byte 10.
    latte_blob = _blob_via_cli_keys(latte, milk=30, milk_break=45)
    assert latte_blob[5 * 2 : 5 * 2 + 2] == "1E"
    assert latte_blob[10 * 2 : 10 * 2 + 2] == "2D"

    c = _paired_with_profile(sim)
    try:
        bypass_reply = run_named(
            c,
            "brew",
            ["cafe_barista", "bypass=30"],
            timeout=1.0,
            allow_destructive=True,
        )
        milk_reply = run_named(
            c,
            "brew",
            ["latte_macchiato", "milk=30", "milk_break=45"],
            timeout=1.0,
            allow_destructive=True,
        )
    finally:
        c.close()
    assert bypass_reply.value.startswith("@an:error")  # type: ignore[union-attr]
    assert milk_reply.value.startswith("@an:error")  # type: ignore[union-attr]


# ---- products: brew-input discovery ----------------------------------


def test_products_lists_brewable_products_with_allowed_values(sim) -> None:
    """`products` reads the loaded profile (no wire I/O) and lists each
    brewable product's resolvable name + allowed param values. The shown
    name must be exactly what `resolve_product`/`brew` accepts."""
    from jura_connect.commands import ParamInfo, ProductCatalogue, ProductInfo

    assert not commands.get_command("products").destructive
    c = _paired_with_profile(sim, "EF538")
    try:
        result = run_named(c, "products", [], timeout=1.0)
        cat = result.value
        assert isinstance(cat, ProductCatalogue)
        assert cat.machine_code == "EF538"
        latte = next(p for p in cat.products if p.name == "latte_macchiato")
        assert isinstance(latte, ProductInfo)
        # The listed name resolves to the same product `brew` would use.
        assert c.resolve_product(latte.name).code == latte.code == 0x07
        by_kind = {pp.kind: pp for pp in latte.params}
        assert {
            "coffee_strength",
            "water_amount",
            "temperature",
            "milk_foam_amount",
            "milk_break",
        } <= set(by_kind)
        # Enumerated param exposes ordered choices + friendly CLI key.
        strength = by_kind["coffee_strength"]
        assert isinstance(strength, ParamInfo)
        assert strength.choices  # (name, value_hex) pairs
        assert "strength" in strength.cli_keys
        assert strength.live_verified is True
        # Ranged/ml param: min–max, step, unit, live-verified.
        water = by_kind["water_amount"]
        assert (water.minimum, water.maximum, water.step, water.unit) == (
            25,
            240,
            5,
            "ml",
        )
        assert "water" in water.cli_keys and "ml" in water.cli_keys
        assert water.live_verified is True
        # Milk foam: seconds, live-verified on a Z10 (EA)/EF545
        # (3 s foam physically poured from blob byte 5). Milk break
        # remains unverified.
        milk = by_kind["milk_foam_amount"]
        assert milk.unit == "s"
        assert milk.live_verified is True
        assert by_kind["milk_break"].live_verified is False
        # format() names the product; the caveat is surfaced.
        text = cat.format()
        assert "latte_macchiato  (0x07)" in text
        assert "not live-verified" in text
        # to_dict() is structured and matches the resolvable name.
        d = cat.to_dict()
        assert d["machine_code"] == "EF538"
        assert any(p["name"] == "latte_macchiato" for p in d["products"])
        # Inactive products (Powderproduct 0x0F, Active="false") excluded.
        assert all(p.code != 0x0F for p in cat.products)
    finally:
        c.close()


def test_products_without_profile_is_refused(sim) -> None:
    c = _paired(sim)  # no profile loaded
    try:
        with pytest.raises(CommandError, match="machine profile"):
            run_named(c, "products", [], timeout=1.0)
    finally:
        c.close()


def test_products_renders_non_overridable_param_read_only(sim) -> None:
    """A param with no `brew` CLI alias (grinder_ratio on the EF0000)
    must render under its kind name with a read-only annotation — never
    a blank key column — and expose settable=False in to_dict()."""
    c = _paired_with_profile(sim, "EF0000")
    try:
        cat = run_named(c, "products", [], timeout=1.0).value
        espresso = next(p for p in cat.products if p.name == "espresso")  # 0x02
        ratio = next(pp for pp in espresso.params if pp.kind == "grinder_ratio")
        # No CLI alias -> not settable via `brew`.
        assert ratio.cli_keys == ()
        assert ratio.settable is False
        # The rendered row uses the kind name, not a blank column, and
        # is annotated read-only.
        row = ratio.format()
        assert row.split("default")[0].strip() == "grinder_ratio"
        assert "read-only: not settable via 'brew'" in row
        assert not row.startswith("     default")  # no empty key column
        # Whole-product format shows it too.
        assert "grinder_ratio" in espresso.format()
        assert "read-only" in espresso.format()
        # Structured output carries settable=False for this param.
        d = espresso.to_dict()
        entry = next(pp for pp in d["params"] if pp["kind"] == "grinder_ratio")
        assert entry["settable"] is False
        assert entry["cli_keys"] == []
        # A settable param (strength) still reports settable=True.
        strength = next(pp for pp in espresso.params if pp.kind == "coffee_strength")
        assert strength.settable is True
        assert strength.to_dict()["settable"] is True
    finally:
        c.close()


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
