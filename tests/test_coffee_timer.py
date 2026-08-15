"""Coffee timer (`@TM:3C` schedule + `@TV:84` clock) end-to-end tests.

Everything here is APK-derived and verified against the in-tree
simulator only — no hardware was involved. See docs/PROTOCOL.md §5.12.
"""

from __future__ import annotations

import datetime

import pytest

from jura_connect.client import (
    COFFEE_TIMER_BLOB_HEX_LEN,
    COFFEE_TIMER_MAX_DELAY_SECONDS,
    COFFEE_TIMER_MIN_DELAY_SECONDS,
    CoffeeTimerSchedule,
    JuraClient,
    _settings_checksum,
    build_coffee_timer_command,
    encode_coffee_timer_clock,
)
from jura_connect.commands import (
    DESTRUCTIVE_PREFIXES,
    CommandError,
    DestructiveCommandError,
    run_named,
)
from jura_connect.profile import load_profile
from jura_connect.simulator import Simulator, SimulatorConfig


def _paired(sim, code: str | None = None) -> JuraClient:
    host, port = sim.address
    c = JuraClient(
        host,
        port=port,
        conn_id="coffee-timer-tests",
        auth_hash="",
        profile=load_profile(code) if code else None,
    )
    r = c.pair(timeout=2.0)
    assert r.state == "CORRECT"
    return c


@pytest.fixture
def timer_sim():
    """Simulator with the coffee-timer paths switched on."""
    s = Simulator(SimulatorConfig(status_interval=0.05, coffee_timer=True))
    s.start()
    try:
        yield s
    finally:
        s.stop()


# --------------------------------------------------------------------- #
# Blob construction (pure, no I/O)
# --------------------------------------------------------------------- #


def test_blob_is_right_padded_to_40_hex_chars() -> None:
    """The @TP: recipe blob (32 hex) is padded with "00" to 40 hex."""
    recipe = load_profile("EF1091").product_by_code[0x02].build_recipe_hex()
    assert len(recipe) == 32
    cmd = build_coffee_timer_command(recipe, 1800)
    body = cmd[len("@TM:3C,") :]
    blob = body[:COFFEE_TIMER_BLOB_HEX_LEN]
    assert COFFEE_TIMER_BLOB_HEX_LEN == 40
    assert blob == recipe + "00000000"


def test_blob_longer_than_40_hex_is_truncated() -> None:
    """StringsKt.take(40) in the APK truncates, it does not error."""
    cmd = build_coffee_timer_command("AB" * 24, 60)
    body = cmd[len("@TM:3C,") :]
    assert body[:COFFEE_TIMER_BLOB_HEX_LEN] == "AB" * 20


def test_command_carries_delay_and_settings_checksum() -> None:
    recipe = "02000809000002000100000000000000"
    cmd = build_coffee_timer_command(recipe, 1800)
    body = cmd[len("@TM:3C,") :]
    payload, checksum = body[:-2], body[-2:]
    assert payload == recipe + "00000000" + "0708"  # 1800 s = 0x0708
    assert checksum == _settings_checksum(f"3C,{payload}")
    assert cmd == f"@TM:3C,{payload}{checksum}"


def test_delay_is_a_16_bit_big_endian_field() -> None:
    """ExtensionsKt.e() is "%04X" of (value & 0xFFFF)."""
    recipe = "00" * 16
    assert build_coffee_timer_command(recipe, 60)[-6:-2] == "003C"
    assert build_coffee_timer_command(recipe, 57600)[-6:-2] == "E100"


def test_delay_out_of_range_is_refused() -> None:
    recipe = "00" * 16
    with pytest.raises(ValueError, match="delay"):
        build_coffee_timer_command(recipe, COFFEE_TIMER_MIN_DELAY_SECONDS - 1)
    with pytest.raises(ValueError, match="delay"):
        build_coffee_timer_command(recipe, COFFEE_TIMER_MAX_DELAY_SECONDS + 60)


# --------------------------------------------------------------------- #
# Clock encoding
# --------------------------------------------------------------------- #


def test_clock_is_ascii_hex_of_hh_mm() -> None:
    """ExtensionsKt.c() hex-encodes every character of "%02d:%02d"."""
    assert encode_coffee_timer_clock("07:30") == "30373A3330"
    assert bytes.fromhex(encode_coffee_timer_clock("07:30")).decode() == "07:30"


def test_clock_accepts_datetime_time_and_normalises() -> None:
    assert encode_coffee_timer_clock(datetime.time(7, 5)) == encode_coffee_timer_clock(
        "07:05"
    )
    assert encode_coffee_timer_clock("7:05") == encode_coffee_timer_clock("07:05")


def test_clock_rejects_garbage() -> None:
    # Minutes must be two digits: "7:5" is ambiguous (07:05 or 07:50?).
    for bad in ("", "07", "7:5", "25:00", "07:61", "half past seven"):
        with pytest.raises(ValueError):
            encode_coffee_timer_clock(bad)


# --------------------------------------------------------------------- #
# Delay derivation from a wall-clock target
# --------------------------------------------------------------------- #


def test_at_in_the_future_today(timer_sim) -> None:
    c = _paired(timer_sim, "EF1091")
    try:
        s = c.schedule_brew(
            "espresso", at="07:30", now=datetime.datetime(2026, 8, 14, 6, 0, 30)
        )
    finally:
        c.close()
    assert s.delay_seconds == 90 * 60
    assert s.ready_at == "07:30"


def test_at_already_passed_rolls_to_tomorrow(timer_sim) -> None:
    c = _paired(timer_sim, "EF1091")
    try:
        s = c.schedule_brew(
            "espresso", at="07:30", now=datetime.datetime(2026, 8, 14, 23, 0)
        )
    finally:
        c.close()
    # 23:00 -> 07:30 next day = 8 h 30 min.
    assert s.delay_seconds == (8 * 60 + 30) * 60


def test_at_beyond_the_16_hour_window_is_refused(timer_sim) -> None:
    c = _paired(timer_sim, "EF1091")
    try:
        with pytest.raises(ValueError, match="delay"):
            c.schedule_brew(
                "espresso", at="07:30", now=datetime.datetime(2026, 8, 14, 8, 0)
            )
    finally:
        c.close()


def test_delay_and_at_are_mutually_exclusive(timer_sim) -> None:
    c = _paired(timer_sim, "EF1091")
    try:
        with pytest.raises(ValueError, match="exactly one"):
            c.schedule_brew("espresso", at="07:30", delay=600)
        with pytest.raises(ValueError, match="exactly one"):
            c.schedule_brew("espresso")
    finally:
        c.close()


# --------------------------------------------------------------------- #
# Profile eligibility
# --------------------------------------------------------------------- #


def test_product_marked_ineligible_is_refused_before_the_wire(timer_sim) -> None:
    """EF1121 declares Coffeetimer="false" on Cappuccino."""
    prof = load_profile("EF1121")
    assert prof.product_by_code[0x04].coffee_timer is False
    c = _paired(timer_sim, "EF1121")
    try:
        with pytest.raises(ValueError, match="coffee timer"):
            c.schedule_brew("cappuccino", delay=1800)
    finally:
        c.close()
    assert timer_sim.config.coffee_timer_blob is None


def test_product_without_the_attribute_stays_eligible() -> None:
    """A missing Coffeetimer attribute defaults to true, like J.O.E."""
    assert load_profile("EF1121").product_by_code[0x02].coffee_timer is True
    assert load_profile("EF1091").product_by_code[0x02].coffee_timer is True


# --------------------------------------------------------------------- #
# Simulator end-to-end
# --------------------------------------------------------------------- #


def test_schedule_then_clock_round_trip(timer_sim) -> None:
    c = _paired(timer_sim, "EF1091")
    try:
        s = c.schedule_brew(
            "espresso",
            at="07:30",
            now=datetime.datetime(2026, 8, 14, 6, 0),
            ml=40,
        )
    finally:
        c.close()
    assert isinstance(s, CoffeeTimerSchedule)
    assert s.accepted is True
    assert s.reply.lower().startswith("@tm:")
    assert s.time_reply == "@tv:84"
    # The machine stored exactly what we computed.
    assert timer_sim.config.coffee_timer_blob == s.blob_hex
    assert timer_sim.config.coffee_timer_delay == s.delay_seconds == 90 * 60
    assert timer_sim.config.coffee_timer_clock == "07:30"
    # 40 ml water = 8 ticks at blob byte 3.
    assert s.recipe_hex[6:8] == "08"


def test_send_clock_alone(timer_sim) -> None:
    c = _paired(timer_sim, "EF1091")
    try:
        reply = c.send_coffee_timer_time("06:45")
    finally:
        c.close()
    assert reply == "@tv:84"
    assert timer_sim.config.coffee_timer_clock == "06:45"


def test_verbatim_blob_escape_hatch(timer_sim) -> None:
    c = _paired(timer_sim)  # no profile at all
    try:
        s = c.schedule_brew(recipe="28000709000001000109000000000000", delay=3600)
    finally:
        c.close()
    assert s.accepted is True
    assert s.product is None
    assert timer_sim.config.coffee_timer_blob == "28000709000001000109000000000000" + (
        "00" * 4
    )
    assert timer_sim.config.coffee_timer_delay == 3600


def test_machine_rejection_token_is_not_an_accept(sim_factory) -> None:
    """A firmware without a coffee timer answers the @tm:00 rejection."""
    s = sim_factory(coffee_timer=True, coffee_timer_reject=True)
    c = _paired(s, "EF1091")
    try:
        schedule = c.schedule_brew("espresso", delay=1800)
    finally:
        c.close()
    assert schedule.accepted is False
    assert schedule.reply == "@tm:00"
    # No clock frame is sent once the schedule was refused.
    assert schedule.time_command is None
    assert s.config.coffee_timer_blob is None


def test_bad_checksum_is_refused_by_the_machine(timer_sim) -> None:
    """The simulator verifies ByteOperations.d like the real dongle."""
    c = _paired(timer_sim, "EF1091")
    try:
        reply = c.request("@TM:3C," + "00" * 22 + "FF", match=r"^@(tm|an)", timeout=2.0)
    finally:
        c.close()
    assert reply == "@an:error"


# --------------------------------------------------------------------- #
# Destructive gating
# --------------------------------------------------------------------- #


def test_wire_prefix_is_registered_as_destructive() -> None:
    assert b"@TM:3C," in DESTRUCTIVE_PREFIXES
    # A bare @TM:3C *read* must not be swallowed by the byte-prefix match.
    assert not any(b"@TM:3C".startswith(p) for p in DESTRUCTIVE_PREFIXES)


def test_named_command_is_gated(sim) -> None:
    c = _paired(sim, "EF1091")
    try:
        with pytest.raises(DestructiveCommandError, match="unattended"):
            run_named(c, "coffee-timer", ["espresso", "30m"], timeout=1.0)
    finally:
        c.close()


def test_raw_payload_is_gated(sim) -> None:
    c = _paired(sim)
    try:
        with pytest.raises(DestructiveCommandError, match="@TM:3C,"):
            run_named(c, "raw", ["@TM:3C," + "00" * 23], timeout=1.0)
    finally:
        c.close()


def test_named_command_reaches_the_wire_with_the_flag(sim_factory) -> None:
    s = sim_factory(coffee_timer=True)
    c = _paired(s, "EF1091")
    try:
        result = run_named(
            c, "coffee-timer", ["espresso", "30m"], timeout=2.0, allow_destructive=True
        )
    finally:
        c.close()
    schedule = result.value
    assert isinstance(schedule, CoffeeTimerSchedule)
    assert schedule.accepted is True
    assert s.config.coffee_timer_delay == 1800
    assert "espresso" in result.format()
    assert result.to_dict()["value"]["delay_seconds"] == 1800  # type: ignore[index]


def test_named_command_accepts_a_wall_clock_target(sim_factory) -> None:
    s = sim_factory(coffee_timer=True)
    c = _paired(s, "EF1091")
    now = datetime.datetime.now()
    target = (now + datetime.timedelta(minutes=45)).strftime("%H:%M")
    try:
        result = run_named(
            c, "coffee-timer", ["espresso", target], timeout=2.0, allow_destructive=True
        )
    finally:
        c.close()
    # The minute may tick over between our target and the runner's own
    # clock read, so allow the one-minute-earlier outcome.
    assert result.value.delay_seconds in (45 * 60, 44 * 60)  # type: ignore[union-attr]
    assert result.value.ready_at.count(":") == 1  # type: ignore[union-attr]


def test_named_command_rejects_a_bad_when(sim) -> None:
    c = _paired(sim, "EF1091")
    try:
        with pytest.raises(CommandError, match="when"):
            run_named(
                c,
                "coffee-timer",
                ["espresso", "tomorrow"],
                timeout=1.0,
                allow_destructive=True,
            )
    finally:
        c.close()


def test_clock_command_is_not_gated(sim_factory) -> None:
    s = sim_factory(coffee_timer=True)
    c = _paired(s)
    try:
        result = run_named(c, "coffee-timer-time", ["06:45"], timeout=2.0)
    finally:
        c.close()
    assert result.value == "@tv:84"
    assert s.config.coffee_timer_clock == "06:45"
