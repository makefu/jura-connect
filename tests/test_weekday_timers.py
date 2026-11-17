"""Weekday settings transactions against the real TCP simulator."""

from datetime import datetime, time, timezone

import pytest

from jura_connect import JuraClient, load_profile, run_named
from jura_connect.commands import DestructiveCommandError
from jura_connect.timers import TIMER_SLOTS, TimerSlot

RAW = dict.fromkeys(TIMER_SLOTS, "2480008000") | {
    "14": "24061E1405",
    "05": "220812",
    "06": "231A0B06",
}


def paired(sim):
    client = JuraClient(
        *sim.address, conn_id="timer-tests", profile=load_profile("EF566")
    )
    client.pair(timeout=2)
    return client


def test_timer_roundtrip_preserves_switch_off_other_days_clock_and_date(sim_factory):
    sim = sim_factory(allow_setting_writes=True, require_user_accept=False)
    sim.config.settings.update(RAW)
    client = paired(sim)
    try:
        result = client.set_weekday_timer("monday", time(6, 35))
        assert result.previous_on == time(6, 30)
        assert result.slots["14"] == TimerSlot(time(6, 35), time(20, 5))
        assert {key: sim.config.settings[key] for key in RAW} == {
            **RAW,
            "14": "2406231405",
        }
        assert result.to_dict()["weekdays"]["monday"] == {
            "on": "06:35:00",
            "off": "20:05:00",
        }
        assert "monday:" in result.format()
        client.set_weekday_timer("monday", None)
        assert sim.config.settings["14"] == "2480001405"
        client.set_weekday_timer("monday", time(6, 40))
        assert sim.config.settings["14"] == "2406281405"
        count = len(sim.sent_commands)
        client.set_weekday_timer("monday", time(6, 40))
        assert not any(c.startswith(b"@TS:") for c in sim.sent_commands[count:])
        assert not sim.config.screen_locked
    finally:
        client.close()


@pytest.mark.parametrize("day", ["1B", "14", "05", "all_days", "Monday", ""])
def test_only_named_weekdays_are_writable(day):
    client = JuraClient("127.0.0.1", port=1, profile=load_profile("EF566"))
    with pytest.raises(ValueError, match="weekday name"):
        client.set_weekday_timer(day, time(7))


@pytest.mark.parametrize(
    "value",
    [
        time(7, 20, 1),
        time(7, 20, 0, 1),
        time(7, 20, tzinfo=timezone.utc),
        datetime(2026, 11, 17, 7, 20),
        "07:20",
        720,
    ],
)
def test_minute_precision_before_io(value):
    client = JuraClient("127.0.0.1", port=1, profile=load_profile("EF566"))
    with pytest.raises(ValueError):
        client.set_weekday_timer("monday", value)


def test_unsupported_profile_before_io():
    client = JuraClient("127.0.0.1", port=1, profile=load_profile("EF1091"))
    with pytest.raises(ValueError, match="only verified"):
        client.read_weekday_timers()
    with pytest.raises(ValueError, match="only verified"):
        client.set_weekday_timer("monday", None)


@pytest.mark.parametrize(
    "fault,kwargs",
    [
        ("lock", {"keypad_lock_reply": "@an:error"}),
        ("write", {"setting_write_reply": "@tm:00"}),
        ("unlock", {"keypad_unlock_reply": "@an:error"}),
        ("collateral", {"setting_collateral": {"15": "2407328000"}}),
    ],
)
def test_failure_never_retries_a_write(sim_factory, fault, kwargs):
    sim = sim_factory(allow_setting_writes=True, require_user_accept=False, **kwargs)
    sim.config.settings.update(RAW)
    client = paired(sim)
    try:
        with pytest.raises(ValueError) as exc:
            client.set_weekday_timer("monday", time(7, 20))
        if fault == "collateral":
            assert "block differs" in str(exc.value) and "tuesday (15)" in str(
                exc.value
            )
            assert "expected" in str(exc.value) and "got" in str(exc.value)
            assert sim.config.settings["15"] == "2407328000"
        cmds = [c.decode().strip() for c in sim.sent_commands]
        writes = [c for c in cmds if c.startswith("@TM:") and "," in c]
        assert len(writes) == (0 if fault == "lock" else 1)
        assert "@TS:00" in cmds
    finally:
        client.close()


def test_all_days_guard_and_invalid_readback(sim_factory):
    sim = sim_factory(allow_setting_writes=True, require_user_accept=False)
    sim.config.settings.update({**RAW, "1B": "2407008000"})
    client = paired(sim)
    try:
        with pytest.raises(ValueError, match="all-days"):
            client.set_weekday_timer("monday", time(7, 20))
        assert not any(c.startswith(b"@TS:") for c in sim.sent_commands)
        sim.config.setting_corrupt_checksum = True
        with pytest.raises(ValueError, match="checksum"):
            client.read_weekday_timers()
    finally:
        client.close()


def test_delayed_readback_after_unlock(sim_factory):
    sim = sim_factory(
        allow_setting_writes=True,
        require_user_accept=False,
        setting_apply_after_reads=1,
    )
    sim.config.settings.update(RAW)
    client = paired(sim)
    try:
        result = client.set_weekday_timer("monday", time(7, 20))
        assert result.slots["14"].on == time(7, 20)
        writes = [c for c in sim.sent_commands if c.startswith(b"@TM:14,")]
        assert len(writes) == 1 and not sim.config.screen_locked
    finally:
        client.close()


def test_named_and_raw_gates(sim_factory):
    sim = sim_factory(allow_setting_writes=True, require_user_accept=False)
    sim.config.settings.update(RAW)
    client = paired(sim)
    try:
        assert (
            run_named(client, "weekday-timers").to_dict()["value"]["weekdays"][
                "monday"
            ]["on"]
            == "06:30:00"
        )
        for name, args in (
            ("set-weekday-timer", ["monday", "07:20"]),
            ("raw", ["@TM:14,240714800066"]),
        ):
            with pytest.raises(DestructiveCommandError):
                run_named(client, name, args)
        result = run_named(
            client, "set-weekday-timer", ["monday", "07:20"], allow_destructive=True
        )
        assert result.value.slots["14"].on == time(7, 20)
    finally:
        client.close()


@pytest.mark.parametrize(
    "day,slot",
    [
        ("monday", "14"),
        ("tuesday", "15"),
        ("wednesday", "16"),
        ("thursday", "17"),
        ("friday", "18"),
        ("saturday", "19"),
        ("sunday", "1A"),
    ],
)
def test_each_weekday_writes_its_own_literal_slot_and_preserves_siblings(
    sim_factory, day, slot
):
    sim = sim_factory(allow_setting_writes=True, require_user_accept=False)
    initial = {
        key: "2480008000" for key in ("14", "15", "16", "17", "18", "19", "1A", "1B")
    }
    sim.config.settings.update(initial)
    client = paired(sim)
    try:
        result = client.set_weekday_timer(day, time(7, 20))
        assert result.slots[slot] == TimerSlot(time(7, 20), None)
        assert {key: sim.config.settings[key] for key in initial} == {
            **initial,
            slot: "2407148000",
        }
        assert client.read_weekday_timers()[slot] == TimerSlot(time(7, 20), None)
        assert (
            len([c for c in sim.sent_commands if c.startswith(f"@TM:{slot},".encode())])
            == 1
        )
    finally:
        client.close()


def test_unsupported_client_cannot_use_armed_simulator(sim_factory):
    sim = sim_factory(allow_setting_writes=True, require_user_accept=False)
    client = JuraClient(*sim.address, profile=load_profile("EF1091"))
    for operation in (
        client.read_weekday_timers,
        lambda: client.set_weekday_timer("monday", time(7, 20)),
    ):
        with pytest.raises(ValueError, match="only verified"):
            operation()
    assert not sim.sent_commands and not sim.handshakes


def test_timer_guard_cancel_and_unlock_failure_preserve_caller_error(sim_factory):
    sim = sim_factory(
        allow_setting_writes=True, require_user_accept=False, keypad_unlock_reply=None
    )
    sim.config.settings.update(RAW)
    client = paired(sim)
    cancelled = RuntimeError("cancelled timer change")

    def guard():
        assert sim.config.screen_locked
        raise cancelled

    try:
        with pytest.raises(RuntimeError) as exc:
            client.set_weekday_timer(
                "monday", time(7, 20), timeout=0.1, before_write=guard
            )
        assert exc.value is cancelled
        assert any("unlock also failed" in note for note in exc.value.__notes__)
        assert not any(c.startswith(b"@TM:14,") for c in sim.sent_commands)
    finally:
        client.close()


def test_timer_write_timeout_is_preserved_with_unlock_timeout(sim_factory):
    sim = sim_factory(
        allow_setting_writes=True,
        require_user_accept=False,
        setting_write_timeout=True,
        keypad_unlock_reply=None,
    )
    sim.config.settings.update(RAW)
    client = paired(sim)
    try:
        with pytest.raises(TimeoutError) as exc:
            client.set_weekday_timer("monday", time(7, 20), timeout=0.1)
        assert any("unlock also failed" in note for note in exc.value.__notes__)
        assert sim.config.settings["14"] == "2407141405"
        assert len([c for c in sim.sent_commands if c.startswith(b"@TM:14,")]) == 1
    finally:
        client.close()


def test_poll_exhaustion_retains_last_observation_without_retry(sim_factory):
    from jura_connect.timers import TimerVerificationError

    sim = sim_factory(
        allow_setting_writes=True,
        require_user_accept=False,
        setting_apply_after_reads=99,
    )
    sim.config.settings.update(RAW)
    client = paired(sim)
    try:
        with pytest.raises(TimerVerificationError, match="did not confirm") as exc:
            client.set_weekday_timer("monday", time(7, 20))
        assert exc.value.last_observed == TimerSlot(time(6, 30), time(20, 5))
        assert len([c for c in sim.sent_commands if c.startswith(b"@TM:14,")]) == 1
        assert sim.config.settings["14"] == RAW["14"]
    finally:
        client.close()


def test_total_deadline_bounds_polling_and_never_retries(sim_factory):
    import time as wall_time

    sim = sim_factory(
        allow_setting_writes=True,
        require_user_accept=False,
        setting_apply_after_reads=99,
    )
    sim.config.settings.update(RAW)
    client = paired(sim)
    start = wall_time.monotonic()
    try:
        with pytest.raises(TimeoutError, match="total deadline") as exc:
            client.set_weekday_timer(
                "monday", time(7, 20), timeout=0.2, total_timeout=3
            )
        assert wall_time.monotonic() - start < 5
        assert any("Last target slot 14" in note for note in exc.value.__notes__)
        assert len([c for c in sim.sent_commands if c.startswith(b"@TM:14,")]) == 1
        assert not sim.config.screen_locked
    finally:
        client.close()


@pytest.mark.parametrize(
    "payload,pair",
    [
        ("2407008000", "switch-on"),
        ("2480001405", "switch-off"),
        ("2407001405", "switch-on, switch-off"),
    ],
)
def test_all_days_guard_names_every_configured_pair(sim_factory, payload, pair):
    sim = sim_factory(allow_setting_writes=True, require_user_accept=False)
    sim.config.settings.update({**RAW, "1B": payload})
    client = paired(sim)
    try:
        with pytest.raises(ValueError, match="configured all-days") as exc:
            client.set_weekday_timer("monday", None)
        assert pair in str(exc.value)
        assert not any(c.startswith(b"@TS:") for c in sim.sent_commands)
        result = run_named(client, "weekday-timers")
        assert "all_days:" in result.format()
        assert "previous_on" not in result.to_dict()["value"]
    finally:
        client.close()


def test_collateral_is_applied_atomically_with_delayed_value(sim_factory):
    sim = sim_factory(
        allow_setting_writes=True,
        require_user_accept=False,
        setting_apply_after_reads=1,
        setting_collateral={"02": "02"},
    )
    sim.config.settings.update(RAW)
    sim.config.settings["02"] = "01"
    client = paired(sim)
    try:
        client.set_clock(time(7, 20))
        assert sim.config.settings["02"] == "01"
        assert client.read_clock() == time(8, 18)
        assert sim.config.settings["02"] == "01"
        assert client.read_clock() == time(7, 20)
        assert sim.config.settings["02"] == "02"
        assert {slot: sim.config.settings[slot] for slot in (*TIMER_SLOTS, "06")} == {
            slot: RAW[slot] for slot in (*TIMER_SLOTS, "06")
        }
    finally:
        client.close()


def test_invalid_slot_diagnostic_includes_wire_address_and_payload(sim_factory):
    sim = sim_factory(require_user_accept=False)
    sim.config.settings.update({**RAW, "15": "2480058000"})
    client = paired(sim)
    try:
        with pytest.raises(ValueError, match="slot 15.*8005"):
            client.read_weekday_timers()
    finally:
        client.close()


def test_timer_gate_registry_tracks_the_entire_slot_catalog():
    from jura_connect.commands import DESTRUCTIVE_PREFIXES, match_destructive

    for slot in TIMER_SLOTS:
        prefix = f"@TM:{slot},"
        assert prefix.encode() in DESTRUCTIVE_PREFIXES
        assert match_destructive(prefix.lower() + "240714800066") == prefix
        assert match_destructive(f"@TM:{slot}") is None
        assert match_destructive(f"@tm:{slot.lower()}") is None


def test_explicit_rejection_never_applies_primary_or_collateral(sim_factory):
    from jura_connect.settings import SettingRejectedError

    sim = sim_factory(
        allow_setting_writes=True,
        require_user_accept=False,
        setting_write_reply="@an:error",
        setting_collateral={"15": "2407328000"},
    )
    sim.config.settings.update(RAW)
    client = paired(sim)
    try:
        with pytest.raises(SettingRejectedError):
            client.set_weekday_timer("monday", time(7, 20))
        assert {slot: sim.config.settings[slot] for slot in RAW} == RAW
        assert len([c for c in sim.sent_commands if c.startswith(b"@TM:14,")]) == 1
    finally:
        client.close()


@pytest.mark.parametrize("budget", [0, -1, float("nan"), float("inf")])
def test_invalid_total_budget_is_rejected_before_io(budget):
    client = JuraClient("127.0.0.1", port=1, profile=load_profile("EF566"))
    with pytest.raises(ValueError, match="finite and positive"):
        client.set_weekday_timer("monday", time(7, 20), total_timeout=budget)
