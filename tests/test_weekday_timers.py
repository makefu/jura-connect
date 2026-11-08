"""Weekday settings transactions against the real TCP simulator."""

from datetime import time, timezone

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
    client = JuraClient("127.0.0.1", profile=load_profile("EF566"))
    with pytest.raises(ValueError, match="weekday name"):
        client.set_weekday_timer(day, time(7))


@pytest.mark.parametrize(
    "value", [time(7, 20, 1), time(7, 20, 0, 1), time(7, 20, tzinfo=timezone.utc)]
)
def test_minute_precision_before_io(value):
    client = JuraClient("127.0.0.1", profile=load_profile("EF566"))
    with pytest.raises(ValueError):
        client.set_weekday_timer("monday", value)


def test_unsupported_profile_before_io():
    client = JuraClient("127.0.0.1", profile=load_profile("EF1091"))
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
        with pytest.raises(ValueError):
            client.set_weekday_timer("monday", time(7, 20))
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
