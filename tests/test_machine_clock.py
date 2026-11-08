"""EF566 clock protocol against the real TCP simulator; no machine writes."""

from datetime import date, time, timezone

import pytest

from jura_connect import JuraClient, load_profile, run_named
from jura_connect.clock import TIMER_ADDRESSES, parse_clock, parse_date, parse_timer
from jura_connect.commands import DestructiveCommandError

RAW = {"05": "220812", "06": "231A0B06", **dict.fromkeys(TIMER_ADDRESSES, "2480008000")}


def paired(sim):
    client = JuraClient(
        *sim.address, conn_id="clock-tests", profile=load_profile("EF566")
    )
    client.pair(timeout=2)
    return client


def test_clock_roundtrip_preserves_date_and_all_timers(sim_factory):
    sim = sim_factory(allow_setting_writes=True, require_user_accept=False)
    sim.config.settings.update(RAW)
    client = paired(sim)
    try:
        assert client.read_clock() == time(8, 18)
        assert client.read_clock_date() == date(2026, 11, 6)
        assert client.read_clock_timers() == ((None, None),) * 8
        assert client.set_clock(time(7, 20)) == "@tm:05"
        assert client.read_clock() == time(7, 20)
        assert {key: sim.config.settings[key] for key in RAW} == {**RAW, "05": "220714"}
        assert not sim.config.screen_locked
        writes = [
            c.decode().strip()
            for c in sim.sent_commands
            if c.startswith(b"@TM:") and b"," in c
        ]
        assert writes == ["@TM:05,2207143E"]
    finally:
        client.close()


@pytest.mark.parametrize(
    "value",
    [time(7, 20, 1), time(7, 20, 0, 1), time(7, 20, tzinfo=timezone.utc), "07:20"],
)
def test_invalid_time_never_connects(value):
    client = JuraClient("127.0.0.1", profile=load_profile("EF566"))
    with pytest.raises(ValueError, match="hours and minutes"):
        client.set_clock(value)


@pytest.mark.parametrize("model", [None, "EF1091", "EF566V2"])
def test_other_profiles_never_connect(model):
    client = JuraClient("127.0.0.1", profile=load_profile(model) if model else None)
    for op in (
        client.read_clock,
        client.read_clock_date,
        client.read_clock_timers,
        lambda: client.set_clock(time(7, 20)),
    ):
        with pytest.raises(ValueError, match="only verified"):
            op()


@pytest.mark.parametrize(
    "raw", ["", "22071400", "22 714", "230714", "221800", "22073C"]
)
def test_invalid_clock_payloads(raw):
    with pytest.raises(ValueError):
        parse_clock(raw)


@pytest.mark.parametrize("raw", ["231A021D", "23640B06", "221A0B06", "23 1A0B06"])
def test_invalid_date_payloads(raw):
    with pytest.raises(ValueError):
        parse_date(raw)


def test_timer_values_are_typed_and_strict():
    assert parse_timer("24061E1405") == (time(6, 30), time(20, 5))
    for raw in ("2480018000", "2418008000", "24063C8000", "0400050B01"):
        with pytest.raises(ValueError):
            parse_timer(raw)


@pytest.mark.parametrize(
    "fault,kwargs",
    [
        ("lock", {"keypad_lock_reply": "@an:error"}),
        ("write", {"setting_write_reply": "@tm:00"}),
        ("unlock", {"keypad_unlock_reply": "@an:error"}),
    ],
)
def test_failed_transactions_do_not_retry_and_attempt_unlock(
    sim_factory, fault, kwargs
):
    sim = sim_factory(allow_setting_writes=True, require_user_accept=False, **kwargs)
    client = paired(sim)
    try:
        with pytest.raises(ValueError):
            client.set_clock(time(7, 20))
        cmds = [
            c.decode().strip()
            for c in sim.sent_commands
            if c.startswith((b"@TS:", b"@TM:"))
        ]
        assert cmds[0] == "@TS:01" and cmds[-1] == "@TS:00"
        assert len([c for c in cmds if c.startswith("@TM:05,")]) == (
            0 if fault == "lock" else 1
        )
    finally:
        client.close()


def test_checksum_error_and_delayed_application_are_not_silent_success(sim_factory):
    sim = sim_factory(
        allow_setting_writes=True,
        require_user_accept=False,
        setting_apply_after_reads=1,
    )
    sim.config.settings.update(RAW)
    client = paired(sim)
    try:
        client.set_clock(time(7, 20))
        assert client.read_clock() == time(8, 18)  # ACK is not application.
        assert client.read_clock() == time(7, 20)
        sim.config.setting_corrupt_checksum = True
        with pytest.raises(ValueError, match="checksum"):
            client.read_clock()
    finally:
        client.close()


def test_named_and_raw_writes_require_the_gate(sim_factory):
    sim = sim_factory(allow_setting_writes=True, require_user_accept=False)
    sim.config.settings.update(RAW)
    client = paired(sim)
    try:
        assert run_named(client, "machine-clock").value == "08:18"
        for name, args in (
            ("set-machine-clock", ["07:20"]),
            ("raw", ["@TM:05,2207143E"]),
        ):
            with pytest.raises(DestructiveCommandError):
                run_named(client, name, args)
        assert (
            run_named(
                client, "set-machine-clock", ["07:20"], allow_destructive=True
            ).value
            == "@tm:05"
        )
    finally:
        client.close()
