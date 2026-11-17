"""EF566 clock protocol against the real TCP simulator; no machine writes."""

from datetime import date, datetime, time, timezone

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


def test_prewrite_guard_runs_after_lock_and_before_setting_write(sim_factory):
    sim = sim_factory(allow_setting_writes=True, require_user_accept=False)
    client = paired(sim)
    observations = []

    def before_write():
        observations.append(sim.config.screen_locked)
        assert not any(command.startswith(b"@TM:05,") for command in sim.sent_commands)

    try:
        assert client.set_clock(time(7, 20), before_write=before_write) == "@tm:05"
        assert observations == [True]
        assert not sim.config.screen_locked
    finally:
        client.close()


def test_rejected_prewrite_guard_never_writes_and_still_releases_keys(sim_factory):
    sim = sim_factory(allow_setting_writes=True, require_user_accept=False)
    client = paired(sim)

    def before_write():
        raise ValueError("The caller cancelled the write")

    try:
        with pytest.raises(ValueError, match="caller cancelled"):
            client.set_clock(time(7, 20), before_write=before_write)
        assert not any(command.startswith(b"@TM:05,") for command in sim.sent_commands)
        assert any(
            command.decode().strip() == "@TS:00" for command in sim.sent_commands
        )
        assert not sim.config.screen_locked
    finally:
        client.close()


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
    [
        time(7, 20, 1),
        time(7, 20, 0, 1),
        time(7, 20, tzinfo=timezone.utc),
        "07:20",
        datetime(2026, 11, 17, 7, 20),
    ],
)
def test_invalid_time_never_connects(value):
    client = JuraClient("127.0.0.1", port=1, profile=load_profile("EF566"))
    with pytest.raises(ValueError, match="hours and minutes"):
        client.set_clock(value)


@pytest.mark.parametrize("model", [None, "EF1091", "EF566V2"])
def test_other_profiles_never_connect(model):
    client = JuraClient(
        "127.0.0.1", port=1, profile=load_profile(model) if model else None
    )
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


def test_unsupported_profile_cannot_lock_or_write_to_armed_simulator(sim_factory):
    sim = sim_factory(allow_setting_writes=True, require_user_accept=False)
    client = JuraClient(*sim.address, profile=load_profile("EF1091"))
    try:
        with pytest.raises(ValueError, match="only verified"):
            client.set_clock(time(7, 20))
        assert not sim.sent_commands
        assert not sim.handshakes
    finally:
        client.close()


def test_timer_guard_order_uses_eight_distinct_slots(sim_factory):
    # Literal wire addresses pin Monday..Sunday and all-days independently
    # of the implementation's TIMER_ADDRESSES constant.
    raw = {
        "14": "2401008000",
        "15": "2402008000",
        "16": "2403008000",
        "17": "2404008000",
        "18": "2405008000",
        "19": "2406008000",
        "1A": "2407008000",
        "1B": "2408008000",
    }
    sim = sim_factory(require_user_accept=False)
    sim.config.settings.update(raw)
    client = paired(sim)
    try:
        assert client.read_clock_timers() == tuple(
            (time(hour), None) for hour in range(1, 9)
        )
    finally:
        client.close()


@pytest.mark.parametrize("unlock_reply", [None, "@an:error"])
def test_guard_exception_is_preserved_when_unlock_also_fails(sim_factory, unlock_reply):
    sim = sim_factory(
        allow_setting_writes=True,
        require_user_accept=False,
        keypad_unlock_reply=unlock_reply,
    )
    client = paired(sim)
    cancelled = RuntimeError("caller cancelled before writing")

    def guard():
        raise cancelled

    try:
        with pytest.raises(RuntimeError) as exc:
            client.set_clock(time(7, 20), timeout=0.1, before_write=guard)
        assert exc.value is cancelled
        assert any(
            "unlock also failed" in note and "No setting write sent" in note
            for note in exc.value.__notes__
        )
        assert not any(c.startswith(b"@TM:05,") for c in sim.sent_commands)
    finally:
        client.close()


@pytest.mark.parametrize("unlock_reply", [None, "@an:error", "@ts"])
def test_write_timeout_survives_unlock_failures(sim_factory, unlock_reply):
    sim = sim_factory(
        allow_setting_writes=True,
        require_user_accept=False,
        setting_write_timeout=True,
        keypad_unlock_reply=unlock_reply,
    )
    client = paired(sim)
    try:
        with pytest.raises(TimeoutError) as exc:
            client.set_clock(time(7, 20), timeout=0.1)
        assert any("read back before retrying" in note for note in exc.value.__notes__)
        assert len([c for c in sim.sent_commands if c.startswith(b"@TM:05,")]) == 1
        assert sim.config.settings["05"] == "220714"
        if unlock_reply != "@ts":
            assert any("unlock also failed" in note for note in exc.value.__notes__)
        assert not sim.config.screen_locked
    finally:
        client.close()


def test_unlock_timeout_remains_timeout(sim_factory):
    sim = sim_factory(
        allow_setting_writes=True, require_user_accept=False, keypad_unlock_reply=None
    )
    client = paired(sim)
    try:
        with pytest.raises(TimeoutError) as exc:
            client.set_clock(time(7, 20), timeout=0.1)
        assert any("unlock not confirmed" in note for note in exc.value.__notes__)
        assert sim.config.settings["05"] == "220714"
    finally:
        client.close()


def test_explicit_rejection_survives_unlock_failure(sim_factory):
    from jura_connect.settings import SettingRejectedError

    sim = sim_factory(
        allow_setting_writes=True,
        require_user_accept=False,
        setting_write_reply="@an:error",
        keypad_unlock_reply=None,
    )
    client = paired(sim)
    try:
        with pytest.raises(SettingRejectedError) as exc:
            client.set_clock(time(7, 20), timeout=0.1)
        assert any("explicitly rejected" in note for note in exc.value.__notes__)
        assert "05" not in sim.config.settings
    finally:
        client.close()


@pytest.mark.parametrize("slot", ["05", "14", "15", "16", "17", "18", "19", "1A", "1B"])
def test_every_setting_write_gated_case_insensitively_and_reads_ungated(
    slot, sim_factory
):
    from jura_connect.commands import DESTRUCTIVE_PREFIXES, match_destructive

    prefix = f"@TM:{slot},"
    assert prefix.encode() in DESTRUCTIVE_PREFIXES
    assert match_destructive(f"@TM:{slot}") is None
    assert match_destructive(f"@tm:{slot.lower()}") is None
    sim = sim_factory(require_user_accept=False)
    client = paired(sim)
    try:
        frame = (prefix + "2207143E").lower()
        with pytest.raises(DestructiveCommandError):
            run_named(client, "raw", [frame])
        assert not any(
            c.lower().startswith(prefix.lower().encode()) for c in sim.sent_commands
        )
        # Explicit client opt-in still reaches the refusing simulator guard.
        result = run_named(client, "raw", [frame], allow_destructive=True)
        assert result.value == "@an:error"
        assert any(
            c.lower().startswith(prefix.lower().encode()) for c in sim.sent_commands
        )
    finally:
        client.close()
