"""Interactive maintenance processes: XML parsing, blocking alerts, runner.

Everything here runs against the real simulator (no mocks). The wire
behaviour of the process state machine is APK-derived and untested on
hardware — see ``docs/PROTOCOL.md`` §5.11.
"""

from __future__ import annotations

import pytest

from jura_connect.client import JuraClient, MachineStatus
from jura_connect.commands import CommandError, run_named
from jura_connect.process import (
    ACCEPT_COMMANDS,
    CANCEL_STEP_COMMAND,
    NEXT_STEP_COMMAND,
    MachineProcess,
    ProcessAction,
    ProcessError,
    ProcessRun,
    ProcessRunner,
    ProcessStep,
    available_processes,
    resolve_process,
)
from jura_connect.profile import iter_profiles, load_profile
from jura_connect.progress import PROCESS_CODES, ProductProgress, ProgressState


def _paired(sim, profile=None) -> JuraClient:
    host, port = sim.address
    c = JuraClient(
        host, port=port, conn_id="process-tests", auth_hash="", profile=profile
    )
    r = c.pair(timeout=2.0)
    assert r.state == "CORRECT"
    return c


# --------------------------------------------------------------------- #
# <PROCESS> / <STATE> parsing
# --------------------------------------------------------------------- #


def test_ef1091_declares_its_five_maintenance_processes() -> None:
    prof = load_profile("EF1091")
    by_name = {p.name: p for p in prof.processes}
    assert set(by_name) == {
        "cleaning",
        "descale",
        "filter_change",
        "cappu_rinse",
        "cappu_clean",
    }
    cleaning = by_name["cleaning"]
    assert cleaning.execute_command == "@TG:24"
    assert cleaning.raw_type == "Cleaning"
    assert cleaning.progress is True
    # FilterChange is the one EF1091 process that declares Progress="false".
    assert by_name["filter_change"].progress is False
    assert prof.process_by_name["cleaning"] is cleaning


def test_ef1091_state_table_carries_names_and_accept_commands() -> None:
    prof = load_profile("EF1091")
    assert len(prof.states) == 83
    press_rinse = prof.state_by_value[0x26]
    assert press_rinse.name == "press_rinse"
    assert press_rinse.raw_name == "Press Rinse"
    assert press_rinse.accept_command == "@TG:10"
    assert press_rinse.needs_confirmation
    assert press_rinse.picture == "pflege_druecken.png"
    # A state without AcceptCommand must not claim to need one.
    empty_tray = prof.state_by_value[0x04]
    assert empty_tray.accept_command is None
    assert not empty_tray.needs_confirmation
    assert empty_tray.name == "empty_tray"


def test_every_profile_uses_only_the_two_known_accept_commands() -> None:
    """`WifiCommandProcessAccept` sends whatever the XML declares. Across
    all 89 bundled profiles that is only ever ``@TG:10`` or ``@TG:04``."""
    seen: set[str] = set()
    profiles = 0
    for prof in iter_profiles():
        profiles += 1
        assert prof.states, f"{prof.code} declares no <STATE> table"
        assert prof.processes, f"{prof.code} declares no <PROCESS> table"
        for state in prof.states:
            if state.accept_command is not None:
                seen.add(state.accept_command)
    assert profiles == 89
    assert seen == set(ACCEPT_COMMANDS)


def test_every_profile_execute_command_is_a_known_process_code() -> None:
    """Process names must share the vocabulary the ``@TV:`` decoder uses,
    so a pushed process frame and a started process agree on the name."""
    known = {f"@TG:{code:02X}": name for code, name in PROCESS_CODES.items()}
    for prof in iter_profiles():
        for proc in prof.processes:
            assert proc.execute_command in known, (
                f"{prof.code}: unknown process command {proc.execute_command}"
            )
            assert proc.name == known[proc.execute_command]


def test_every_profile_declares_the_same_finish_states() -> None:
    """The runner detects completion by state code; the codes are the
    same in all 89 XMLs, which is what makes the constant safe."""
    for prof in iter_profiles():
        for value, expected in (
            (0x0B, "cappurinse_finished"),
            (0x56, "descale_finished"),
            (0x65, "filter_rinse_finished"),
            (0x76, "cleaning_process_finished"),
            (0x95, "cappu_clean_finish"),
        ):
            state = prof.state_by_value[value]
            assert state.name == expected, f"{prof.code}: 0x{value:02X}"


def test_the_state_table_names_states_the_tv_decoder_cannot() -> None:
    """Why the XML table is needed at all: 18 of EF1091's 83 states are
    missing from the app's ``ProgressState`` enum — including ``26``
    "Press Rinse", the very state a cleaning cycle waits on."""
    prof = load_profile("EF1091")
    unknown_to_decoder = [
        s for s in prof.states if ProgressState.from_code(s.value) is None
    ]
    assert len(unknown_to_decoder) == 18
    assert 0x26 in {s.value for s in unknown_to_decoder}
    assert prof.state_by_value[0x26].name == "press_rinse"


def test_step_falls_back_to_the_decoder_name_without_a_profile() -> None:
    """No profile: a step still decodes, it just cannot be named or
    confirmed from the XML."""
    frame = "@TV:" + f"{ProgressState.CLEANING_ADD_TABLET:02X}24" + "00" * 14
    named = ProcessStep.from_progress(ProductProgress.parse(frame), None)
    assert named.name == "cleaning_add_tablet"
    assert named.raw_name is None
    assert named.accept_command is None
    # A state the enum does not know keeps the raw code.
    press_rinse = ProcessStep.from_progress(
        ProductProgress.parse("@TV:2624" + "00" * 14), None
    )
    assert press_rinse.name == "unknown_26"
    assert not press_rinse.needs_confirmation


# --------------------------------------------------------------------- #
# Alert metadata: Blocked / Process
# --------------------------------------------------------------------- #


def test_alert_blocked_and_process_are_parsed() -> None:
    prof = load_profile("EF1091")
    no_beans = prof.alert_by_bit[10]
    assert no_beans.raw_type == "info"
    assert no_beans.blocked == "C"
    # "C" blocks plain coffee *and* every combination containing coffee.
    assert set(no_beans.blocked_kinds) == {"C", "CM"}
    assert no_beans.process is None

    cleaning = prof.alert_by_bit[34]
    assert cleaning.raw_type == "ip"
    assert cleaning.process == "cleaning"
    assert cleaning.process_button == "206"
    assert cleaning.cancel_button == "72"
    assert cleaning.picture == "geraet_reinigen.png"

    descale = prof.alert_by_bit[33]
    assert descale.process == "descale"  # XML says "Decalc"

    # Type="block" blocks every product kind, with no Blocked attribute.
    insert_tray = prof.alert_by_bit[0]
    assert insert_tray.raw_type == "block"
    assert insert_tray.blocked is None
    assert set(insert_tray.blocked_kinds) >= {"C", "M", "CM", "T", "P"}

    # A bare informational alert blocks nothing at all.
    coffee_ready = prof.alert_by_bit[13]
    assert coffee_ready.raw_type is None
    assert coffee_ready.blocked_kinds == ()
    assert coffee_ready.process is None


def test_alert_process_names_use_the_process_vocabulary() -> None:
    """An alert's ``Process`` always names a known process — but not
    always one the same XML declares.

    13 of the 89 profiles (machines with no milk system) keep the
    boilerplate "cappu rinse"/"cappu clean" alerts while declaring no
    ``CappuRinse``/``CappuClean`` process. Consumers must therefore treat
    ``MachineStatus.alert_processes`` as a hint and be ready for
    ``resolve_process`` to refuse it.
    """
    known = set(PROCESS_CODES.values())
    undeclared: dict[str, set[str]] = {}
    for prof in iter_profiles():
        declared = {p.name for p in prof.processes}
        for alert in prof.alerts:
            if alert.process is None:
                continue
            assert alert.process in known, (
                f"{prof.code}: alert {alert.name!r} names an unknown "
                f"process {alert.process!r}"
            )
            if alert.process not in declared:
                undeclared.setdefault(prof.code, set()).add(alert.process)
    assert len(undeclared) == 13
    assert set().union(*undeclared.values()) == {"cappu_rinse", "cappu_clean"}
    # And such a process must be refused rather than sent blindly.
    code = sorted(undeclared)[0]
    with pytest.raises(ProcessError, match="does not declare"):
        resolve_process("cappu_clean", load_profile(code))


def test_milk_alert_blocks_every_kind_containing_milk() -> None:
    prof = load_profile("EF1091")
    no_milk = prof.alert_by_bit[14]
    assert no_milk.blocked == "M"
    assert set(no_milk.blocked_kinds) == {"M", "CM", "TM"}


@pytest.mark.parametrize(
    ("bit", "name"),
    [
        (14, "no_milk_sensor"),
        (15, "milk_sensor_error"),
        (16, "milk_sensor_no_signal"),
    ],
)
def test_status_uses_canonical_milk_sensor_alert_names(bit: int, name: str) -> None:
    status = MachineStatus.parse(_frame(bit), profile=load_profile("EF545"))

    assert status.active_alerts == (name,)
    assert status.info == (name,)


# --------------------------------------------------------------------- #
# MachineStatus: blocked kinds + clearing processes
# --------------------------------------------------------------------- #


def _frame(*bits: int) -> str:
    data = bytearray(8)
    for bit in bits:
        byte_i, bit_in_byte = divmod(bit, 8)
        data[byte_i] |= 1 << (7 - bit_in_byte)
    return "@TF:" + data.hex().upper()


def test_status_reports_blocked_kinds_for_a_blocking_alert() -> None:
    prof = load_profile("EF1091")
    st = MachineStatus.parse(_frame(1), profile=prof)  # fill water, Type=block
    assert "fill_water" in st.errors
    assert set(st.blocked_kinds) >= {"C", "M", "CM", "T", "P"}
    assert st.blocking_alerts == ("fill_water",)
    assert not st.can_brew_kind("C")
    assert "espresso" in st.blocked_products


def test_status_reports_partial_block_and_the_clearing_process() -> None:
    prof = load_profile("EF1091")
    # bit 10 = no beans (Blocked="C"), bit 34 = cleaning alert (Type="ip").
    st = MachineStatus.parse(_frame(10, 34), profile=prof)
    assert set(st.blocked_kinds) == {"C", "CM"}
    assert st.can_brew_kind("T")
    assert not st.can_brew_kind("CM")
    assert dict(st.alert_processes)["cleaning_alert"] == "cleaning"
    assert "espresso" in st.blocked_products
    assert "hotwater" not in st.blocked_products
    payload = st.to_dict()
    assert payload["blocked_kinds"] == list(st.blocked_kinds)
    assert payload["alert_processes"] == {"cleaning_alert": "cleaning"}
    # Nothing that already existed may disappear — Home Assistant reads it.
    for key in ("bits_hex", "active_alerts", "errors", "info", "process"):
        assert key in payload


def test_info_only_status_blocks_nothing() -> None:
    prof = load_profile("EF1091")
    st = MachineStatus.parse(_frame(13), profile=prof)  # coffee ready
    assert st.blocked_kinds == ()
    assert st.blocked_products == ()
    assert st.blocking_alerts == ()
    assert st.alert_processes == ()
    assert st.can_brew_kind("CM")


def test_status_without_a_profile_keeps_the_legacy_shape() -> None:
    st = MachineStatus.parse(_frame(1))
    assert "fill_water" in st.errors
    # The baseline codebook carries no Blocked/Process metadata.
    assert st.blocked_kinds == ()
    assert st.alert_processes == ()


# --------------------------------------------------------------------- #
# Process resolution
# --------------------------------------------------------------------- #


def test_resolve_process_uses_the_profile_when_there_is_one() -> None:
    prof = load_profile("EF1091")
    proc = resolve_process("cleaning", prof)
    assert isinstance(proc, MachineProcess)
    assert proc.execute_command == "@TG:24"
    assert proc.code == 0x24
    assert proc.finish_state == 0x76
    assert "cleaning" in proc.format()
    assert proc.to_dict()["execute_command"] == "@TG:24"


def test_resolve_process_falls_back_to_the_builtin_table() -> None:
    """A client with no profile loaded must still be able to clean."""
    proc = resolve_process("cleaning", None)
    assert proc.execute_command == "@TG:24"
    assert {p.name for p in available_processes(None)} == set(PROCESS_CODES.values())


def test_resolve_process_rejects_an_unknown_name() -> None:
    with pytest.raises(ProcessError, match="unknown maintenance process"):
        resolve_process("polish-the-spout", None)


def test_resolve_process_rejects_a_process_the_machine_lacks() -> None:
    prof = load_profile("EF1091")
    with pytest.raises(ProcessError, match="does not declare"):
        resolve_process("coffee_rinse", prof)


# --------------------------------------------------------------------- #
# End-to-end against the simulator
# --------------------------------------------------------------------- #


def test_process_run_walks_the_state_machine_to_completion(sim_factory) -> None:
    sim = sim_factory(allow_process=True)
    c = _paired(sim, load_profile("EF1091"))
    try:
        run = c.run_process(
            "cleaning", auto_accept=True, timeout=15.0, step_timeout=5.0
        )
    finally:
        c.close()
    assert isinstance(run, ProcessRun)
    assert run.completed and not run.cancelled and not run.timed_out
    names = [s.name for s in run.steps]
    assert names[0] == "cleaning_start"
    assert "press_rinse" in names
    assert names[-1] == "cleaning_process_finished"
    assert run.steps[-1].terminal
    # The confirmation the XML declares for "Press Rinse" reached the wire.
    assert b"@TG:10" in sim.sent_commands
    assert b"@TG:24" in sim.sent_commands
    assert "cleaning" in run.format()
    payload = run.to_dict()
    assert payload["completed"] is True
    assert payload["steps"][-1]["name"] == "cleaning_process_finished"


def test_process_run_can_be_driven_step_by_step(sim_factory) -> None:
    sim = sim_factory(allow_process=True)
    c = _paired(sim, load_profile("EF1091"))
    try:
        runner = ProcessRunner(c, resolve_process("cleaning", c.profile))
        reply = runner.start(timeout=3.0)
        assert reply == "@tg:24"
        assert runner.started
        step = runner.wait_step(timeout=3.0)
        assert step is not None and step.name == "cleaning_start"
        assert not step.needs_confirmation
        # Walk until the machine asks for a confirmation.
        while step is not None and not step.needs_confirmation:
            step = runner.wait_step(timeout=3.0)
        assert step is not None
        assert step.accept_command == "@TG:10"
        assert runner.accept(timeout=3.0) == "@tg:10"
        # After the confirmation the machine finishes on its own.
        last = step
        while last is not None and not last.terminal:
            last = runner.wait_step(timeout=3.0)
        assert last is not None and last.name == "cleaning_process_finished"
    finally:
        c.close()


def test_process_run_cancel_path(sim_factory) -> None:
    sim = sim_factory(allow_process=True)
    c = _paired(sim, load_profile("EF1091"))

    def decide(step) -> ProcessAction:
        return ProcessAction.CANCEL if step.needs_confirmation else ProcessAction.WAIT

    try:
        run = c.run_process("cleaning", on_step=decide, timeout=15.0, step_timeout=5.0)
    finally:
        c.close()
    assert run.cancelled
    assert not run.completed
    assert CANCEL_STEP_COMMAND.encode() in sim.sent_commands
    assert "cancelled" in run.format()


def test_process_run_times_out_when_nobody_confirms(sim_factory) -> None:
    """Without auto-accept the machine parks on the confirmation state and
    the run must come back with what it saw instead of blocking forever."""
    sim = sim_factory(allow_process=True)
    c = _paired(sim, load_profile("EF1091"))
    try:
        run = c.run_process("cleaning", timeout=1.5, step_timeout=0.5)
    finally:
        c.close()
    assert run.timed_out
    assert not run.completed
    assert run.last_step is not None
    assert run.last_step.needs_confirmation
    assert run.needs_confirmation
    assert b"@TG:10" not in sim.sent_commands


def test_start_refused_by_the_machine_raises(sim_factory) -> None:
    """Default simulator config refuses every destructive prefix — that is
    the guardrail, and a refused start must not look like a running one."""
    sim = sim_factory()  # allow_process stays False
    c = _paired(sim, load_profile("EF1091"))
    try:
        runner = ProcessRunner(c, resolve_process("cleaning", c.profile))
        with pytest.raises(ProcessError, match="refused"):
            runner.start(timeout=2.0)
        assert not runner.started
        # Non-strict mode hands the refusal back instead of raising.
        assert runner.start(timeout=2.0, strict=False) == "@an:error"
    finally:
        c.close()


def test_next_step_is_rejected_when_no_process_runs(sim_factory) -> None:
    sim = sim_factory(allow_process=True)
    c = _paired(sim, load_profile("EF1091"))
    try:
        result = run_named(c, "process-next", timeout=2.0, allow_destructive=True)
    finally:
        c.close()
    # @tg:00 is J.O.E.'s "rejected" answer for WiFiCommandNextProductStep.
    assert result.value == "@tg:00"
    assert NEXT_STEP_COMMAND.encode() in sim.sent_commands


def test_process_next_advances_a_running_process(sim_factory) -> None:
    """A machine that waits for "Press Rotary or Next" between steps is
    driven with @TG:01 rather than a confirmation."""
    sim = sim_factory(allow_process=True, process_auto_advance=False)
    c = _paired(sim, load_profile("EF1091"))
    try:
        runner = ProcessRunner(c, resolve_process("cleaning", c.profile))
        runner.start(timeout=3.0)
        step = runner.wait_step(timeout=3.0)
        assert step is not None and step.name == "cleaning_start"
        assert runner.next_step(timeout=3.0) == "@tg:01"
        second = runner.wait_step(timeout=3.0)
        assert second is not None and second.name == "cleaning_empty_tray"
    finally:
        c.close()


# --------------------------------------------------------------------- #
# Named commands
# --------------------------------------------------------------------- #


def test_processes_command_lists_what_the_machine_declares(sim) -> None:
    c = _paired(sim, load_profile("EF1091"))
    try:
        result = run_named(c, "processes", timeout=2.0)
    finally:
        c.close()
    text = result.format()
    assert "cleaning" in text
    assert "@TG:24" in text
    assert "coffee_rinse" not in text  # EF1091 declares no CoffeeRinse
    names = [p["name"] for p in result.to_dict()["value"]["processes"]]
    assert "descale" in names


def test_process_run_command_returns_the_refusal_string(sim) -> None:
    """The registry command must survive a machine that says no: the
    destructive-gating test asserts a plain reply string comes back."""
    c = _paired(sim, load_profile("EF1091"))
    try:
        result = run_named(
            c, "process-run", ["cleaning"], timeout=2.0, allow_destructive=True
        )
    finally:
        c.close()
    assert result.value == "@an:error"


def test_process_watch_is_read_only(sim_factory) -> None:
    """`process-watch` only listens; it must never put a frame on the wire."""
    sim = sim_factory(allow_process=True)
    c = _paired(sim, load_profile("EF1091"))
    try:
        before = len(sim.sent_commands)
        result = run_named(c, "process-watch", ["0.3"], timeout=2.0)
        # Counted before close() so the teardown frame can't race us.
        after = len(sim.sent_commands)
    finally:
        c.close()
    assert isinstance(result.value, ProcessRun)
    assert after == before


def test_process_accept_defaults_to_the_profiles_accept_command(sim_factory) -> None:
    sim = sim_factory(allow_process=True)
    c = _paired(sim, load_profile("EF1091"))
    try:
        runner = ProcessRunner(c, resolve_process("cleaning", c.profile))
        runner.start(timeout=3.0)
        step = runner.wait_step(timeout=3.0)
        while step is not None and not step.needs_confirmation:
            step = runner.wait_step(timeout=3.0)
        result = run_named(c, "process-accept", timeout=3.0, allow_destructive=True)
    finally:
        c.close()
    assert result.value == "@tg:10"


def test_process_accept_rejects_a_command_outside_the_known_pair(sim) -> None:
    c = _paired(sim, load_profile("EF1091"))
    try:
        # The registry re-raises ProcessError as a CommandError so the
        # CLI prints it instead of tracebacking.
        with pytest.raises(CommandError, match="not a process-accept command"):
            run_named(
                c, "process-accept", ["@TG:24"], timeout=2.0, allow_destructive=True
            )
    finally:
        c.close()
