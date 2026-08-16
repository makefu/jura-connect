"""Interactive maintenance processes (cleaning, descale, filter change).

Starting a maintenance cycle is not a fire-and-forget command. The
machine answers the start verb with a lower-cased echo and then *drives
the client* through its ``<STATE>`` table — "Empty tray", "Add tablet",
"Press Rinse", … — by pushing ``@TV:`` progress frames. Some of those
states park the machine until the client confirms with the
``AcceptCommand`` the XML declares for that state (``@TG:10`` on 78 of
the 89 bundled profiles, ``@TG:04`` on the other 10). ``@TG:01``
advances to the next step and ``@TG:FF`` cancels the current one.

This module wraps that conversation:

* :class:`MachineProcess` — one runnable cycle (name, wire verb, the
  state code that ends it), resolved from the machine's profile or from
  the built-in fallback table when no profile is loaded;
* :class:`ProcessStep` — one state the machine drove us to, with the
  profile's name for it and whether it needs a confirmation;
* :class:`ProcessRunner` — drive it: :meth:`~ProcessRunner.start`,
  :meth:`~ProcessRunner.wait_step`, :meth:`~ProcessRunner.accept`,
  :meth:`~ProcessRunner.next_step`, :meth:`~ProcessRunner.cancel`, or
  :meth:`~ProcessRunner.follow` to run it to completion with a decision
  callback;
* :class:`ProcessRun` — the transcript, with ``format()`` / ``to_dict()``.

Provenance
----------

**APK-derived, untested on hardware.** The wire verbs come from
``WifiCommandStartProcess`` (sends the XML's ``ExecuteCommand``, expects
the lower-cased echo), ``WifiCommandProcessAccept`` (sends the state's
``AcceptCommand`` verbatim, no reply matcher) and
``WiFiCommandNextProductStep`` (``@TG:01`` → ``@tg:(01|00)``) in the
decompiled J.O.E. app; the state table and the accept commands come from
the bundled machine XMLs. Nothing here was run against a real machine —
every confirmation on a real machine advances a real cycle and consumes
supplies. See ``docs/PROTOCOL.md`` §5.11.
"""

from __future__ import annotations

import dataclasses
import enum
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

from .profile import MachineProfile, ProcessDef, StateDef
from .progress import PROCESS_CODES, ProductProgress, ProgressState

if TYPE_CHECKING:  # pragma: no cover - import cycle guard
    from .client import JuraClient

#: ``WiFiCommandNextProductStep`` — advance to the next step. The app
#: matches ``@tg:(01|00)``; ``@tg:00`` means "rejected / nothing to
#: advance".
NEXT_STEP_COMMAND = "@TG:01"

#: ``WifiCommandCancelProductStep`` — abort the running step. Already
#: exposed ungated as the ``cancel`` named command.
CANCEL_STEP_COMMAND = "@TG:FF"

#: The only two ``AcceptCommand`` values any of the 89 bundled machine
#: XMLs declares (``WifiCommandProcessAccept`` sends whichever the state
#: names). Pinned by a test over every profile.
ACCEPT_COMMANDS: tuple[str, ...] = ("@TG:04", "@TG:10")

#: Reply matcher for every verb in this module. The machine's answer is
#: whatever it says (``@tg:24``, ``@tg:00``, ``@an:error`` when it
#: refuses), so the pattern is "any reply that is not a frame the
#: machine pushes on its own" — the ``@TF:`` status and ``@TV:``
#: progress broadcasts keep flowing during a cycle, and so do the bare
#: upper-case markers ``@TB`` / ``@TS`` (PROTOCOL.md §5.2), which a
#: ``@TG:24`` start would otherwise read as its acknowledgement and
#: report as a refusal. The marker exclusion is case-sensitive on
#: purpose: the lower-case ``@ts`` *is* a legitimate reply.
PROCESS_REPLY_MATCH = r"^(?!@T[BS]$)(?i:@(?!t[fv]:))"

#: Accept command assumed when no profile is loaded and the caller names
#: none. 87 of the 89 profiles declare ``@TG:10`` somewhere and 78
#: declare nothing else, so it is the best guess — but a client with a
#: profile always uses what its own XML says.
DEFAULT_ACCEPT_COMMAND = "@TG:10"

#: State code that ends each process, i.e. the machine's "…finished"
#: screen. Every bundled profile spells these five states identically
#: (pinned by a test), so the mapping is machine-independent.
#: ``coffee_rinse`` has no dedicated finish state — it falls back to the
#: generic terminal set below.
PROCESS_FINISH_STATES: dict[str, int] = {
    "cappu_rinse": 0x0B,  # "Cappurinse finished"
    "descale": 0x56,  # "Descale finished"
    "filter_change": 0x65,  # "Filter Rinse finished"
    "cleaning": 0x76,  # "Cleaning Process finished"
    "cappu_clean": 0x95,  # "Cappu Clean finish"
}

#: Any of these ends a run even when it is not the process's own finish
#: state: the five "…finished" screens plus ``ENJOY`` (``3E``), which is
#: what a machine sends when it treats the cycle as a product.
TERMINAL_STATE_CODES: frozenset[int] = frozenset(
    {*PROCESS_FINISH_STATES.values(), int(ProgressState.ENJOY)}
)


class ProcessError(ValueError):
    """Unknown/undeclared process, bad accept command, or a refused start.

    Subclasses :class:`ValueError` so callers can treat it like the rest
    of the library's input errors; the named-command layer re-raises it
    as :class:`jura_connect.commands.CommandError`.
    """


class ProcessAction(enum.Enum):
    """What :meth:`ProcessRunner.follow` should do about a step."""

    WAIT = "wait"  # do nothing, keep listening
    ACCEPT = "accept"  # send the state's AcceptCommand
    NEXT = "next"  # send @TG:01
    CANCEL = "cancel"  # send @TG:FF and stop


@dataclasses.dataclass(slots=True, frozen=True)
class MachineProcess:
    """One maintenance cycle bound to the verb that starts it.

    Built from the machine's ``<PROCESS>`` entry
    (:meth:`from_definition`) or, for a client with no profile loaded,
    from :data:`jura_connect.progress.PROCESS_CODES` — both name the
    process the same way, so ``"cleaning"`` means ``@TG:24`` either way.
    """

    name: str  # "cleaning", "descale", "filter_change", …
    execute_command: str  # "@TG:24"
    progress: bool = True  # machine pushes @TV: frames while it runs
    title: str | None = None
    picture: str | None = None
    declared: bool = True  # False when it came from the fallback table

    @property
    def code(self) -> int:
        """Command byte of :attr:`execute_command` (``0x24`` = cleaning)."""
        return int(self.execute_command.rsplit(":", 1)[-1], 16)

    @property
    def expected_reply(self) -> str:
        """The acknowledgement the machine echoes (``"@tg:24"``).

        ``WifiCommandStartProcess`` matches exactly the lower-cased
        command it sent.
        """
        return self.execute_command.lower()

    @property
    def finish_state(self) -> int | None:
        """State code that ends this process, if it has a dedicated one."""
        return PROCESS_FINISH_STATES.get(self.name)

    @classmethod
    def from_definition(cls, definition: ProcessDef) -> MachineProcess:
        return cls(
            name=definition.name,
            execute_command=definition.execute_command,
            progress=definition.progress,
            title=definition.title,
            picture=definition.picture,
            declared=True,
        )

    def format(self) -> str:
        bits = [f"{self.name} ({self.execute_command})"]
        if not self.progress:
            bits.append("no progress frames")
        if not self.declared:
            bits.append("not declared by this machine's profile")
        return "  ".join(bits)

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "execute_command": self.execute_command,
            "code": f"{self.code:02X}",
            "progress": self.progress,
            "finish_state": (
                f"{self.finish_state:02X}" if self.finish_state is not None else None
            ),
            "declared": self.declared,
        }


@dataclasses.dataclass(slots=True, frozen=True)
class ProcessCatalogue:
    """Every maintenance process a machine offers (no machine I/O)."""

    processes: tuple[MachineProcess, ...]
    machine: str | None = None  # EF code, when a profile is loaded

    def format(self) -> str:
        head = (
            f"processes declared by {self.machine}"
            if self.machine
            else "processes (no machine profile loaded — built-in table)"
        )
        lines = [head]
        lines.extend(f"  {p.format()}" for p in self.processes)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        return {
            "machine": self.machine,
            "processes": [p.to_dict() for p in self.processes],
        }


@dataclasses.dataclass(slots=True, frozen=True)
class ProcessStep:
    """One state the machine drove the client to.

    ``name`` prefers the machine XML's own label for the state code and
    falls back to the ``@TV:`` decoder's enum name, so a machine whose
    XML we do not have still produces something readable.
    """

    progress: ProductProgress  # the decoded frame this step came from
    state_code: int
    name: str  # snake_case, e.g. "press_rinse"
    raw_name: str | None  # XML label, e.g. "Press Rinse"
    accept_command: str | None  # confirmation this state waits for
    title: str | None
    picture: str | None
    terminal: bool  # this state ends the process

    @property
    def needs_confirmation(self) -> bool:
        """True when the machine parks here until the client accepts."""
        return self.accept_command is not None

    @property
    def percent(self) -> int | None:
        """Progress percentage the frame carried, when it carried one."""
        return self.progress.percent

    @classmethod
    def from_progress(
        cls,
        update: ProductProgress,
        profile: MachineProfile | None,
        process: MachineProcess | None = None,
    ) -> ProcessStep:
        definition: StateDef | None = None
        if profile is not None:
            definition = profile.state_by_value.get(update.state_code)
        name = definition.name if definition is not None else _fallback_name(update)
        finish = process.finish_state if process is not None else None
        terminal = update.state_code in TERMINAL_STATE_CODES or (
            finish is not None and update.state_code == finish
        )
        return cls(
            progress=update,
            state_code=update.state_code,
            name=name,
            raw_name=definition.raw_name if definition is not None else None,
            accept_command=definition.accept_command
            if definition is not None
            else None,
            title=definition.title if definition is not None else None,
            picture=definition.picture if definition is not None else None,
            terminal=terminal,
        )

    def format(self) -> str:
        bits = [f"{self.state_code:02X} {self.name}"]
        if self.needs_confirmation:
            bits.append(f"needs {self.accept_command}")
        if self.percent is not None:
            bits.append(f"{self.percent}%")
        if self.terminal:
            bits.append("(done)")
        return "  ".join(bits)

    def to_dict(self) -> dict[str, object]:
        return {
            "state_code": f"{self.state_code:02X}",
            "name": self.name,
            "raw_name": self.raw_name,
            "accept_command": self.accept_command,
            "needs_confirmation": self.needs_confirmation,
            "title": self.title,
            "picture": self.picture,
            "percent": self.percent,
            "terminal": self.terminal,
            "progress": self.progress.to_dict(),
        }


def _fallback_name(update: ProductProgress) -> str:
    """Readable state name without a profile: the ``@TV:`` enum name."""
    if update.state is not None:
        return update.state.name.lower()
    return f"unknown_{update.state_code:02X}"


@dataclasses.dataclass(slots=True, frozen=True)
class ProcessRun:
    """Transcript of one (attempted) process run."""

    process: MachineProcess | None  # None for a bare watch
    steps: tuple[ProcessStep, ...]
    start_reply: str | None = None
    completed: bool = False  # ended on a terminal state
    cancelled: bool = False  # we sent @TG:FF
    timed_out: bool = False  # deadline hit first
    accepts_sent: tuple[str, ...] = ()  # confirmations we put on the wire

    @property
    def last_step(self) -> ProcessStep | None:
        return self.steps[-1] if self.steps else None

    @property
    def needs_confirmation(self) -> bool:
        """True when the run stopped on a state waiting for an accept."""
        last = self.last_step
        return last is not None and last.needs_confirmation

    def format(self) -> str:
        name = self.process.name if self.process is not None else "(watch)"
        lines = [f"process {name}"]
        if self.start_reply is not None:
            lines.append(f"  start reply: {self.start_reply}")
        lines.extend(f"  {s.format()}" for s in self.steps)
        if not self.steps:
            lines.append("  (no state frames seen)")
        if self.cancelled:
            tail = "cancelled"
        elif self.completed:
            tail = "finished"
        elif self.timed_out:
            tail = "timed out"
            last = self.last_step
            if last is not None and last.needs_confirmation:
                tail += f" waiting for {last.accept_command}"
        else:
            tail = "still running"
        return "\n".join([*lines, f"-- {tail}"])

    def to_dict(self) -> dict[str, object]:
        return {
            "process": self.process.to_dict() if self.process is not None else None,
            "start_reply": self.start_reply,
            "steps": [s.to_dict() for s in self.steps],
            "completed": self.completed,
            "cancelled": self.cancelled,
            "timed_out": self.timed_out,
            "needs_confirmation": self.needs_confirmation,
            "accepts_sent": list(self.accepts_sent),
        }


# --------------------------------------------------------------------- #
# Resolution
# --------------------------------------------------------------------- #


def available_processes(profile: MachineProfile | None) -> tuple[MachineProcess, ...]:
    """Every process ``profile`` declares, or the built-in fallback table.

    The fallback covers the six ``@TG:2x`` verbs J.O.E. knows; it is what
    a client without a loaded profile has to go on.
    """
    if profile is not None and profile.processes:
        return tuple(MachineProcess.from_definition(p) for p in profile.processes)
    return tuple(
        MachineProcess(
            name=name,
            execute_command=f"@TG:{code:02X}",
            declared=False,
        )
        for code, name in sorted(PROCESS_CODES.items())
    )


def resolve_process(name: str, profile: MachineProfile | None) -> MachineProcess:
    """Look one process up by name (``"cleaning"``, ``"descale"``, …).

    With a profile the machine's own ``<PROCESS>`` table decides — a
    process the machine does not declare is refused rather than sent,
    because a machine without a milk system has no ``CappuClean`` and
    the verb would just bounce. Without a profile the built-in table is
    used. Raises :class:`ProcessError` for anything unknown.
    """
    wanted = name.strip().lower().replace("-", "_")
    if not wanted:
        raise ProcessError("no maintenance process named")
    known = set(PROCESS_CODES.values())
    if wanted not in known:
        raise ProcessError(
            f"unknown maintenance process {name!r}. Known: {', '.join(sorted(known))}"
        )
    for process in available_processes(profile):
        if process.name == wanted:
            return process
    machine = profile.code if profile is not None else "this machine"
    raise ProcessError(
        f"{machine} does not declare the {wanted!r} process in its XML; "
        "starting it would be a guess"
    )


def resolve_accept_command(
    argument: str | None,
    profile: MachineProfile | None,
    step: ProcessStep | None = None,
) -> str:
    """Decide which confirmation verb to send.

    Preference order: an explicit ``argument`` (a command or a state
    code), then the state the machine is currently parked on, then the
    profile's own declaration when it is unambiguous, then
    :data:`DEFAULT_ACCEPT_COMMAND`. Raises :class:`ProcessError` for an
    argument that is neither a known accept command nor a state that
    declares one, and for a profile that declares both commands with no
    current state to disambiguate.
    """
    if argument:
        candidate = argument.strip().upper()
        if candidate in ACCEPT_COMMANDS:
            return candidate
        if candidate.startswith("@"):
            raise ProcessError(
                f"{argument!r} is not a process-accept command; "
                f"expected one of {', '.join(ACCEPT_COMMANDS)}"
            )
        try:
            value = int(candidate, 16)
        except ValueError as exc:
            raise ProcessError(
                f"{argument!r} is neither a process-accept command nor a hex state code"
            ) from exc
        definition = profile.state_by_value.get(value) if profile is not None else None
        if definition is None or definition.accept_command is None:
            raise ProcessError(
                f"state 0x{value:02X} declares no AcceptCommand on this machine"
            )
        return definition.accept_command
    if step is not None and step.accept_command is not None:
        return step.accept_command
    declared = _declared_accept_commands(profile)
    if len(declared) == 1:
        return declared[0]
    if len(declared) > 1:
        raise ProcessError(
            "this machine declares more than one accept command "
            f"({', '.join(declared)}); name the one you mean, or the state "
            "the machine is waiting on"
        )
    return DEFAULT_ACCEPT_COMMAND


def _declared_accept_commands(profile: MachineProfile | None) -> tuple[str, ...]:
    if profile is None:
        return ()
    seen = {s.accept_command for s in profile.states if s.accept_command is not None}
    return tuple(sorted(seen))


# --------------------------------------------------------------------- #
# The runner
# --------------------------------------------------------------------- #


#: Decision callback: sees each step, returns what to do about it (or
#: ``None`` to fall back to the runner's default).
StepDecider = Callable[[ProcessStep], ProcessAction | None]


class ProcessRunner:
    """Drive one maintenance process over an established session.

    Step by step::

        runner = ProcessRunner(client, resolve_process("cleaning", client.profile))
        runner.start()
        step = runner.wait_step(timeout=60)
        if step.needs_confirmation:
            runner.accept()

    or in one go::

        run = runner.run(auto_accept=True, timeout=900)

    Nothing here consults the destructive gate — that lives in
    :mod:`jura_connect.commands`. A library caller reaching for this
    class is opting in by construction.
    """

    def __init__(self, client: JuraClient, process: MachineProcess) -> None:
        self.client = client
        self.process = process
        self.started = False
        self.start_reply: str | None = None
        self.steps: list[ProcessStep] = []
        self.accepts_sent: list[str] = []
        self.cancelled = False

    # -- wire verbs ----------------------------------------------------
    def start(self, *, timeout: float = 6.0, strict: bool = True) -> str:
        """Send the process's ``ExecuteCommand`` and return the reply.

        The machine acknowledges with the lower-cased echo of the command
        (``@tg:24``); a trailing payload is tolerated because firmware
        families differ there, but anything that does not start with the
        echo counts as a refusal. With ``strict`` (the default) that
        raises :class:`ProcessError` — a refused start must not be
        mistaken for a running cycle. ``strict=False`` hands the raw
        reply back so a CLI can print what the machine actually said.
        """
        reply = self.client.request(
            self.process.execute_command, match=PROCESS_REPLY_MATCH, timeout=timeout
        )
        self.start_reply = reply
        if reply.strip().lower().startswith(self.process.expected_reply):
            self.started = True
            return reply
        if strict:
            raise ProcessError(
                f"machine refused to start {self.process.name!r}: sent "
                f"{self.process.execute_command}, expected "
                f"{self.process.expected_reply!r}, got {reply!r}"
            )
        return reply

    def wait_step(self, *, timeout: float = 60.0) -> ProcessStep | None:
        """Wait for the machine's next state frame.

        Returns ``None`` when nothing arrives within ``timeout`` —
        maintenance states can be minutes apart, so a quiet stretch is
        not an error. Every decoded step is appended to :attr:`steps`.
        """
        for update in self.client.iter_progress(timeout=timeout):
            step = ProcessStep.from_progress(update, self.client.profile, self.process)
            self.steps.append(step)
            return step
        return None

    def accept(
        self,
        *,
        command: str | None = None,
        timeout: float = 6.0,
    ) -> str:
        """Confirm the state the machine is waiting on.

        ``command`` overrides the state's own ``AcceptCommand``; without
        it the current step decides, falling back to what the profile
        declares (see :func:`resolve_accept_command`).
        """
        wire = resolve_accept_command(command, self.client.profile, self.current_step)
        self.accepts_sent.append(wire)
        return self.client.request(wire, match=PROCESS_REPLY_MATCH, timeout=timeout)

    def next_step(self, *, timeout: float = 6.0) -> str:
        """Send ``@TG:01`` (``WiFiCommandNextProductStep``).

        The machine answers ``@tg:01`` when it advanced and ``@tg:00``
        when it had nothing to advance.
        """
        return self.client.request(
            NEXT_STEP_COMMAND, match=PROCESS_REPLY_MATCH, timeout=timeout
        )

    def cancel(self, *, timeout: float = 6.0) -> str:
        """Send ``@TG:FF`` (``WifiCommandCancelProductStep``)."""
        reply = self.client.request(
            CANCEL_STEP_COMMAND, match=PROCESS_REPLY_MATCH, timeout=timeout
        )
        self.cancelled = True
        return reply

    # -- state ---------------------------------------------------------
    @property
    def current_step(self) -> ProcessStep | None:
        return self.steps[-1] if self.steps else None

    def result(self, *, completed: bool = False, timed_out: bool = False) -> ProcessRun:
        """Snapshot everything seen so far as a :class:`ProcessRun`."""
        return ProcessRun(
            process=self.process,
            steps=tuple(self.steps),
            start_reply=self.start_reply,
            completed=completed,
            cancelled=self.cancelled,
            timed_out=timed_out,
            accepts_sent=tuple(self.accepts_sent),
        )

    # -- driving -------------------------------------------------------
    def follow(
        self,
        *,
        timeout: float = 900.0,
        step_timeout: float = 120.0,
        auto_accept: bool = False,
        on_step: StepDecider | None = None,
    ) -> ProcessRun:
        """Follow the state stream until the process ends.

        ``on_step`` is called with each step and decides what to do
        (:class:`ProcessAction`); returning ``None`` falls back to
        ``auto_accept`` — which confirms every state that asks for a
        confirmation and otherwise waits. Stops on a terminal state, on
        a cancel, or when ``timeout`` seconds have passed overall
        (``step_timeout`` bounds one quiet stretch).

        **Every confirmation this sends advances a real cycle on a real
        machine.** ``auto_accept=True`` means "press every button the
        machine asks for, unattended".
        """
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return self.result(timed_out=True)
            step = self.wait_step(timeout=min(step_timeout, remaining))
            if step is None:
                continue
            if step.terminal:
                return self.result(completed=True)
            action = on_step(step) if on_step is not None else None
            if action is None:
                action = (
                    ProcessAction.ACCEPT
                    if auto_accept and step.needs_confirmation
                    else ProcessAction.WAIT
                )
            if action is ProcessAction.CANCEL:
                self.cancel()
                return self.result()
            if action is ProcessAction.ACCEPT:
                self.accept()
            elif action is ProcessAction.NEXT:
                self.next_step()

    def run(
        self,
        *,
        timeout: float = 900.0,
        step_timeout: float = 120.0,
        start_timeout: float = 6.0,
        auto_accept: bool = False,
        on_step: StepDecider | None = None,
    ) -> ProcessRun:
        """:meth:`start` the process, then :meth:`follow` it to the end."""
        self.start(timeout=start_timeout)
        return self.follow(
            timeout=timeout,
            step_timeout=step_timeout,
            auto_accept=auto_accept,
            on_step=on_step,
        )


def watch_states(
    client: JuraClient,
    *,
    timeout: float = 60.0,
    on_step: Callable[[ProcessStep], None] | None = None,
) -> ProcessRun:
    """Listen to the state stream without sending anything.

    The read-only half of this module: decode whatever ``@TV:`` frames
    the machine pushes — during a cycle somebody started on the front
    panel, for instance — into named steps. Returns when a terminal
    state arrives or ``timeout`` elapses.
    """
    steps: list[ProcessStep] = []
    completed = False
    for update in client.iter_progress(timeout=timeout):
        step = ProcessStep.from_progress(update, client.profile)
        steps.append(step)
        if on_step is not None:
            on_step(step)
        if step.terminal:
            completed = True
            break
    return ProcessRun(
        process=None,
        steps=tuple(steps),
        completed=completed,
        timed_out=not completed,
    )
