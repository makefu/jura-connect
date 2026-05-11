"""Named-command registry for the WiFi protocol.

Maps user-friendly names (``info``, ``counters``, ``clean``,
``set-pin`` …) onto the underlying wire commands so callers — both
the CLI and library users — never have to remember the hex codes.
The CLI's ``command`` subcommand is a thin shell over :func:`run_named`.

The registry is split into two tiers:

* **Read-only commands** (``info``, ``counters``, ``status``, …) — safe
  to invoke at any time. The CLI lets these through unconditionally.

* **Destructive commands** (``clean``, ``decalc``, ``set-pin``, …) —
  these change the machine's physical state, consume supplies, can
  lock you out of the dongle (wrong PIN / WiFi credentials), or kick
  off long-running cycles you cannot abort remotely. They are gated
  behind ``allow_destructive=True`` on :func:`run_named` and the
  matching ``--allow-destructive-commands`` CLI flag. Without the
  flag a :class:`DestructiveCommandError` is raised *before* the
  command reaches the wire.

The ``raw`` command is a single escape hatch that sends an arbitrary
``@…`` frame; it inspects its payload against
:data:`DESTRUCTIVE_PREFIXES` and is subject to the same gate so the
escape hatch can't be used as an accidental bypass.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable, Sequence

from .client import JuraClient

CommandRunner = Callable[["CommandSpec", JuraClient, "tuple[str, ...]", float], object]


# Wire-level prefixes that mutate the machine. These are the patterns
# both :class:`~jura_wifi.simulator.Simulator` refuses-by-default and
# the registry refuses-by-default through the destructive gate.
DESTRUCTIVE_PREFIXES: tuple[bytes, ...] = (
    b"@TG:21",  # CappuClean
    b"@TG:23",  # CappuRinse
    b"@TG:24",  # Cleaning
    b"@TG:25",  # Decalc
    b"@TG:26",  # FilterChange
    b"@TG:7E",  # reset maintenance counter (with or without arg)
    b"@TG:FF",  # reset (broad)
    b"@TF:02",  # restart machine
    b"@AN:02",  # power off
    b"@TP:",    # start product (brewing)
    b"@HW:",    # write (PIN / SSID / password / dongle name)
)


class CommandError(ValueError):
    """Unknown command name, bad argument, or wrong argument count."""


class DestructiveCommandError(CommandError):
    """Raised when a destructive command is invoked without the explicit gate.

    The exception message embeds the human-readable danger
    description so a CLI can print it directly. Set
    ``allow_destructive=True`` on :func:`run_named` (or pass
    ``--allow-destructive-commands`` on the CLI) to bypass.
    """


@dataclasses.dataclass(slots=True, frozen=True)
class Argument:
    """One positional argument accepted by a :class:`CommandSpec`."""

    name: str
    help: str


@dataclasses.dataclass(slots=True, frozen=True)
class CommandSpec:
    """A user-facing command name bound to a wire-level operation."""

    name: str
    description: str
    arguments: tuple[Argument, ...]
    runner: CommandRunner
    destructive: bool = False
    # When ``destructive`` is True, ``danger`` is the human-readable
    # explanation surfaced by :class:`DestructiveCommandError`. Keep it
    # specific: what the command does on the machine *and* what can
    # bite the user (locked out, supplies consumed, irreversible…).
    danger: str | None = None

    def usage(self) -> str:
        if not self.arguments:
            return self.name
        return f"{self.name} " + " ".join(f"<{a.name}>" for a in self.arguments)

    def run(
        self,
        client: JuraClient,
        args: Sequence[str],
        *,
        timeout: float,
        allow_destructive: bool = False,
    ) -> CommandResult:
        if len(args) != len(self.arguments):
            expected = (
                ", ".join(a.name for a in self.arguments) if self.arguments else "none"
            )
            raise CommandError(
                f"{self.name}: expected {len(self.arguments)} argument(s) "
                f"({expected}); got {len(args)}"
            )

        # Static gate: the command is destructive by registry declaration.
        if self.destructive and not allow_destructive:
            raise DestructiveCommandError(_format_named_gate(self))

        # Dynamic gate: the raw escape hatch can carry a destructive
        # payload even though the *command* (raw) is not marked so. Check
        # here so the bypass can't be used by accident.
        if self.name == "raw" and not allow_destructive:
            _ensure_raw_payload_is_safe(args[0])

        value = self.runner(self, client, tuple(args), timeout)
        return CommandResult(name=self.name, value=value)


@dataclasses.dataclass(slots=True, frozen=True)
class CommandResult:
    """One command's outcome with a uniform pretty-print entry point."""

    name: str
    value: object

    def format(self) -> str:
        formatter = getattr(self.value, "format", None)
        if callable(formatter) and not isinstance(self.value, str):
            return formatter()
        return str(self.value)


# --------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------- #


def _ascii_arg(name: str, value: str) -> str:
    if not value:
        raise CommandError(f"{name}: must not be empty")
    if not all(0x20 <= ord(c) < 0x7F for c in value):
        raise CommandError(f"{name}: non-ASCII or control char in {value!r}")
    return value


def _format_named_gate(spec: CommandSpec) -> str:
    danger = spec.danger or (
        f"{spec.name!r} modifies machine state."
    )
    return (
        f"'{spec.name}' is a destructive command — {danger}\n"
        "Re-run with --allow-destructive-commands (CLI) or "
        "allow_destructive=True (library) if you really mean it."
    )


def _ensure_raw_payload_is_safe(cmd: str) -> None:
    b = cmd.encode("ascii", errors="replace")
    for prefix in DESTRUCTIVE_PREFIXES:
        if b.startswith(prefix):
            raise DestructiveCommandError(
                f"'raw' targets the destructive wire prefix "
                f"{prefix.decode('ascii')!r}.\n"
                "  This can consume cleaning/descaler supplies, lock the\n"
                "  machine into a long-running cycle, or persist WiFi or PIN\n"
                "  settings that may make the dongle unreachable until a\n"
                "  factory reset on the machine itself.\n"
                "Re-run with --allow-destructive-commands if you really mean it."
            )


# --------------------------------------------------------------------- #
# Read-only runners
# --------------------------------------------------------------------- #


def _r_info(_spec, client, _args, timeout):
    return client.read_machine_info(timeout=timeout)


def _r_counters(_spec, client, _args, timeout):
    return client.read_maintenance_counter(timeout=timeout)


def _r_percent(_spec, client, _args, timeout):
    return client.read_maintenance_percent(timeout=timeout)


def _r_status(_spec, client, _args, timeout):
    return client.read_status(timeout=timeout)


def _r_lock(_spec, client, _args, _timeout):
    return client.lock_screen()


def _r_unlock(_spec, client, _args, _timeout):
    return client.unlock_screen()


def _r_mem_read(_spec, client, args, timeout):
    addr = _ascii_arg("addr", args[0])
    return client.request(f"@TM:{addr}", match=r"^@tm", timeout=timeout)


def _r_register_read(_spec, client, args, timeout):
    bank = _ascii_arg("bank", args[0])
    return client.request(f"@TR:{bank}", match=r"^@tr", timeout=timeout)


def _r_raw(_spec, client, args, timeout):
    cmd = args[0]
    if not cmd.startswith("@"):
        raise CommandError(f"raw: command must start with '@', got {cmd!r}")
    if not all(0x20 <= ord(c) < 0x7F for c in cmd):
        raise CommandError(f"raw: non-ASCII characters in {cmd!r}")
    return client.request(cmd, timeout=timeout)


# --------------------------------------------------------------------- #
# Destructive runners
# --------------------------------------------------------------------- #


def _request_or_disconnect(client, cmd, timeout, note):
    """For commands like restart/power-off where the machine drops the
    connection mid-reply. Return ``note`` instead of bubbling the
    ConnectionError so CLI users see something useful."""
    try:
        return client.request(cmd, timeout=timeout)
    except (ConnectionError, OSError):
        return f"({note}: connection closed by machine)"


def _r_clean(_spec, client, _args, timeout):
    return client.request("@TG:24", timeout=timeout)


def _r_decalc(_spec, client, _args, timeout):
    return client.request("@TG:25", timeout=timeout)


def _r_filter_change(_spec, client, _args, timeout):
    return client.request("@TG:26", timeout=timeout)


def _r_cappu_clean(_spec, client, _args, timeout):
    return client.request("@TG:21", timeout=timeout)


def _r_cappu_rinse(_spec, client, _args, timeout):
    return client.request("@TG:23", timeout=timeout)


def _r_reset_counters(_spec, client, _args, timeout):
    return client.request("@TG:7E", timeout=timeout)


def _r_restart(_spec, client, _args, timeout):
    return _request_or_disconnect(client, "@TF:02", timeout, "machine restarting")


def _r_power_off(_spec, client, _args, timeout):
    return _request_or_disconnect(client, "@AN:02", timeout, "machine powering off")


def _r_brew(_spec, client, args, timeout):
    recipe = _ascii_arg("recipe", args[0])
    return client.request(f"@TP:{recipe}", timeout=timeout)


def _r_set_pin(_spec, client, args, timeout):
    pin = _ascii_arg("pin", args[0])
    if not pin.isdigit():
        raise CommandError(f"set-pin: PIN must be numeric, got {pin!r}")
    return client.request(f"@HW:01,{pin}", timeout=timeout)


def _r_set_ssid(_spec, client, args, timeout):
    ssid = _ascii_arg("ssid", args[0])
    return client.request(f"@HW:80,{ssid}", timeout=timeout)


def _r_set_password(_spec, client, args, timeout):
    pwd = _ascii_arg("password", args[0])
    return client.request(f"@HW:81,{pwd}", timeout=timeout)


def _r_set_name(_spec, client, args, timeout):
    name = _ascii_arg("name", args[0])
    return client.request(f"@HW:82,{name}", timeout=timeout)


# --------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------- #


_SPECS: tuple[CommandSpec, ...] = (
    # ---- read-only ------------------------------------------------------
    CommandSpec(
        name="info",
        description="full read-only snapshot (status + counters + percent)",
        arguments=(),
        runner=_r_info,
    ),
    CommandSpec(
        name="counters",
        description="maintenance counters (@TG:43)",
        arguments=(),
        runner=_r_counters,
    ),
    CommandSpec(
        name="percent",
        description="maintenance percent indicators (@TG:C0)",
        arguments=(),
        runner=_r_percent,
    ),
    CommandSpec(
        name="status",
        description="parsed status / active alerts (@HU? -> @TF:)",
        arguments=(),
        runner=_r_status,
    ),
    CommandSpec(
        name="lock",
        description="lock the front-panel display (@TS:01)",
        arguments=(),
        runner=_r_lock,
    ),
    CommandSpec(
        name="unlock",
        description="unlock the front-panel display (@TS:00)",
        arguments=(),
        runner=_r_unlock,
    ),
    CommandSpec(
        name="mem-read",
        description="read a memory/setting slot (@TM:<addr>); firmware-specific",
        arguments=(Argument("addr", "hex slot identifier, e.g. 50"),),
        runner=_r_mem_read,
    ),
    CommandSpec(
        name="register-read",
        description="read a register bank (@TR:<bank>); firmware-specific",
        arguments=(Argument("bank", "hex bank id, e.g. 32"),),
        runner=_r_register_read,
    ),
    CommandSpec(
        name="raw",
        description="send a verbatim '@…' command; payload checked against the destructive set",
        arguments=(Argument("frame", "command frame, e.g. '@TG:43'"),),
        runner=_r_raw,
    ),
    # ---- destructive ----------------------------------------------------
    CommandSpec(
        name="clean",
        description="[destructive] start coffee-system cleaning cycle (@TG:24)",
        arguments=(),
        runner=_r_clean,
        destructive=True,
        danger=(
            "starts a real cleaning cycle (~5 min) that consumes a cleaning "
            "tablet and locks the machine until the cycle finishes. There is "
            "no remote 'abort'."
        ),
    ),
    CommandSpec(
        name="decalc",
        description="[destructive] start descaling cycle (@TG:25)",
        arguments=(),
        runner=_r_decalc,
        destructive=True,
        danger=(
            "starts a real descaling cycle (30+ min). The machine expects "
            "descaler solution in the water tank — running this without "
            "descaler can damage the boiler. Cannot be aborted remotely."
        ),
    ),
    CommandSpec(
        name="filter-change",
        description="[destructive] run water-filter change procedure (@TG:26)",
        arguments=(),
        runner=_r_filter_change,
        destructive=True,
        danger=(
            "starts the water-filter change procedure; the machine expects "
            "a fresh filter to be installed in the tank."
        ),
    ),
    CommandSpec(
        name="cappu-clean",
        description="[destructive] start cappuccino-system cleaning (@TG:21)",
        arguments=(),
        runner=_r_cappu_clean,
        destructive=True,
        danger=(
            "starts the cappuccino-system cleaning cycle; consumes a milk-"
            "system cleaning tablet and produces hot soapy water at the "
            "cappuccino spout — make sure a container is in place."
        ),
    ),
    CommandSpec(
        name="cappu-rinse",
        description="[destructive] rinse the milk system (@TG:23)",
        arguments=(),
        runner=_r_cappu_rinse,
        destructive=True,
        danger=(
            "rinses the milk system with hot water at the cappuccino spout "
            "— make sure a container is in place."
        ),
    ),
    CommandSpec(
        name="reset-counters",
        description="[destructive] zero every maintenance counter (@TG:7E)",
        arguments=(),
        runner=_r_reset_counters,
        destructive=True,
        danger=(
            "irreversibly resets every maintenance counter (cleaning / "
            "decalc / filter / etc.) to zero. The machine will then "
            "'forget' when it was last serviced. There is no undo."
        ),
    ),
    CommandSpec(
        name="restart",
        description="[destructive] reboot the WiFi dongle (@TF:02)",
        arguments=(),
        runner=_r_restart,
        destructive=True,
        danger=(
            "reboots the WiFi dongle, killing the current TCP session. The "
            "machine itself stays on, but you'll need to reconnect and any "
            "in-flight commands are lost."
        ),
    ),
    CommandSpec(
        name="power-off",
        description="[destructive] put the machine into standby (@AN:02)",
        arguments=(),
        runner=_r_power_off,
        destructive=True,
        danger=(
            "powers the coffee machine into standby. Reaching it again "
            "afterwards requires somebody to wake it up physically."
        ),
    ),
    CommandSpec(
        name="brew",
        description="[destructive] start brewing a recipe (@TP:<recipe>)",
        arguments=(Argument("recipe", "product code, e.g. 01 (espresso). Firmware-specific."),),
        runner=_r_brew,
        destructive=True,
        danger=(
            "immediately starts brewing the given product recipe. The "
            "machine will draw water, run the grinder, and dispense at the "
            "spout — make sure a suitable cup is in place. Wrong recipe "
            "codes can waste beans, water, or steam."
        ),
    ),
    CommandSpec(
        name="set-pin",
        description="[destructive] write a new front-panel PIN (@HW:01,<pin>)",
        arguments=(Argument("pin", "new numeric PIN, e.g. 1234"),),
        runner=_r_set_pin,
        destructive=True,
        danger=(
            "writes a new front-panel PIN. Forgetting or mistyping the "
            "value can lock you out of the machine's UI until a factory "
            "reset on the machine itself."
        ),
    ),
    CommandSpec(
        name="set-ssid",
        description="[destructive] write a new WiFi SSID for the dongle (@HW:80,<ssid>)",
        arguments=(Argument("ssid", "new WiFi network name"),),
        runner=_r_set_ssid,
        destructive=True,
        danger=(
            "writes a new WiFi SSID. If the network does not exist, or the "
            "SSID is typed wrong, the dongle goes offline and the only "
            "recovery is a factory reset on the machine itself — you cannot "
            "fix it from this side."
        ),
    ),
    CommandSpec(
        name="set-password",
        description="[destructive] write a new WiFi password (@HW:81,<pwd>)",
        arguments=(Argument("password", "new WiFi password"),),
        runner=_r_set_password,
        destructive=True,
        danger=(
            "writes a new WiFi password. A wrong value leaves the dongle "
            "unable to associate and only recoverable via a factory reset "
            "on the machine itself."
        ),
    ),
    CommandSpec(
        name="set-name",
        description="[destructive] rename the dongle (@HW:82,<name>)",
        arguments=(Argument("name", "new dongle name (shown in discovery)"),),
        runner=_r_set_name,
        destructive=True,
        danger=(
            "renames the dongle. Persistent across reboots; cosmetic only "
            "but still a write to the device, so behind the gate by default."
        ),
    ),
)

COMMANDS: dict[str, CommandSpec] = {spec.name: spec for spec in _SPECS}


def list_commands() -> list[CommandSpec]:
    """Return every registered command in declaration order."""
    return list(_SPECS)


def get_command(name: str) -> CommandSpec:
    """Look up one command by name; raises :class:`CommandError` if absent."""
    try:
        return COMMANDS[name]
    except KeyError as exc:
        known = ", ".join(sorted(COMMANDS))
        raise CommandError(f"unknown command {name!r}. Known: {known}") from exc


def run_named(
    client: JuraClient,
    name: str,
    args: Sequence[str] = (),
    *,
    timeout: float = 6.0,
    allow_destructive: bool = False,
) -> CommandResult:
    """Dispatch a named command on an already-handshaken ``client``.

    Destructive commands (and ``raw`` with a destructive payload) raise
    :class:`DestructiveCommandError` unless ``allow_destructive=True``
    is passed explicitly — the safety gate that backs the CLI's
    ``--allow-destructive-commands`` flag.
    """
    return get_command(name).run(
        client, args, timeout=timeout, allow_destructive=allow_destructive
    )
