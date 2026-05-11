"""Named-command registry for the WiFi protocol.

Maps user-friendly names (``info``, ``counters``, ``mem-read`` …) onto
the underlying wire commands so callers — both the CLI and library
users — never have to remember the hex codes. The CLI's ``command``
subcommand is a thin shell over :func:`run_named`.

Destructive process commands (``@TG:24`` cleaning, ``@TP:`` brewing,
``@HW:`` writes …) are *deliberately* absent from the registry; see
``docs/PROTOCOL.md`` §5.5. They remain reachable through
:meth:`JuraClient.request` for advanced/explicit use, never by name.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable, Sequence

from .client import JuraClient

CommandRunner = Callable[["CommandSpec", JuraClient, "tuple[str, ...]", float], object]


class CommandError(ValueError):
    """Unknown command name, bad argument, or wrong argument count."""


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
    ) -> CommandResult:
        if len(args) != len(self.arguments):
            expected = (
                ", ".join(a.name for a in self.arguments) if self.arguments else "none"
            )
            raise CommandError(
                f"{self.name}: expected {len(self.arguments)} argument(s) "
                f"({expected}); got {len(args)}"
            )
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
# Runners
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


def _ascii_arg(name: str, value: str) -> str:
    if not value:
        raise CommandError(f"{name}: must not be empty")
    if not all(0x20 <= ord(c) < 0x7F for c in value):
        raise CommandError(f"{name}: non-ASCII or control char in {value!r}")
    return value


# --------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------- #


_SPECS: tuple[CommandSpec, ...] = (
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
        description="send a verbatim '@…' command; use with care",
        arguments=(Argument("frame", "command frame, e.g. '@TG:43'"),),
        runner=_r_raw,
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
) -> CommandResult:
    """Dispatch a named command on an already-handshaken ``client``.

    Raises :class:`CommandError` for unknown names or wrong argument
    counts; propagates :class:`TimeoutError` from the underlying
    request when the machine doesn't reply in time.
    """
    return get_command(name).run(client, args, timeout=timeout)
