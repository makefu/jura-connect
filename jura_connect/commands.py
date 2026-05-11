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
# both :class:`~jura_connect.simulator.Simulator` refuses-by-default and
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
    b"@TP:",  # start product (brewing)
    b"@HW:",  # write (PIN / SSID / password / dongle name)
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
    optional: bool = False  # if True, the arg may be omitted on the CLI


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
    # Optional callable that decides destructiveness from the parsed
    # arguments — used by commands that combine a safe read and a
    # destructive write under one name (e.g. ``setting <name>`` reads,
    # ``setting <name> <value>`` writes). Takes the args tuple, returns
    # a danger string when destructive, ``None`` when safe.
    dynamic_danger: Callable[["tuple[str, ...]"], str | None] | None = None

    def usage(self) -> str:
        if not self.arguments:
            return self.name
        parts = [
            f"[<{a.name}>]" if a.optional else f"<{a.name}>" for a in self.arguments
        ]
        return f"{self.name} " + " ".join(parts)

    def run(
        self,
        client: JuraClient,
        args: Sequence[str],
        *,
        timeout: float,
        allow_destructive: bool = False,
    ) -> CommandResult:
        required = sum(1 for a in self.arguments if not a.optional)
        if not required <= len(args) <= len(self.arguments):
            expected_summary = (
                ", ".join(a.name + ("?" if a.optional else "") for a in self.arguments)
                or "none"
            )
            raise CommandError(
                f"{self.name}: expected {required}..{len(self.arguments)} "
                f"argument(s) ({expected_summary}); got {len(args)}"
            )

        # Static gate: the command is destructive by registry declaration.
        if self.destructive and not allow_destructive:
            raise DestructiveCommandError(_format_named_gate(self))

        # Dynamic gate: ``setting <n> <v>`` and ``raw '@TG:24'`` are
        # destructive even though the *command* (setting, raw) is not
        # marked statically. The decision must run before any wire I/O.
        if not allow_destructive:
            if self.dynamic_danger is not None:
                dynamic = self.dynamic_danger(tuple(args))
                if dynamic is not None:
                    raise DestructiveCommandError(
                        _format_named_gate(dataclasses.replace(self, danger=dynamic))
                    )
            if self.name == "raw":
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

    def to_dict(self) -> dict[str, object]:
        """JSON-serialisable representation: ``{"name": ..., "value": ...}``.

        Structured values that expose their own ``to_dict()`` are
        recursed into; plain strings (lock/unlock/raw replies, etc.)
        are passed through verbatim.
        """
        v = self.value
        serialiser = getattr(v, "to_dict", None)
        if callable(serialiser) and not isinstance(v, str):
            value: object = serialiser()
        else:
            value = v
        return {"name": self.name, "value": value}


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
    danger = spec.danger or (f"{spec.name!r} modifies machine state.")
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


def _r_brews(_spec, client, _args, timeout):
    return client.read_product_counters(timeout_per_page=timeout)


def _r_pmode(_spec, client, _args, timeout):
    return client.read_pmode_slots(timeout=timeout)


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
# Setting (read or write, depending on argv length)
# --------------------------------------------------------------------- #


def _require_profile(client: JuraClient) -> object:
    if client.profile is None:
        raise CommandError(
            "this command needs a MachineProfile. Pair with "
            "--machine-type <EF_code> or pass --machine-type to "
            "'command'. See 'jura-connect machine-types' for the "
            "catalogue."
        )
    return client.profile


def _resolve_setting(profile, name: str):
    """Return the SettingDef for the given user-supplied name.

    Looks up by snake_case identifier first; falls back to a
    case-insensitive substring match so the user can type ``bright``
    instead of ``display_brightness_setting``.
    """
    from .profile import _snake  # local import to dodge cycles

    target = _snake(name)
    catalogue = profile.setting_by_name
    if target in catalogue:
        return catalogue[target]
    # Substring fallback. Bail if ambiguous.
    matches = [s for s in catalogue.values() if target in s.name]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        names = ", ".join(s.name for s in matches)
        raise CommandError(
            f"setting {name!r} is ambiguous on profile {profile.code}; matches {names}"
        )
    known = ", ".join(sorted(catalogue))
    raise CommandError(
        f"setting {name!r} not known on profile {profile.code}. "
        f"Known: {known or '(none — profile has no MACHINESETTINGS)'}"
    )


def _format_setting_result(definition, raw_value: str) -> str:
    """Render a setting's wire-format value back as a human string.

    For ITEM-driven settings, look the raw hex up in the catalogue and
    surface both the friendly name and the raw hex. For step-sliders,
    parse the hex back into an integer.
    """
    cleaned = raw_value.strip().lstrip(",").upper()
    if definition.kind == "step_slider":
        try:
            n = int(cleaned, 16)
        except ValueError:
            return f"{definition.name} = {cleaned!r} (raw)"
        return f"{definition.name} = {n} (0x{cleaned})"
    for item in definition.items:
        if item.value.upper() == cleaned:
            return f"{definition.name} = {item.name} (0x{cleaned})"
    return f"{definition.name} = 0x{cleaned} (unknown — not in catalogue)"


def _r_setting(_spec, client, args, timeout):
    profile = _require_profile(client)
    if not args:
        raise CommandError(
            "setting: expected at least 1 argument (name). "
            "Pass a second argument to write."
        )
    definition = _resolve_setting(profile, args[0])
    if len(args) == 1:
        raw = client.read_setting(definition.p_argument, timeout=timeout)
        return _format_setting_result(definition, raw)
    # Write path. The destructive gate runs in CommandSpec.run() before
    # we get here, so by this point the user has acknowledged the risk.
    try:
        value_hex = definition.normalise_value(args[1])
    except ValueError as exc:
        raise CommandError(str(exc)) from exc
    reply = client.write_setting(definition.p_argument, value_hex, timeout=timeout)
    if reply.lower().startswith("@an:error"):
        raise CommandError(
            f"setting {definition.name} write was refused by the machine "
            f"(reply: {reply!r}). The value passed client-side validation "
            f"but the firmware rejected it — possibly the setting is "
            f"read-only on this firmware or the catalogue's allowed "
            f"values are stale for your EF code."
        )
    return f"set {definition.name} = 0x{value_hex} (reply: {reply})"


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
        name="brews",
        description="per-product brew counters (@TR:32 paginated; 16 pages)",
        arguments=(),
        runner=_r_brews,
    ),
    CommandSpec(
        name="pmode",
        description="programmable-mode slots (@TM:50 + @TM:42); empty on the S8 EB",
        arguments=(),
        runner=_r_pmode,
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
    CommandSpec(
        name="setting",
        description=(
            "read or write one machine setting ('hardness', 'language', "
            "'units', 'auto_off', 'brightness', 'milk_rinsing', "
            "'frother_instructions' on the S8 EB / EF1091); the second "
            "arg writes and is gated"
        ),
        arguments=(
            Argument("name", "setting identifier (substring match OK)"),
            Argument("value", "value to write; omit for read", optional=True),
        ),
        runner=_r_setting,
        dynamic_danger=lambda args: (
            None
            if len(args) < 2
            else (
                "writes a machine setting via @TM:<arg>,<val><checksum>. "
                "The value passes client-side validation against the "
                "machine's XML catalogue (kind, range, allowed items), "
                "but Jura's firmware can still refuse it. A bad write to "
                "language or brightness is easily reversed; a bad "
                "auto-off / hardness can survive on the machine after "
                "this CLI exits."
            )
        ),
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
        description="[destructive] standby command (@AN:02); likely no-op on WiFi",
        arguments=(),
        runner=_r_power_off,
        destructive=True,
        danger=(
            "tries to put the machine into standby via @AN:02 — but this "
            "is a UART / Bluetooth-era command the J.O.E. Android app "
            "does NOT use over WiFi. Live testing against TT237W "
            "(S8 EB) shows the dongle silently ignores it: the request "
            "lands but the machine stays on. Kept in the registry for "
            "completeness; if it actually starts working on your "
            "firmware, please open an issue with the model + firmware "
            "string."
        ),
    ),
    CommandSpec(
        name="brew",
        description="[destructive] start brewing a recipe (@TP:<recipe>)",
        arguments=(
            Argument("recipe", "product code, e.g. 01 (espresso). Firmware-specific."),
        ),
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
