"""Named-command registry for the WiFi protocol.

Maps user-friendly names (``info``, ``counters``, ``clean``,
``set-pin`` …) onto the underlying wire commands so callers — both
the CLI and library users — never have to remember the hex codes.
The CLI's ``command`` subcommand is a thin shell over :func:`run_named`.

The registry is split into two tiers:

* **Read-only commands** (``info``, ``counters``, ``status``, …) — safe
  to invoke at any time. The CLI lets these through unconditionally.

* **Destructive commands** (``clean``, ``descale``, ``set-pin``, …) —
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
import re
from collections.abc import Callable, Sequence

from . import profile
from .client import (
    BARISTA_COUNTER_BANK,
    DAILY_BARISTA_COUNTER_BANK,
    DAILY_COUNTER_RESET,
    DAILY_PRODUCT_COUNTER_BANK,
    SPECIAL_COUNTER_BANK,
    JuraClient,
)
from .profile import RECIPE_BLOB_BYTES
from .progress import ProgressLog

CommandRunner = Callable[["CommandSpec", JuraClient, "tuple[str, ...]", float], object]


# Wire-level prefixes that mutate the machine. These are the patterns
# both :class:`~jura_connect.simulator.Simulator` refuses-by-default and
# the registry refuses-by-default through the destructive gate.
DESTRUCTIVE_PREFIXES: tuple[bytes, ...] = (
    b"@TG:21",  # CappuClean
    b"@TG:23",  # CappuRinse
    b"@TG:24",  # Cleaning
    b"@TG:25",  # Descale
    b"@TG:26",  # FilterChange
    # J.O.E. calls this WifiCommandCancelQualityAssistantStep (bare form
    # skips one step, the 32×F argument skips all). On TT237W it was
    # observed to zero the maintenance counters instead — see the
    # ``skip-quality-step`` danger string. Gated under either reading.
    b"@TG:7E",
    b"@TF:02",  # restart machine
    b"@TF:05",  # zero the <DAILYCOUNTER> banks (irreversible)
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
    """One positional argument accepted by a :class:`CommandSpec`.

    ``variadic=True`` marks a trailing argument that soaks up zero or
    more values (like ``nargs="*"``). It must be the last argument in a
    :class:`CommandSpec`, and implies ``optional``.
    """

    name: str
    help: str
    optional: bool = False  # if True, the arg may be omitted on the CLI
    variadic: bool = False  # if True, soaks up all remaining values


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
        parts = []
        for a in self.arguments:
            if a.variadic:
                parts.append(f"[<{a.name}>...]")
            elif a.optional:
                parts.append(f"[<{a.name}>]")
            else:
                parts.append(f"<{a.name}>")
        return f"{self.name} " + " ".join(parts)

    def run(
        self,
        client: JuraClient,
        args: Sequence[str],
        *,
        timeout: float,
        allow_destructive: bool = False,
    ) -> CommandResult:
        required = sum(1 for a in self.arguments if not a.optional and not a.variadic)
        has_variadic = any(a.variadic for a in self.arguments)
        upper = float("inf") if has_variadic else len(self.arguments)
        if not required <= len(args) <= upper:
            expected_summary = (
                ", ".join(
                    a.name + ("..." if a.variadic else "?" if a.optional else "")
                    for a in self.arguments
                )
                or "none"
            )
            upper_txt = "∞" if has_variadic else str(len(self.arguments))
            raise CommandError(
                f"{self.name}: expected {required}..{upper_txt} "
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


def _r_cancel(_spec, client, _args, timeout):
    """Cancel the product step the machine is currently running.

    ``@TG:FF`` is J.O.E.'s ``WifiCommandCancelProductStep``: the "abort
    this brew / stop the running step" verb, which is why it is *not*
    gated (earlier versions of this library mislabelled it a broad
    reset). The app matches the acknowledgement as ``@tg:FF``; we accept
    any ``@tg`` reply, case-insensitively, because firmware families
    differ in case and trailing payload.
    """
    return client.request("@TG:FF", match=r"(?i)^@tg", timeout=timeout)


def _r_progress(_spec, client, args, timeout):
    """Watch the unsolicited ``@TV:`` stream and decode every frame.

    Read-only: it sends nothing, it only listens. Returns as soon as the
    machine reports ``ENJOY`` (the product is done) or after the watch
    window elapses, whichever comes first.
    """
    seconds = timeout
    if args:
        try:
            seconds = float(args[0])
        except ValueError as exc:
            raise CommandError(
                f"progress: <seconds> must be a number, got {args[0]!r}"
            ) from exc
        if seconds <= 0:
            raise CommandError(f"progress: <seconds> must be > 0, got {args[0]!r}")
    return ProgressLog(frames=tuple(client.follow_progress(timeout=seconds)))


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


def _r_descale(_spec, client, _args, timeout):
    return client.request("@TG:25", timeout=timeout)


def _r_filter_change(_spec, client, _args, timeout):
    return client.request("@TG:26", timeout=timeout)


def _r_cappu_clean(_spec, client, _args, timeout):
    return client.request("@TG:21", timeout=timeout)


def _r_cappu_rinse(_spec, client, _args, timeout):
    return client.request("@TG:23", timeout=timeout)


#: Argument J.O.E. appends to ``@TG:7E`` to skip *every* remaining
#: quality-assistant step at once (32 hex F's).
_SKIP_ALL_QUALITY_STEPS = "F" * 32


def _r_skip_quality_step(_spec, client, args, timeout):
    """Send ``@TG:7E`` — one quality-assistant step, or all of them.

    ``scope`` is ``one`` (default, bare ``@TG:7E``) or ``all``
    (``@TG:7E,FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF``), matching J.O.E.'s
    ``WifiCommandCancelQualityAssistantStep``. Both forms are gated:
    the same opcode has been observed zeroing the maintenance counters
    on TT237W.
    """
    scope = (args[0] if args else "one").strip().lower()
    if scope not in ("one", "all"):
        raise CommandError(
            f"skip-quality-step: scope must be 'one' or 'all', got {args[0]!r}"
        )
    cmd = "@TG:7E" if scope == "one" else f"@TG:7E,{_SKIP_ALL_QUALITY_STEPS}"
    return client.request(cmd, timeout=timeout)


def _r_restart(_spec, client, _args, timeout):
    return _request_or_disconnect(client, "@TF:02", timeout, "machine restarting")


def _r_power_off(_spec, client, _args, timeout):
    return _request_or_disconnect(client, "@AN:02", timeout, "machine powering off")


# CLI override alias -> recipe-parameter kind. Two tiers so the help
# text (built from _BREW_KEY_ALIASES) doesn't leak the canonical kind
# names as duplicate keys: friendly aliases first, then every canonical
# kind maps to itself so the full name works too.
_BREW_KEY_ALIASES = {
    "water": profile.KIND_WATER_AMOUNT,
    "ml": profile.KIND_WATER_AMOUNT,
    "strength": profile.KIND_COFFEE_STRENGTH,
    "temp": profile.KIND_TEMPERATURE,
    "milk": profile.KIND_MILK_FOAM_AMOUNT,
    "milk_foam": profile.KIND_MILK_FOAM_AMOUNT,
}
_BREW_KEY_TO_KIND = {
    **_BREW_KEY_ALIASES,
    **{kind: kind for kind in profile.RECIPE_PARAM_KINDS},
}

#: A full verbatim recipe blob is 16 bytes = 32 hex chars. Only treat
#: input of at least this length as a raw blob, so short product names
#: that happen to be all-hex ("dec", "feed", "face") stay names.
_VERBATIM_BLOB_MIN_HEX = RECIPE_BLOB_BYTES * 2


def _r_brew(_spec, client, args, timeout):
    """Start a product. Three input forms for ``<product>``:

    * a product name from the machine profile (``espresso``,
      ``hotwater`` — unambiguous prefixes OK) — requires a profile;
    * a 2-hex product code (``0D``) — resolved against the profile;
    * a full recipe blob (32+ hex chars) — sent verbatim, escape hatch
      for firmware variants with a different layout.

    Optional ``param=value`` args override the XML defaults, e.g.
    ``water=220 strength=6 temp=high``. Values are validated against
    the profile's catalogue before anything goes on the wire.
    """
    target = _ascii_arg("product", args[0])
    overrides: dict[str, int | str] = {}
    for raw in args[1:]:
        key, sep, value = raw.partition("=")
        if not sep or not value:
            raise CommandError(
                f"brew: expected param=value (e.g. water=220), got {raw!r}"
            )
        kind = _BREW_KEY_TO_KIND.get(key.strip().lower())
        if kind is None:
            known = ", ".join(sorted(_BREW_KEY_TO_KIND))
            raise CommandError(f"brew: unknown parameter {key!r}. Known: {known}")
        overrides[kind] = value.strip()

    # A full recipe blob (>= 32 hex chars, even length) is trusted and
    # sent verbatim. Shorter all-hex strings are product codes/names.
    is_blob = (
        bool(re.fullmatch(r"[0-9A-Fa-f]+", target))
        and len(target) % 2 == 0
        and len(target) >= _VERBATIM_BLOB_MIN_HEX
    )
    if is_blob:
        if overrides:
            raise CommandError(
                "brew: param=value overrides cannot be combined with a "
                "raw recipe blob — bake the values into the blob instead."
            )
        return client.request(f"@TP:{target}", timeout=timeout)
    if client.profile is None:
        raise CommandError(
            "brew: product names and codes need a machine profile. Pair "
            "with --machine-type <EF_code> (or pass --machine-type to "
            "'command'); see 'jura-connect machine-types'. A full 32-hex "
            "recipe blob is accepted without a profile as an escape hatch."
        )
    try:
        definition = client.resolve_product(target)
        recipe = definition.build_recipe_hex(overrides)
    except ValueError as exc:
        raise CommandError(str(exc)) from exc
    return client.request(f"@TP:{recipe}", timeout=timeout)


# -- products discovery -------------------------------------------------

#: Recipe kinds whose blob byte is NOT confirmed against real hardware.
_NOT_LIVE_VERIFIED_KINDS = frozenset(
    {
        profile.KIND_BYPASS,
        profile.KIND_MILK_BREAK,
    }
)
_NOT_LIVE_VERIFIED_CAVEAT = "not live-verified — may misbrew, verify on your hardware"

#: kind -> (unit label, wire-encoding note) for ranged parameters.
_KIND_UNIT: dict[str, tuple[str, str]] = {
    profile.KIND_WATER_AMOUNT: ("ml", "value ÷ 5 = 5 ml wire ticks"),
    profile.KIND_BYPASS: ("ml", "value ÷ 5 = 5 ml wire ticks"),
    profile.KIND_MILK_AMOUNT: ("s", "seconds, sent as-is"),
    profile.KIND_MILK_FOAM_AMOUNT: ("s", "seconds, sent as-is"),
    profile.KIND_MILK_BREAK: ("s", "seconds, sent as-is"),
}


def _cli_keys_for_kind(kind: str) -> tuple[str, ...]:
    """Every ``brew`` param=value key that maps to ``kind`` (short first)."""
    keys = [k for k, v in _BREW_KEY_TO_KIND.items() if v == kind]
    return tuple(sorted(keys, key=lambda k: (len(k), k)))


@dataclasses.dataclass(slots=True, frozen=True)
class ParamInfo:
    """One brewable recipe parameter, described for a CLI user.

    ``cli_keys`` are the ``brew <product> <key>=<value>`` keys that set
    this parameter; ``settable`` is True exactly when it has at least
    one such key. Some product params (e.g. ``milk_amount`` on the S8)
    are reported by the machine XML but are NOT overridable via
    ``brew`` — they carry no CLI key and are shown read-only under
    their kind name. Enumerated params carry ``choices`` (``(name,
    value_hex)`` in menu order); ranged params carry ``minimum`` /
    ``maximum`` / ``step`` with a ``unit`` and ``encoding`` note.
    ``live_verified`` is False for parameters whose wire byte has not
    been confirmed on hardware (bypass / milk).
    """

    kind: str
    cli_keys: tuple[str, ...]
    settable: bool  # overridable via `brew` param=value (i.e. has a CLI key)
    default: object  # int|None (ranged) or the default item name (enum)
    default_hex: str | None
    choices: tuple[tuple[str, str], ...]  # (name, value_hex), enum only
    minimum: int | None
    maximum: int | None
    step: int | None
    unit: str | None
    encoding: str | None
    live_verified: bool

    def format(self) -> str:
        # Never emit a blank key column: fall back to the kind name for
        # params with no `brew` CLI alias.
        label = " / ".join(self.cli_keys) if self.settable else self.kind
        if self.choices:
            choices = ", ".join(f"{name}={val}" for name, val in self.choices)
            default = f"{self.default}" if self.default is not None else "-"
            body = f"choices: {choices}"
        else:
            rng = f"{self.minimum}–{self.maximum}" if self.maximum is not None else "?"
            step = f", step {self.step}" if self.step else ""
            unit = f" {self.unit}" if self.unit else ""
            enc = f" ({self.encoding})" if self.encoding else ""
            default = f"{self.default}" if self.default is not None else "-"
            body = f"range {rng}{unit}{step}{enc}"
        if not self.settable:
            annot = "  (read-only: not settable via 'brew')"
        elif not self.live_verified:
            annot = f"  [{_NOT_LIVE_VERIFIED_CAVEAT}]"
        else:
            annot = ""
        return f"    {label:<28} default {default:<8} {body}{annot}"

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "cli_keys": list(self.cli_keys),
            "settable": self.settable,
            "default": self.default,
            "default_hex": self.default_hex,
            "choices": [{"name": n, "value": v} for n, v in self.choices],
            "minimum": self.minimum,
            "maximum": self.maximum,
            "step": self.step,
            "unit": self.unit,
            "encoding": self.encoding,
            "live_verified": self.live_verified,
        }


@dataclasses.dataclass(slots=True, frozen=True)
class ProductInfo:
    """One brewable product and its recipe parameters."""

    code: int
    name: str  # resolvable snake_case name (what ``brew <name>`` accepts)
    raw_name: str
    params: tuple[ParamInfo, ...]

    def format(self) -> str:
        head = f"{self.name}  (0x{self.code:02X})"
        if not self.params:
            return head + "\n    (no adjustable parameters)"
        return "\n".join([head, *(p.format() for p in self.params)])

    def to_dict(self) -> dict[str, object]:
        return {
            "code": f"{self.code:02X}",
            "name": self.name,
            "raw_name": self.raw_name,
            "params": [p.to_dict() for p in self.params],
        }


@dataclasses.dataclass(slots=True, frozen=True)
class ProductCatalogue:
    """Brewable products of a machine, with allowed parameter values.

    Built from the loaded :class:`~jura_connect.profile.MachineProfile`
    — the same source :meth:`~jura_connect.client.JuraClient.brew` and
    ``resolve_product`` use — so ``name`` is exactly what
    ``brew <name>`` accepts. Only active (brewable) products are listed.
    """

    machine_code: str
    products: tuple[ProductInfo, ...]

    def format(self) -> str:
        header = f"{self.machine_code} — {len(self.products)} brewable product(s)"
        blocks = [p.format() for p in self.products]
        return "\n\n".join([header, *blocks])

    def to_dict(self) -> dict[str, object]:
        return {
            "machine_code": self.machine_code,
            "products": [p.to_dict() for p in self.products],
        }


def _param_info(param) -> ParamInfo:
    kind = param.kind
    cli_keys = _cli_keys_for_kind(kind)
    # A param is overridable via `brew` only when it has a CLI key. Some
    # machine-reported params (e.g. milk_amount on the S8) have none.
    settable = bool(cli_keys)
    live = kind not in _NOT_LIVE_VERIFIED_KINDS
    unit, encoding = _KIND_UNIT.get(kind, (None, None))
    if param.items:  # enumerated (strength / temperature)
        choices = tuple((it.name, it.value) for it in param.items)
        default_name: str | None = None
        default_hex: str | None = None
        if param.default is not None:
            default_hex = f"{param.default:02X}"
            match = next((it for it in param.items if it.value == default_hex), None)
            default_name = match.name if match is not None else default_hex
        return ParamInfo(
            kind=kind,
            cli_keys=cli_keys,
            settable=settable,
            default=default_name,
            default_hex=default_hex,
            choices=choices,
            minimum=None,
            maximum=None,
            step=None,
            unit=None,
            encoding=None,
            live_verified=live,
        )
    return ParamInfo(
        kind=kind,
        cli_keys=cli_keys,
        settable=settable,
        default=param.default,
        default_hex=None,
        choices=(),
        minimum=param.minimum,
        maximum=param.maximum,
        step=param.step,
        unit=unit,
        encoding=encoding,
        live_verified=live,
    )


def _r_products(_spec, client, _args, _timeout):
    prof = client.profile
    if prof is None:
        raise CommandError(
            "products: needs a machine profile. Pair with "
            "--machine-type <EF_code> (or pass --machine-type to "
            "'command'); see 'jura-connect machine-types'."
        )
    products = tuple(
        ProductInfo(
            code=p.code,
            name=p.name,
            raw_name=p.raw_name,
            params=tuple(_param_info(pp) for pp in p.params),
        )
        for p in prof.products
        if p.active
    )
    return ProductCatalogue(machine_code=prof.code, products=products)


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
    item = definition.item_from_hex(cleaned)
    if item is not None:
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


def _r_settings(_spec, client, _args, timeout):
    _require_profile(client)
    return client.read_all_settings(timeout=timeout)


def _r_limits(_spec, client, args, timeout):
    _require_profile(client)
    try:
        return client.read_limit_load(_ascii_arg("product", args[0]), timeout=timeout)
    except ValueError as exc:
        raise CommandError(str(exc)) from exc


# --------------------------------------------------------------------- #
# Counter banks beyond @TR:32 (see docs/PROTOCOL.md §5.5)
# --------------------------------------------------------------------- #


def _read_bank(client: JuraClient, bank: str, timeout: float) -> object:
    """Read one counter bank, or explain why there is nothing to read.

    ``JuraClient.read_counter_bank`` returns ``None`` both for "your
    machine's profile does not declare this bank" and for "the machine
    answered @tr:00". Neither is an error — most machines have most of
    these banks missing — so the command reports it as text instead of
    raising.
    """
    result = client.read_counter_bank(bank, timeout_per_page=timeout)
    if result is not None:
        return result
    machine = client.profile.code if client.profile is not None else "this machine"
    return (
        f"{machine} does not implement the {bank} counter bank "
        f"(not declared in its XML, or answered @tr:00)"
    )


def _r_special_counters(_spec, client, _args, timeout):
    return _read_bank(client, SPECIAL_COUNTER_BANK, timeout)


def _r_barista_counters(_spec, client, _args, timeout):
    return _read_bank(client, BARISTA_COUNTER_BANK, timeout)


def _r_daily_brews(_spec, client, _args, timeout):
    return _read_bank(client, DAILY_PRODUCT_COUNTER_BANK, timeout)


def _r_daily_barista_counters(_spec, client, _args, timeout):
    return _read_bank(client, DAILY_BARISTA_COUNTER_BANK, timeout)


def _r_reset_daily_counters(_spec, client, _args, timeout):
    return client.request(DAILY_COUNTER_RESET, timeout=timeout)


# --------------------------------------------------------------------- #
# Programmable-recipe (PMode) runners — APK-derived, untested
# --------------------------------------------------------------------- #
#
# The wire prefixes ``@TM:41,`` and ``@TM:42,`` deliberately do NOT go
# into :data:`DESTRUCTIVE_PREFIXES`: that list is matched as a byte
# prefix, and the very same prefixes carry the *reads* (``pmode``,
# ``pmode-product``) — gating them would break the read path. Only the
# payload length tells a read from a write. These commands are gated
# statically instead, exactly like the ``@TM:<arg>,<val><csum>``
# settings write, which is not in the prefix list for the same reason.

#: Shared danger text for both PMode writes.
_PMODE_WRITE_DANGER = (
    "overwrites a user-programmable recipe stored on the machine — the "
    "previous contents of that product's settings (or of that slot) are "
    "gone the moment the machine ACKs, and there is no undo: the "
    "protocol has no read-modify-restore and no factory-default command "
    "for a single slot. Read the current values with 'pmode' / "
    "'pmode-product' first if you want to be able to put them back. The "
    "wire format is derived from the J.O.E. APK and has never been "
    "verified against a real machine."
)

#: A verbatim PMode blob is 17 bytes = 34 hex chars (see
#: :data:`jura_connect.profile.PMODE_BLOB_BYTES`).
_VERBATIM_PMODE_BLOB_HEX = profile.PMODE_BLOB_BYTES * 2


def _pmode_overrides(name: str, args: Sequence[str]) -> dict[str, int | str]:
    """Parse ``param=value`` args with the same keys ``brew`` accepts."""
    overrides: dict[str, int | str] = {}
    for raw in args:
        key, sep, value = raw.partition("=")
        if not sep or not value:
            raise CommandError(
                f"{name}: expected param=value (e.g. water=220), got {raw!r}"
            )
        kind = _BREW_KEY_TO_KIND.get(key.strip().lower())
        if kind is None:
            known = ", ".join(sorted(_BREW_KEY_TO_KIND))
            raise CommandError(f"{name}: unknown parameter {key!r}. Known: {known}")
        overrides[kind] = value.strip()
    return overrides


def _r_pmode_product(_spec, client, args, timeout):
    product = _ascii_arg("product", args[0])
    try:
        stored = client.read_pmode_product(product, timeout=timeout)
    except ValueError as exc:
        raise CommandError(str(exc)) from exc
    if stored is None:
        # @tm:C1 — the same "this firmware doesn't expose it" shape the
        # `pmode` command reports for @tm:C2, not an error.
        return (
            f"pmode-product: the machine answered @tm:C1 for {product!r} "
            "(= 'product programming is not supported'). This firmware "
            "does not expose per-product PMode settings over WiFi."
        )
    return stored


def _r_pmode_set_product(_spec, client, args, timeout):
    overrides = _pmode_overrides("pmode-set-product", args[1:])
    try:
        return client.write_pmode_product(
            _ascii_arg("product", args[0]), overrides, timeout=timeout
        )
    except ValueError as exc:
        raise CommandError(str(exc)) from exc


def _r_pmode_set_slot(_spec, client, args, timeout):
    raw_slot = _ascii_arg("slot", args[0])
    try:
        slot = int(raw_slot, 0)
    except ValueError as exc:
        raise CommandError(
            f"pmode-set-slot: slot must be a decimal or 0x-hex index, got {raw_slot!r}"
        ) from exc
    overrides = _pmode_overrides("pmode-set-slot", args[2:])
    try:
        return client.write_pmode_slot(
            slot, _ascii_arg("product", args[1]), overrides, timeout=timeout
        )
    except ValueError as exc:
        raise CommandError(str(exc)) from exc


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
        description="parsed status / active alerts (waits for a pushed @TF: frame)",
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
        name="products",
        description=(
            "list brewable products and their allowed 'brew' param=value "
            "ranges/choices (from the machine profile; no machine I/O)"
        ),
        arguments=(),
        runner=_r_products,
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
        name="cancel",
        description="cancel the running product step (@TG:FF); the 'abort this brew' verb",
        arguments=(),
        runner=_r_cancel,
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
        name="descale",
        description="[destructive] start descaling cycle (@TG:25)",
        arguments=(),
        runner=_r_descale,
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
        name="skip-quality-step",
        description=(
            "[destructive] skip a quality-assistant step (@TG:7E); "
            "'all' skips every remaining step. Has also been seen to "
            "zero the maintenance counters"
        ),
        arguments=(
            Argument(
                "scope",
                "'one' (default) sends bare @TG:7E; 'all' sends the "
                "@TG:7E,FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF skip-everything form",
                optional=True,
            ),
        ),
        runner=_r_skip_quality_step,
        destructive=True,
        danger=(
            "@TG:7E has two known readings and we cannot tell them apart "
            "without firing it. In the J.O.E. Android app it is "
            "WifiCommandCancelQualityAssistantStep — it skips one "
            "quality-assistant step ('all' skips every remaining one), "
            "so the machine stops asking for a service it believes is "
            "due. On a TT237W S8 EB an accidental @TG:7E instead zeroed "
            "every maintenance counter (cleaning / descale / filter), "
            "leaving the machine with no record of when it was last "
            "serviced. Both outcomes are irreversible — there is no undo "
            "and no way to restore the previous counter values."
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
        description=(
            "[destructive] start brewing a product (@TP:<recipe blob>); "
            "run 'products' to discover valid names and param=value ranges"
        ),
        arguments=(
            Argument(
                "product",
                "profile product name ('espresso', 'hotwater'…; prefix "
                "OK), 2-hex product code, or a full recipe blob (32+ hex). "
                "Run 'products' to list valid names",
            ),
            Argument(
                "param=value",
                "recipe override(s): water=<ml> strength=<level> "
                "temp=<low|normal|high> milk=<s> milk_break=<s> "
                "bypass=<ml>; defaults come from the machine XML. Run "
                "'products' for each product's allowed values",
                optional=True,
                variadic=True,
            ),
        ),
        runner=_r_brew,
        destructive=True,
        danger=(
            "immediately starts brewing the given product. The machine "
            "will draw water, run the grinder, and dispense at the "
            "spout — make sure a suitable cup is in place; there is no "
            "remote abort. Quantities are validated against the machine "
            "XML, but a wrong product still wastes beans, water, or milk."
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
    # ---- read-only (appended) -------------------------------------------
    CommandSpec(
        name="progress",
        description=(
            "watch the machine's @TV: product-progress stream and decode "
            "it (read-only; stops on the ENJOY frame or after <seconds>)"
        ),
        arguments=(
            Argument(
                "seconds",
                "how long to watch before giving up; defaults to the command timeout",
                optional=True,
            ),
        ),
        runner=_r_progress,
    ),
    # ---- counter banks beyond @TR:32 ------------------------------------
    CommandSpec(
        name="special-counters",
        description=(
            "special counter bank (@TR:52 paginated; 4 pages) — cold brew, "
            "sweet foam & friends; declared by 14 of the 89 profiles"
        ),
        arguments=(),
        runner=_r_special_counters,
    ),
    CommandSpec(
        name="barista-counters",
        description=(
            "barista counter bank (@TR:34 paginated) — declared by 4 "
            "profiles; not read by the J.O.E. app, so untested on hardware"
        ),
        arguments=(),
        runner=_r_barista_counters,
    ),
    CommandSpec(
        name="daily-brews",
        description=(
            "per-product brew counters since the last daily reset "
            "(@TR:42 paginated); not read by the J.O.E. app"
        ),
        arguments=(),
        runner=_r_daily_brews,
    ),
    CommandSpec(
        name="daily-barista-counters",
        description=(
            "barista counters since the last daily reset (@TR:44 "
            "paginated); not read by the J.O.E. app"
        ),
        arguments=(),
        runner=_r_daily_barista_counters,
    ),
    CommandSpec(
        name="reset-daily-counters",
        description="[destructive] zero the daily counter banks (@TF:05)",
        arguments=(),
        runner=_r_reset_daily_counters,
        destructive=True,
        danger=(
            "irreversibly zeroes every <DAILYCOUNTER> bank (@TR:42..@TR:45 "
            "— today's brews per product). The machine keeps its lifetime "
            "counters, but the daily numbers are gone with no undo: read "
            "'daily-brews' first if you want to keep them. The command is "
            "the XML's own Reset verb; no J.O.E. code path sends it, so "
            "what a real machine does with it has never been observed."
        ),
    ),
    # ---- read-only, appended ------------------------------------------
    CommandSpec(
        name="settings",
        description=(
            "read every machine setting; tries the XML's batch bank "
            "(@TM:00,FC) and falls back to one @TM:<arg> per setting"
        ),
        arguments=(),
        runner=_r_settings,
    ),
    CommandSpec(
        name="limits",
        description=(
            "live per-product parameter limits (@TM:60); the ranges the "
            "machine allows right now, as opposed to the XML's static ones"
        ),
        arguments=(Argument("product", "product name or 2-hex code"),),
        runner=_r_limits,
    ),
    # ---- programmable recipes (PMode) -----------------------------------
    CommandSpec(
        name="pmode-product",
        description=(
            "read one product's stored programmable-recipe settings "
            "(@TM:41,<code>); APK-derived, hardware-untested"
        ),
        arguments=(Argument("product", "profile product name or 2-hex code"),),
        runner=_r_pmode_product,
    ),
    CommandSpec(
        name="pmode-set-product",
        description=(
            "[destructive] overwrite a product's programmable-recipe "
            "settings (@TM:41,<blob>)"
        ),
        arguments=(
            Argument(
                "product",
                "profile product name, 2-hex code, or a full "
                f"{_VERBATIM_PMODE_BLOB_HEX}-hex blob sent verbatim",
            ),
            Argument(
                "param=value",
                "recipe override(s), same keys as 'brew'; defaults come "
                "from the machine XML",
                optional=True,
                variadic=True,
            ),
        ),
        runner=_r_pmode_set_product,
        destructive=True,
        danger=_PMODE_WRITE_DANGER,
    ),
    CommandSpec(
        name="pmode-set-slot",
        description=(
            "[destructive] assign a product (with settings) to a "
            "programmable-recipe slot (@TM:42,<slot>,<blob>)"
        ),
        arguments=(
            Argument("slot", "slot index, decimal or 0x-prefixed hex"),
            Argument(
                "product",
                "profile product name, 2-hex code, or a full "
                f"{_VERBATIM_PMODE_BLOB_HEX}-hex blob sent verbatim",
            ),
            Argument(
                "param=value",
                "recipe override(s), same keys as 'brew'",
                optional=True,
                variadic=True,
            ),
        ),
        runner=_r_pmode_set_slot,
        destructive=True,
        danger=_PMODE_WRITE_DANGER,
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
