"""Dongle firmware OTA, dongle restart and milk-cooler update.

**Everything in this module is APK-derived and untested on hardware,
except the read-only `@HU?` milk-cooler status** — an S8 EB / EF1091
answered `@hu:800` (`no_cooler`) to it on 2026-08-16
(`docs/captures/2026-08-16-kaffeebert-s8eb.md` §5). No OTA, restart or
milk-cooler *update* verb has ever been put on a wire.
The wire forms come from the J.O.E. Android app's `WifiCommand*`
classes (`WifiCommandBootloaderMode`, `WifiCommandSendApplicationDat`,
`WifiCommandSendApplicationBin`, `WifiCommandOTAEnd`,
`WifiCommandRestartFrog`, `WifiCommandMilkCoolerUpdateStart` /
`…Status`) and from `CoffeeMachineAdapterWifi.sendFrogToBootloader`,
which is the only place the full ordering is visible. No step of the
OTA sequence has ever been run against a real Smart Connect dongle by
this project, and it must not be run casually: an interrupted or
mismatched image leaves the dongle in bootloader mode with no working
application firmware, and there is no remote recovery — the dongle has
to be replaced or serviced physically.

Consequences for the API:

* Every mutating entry point takes a keyword-only
  ``acknowledge_bricking_risk`` flag and raises
  :class:`FirmwareSafetyError` when it is not ``True``. The check runs
  *before* anything is written to the socket.
* The OTA sequencer is **library-only**: it is deliberately not
  registered in :mod:`jura_connect.commands`, because a CLI invocation
  can only ever perform one step, and a partially applied image is
  exactly what bricks the dongle. See ``docs/PROTOCOL.md`` §5.15.
* No firmware is fetched from anywhere. J.O.E. downloads a ZIP from
  ``digitalassets.jura.com`` and splits it into an nRF-DFU style
  ``.dat`` init packet plus an application ``.bin``; this library only
  accepts the two byte strings the caller supplies and does not
  validate, sign-check or version-check them.

Wire summary (see ``docs/PROTOCOL.md`` §5.15 for the full table)::

    @HB                                   -> @hb:ok | @hb:abort | @hb
    @HO:<dat hex>                         -> @ho:ok | @ho:error
    @HD:<offset:08X><len:04X><chunk hex>  -> @hd:<echo> | @hd:error
    @HE                                   -> @he:ok | @he:error
    @HT:3                                 -> @ht
    @HU                                   -> @hu:(ok|wait|busy|abort|error)
    @HU?                                  -> @hu:<3 hex digits>
"""

from __future__ import annotations

import dataclasses
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids an import cycle
    from .client import JuraClient

#: Application-image chunk size. `CoffeeMachineAdapterWifi` chunks the
#: `.bin` with `CollectionsKt.chunked(0x200)` before handing each window
#: to `WifiCommandSendApplicationBin`.
OTA_CHUNK_BYTES = 512

#: Per-step reply timeouts J.O.E. uses (seconds). Kept for reference and
#: as the default of :func:`run_ota`'s ``timeout``; the app allows 30 s
#: for `@HB` / `@HD:`, 15 s for `@HO:` and its default 5 s for `@HE`.
OTA_STEP_TIMEOUT = 30.0

#: `@HU` reply tokens, mirroring `MilkCoolerUpdateStartParser`.
MILK_COOLER_TOKENS = ("ok", "wait", "busy", "abort", "error")

#: First hex digit of a `@hu:<3 hex>` status reply -> state name. Derived
#: from `MilkCoolerUpdateStatusParser.e()`: "0" is the not-running state
#: (with the low byte reading 100 or more meaning "finished"), "1" is an
#: update in progress with the low byte as a percentage, "8" is the
#: "no milk cooler connected" state the S8 EB answers with (`@hu:800`).
MILK_COOLER_STATES: dict[int, str] = {0: "idle", 1: "updating", 8: "no_cooler"}


class FirmwareError(RuntimeError):
    """Base class for firmware / milk-cooler update failures."""


class FirmwareSafetyError(FirmwareError):
    """A mutating firmware entry point was called without acknowledgement."""


def _require_acknowledgement(acknowledged: bool, what: str, danger: str) -> None:
    if acknowledged:
        return
    raise FirmwareSafetyError(
        f"{what} is not safe to run by accident — {danger}\n"
        "Pass acknowledge_bricking_risk=True if you really mean it."
    )


# --------------------------------------------------------------------- #
# Wire forms (pure functions — no I/O, easy to assert against)
# --------------------------------------------------------------------- #


def bootloader_command() -> str:
    """`@HB` — ask the dongle to jump into its bootloader."""
    return "@HB"


def ota_dat_command(payload: bytes) -> str:
    """`@HO:<hex>` — the DFU init packet (`.dat`), hex-encoded ASCII."""
    if not payload:
        raise ValueError("ota_dat_command: empty .dat payload")
    return "@HO:" + payload.hex().upper()


def ota_bin_command(offset: int, chunk: bytes) -> str:
    """`@HD:<offset:08X><len:04X><hex>` — one application-image window.

    Offset and length are ASCII hex *text*, not packed bytes: the APK
    builds them with ``ByteOperations.h(value, width)``, which formats
    ``%0<width>X`` and then takes the characters' byte values.
    """
    if not chunk:
        raise ValueError("ota_bin_command: empty chunk")
    if offset < 0 or offset > 0xFFFFFFFF:
        raise ValueError(f"ota_bin_command: offset out of range: {offset}")
    if len(chunk) > 0xFFFF:
        raise ValueError(f"ota_bin_command: chunk too large: {len(chunk)} bytes")
    return f"@HD:{offset:08X}{len(chunk):04X}{chunk.hex().upper()}"


def ota_end_command() -> str:
    """`@HE` — finish the OTA session so the dongle applies the image."""
    return "@HE"


def restart_dongle_command() -> str:
    """`@HT:3` — restart the WiFi dongle ("frog")."""
    return "@HT:3"


def milk_cooler_start_command() -> str:
    """`@HU` — start a milk-cooler (Cool Control) firmware update."""
    return "@HU"


def milk_cooler_status_command() -> str:
    """`@HU?` — read the milk-cooler update state. Read-only."""
    return "@HU?"


def split_chunks(data: bytes, size: int = OTA_CHUNK_BYTES) -> list[bytes]:
    """Split an application image into ``size``-byte transfer windows."""
    if size <= 0:
        raise ValueError(f"split_chunks: size must be positive, got {size}")
    return [data[i : i + size] for i in range(0, len(data), size)]


def _display(command: str, limit: int = 48) -> str:
    """Shorten a payload-carrying command for logs and result dicts."""
    if len(command) <= limit:
        return command
    return f"{command[:limit]}…(+{len(command) - limit} chars)"


# --------------------------------------------------------------------- #
# Result types
# --------------------------------------------------------------------- #


@dataclasses.dataclass(slots=True, frozen=True)
class OtaStep:
    """One request/response pair of the OTA sequence."""

    name: str
    command: str  # already shortened for display
    reply: str
    ok: bool
    note: str | None = None

    def format(self) -> str:
        mark = "ok " if self.ok else "FAIL"
        tail = f"  ({self.note})" if self.note else ""
        return f"  [{mark}] {self.name:<12} {self.command} -> {self.reply!r}{tail}"

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "command": self.command,
            "reply": self.reply,
            "ok": self.ok,
            "note": self.note,
        }


@dataclasses.dataclass(slots=True, frozen=True)
class OtaProgress:
    """Progress notification handed to :func:`run_ota`'s callback."""

    stage: str  # bootloader | dat | bin | end | restart
    index: int  # 1-based within the stage
    total: int  # steps in this stage
    percent: float  # overall completion, 0..100
    ok: bool

    def format(self) -> str:
        return f"{self.stage} {self.index}/{self.total} — {self.percent:.1f}%"

    def to_dict(self) -> dict[str, object]:
        return {
            "stage": self.stage,
            "index": self.index,
            "total": self.total,
            "percent": self.percent,
            "ok": self.ok,
        }


@dataclasses.dataclass(slots=True, frozen=True)
class OtaResult:
    """Outcome of a full OTA run."""

    steps: tuple[OtaStep, ...]
    chunks_total: int
    chunks_sent: int
    bytes_sent: int
    completed: bool
    restarted: bool

    @property
    def failed_step(self) -> OtaStep | None:
        """The first step the dongle refused, or ``None`` when all passed."""
        return next((s for s in self.steps if not s.ok), None)

    def format(self) -> str:
        head = (
            f"firmware OTA: {'completed' if self.completed else 'FAILED'} — "
            f"{self.chunks_sent}/{self.chunks_total} chunks, "
            f"{self.bytes_sent} byte(s) sent"
            f"{', dongle restarted' if self.restarted else ''}"
        )
        lines = [head, *(s.format() for s in self.steps)]
        failed = self.failed_step
        if failed is not None:
            lines.append(
                f"  aborted at {failed.name}: the dongle may still be in "
                f"bootloader mode — do NOT power-cycle it blindly, re-run "
                f"the OTA with the same image."
            )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        return {
            "completed": self.completed,
            "restarted": self.restarted,
            "chunks_total": self.chunks_total,
            "chunks_sent": self.chunks_sent,
            "bytes_sent": self.bytes_sent,
            "failed_step": (
                self.failed_step.name if self.failed_step is not None else None
            ),
            "steps": [s.to_dict() for s in self.steps],
        }


@dataclasses.dataclass(slots=True, frozen=True)
class MilkCoolerStatus:
    """Decoded `@hu:<3 hex digits>` milk-cooler update state."""

    raw: str  # the three hex digits, uppercase
    state_code: int
    state: str  # idle | updating | no_cooler | unknown
    percent: int | None  # None when the state carries no progress byte

    @classmethod
    def parse(cls, reply: str) -> MilkCoolerStatus:
        body = reply.strip()
        lowered = body.lower()
        if lowered.startswith("@hu:"):
            body = body[4:]
        elif lowered.startswith("@hu"):
            body = body[3:]
        else:
            raise ValueError(f"not a milk-cooler status reply: {reply!r}")
        body = body.strip().strip(",")
        if len(body) != 3:
            raise ValueError(
                f"milk-cooler status must be 3 hex digits, got {body!r} "
                f"(from {reply!r})"
            )
        try:
            state_code = int(body[0], 16)
            value = int(body[1:], 16)
        except ValueError as exc:
            raise ValueError(f"non-hex milk-cooler status {reply!r}") from exc
        state = MILK_COOLER_STATES.get(state_code, "unknown")
        percent = value if state in ("idle", "updating") else None
        return cls(
            raw=body.upper(), state_code=state_code, state=state, percent=percent
        )

    @property
    def running(self) -> bool:
        """True while the cooler reports an update in progress."""
        return self.state == "updating"

    @property
    def finished(self) -> bool:
        """True once the cooler is idle again *and* reports 100 %.

        `MilkCoolerUpdateStatusParser` clamps the "0" state's low byte to
        100 and treats anything below that as "not running", which is how
        J.O.E. distinguishes "done" from "never started".
        """
        return self.state == "idle" and self.percent is not None and self.percent >= 100

    def format(self) -> str:
        pct = "" if self.percent is None else f" — {self.percent}%"
        return f"milk cooler: {self.state}{pct} (@hu:{self.raw})"

    def to_dict(self) -> dict[str, object]:
        return {
            "raw": self.raw,
            "state": self.state,
            "state_code": self.state_code,
            "percent": self.percent,
            "running": self.running,
            "finished": self.finished,
        }


@dataclasses.dataclass(slots=True, frozen=True)
class MilkCoolerUpdate:
    """Decoded `@HU` reply — the milk-cooler update start acknowledgement."""

    raw: str
    token: str  # ok | wait | busy | abort | error | unknown

    @classmethod
    def parse(cls, reply: str) -> MilkCoolerUpdate:
        body = reply.strip()
        if not body.lower().startswith("@hu"):
            raise ValueError(f"not a milk-cooler update reply: {reply!r}")
        token = body.split(":", 1)[1].strip().lower() if ":" in body else ""
        if token not in MILK_COOLER_TOKENS:
            token = "unknown"
        return cls(raw=body, token=token)

    @property
    def accepted(self) -> bool:
        """True when the dongle took the request (``ok`` / ``wait`` / ``busy``)."""
        return self.token in ("ok", "wait", "busy")

    def format(self) -> str:
        verdict = "accepted" if self.accepted else "refused"
        return f"milk cooler update {verdict}: {self.token} ({self.raw})"

    def to_dict(self) -> dict[str, object]:
        return {"raw": self.raw, "token": self.token, "accepted": self.accepted}


@dataclasses.dataclass(slots=True, frozen=True)
class MilkCoolerUpdateRun:
    """Start acknowledgement plus every status poll of one update run."""

    start: MilkCoolerUpdate
    polls: tuple[MilkCoolerStatus, ...]
    final: MilkCoolerStatus | None
    completed: bool

    def format(self) -> str:
        lines = [
            f"milk cooler update: {'completed' if self.completed else 'incomplete'}",
            "  " + self.start.format(),
        ]
        for status in self.polls:
            pct = "?" if status.percent is None else str(status.percent)
            lines.append(f"  poll: {status.state}, percent {pct}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        return {
            "completed": self.completed,
            "start": self.start.to_dict(),
            "polls": [s.to_dict() for s in self.polls],
            "final": self.final.to_dict() if self.final is not None else None,
        }


# --------------------------------------------------------------------- #
# Sequencer
# --------------------------------------------------------------------- #

_OTA_DANGER = (
    "it rewrites the WiFi dongle's firmware. An interrupted or mismatched "
    "image leaves the dongle in bootloader mode with no application "
    "firmware; there is no remote recovery, the dongle has to be serviced "
    "or replaced physically."
)


def _exchange(
    client: JuraClient,
    name: str,
    command: str,
    *,
    match: str,
    timeout: float,
) -> OtaStep:
    """Send one command, classify the reply, never raise on the wire path.

    Any transport failure becomes a failed :class:`OtaStep` so the
    sequencer can stop cleanly instead of unwinding mid-transfer.
    """
    try:
        reply = client.request(command, match=match, timeout=timeout)
    except TimeoutError as exc:
        return OtaStep(name, _display(command), "", False, f"no reply: {exc}")
    except (ConnectionError, OSError) as exc:
        return OtaStep(name, _display(command), "", False, f"connection lost: {exc}")
    ok = not reply.lower().startswith("@an:error")
    return OtaStep(name, _display(command), reply, ok)


def _classify(step: OtaStep, expected: str) -> OtaStep:
    """Mark a step failed unless its reply is the expected success token."""
    if not step.ok:
        return step
    if step.reply.strip().lower() == expected:
        return step
    return dataclasses.replace(step, ok=False, note=f"expected {expected!r}")


def run_ota(
    client: JuraClient,
    *,
    dat: bytes,
    application: bytes,
    acknowledge_bricking_risk: bool = False,
    chunk_size: int = OTA_CHUNK_BYTES,
    restart: bool = False,
    progress: Callable[[OtaProgress], None] | None = None,
    timeout: float = OTA_STEP_TIMEOUT,
) -> OtaResult:
    """Run the whole OTA sequence: `@HB` → `@HO:` → `@HD:`… → `@HE`.

    ``dat`` is the DFU init packet, ``application`` the raw firmware
    image; both come from the caller (this library never downloads
    firmware). ``restart`` additionally sends `@HT:3` — only ever after
    a successful `@HE`, because restarting a dongle that has a partial
    image is what makes the failure permanent.

    Returns an :class:`OtaResult`; wire-level refusals do **not** raise,
    they end the sequence and are reported through
    :attr:`OtaResult.failed_step`, leaving the session usable.

    APK-derived, never executed against hardware by this project.
    """
    _require_acknowledgement(
        acknowledge_bricking_risk, "run_ota (firmware OTA)", _OTA_DANGER
    )
    if not dat:
        raise ValueError("run_ota: the .dat init packet must not be empty")
    if not application:
        raise ValueError("run_ota: the application image must not be empty")

    chunks = split_chunks(application, chunk_size)
    total_steps = len(chunks) + 3 + (1 if restart else 0)
    steps: list[OtaStep] = []
    sent_chunks = 0
    sent_bytes = 0
    restarted = False

    def _emit(stage: str, index: int, total: int, ok: bool) -> None:
        if progress is None:
            return
        progress(
            OtaProgress(
                stage=stage,
                index=index,
                total=total,
                percent=100.0 * len(steps) / total_steps,
                ok=ok,
            )
        )

    def _finish() -> OtaResult:
        # "completed" is exactly "the dongle acked @HE" — a failed
        # optional restart afterwards does not undo an applied image.
        return OtaResult(
            steps=tuple(steps),
            chunks_total=len(chunks),
            chunks_sent=sent_chunks,
            bytes_sent=sent_bytes,
            completed=any(s.name == "end" and s.ok for s in steps),
            restarted=restarted,
        )

    # 1. Bootloader. `@hb:ok` is the only go-ahead; `@hb:abort` and a bare
    #    `@hb` both mean the dongle declined.
    step = _classify(
        _exchange(
            client,
            "bootloader",
            bootloader_command(),
            match=r"(?i)^(@hb|@an:error)",
            timeout=timeout,
        ),
        "@hb:ok",
    )
    steps.append(step)
    _emit("bootloader", 1, 1, step.ok)
    if not step.ok:
        return _finish()

    # 2. The .dat init packet.
    step = _classify(
        _exchange(
            client,
            "dat",
            ota_dat_command(dat),
            match=r"(?i)^(@ho:|@an:error)",
            timeout=timeout,
        ),
        "@ho:ok",
    )
    steps.append(step)
    _emit("dat", 1, 1, step.ok)
    if not step.ok:
        return _finish()

    # 3. The application image, one 512-byte window at a time. The reply
    #    body is undocumented; `WifiCommandSendApplicationBin` only ever
    #    checks it against the literal "error".
    offset = 0
    for index, chunk in enumerate(chunks, start=1):
        step = _exchange(
            client,
            f"bin[{index}/{len(chunks)}]",
            ota_bin_command(offset, chunk),
            match=r"(?i)^(@hd:|@an:error)",
            timeout=timeout,
        )
        if step.ok and step.reply.strip().lower().removeprefix("@hd:") == "error":
            step = dataclasses.replace(step, ok=False, note="dongle rejected the chunk")
        steps.append(step)
        _emit("bin", index, len(chunks), step.ok)
        if not step.ok:
            return _finish()
        sent_chunks += 1
        sent_bytes += len(chunk)
        offset += len(chunk)

    # 4. End of transfer — this is what makes the dongle apply the image.
    step = _classify(
        _exchange(
            client,
            "end",
            ota_end_command(),
            match=r"(?i)^(@he:|@an:error)",
            timeout=timeout,
        ),
        "@he:ok",
    )
    steps.append(step)
    _emit("end", 1, 1, step.ok)
    if not step.ok:
        return _finish()

    # 5. Optional restart, only on a clean run.
    if restart:
        step = _exchange(
            client,
            "restart",
            restart_dongle_command(),
            match=r"(?i)^(@ht|@an:error)",
            timeout=timeout,
        )
        if step.ok and not step.reply.lower().startswith("@ht"):
            step = dataclasses.replace(step, ok=False, note="expected '@ht'")
        steps.append(step)
        restarted = step.ok
        _emit("restart", 1, 1, step.ok)

    return _finish()


# --------------------------------------------------------------------- #
# Dongle restart
# --------------------------------------------------------------------- #

_RESTART_DANGER = (
    "it reboots the WiFi dongle. The TCP session dies with it, in-flight "
    "commands are lost, and a dongle that is sitting in bootloader mode "
    "after a failed OTA can come back with no working firmware at all."
)


def restart_dongle(
    client: JuraClient,
    *,
    acknowledge_bricking_risk: bool = False,
    timeout: float = 6.0,
) -> str:
    """Send `@HT:3`. Returns the dongle's reply (`@ht`) or a closed note.

    The real dongle drops the connection while rebooting, so a
    connection error here is an expected outcome, not a failure.
    """
    _require_acknowledgement(
        acknowledge_bricking_risk, "restart_dongle (@HT:3)", _RESTART_DANGER
    )
    try:
        return client.request(
            restart_dongle_command(), match=r"(?i)^(@ht|@an:error)", timeout=timeout
        )
    except (ConnectionError, OSError):
        return "(dongle restarting: connection closed by machine)"


# --------------------------------------------------------------------- #
# Milk cooler
# --------------------------------------------------------------------- #

_MILK_COOLER_DANGER = (
    "it starts a firmware update of the connected milk cooler (Cool "
    "Control). The cooler is unusable while it runs, and an update that "
    "is interrupted (cooler unplugged, dongle rebooted) can leave it "
    "needing a service visit."
)


def read_milk_cooler_status(
    client: JuraClient, *, timeout: float = 6.0
) -> MilkCoolerStatus:
    """Read `@HU?` and decode the three-hex-digit state. Read-only.

    Note that the same `@HU?` frame doubles as the status *nudge* the
    client uses to make chatty firmwares emit a `@TF:` frame; a machine
    with no milk cooler answers `@hu:800` (observed on the S8 EB).
    """
    reply = client.request(
        milk_cooler_status_command(), match=r"(?i)^@hu:", timeout=timeout
    )
    return MilkCoolerStatus.parse(reply)


def start_milk_cooler_update(
    client: JuraClient,
    *,
    acknowledge_bricking_risk: bool = False,
    timeout: float = 6.0,
) -> MilkCoolerUpdate:
    """Send `@HU` once and decode the acknowledgement token."""
    _require_acknowledgement(
        acknowledge_bricking_risk,
        "start_milk_cooler_update (@HU)",
        _MILK_COOLER_DANGER,
    )
    reply = client.request(
        milk_cooler_start_command(), match=r"(?i)^@hu:", timeout=timeout
    )
    return MilkCoolerUpdate.parse(reply)


def run_milk_cooler_update(
    client: JuraClient,
    *,
    acknowledge_bricking_risk: bool = False,
    timeout: float = 6.0,
    poll_interval: float = 0.5,
    max_wait: float = 300.0,
    max_restarts: int = 3,
    progress: Callable[[MilkCoolerStatus], None] | None = None,
) -> MilkCoolerUpdateRun:
    """Start a milk-cooler update and poll `@HU?` until it settles.

    Mirrors J.O.E.'s loop (`h8.a`): a ``wait`` / ``busy`` start is
    followed by status polls every 500 ms, and a cooler that reports the
    idle state without having reached 100 % gets another `@HU`. Bounded
    by ``max_wait`` and ``max_restarts`` so a stuck cooler cannot spin
    forever.
    """
    start = start_milk_cooler_update(
        client,
        acknowledge_bricking_risk=acknowledge_bricking_risk,
        timeout=timeout,
    )
    polls: list[MilkCoolerStatus] = []
    if not start.accepted:
        return MilkCoolerUpdateRun(start=start, polls=(), final=None, completed=False)

    deadline = time.monotonic() + max_wait
    completed = False
    restarts = 0
    final: MilkCoolerStatus | None = None
    while time.monotonic() <= deadline:
        status = read_milk_cooler_status(client, timeout=timeout)
        polls.append(status)
        final = status
        if progress is not None:
            progress(status)
        if status.finished:
            completed = True
            break
        if status.state in ("no_cooler", "unknown"):
            break
        if status.state == "idle":
            # Cooler is not running: J.O.E. re-issues @HU here.
            if restarts >= max_restarts:
                break
            restarts += 1
            again = start_milk_cooler_update(
                client, acknowledge_bricking_risk=True, timeout=timeout
            )
            if not again.accepted:
                break
        if poll_interval > 0:
            time.sleep(poll_interval)

    return MilkCoolerUpdateRun(
        start=start, polls=tuple(polls), final=final, completed=completed
    )
