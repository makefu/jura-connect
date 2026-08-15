"""In-process Jura coffee-machine simulator.

A small TCP server that speaks the same WiFi protocol as the real
machine. Uses the *same* :mod:`jura_connect.crypto` and
:mod:`jura_connect.protocol` modules as the client, so encoding /
decoding is verified symmetric by construction (no mocking).

Used by the test-suite via :func:`run_in_thread`, but can also be
launched as a standalone process via ``python -m jura_connect.simulator``.

The simulator models:

* ``@HP:<pin>,<conn_id_hex>,<hash>`` handshake including the "press OK
  on machine" pairing window for an empty hash.
* The batch settings read ``@TM:00,FC`` (the XML's
  ``<BANK Name="Setting">``) and the per-product limit load
  ``@TM:60,<code><csum>``, including their rejection tokens
  (``@tm:00`` / ``@tm:C1``) so the client's fallback paths are covered.
* Read commands ``@TG:43`` (maintenance counters), ``@TG:C0``
  (maintenance percent), ``@TS:01``/``@TS:00`` (lock/unlock display),
  ``@TG:FF`` (cancel the running product step),
  ``@HU?`` (milk-cooler update status — answered ``@hu:800``, *not* a
  status query).
* Every paginated counter bank (``@TR:32``/``@TR:33`` product,
  ``@TR:34``/``@TR:35`` barista, ``@TR:42``..``@TR:45`` daily,
  ``@TR:52``/``@TR:53`` special). Each has its own
  :class:`SimulatorConfig` table, and a table left at ``None`` models a
  machine without that bank: it answers the bare ``@tr:00``.
* Session teardown: an **empty frame**, which is what J.O.E.'s
  ``WifiCommandCloseConnection`` sends. ``@HE`` is accepted as a close
  too because real dongles answer it and older jura-connect releases
  used it, but it is really the OTA-end verb (``WifiCommandOTAEnd``,
  ``@he:ok``) and no longer sent by this library.
* Periodic unsolicited ``@TF:<hex>`` status broadcasts on the
  connection so reader code in the client can be exercised. This is the
  only way status reaches a client — nothing requests it.

It deliberately refuses to model write/process commands (``@TG:24``
cleaning, ``@TG:25`` descale, etc.) -- it answers ``@an:error`` so
tests that accidentally trigger those during development surface a
clear failure instead of silently "working". ``@TP:`` (start product)
is refused the same way *unless* a test opts in with
``SimulatorConfig(allow_brew=True)``, which turns on the full
start -> ``@TB`` -> ``@TV:`` progress stream -> ``@TV:3E`` chain.
"""

from __future__ import annotations

import contextlib
import dataclasses
import logging
import secrets
import socket
import threading
import time
from collections.abc import Iterator

from . import protocol
from .client import OVERFLOW_COUNTER_BANK, _settings_checksum
from .commands import DESTRUCTIVE_PREFIXES
from .profile import RECIPE_BLOB_BYTES
from .progress import (
    BYPASS_MARKER_INDEX,
    PERCENT_INDEX,
    PRODUCT_ARGUMENTS,
    ProgressState,
)

log = logging.getLogger(__name__)

# Maintenance defaults that line up with what the real Kaffeebert returned
# during our probe -- this lets tests assert against realistic data.
DEFAULT_MAINT_COUNTERS = bytes.fromhex("0015000100080158 0E21 005B".replace(" ", ""))
DEFAULT_MAINT_PERCENT = bytes.fromhex("50FF1E")
# Synthetic frame that activates bit 10 (no_beans, info) and bit 34
# (cleaning_alert, process) — picked to exercise both severities the
# test-suite cares about. MSB-first within each byte per the APK's
# Status.a() decoder, so bit N lives at byte N//8 mask 1<<(7-N%8).
DEFAULT_STATUS_PAYLOAD = bytes.fromhex("0020000020000000")

# The real frame Kaffeebert returns at idle: bit 13 (coffee_ready) +
# bit 36 (energy_safe). Used in regression tests so we keep verifying
# the live decode end-to-end.
KAFFEEBERT_IDLE_STATUS_PAYLOAD = bytes.fromhex("0004000008000000")

# Sentinel for "no count" inside an @TR:32 page.
_PC_UNUSED = 0xFFFF

# Every counter bank the simulator can serve:
#   wire command -> (SimulatorConfig attribute, bytes per value, pad).
# The pad is what a page shorter than 8 bytes is filled with: the
# not-configured sentinel for a counter bank, "no overflow yet" for an
# overflow bank. Mirrors jura_connect.client.COUNTER_BANK_SPECS.
_COUNTER_BANK_TABLES: dict[str, tuple[str, int, int]] = {
    "@TR:32": ("product_counters", 2, _PC_UNUSED),
    "@TR:33": ("product_counter_overflow", 1, 0x00),
    "@TR:34": ("barista_counters", 2, _PC_UNUSED),
    "@TR:35": ("barista_counter_overflow", 1, 0x00),
    "@TR:42": ("daily_product_counters", 2, _PC_UNUSED),
    "@TR:43": ("daily_product_counter_overflow", 1, 0x00),
    "@TR:44": ("daily_barista_counters", 2, _PC_UNUSED),
    "@TR:45": ("daily_barista_counter_overflow", 1, 0x00),
    "@TR:52": ("special_counters", 2, _PC_UNUSED),
    "@TR:53": ("special_counter_overflow", 1, 0x00),
}


# Default @TM:60 limit-load table: product code -> the five min/max byte
# pairs for F4, F5, F6, F10, F11 (see client.LIMIT_LOAD_ARGUMENTS).
# Populated for Cappuccino (0x04) with EF1091's own XML ranges expressed
# the way LimitLoadParser reads them — in Step units, so F4's 25..240 ml
# arrive as 05..30 (×5) and F6's 1..45 s as 01..2D (×1). "FFFF" marks a
# parameter the product does not have.
def _default_limit_load() -> dict[int, str]:
    #        F4     F5     F6     F10    F11
    return {0x04: "0530" + "FFFF" + "012D" + "FFFF" + "FFFF"}


def _flip_checksum(csum: str) -> str:
    """Return a deliberately wrong checksum for the negative paths."""
    return f"{int(csum, 16) ^ 0xFF:02X}"


def _default_product_counters() -> list[int]:
    """64-slot product counter table populated with Kaffeebert's numbers.

    Slot 0 is the total brews; other slots are indexed by product code.
    Used as the simulator's default so the test-suite asserts against
    realistic values lifted from the real machine.
    """
    slots = [_PC_UNUSED] * 64
    slots[0] = 3229  # total brews
    slots[0x02] = 78  # espresso
    slots[0x03] = 595  # coffee
    slots[0x04] = 64  # cappuccino
    slots[0x06] = 3  # espresso macchiato
    slots[0x07] = 19  # latte macchiato
    slots[0x08] = 52  # milk foam
    slots[0x0A] = 0  # milk portion
    slots[0x0D] = 903  # hotwater portion
    slots[0x0F] = 238  # powder product
    slots[0x28] = 1019  # americano
    slots[0x29] = 3  # lungo
    slots[0x2B] = 2  # unnamed slot present on Kaffeebert
    slots[0x2C] = 1  # unnamed slot
    slots[0x2E] = 210  # flat white
    slots[0x30] = 20  # espresso doppio
    slots[0x31] = 1  # 2 espressi (EF1091 code)
    slots[0x36] = 10  # 2 coffee (EF1091 code)
    return slots


# DESTRUCTIVE_PREFIXES is re-exported for backwards compatibility with
# tests that still import it from this module; the canonical home is
# :mod:`jura_connect.commands`. The simulator refuses-by-default for the
# same prefixes the client gate refuses-by-default.
__all__ = ["DESTRUCTIVE_PREFIXES", "Simulator", "SimulatorConfig", "run_in_thread"]


@dataclasses.dataclass(slots=True)
class SimulatorConfig:
    """Tweakable knobs for the simulator's behaviour.

    Tests override these to verify each handshake branch (CORRECT,
    WRONG_PIN, WRONG_HASH, ABORTED) and edge cases.
    """

    pin: str = ""  # required PIN; "" disables
    require_user_accept: bool = False  # set True to simulate the on-machine prompt
    user_accept_delay: float = 0.0  # how long the simulated user takes to press OK
    paired_hashes: dict[str, str] = dataclasses.field(default_factory=dict)
    name: str = "TestMachine"
    machine_type: str = "S8 (simulated)"
    fw_version: str = "TT237W V06.11"
    maint_counters: bytes = DEFAULT_MAINT_COUNTERS
    maint_percent: bytes = DEFAULT_MAINT_PERCENT
    status_payload: bytes = DEFAULT_STATUS_PAYLOAD
    status_interval: float = 1.0
    screen_locked: bool = False
    # 64 u16 slots making up the @TR:32 response. Slot 0 = total brews;
    # slots 1..63 are per-product counts indexed by product code, with
    # 0xFFFF marking "this code is not configured on this machine".
    product_counters: list[int] = dataclasses.field(
        default_factory=_default_product_counters
    )
    # Per-slot high bytes of the @TR:33 "Overflow Product Counter" bank,
    # for machines whose XML declares it (34 of the 89 bundled profiles;
    # no S8/Z10 among them). None models a machine without the bank,
    # which answers a bare "@tr:00" — the same shape J.O.E.'s matcher
    # accepts as "bank not implemented".
    product_counter_overflow: list[int] | None = None
    # Reply served for @TR:33 when no overflow table is configured.
    # "@tr:00" is the shape J.O.E.'s matcher accepts as "bank not
    # implemented"; tests override it to model a firmware that answers
    # something else entirely.
    overflow_bank_reply: str = "@tr:00"
    # The remaining counter banks a machine XML may declare, with the
    # same convention: a list of slot values, or None for a machine that
    # answers the bare "@tr:00" (= bank not implemented). All default to
    # None, matching the S8 EB, which declares @TR:32 alone.
    #
    # The special bank's slots are fixed functions, not product codes
    # (see jura_connect.client.SPECIAL_COUNTER_SLOTS); the barista and
    # daily banks index the same product-code space as @TR:32. Neither
    # the barista nor the daily banks appear anywhere in the J.O.E. APK,
    # so their wire behaviour here is XML-derived, not observed.
    special_counters: list[int] | None = None
    special_counter_overflow: list[int] | None = None
    barista_counters: list[int] | None = None
    barista_counter_overflow: list[int] | None = None
    daily_product_counters: list[int] | None = None
    daily_product_counter_overflow: list[int] | None = None
    daily_barista_counters: list[int] | None = None
    daily_barista_counter_overflow: list[int] | None = None
    # @TM:50 reply bytes (per-kind slot counts; summed = total slots).
    # Default matches Kaffeebert: 5 kinds × 4 slots = 20 reported.
    pmode_slot_bytes: bytes = bytes.fromhex("0404040404")
    # @TM:42,<slot> → product code at that slot. None entries (or
    # missing slots) cause the simulator to answer "@tm:C2" mirroring
    # the real EF1091 firmware that reports slots but doesn't expose
    # them over WiFi.
    pmode_slots: dict[int, int] = dataclasses.field(default_factory=dict)

    # -- brewing ------------------------------------------------------
    # Off by default: @TP: is a destructive prefix and the simulator's
    # job is to make an accidental brew in a test scream (@an:error).
    # Tests that want the whole start -> progress -> done chain opt in.
    allow_brew: bool = False
    # How many @TV:41 progress frames a modelled brew emits before the
    # @TV:3E (ENJOY) completion frame.
    brew_progress_steps: int = 4
    # Delay between the frames of a modelled brew. 0 keeps tests fast;
    # raise it to watch the stream at human speed.
    brew_progress_interval: float = 0.0
    # Target water ticks reported as the maximum in the progress frames.
    brew_target_ticks: int = 0x1E

    # Machine settings: P_Argument (uppercase hex) -> stored hex value.
    # Defaults populated to mirror EF1091's <MACHINESETTINGS> defaults
    # so the test-suite can read/write the same arguments the J.O.E.
    # app exercises against a real S8 EB.
    settings: dict[str, str] = dataclasses.field(
        default_factory=lambda: {
            "02": "10",  # hardness = 16 decimal
            "13": "211E",  # auto-off = 30min
            "08": "00",  # units = ML
            "09": "02",  # language = English
            "0A": "04",  # brightness = 40%
            "04": "00",  # milk rinsing = Automatic
            "62": "01",  # frother instructions = On
        }
    )

    # Batch settings read (@TM:00,FC). The CommandArgument the simulated
    # machine's XML declares — the values are answered in this order.
    # None models a machine with no batch read at all, which replies
    # with the bare rejection token below (32 of the 89 bundled profiles
    # carry no <MACHINESETTINGS> block, so no bank either).
    settings_bank_arguments: str | None = "02080913"
    # Rejection token for the batch read. "@tm:00" is the short "frame
    # refused" answer the dongle already uses for settings writes.
    settings_bank_reject_reply: str = "@tm:00"
    # Model a firmware that only accepts the checksummed request form
    # (@TM:00,FC<csum>) — which of the two forms a real machine wants is
    # unknown, so both are exercised.
    settings_bank_requires_checksum: bool = False
    # Corrupt the reply checksum to exercise the client's verification.
    settings_bank_corrupt_checksum: bool = False

    # Limit load (@TM:60,<product code><csum>): product code -> the five
    # min/max byte pairs. Codes outside the table get "@tm:C1" — the
    # APK's "machine does not support product programming" token.
    limit_load: dict[int, str] = dataclasses.field(default_factory=_default_limit_load)
    limit_load_corrupt_checksum: bool = False
    limit_load_echo_wrong_code: bool = False


def _blob_is_accepted(blob: str) -> bool:
    """Mirror the machine's accept/ignore rule for a ``@TP:`` blob.

    PROTOCOL.md §5.9, live-verified on an S8 EB: only the 16-byte,
    ``0x00``-padded blob whose byte 8 is ``0x01`` actually brews. A bare
    product code or the old FF-padded layout is ACKed with ``@tp:00``
    and then silently ignored — no ``@TB``, no ``@TV:``.
    """
    if len(blob) != RECIPE_BLOB_BYTES * 2:
        return False
    try:
        data = bytes.fromhex(blob)
    except ValueError:
        return False
    return data[8] == 0x01


def _brew_frames(blob: str, config: SimulatorConfig) -> list[str]:
    """The unsolicited frames a real dongle pushes after an accepted brew.

    Models what PROTOCOL.md §5.9 records from a live S8 EB: a ``@TB``
    brew-start marker, a run of ``@TV:41<product>…`` progress frames
    with a rising tick count and percentage, then ``@TV:3E<product>``
    (``ENJOY``) when the cup is done. The frame *layout* is APK-derived
    (§5.10): a 16-byte payload whose 14-byte value window carries the
    current/target water ticks at slots 2/3 and the percentage at slot
    12. Slot 6 is ``0xFF`` so state ``41`` reads as ``HOTWATER_VOLUME``
    rather than ``BYPASS_WATER_VOLUME``.
    """
    product = blob[:2].upper() if len(blob) >= 2 else "00"
    frames = ["@TB"]
    steps = max(1, config.brew_progress_steps)
    target = config.brew_target_ticks & 0xFF
    for step in range(1, steps + 1):
        window = bytearray(len(PRODUCT_ARGUMENTS))
        window[2] = round(target * step / steps)
        window[3] = target
        window[BYPASS_MARKER_INDEX] = 0xFF
        window[PERCENT_INDEX] = round(100 * step / steps)
        head = f"{ProgressState.HOTWATER_VOLUME:02X}{product}"
        frames.append(f"@TV:{head}{window.hex().upper()}")
    done = bytearray(len(PRODUCT_ARGUMENTS))
    frames.append(f"@TV:{ProgressState.ENJOY:02X}{product}{done.hex().upper()}")
    return frames


class Simulator:
    """A single-connection-at-a-time TCP server speaking the WiFi protocol."""

    def __init__(
        self,
        config: SimulatorConfig | None = None,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self.config = config or SimulatorConfig()
        self.host = host
        self.port = port
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        # Public for tests to inspect:
        self.sent_commands: list[bytes] = []
        self.handshakes: list[tuple[str, str, str]] = []  # (pin, conn_id, hash)
        # Frames queued by a command handler to be pushed after its
        # reply (the brew progress stream).
        self._queued: list[str] = []

    # -- lifecycle -----------------------------------------------------
    @property
    def address(self) -> tuple[str, int]:
        if self._server is None:
            raise RuntimeError("simulator not started")
        return self._server.getsockname()[:2]

    def start(self) -> None:
        if self._server is not None:
            return
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(1)
        s.settimeout(0.2)
        self._server = s
        self.port = s.getsockname()[1]
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        s, self._server = self._server, None
        if s is not None:
            with contextlib.suppress(OSError):
                s.close()
        t, self._thread = self._thread, None
        if t is not None:
            t.join(timeout=2.0)

    def __enter__(self) -> Simulator:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- serving loop --------------------------------------------------
    def _serve_forever(self) -> None:
        assert self._server is not None
        while not self._stop.is_set():
            try:
                conn, _addr = self._server.accept()
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                return
            try:
                self._handle(conn)
            except Exception:  # noqa: BLE001
                log.exception("simulator: client handler crashed")
            finally:
                with contextlib.suppress(OSError):
                    conn.close()

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(0.5)
        reader = protocol.FrameReader(conn)
        last_status_ts = 0.0
        authenticated = False
        while not self._stop.is_set():
            # Periodic unsolicited @TF: status frame.
            now = time.monotonic()
            if (
                authenticated
                and self.config.status_interval > 0
                and now - last_status_ts >= self.config.status_interval
            ):
                self._emit_status(conn)
                last_status_ts = now
            try:
                frame = reader.next_frame(timeout=0.2)
            except (TimeoutError, socket.timeout):
                continue
            except ConnectionError:
                return
            self.sent_commands.append(frame)
            text = frame.decode("ascii", errors="replace").rstrip("\r\n")
            log.debug("simulator <- %r", text)
            if text.startswith("@HP:"):
                reply = self._handle_handshake(text)
                self._send(conn, reply)
                if reply.startswith("@hp4"):
                    authenticated = True
                else:
                    # WRONG_*/ABORTED -> close, matching real machine behaviour
                    return
                continue
            if not authenticated:
                # Real dongle drops unauthenticated commands silently.
                continue
            reply = self._handle_command(text)
            if reply is None:
                continue  # mimic dongle's silent ignore for unknown commands
            if reply == "@@CLOSE":
                return
            self._send(conn, reply)
            self._drain_queue(conn)

    # -- handshake -----------------------------------------------------
    def _handle_handshake(self, cmd: str) -> str:
        # "@HP:<pin>,<conn_id_hex>,<hash>" -- the only command parsed here.
        try:
            _, body = cmd.split(":", 1)
            pin, conn_id_hex, given_hash = body.split(",", 2)
        except ValueError:
            return "@hp5:02"
        self.handshakes.append((pin, conn_id_hex, given_hash))

        # PIN check
        if self.config.pin and pin != self.config.pin:
            return "@hp5"

        # Pairing flow: empty hash from a new conn_id triggers the dongle's
        # "Connect" dialog on its own screen.
        existing = self.config.paired_hashes.get(conn_id_hex)
        if not given_hash:
            if existing is not None:
                # Caller wiped its hash but the dongle still has one -> reject.
                return "@hp5:02"
            if self.config.require_user_accept:
                time.sleep(self.config.user_accept_delay)
            # Generate a fresh 64-char hash and register the conn_id.
            new_hash = secrets.token_hex(32).upper()
            self.config.paired_hashes[conn_id_hex] = new_hash
            return f"@hp4:{new_hash}"

        if existing is None:
            return "@hp5:01"
        if existing.lower() != given_hash.lower():
            return "@hp5:01"
        return "@hp4"

    # -- read commands -------------------------------------------------
    def _handle_command(self, cmd: str) -> str | None:
        b = cmd.encode("ascii")
        if cmd.startswith("@TP:") and self.config.allow_brew:
            # Opt-in only. An accepted blob is ACKed with a bare "@tp"
            # and followed by the frames the real dongle pushes: @TB,
            # then the @TV: progress stream, then @TV:3E (ENJOY). A blob
            # the machine would ignore gets "@tp:00" and nothing else.
            blob = cmd[len("@TP:") :].strip()
            if not _blob_is_accepted(blob):
                return "@tp:00"
            self._queued.extend(_brew_frames(blob, self.config))
            return "@tp"
        for prefix in DESTRUCTIVE_PREFIXES:
            if b.startswith(prefix):
                log.warning("simulator: refusing destructive command %r", cmd)
                return "@an:error"

        if cmd == "":
            # J.O.E.'s WifiCommandCloseConnection: an empty frame ends
            # the session. This is what JuraClient.close() sends.
            return "@@CLOSE"
        if cmd == "@HE":
            # Really WifiCommandOTAEnd (firmware update), but dongles do
            # answer it and pre-0.13 clients closed with it, so keep
            # tearing the session down here.
            return "@@CLOSE"
        if cmd == "@HB":
            return None
        if cmd == "@HU?":
            # WifiCommandMilkCoolerUpdateStatus — matcher @hu:[0-9a-fA-F]{3}.
            # Kaffeebert answers @hu:800. Status is NOT part of this
            # reply; it arrives with the next unsolicited @TF: frame.
            return "@hu:800"
        if cmd == "@TG:FF":
            # WifiCommandCancelProductStep — cancel the running step.
            return "@tg:FF"
        if cmd == "@TG:43":
            return "@tg:43" + self.config.maint_counters.hex().upper()
        if cmd == "@TG:C0":
            return "@tg:C0" + self.config.maint_percent.hex().upper()
        if cmd == "@TS:01":
            self.config.screen_locked = True
            return "@ts"
        if cmd == "@TS:00":
            self.config.screen_locked = False
            return "@ts"
        if cmd == "@TM:50":
            # Per-kind slot counts. Append a fake checksum byte so the
            # client's parser sees a well-formed reply (the checksum
            # algorithm is opaque; the client doesn't currently verify).
            body = self.config.pmode_slot_bytes.hex().upper()
            return f"@tm:50,{body}7A"
        if cmd.upper().startswith("@TM:00,FC"):
            return self._handle_settings_bank(cmd)
        if cmd.upper().startswith("@TM:60,"):
            return self._handle_limit_load(cmd)
        if cmd.startswith("@TM:42,"):
            try:
                slot = int(cmd[len("@TM:42,") :], 16)
            except ValueError:
                return "@tm:C2"
            product = self.config.pmode_slots.get(slot)
            if product is None:
                return "@tm:C2"
            # Real reply format: @tm:42,<slot>,<product_code>...<checksum>
            return f"@tm:42,{slot:02X},{product:02X}"
        if cmd.startswith("@TM:"):
            arg_full = cmd[4:]
            # Distinguish writes (@TM:<arg>,<val><checksum>) from reads
            # by the presence of a comma. Per the J.O.E. APK's
            # WifiCommandWritePMode and ByteOperations.d, the trailing
            # two hex chars are a checksum over <arg>,<val>.
            if "," in arg_full:
                arg, _, rest = arg_full.partition(",")
                arg = arg.upper()
                if len(rest) < 2:
                    return "@an:error"
                value_hex = rest[:-2].upper()
                csum_recv = rest[-2:].upper()
                payload_for_csum = f"{arg},{value_hex}"
                expected = _settings_checksum(payload_for_csum)
                if csum_recv != expected:
                    log.warning(
                        "simulator: bad settings checksum for %s (got %s, expected %s)",
                        cmd,
                        csum_recv,
                        expected,
                    )
                    return "@an:error"
                self.config.settings[arg] = value_hex
                return f"@tm:{arg.lower()}"
            arg = arg_full.upper()
            stored = self.config.settings.get(arg)
            if stored is not None:
                # Real dongle appends the same ByteOperations.d checksum
                # used on the write side; the client verifies it.
                csum = _settings_checksum(f"{arg},{stored}")
                return f"@tm:{arg.lower()},{stored}{csum}"
            # Unknown address — echo the high nibble like the real dongle.
            return f"@tm:{arg_full[:2].lower()}"
        if cmd.startswith("@TR:") and "," in cmd:
            return self._counter_bank_page(cmd)
        if cmd.startswith("@TR:"):
            return f"@tr:{cmd[4:6]}00"
        # Unknown -> dongle stays silent
        return None

    # -- queued (unsolicited) frames -----------------------------------
    def _drain_queue(self, conn: socket.socket) -> None:
        """Push frames a handler queued behind its reply, in order."""
        queued, self._queued = self._queued, []
        for frame in queued:
            if self.config.brew_progress_interval > 0:
                time.sleep(self.config.brew_progress_interval)
            self._send(conn, frame)

    # -- counter banks -------------------------------------------------
    def _counter_bank_page(self, cmd: str) -> str | None:
        """Serve one page of a paginated counter bank.

        Wire format, identical for every bank:

            request : @TR:<bank>,<page_hex>
            reply   : @tr:<bank>,<page_hex>,<8 hex bytes>

        The 8-byte payload holds 4 ``u16`` slots for a counter bank or 8
        ``u8`` high bytes for an overflow bank. A machine without the
        bank answers the bare ``@tr:00`` J.O.E.'s matcher accepts as
        "not implemented", and a bank shorter than the client's page
        budget answers the same once its table runs out — the "bank ends
        here" case the client keeps partial results for.
        """
        bank, _, page_hex = cmd.partition(",")
        bank = bank.upper()
        entry = _COUNTER_BANK_TABLES.get(bank)
        if entry is None:
            # Unknown bank — the dongle echoes it back with a 00 tail.
            return f"@tr:{cmd[4:6]}00"
        attr, width, pad = entry
        table = getattr(self.config, attr)
        if table is None:
            return (
                self.config.overflow_bank_reply
                if bank == OVERFLOW_COUNTER_BANK
                else "@tr:00"
            )
        try:
            page = int(page_hex.strip(), 16)
        except ValueError:
            return "@tr:00"
        per_page = 8 // width
        start = page * per_page
        if page < 0 or start >= len(table):
            return "@tr:00"
        values = list(table[start : start + per_page])
        values += [pad] * (per_page - len(values))
        mask = (1 << (8 * width)) - 1
        payload = "".join(f"{v & mask:0{width * 2}X}" for v in values)
        return f"@tr:{bank[4:6].lower()},{page:02X},{payload}"

    # -- batch settings read / limit load ------------------------------
    def _handle_settings_bank(self, cmd: str) -> str:
        """Answer the XML's ``<BANK Name="Setting" Command="@TM:00,FC">``.

        The reply layout mirrors ``client._parse_settings_bank_reply``:
        the stored values of the bank's arguments concatenated in
        declaration order (self-delimited by the ItemSlider type tags)
        plus the usual ``ByteOperations.d`` checksum over
        ``"00,<values>"``. Nothing about it is hardware-verified — no
        J.O.E. code path issues this command — so the simulator also
        models the rejection token that makes the client fall back to
        per-setting reads.
        """
        tail = cmd[len("@TM:00,FC") :].strip().upper()
        expected_request_csum = _settings_checksum("00,FC")
        if tail and tail != expected_request_csum:
            return "@an:error"
        if self.config.settings_bank_requires_checksum and not tail:
            return self.config.settings_bank_reject_reply
        declared = self.config.settings_bank_arguments
        if not declared:
            return self.config.settings_bank_reject_reply
        values: list[str] = []
        for i in range(0, len(declared), 2):
            stored = self.config.settings.get(declared[i : i + 2].upper())
            if stored is None:
                # A bank argument this machine has no value for: the
                # whole batch read is refused rather than half-answered.
                return self.config.settings_bank_reject_reply
            values.append(stored.upper())
        body = "".join(values)
        csum = _settings_checksum(f"00,{body}")
        if self.config.settings_bank_corrupt_checksum:
            csum = _flip_checksum(csum)
        return f"@tm:00,{body}{csum}"

    def _handle_limit_load(self, cmd: str) -> str:
        """Answer ``@TM:60,<product code><csum>`` (``WifiCommandReadLimitLoad``).

        Reply shape from the APK's ``LimitLoadParser``:
        ``@tm:60,<code><5 min/max byte pairs><checksum>``.
        """
        body = cmd[len("@TM:60,") :].strip()
        if len(body) < 4:
            return "@an:error"
        code_hex, csum_recv = body[:2].upper(), body[2:].upper()
        if csum_recv != _settings_checksum(f"60,{code_hex}"):
            log.warning("simulator: bad limit-load checksum for %r", cmd)
            return "@an:error"
        try:
            code = int(code_hex, 16)
        except ValueError:
            return "@an:error"
        blob = self.config.limit_load.get(code)
        if blob is None:
            # "Machine does not support Product Programming".
            return "@tm:C1"
        echoed = code_hex
        if self.config.limit_load_echo_wrong_code:
            echoed = f"{(code + 1) & 0xFF:02X}"
        payload = f"{echoed}{blob.upper()}"
        csum = _settings_checksum(f"60,{payload}")
        if self.config.limit_load_corrupt_checksum:
            csum = _flip_checksum(csum)
        return f"@tm:60,{payload}{csum}"

    # -- status emission -----------------------------------------------
    def _emit_status(self, conn: socket.socket) -> None:
        msg = f"@TF:{self.config.status_payload.hex().upper()}"
        self._send(conn, msg)

    def _send(self, conn: socket.socket, payload: str) -> None:
        log.debug("simulator -> %r", payload)
        body = (payload + "\r\n").encode("ascii")
        # The protocol framing terminates on the FIRST \r\n inside the
        # plaintext, so the reply itself must not embed a CRLF. Strip the
        # trailing CRLF we just added before encoding to avoid double-wrapping.
        protocol.send_frame(conn, payload.encode("ascii"))
        del body  # unused; keeping for traceability


# --------------------------------------------------------------------- #
# Test harness helpers
# --------------------------------------------------------------------- #


@contextlib.contextmanager
def run_in_thread(config: SimulatorConfig | None = None) -> Iterator[Simulator]:
    """Context manager: start a simulator, yield it, tear it down."""
    sim = Simulator(config)
    sim.start()
    try:
        yield sim
    finally:
        sim.stop()


def _cli() -> None:  # pragma: no cover - manual debugging utility
    import argparse

    ap = argparse.ArgumentParser(description="Standalone Jura simulator")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=51515)
    ap.add_argument("--pin", default="")
    ap.add_argument("--name", default="Sim")
    ap.add_argument(
        "--require-accept",
        action="store_true",
        help="simulate the on-machine 'Connect' prompt by delaying the @hp4",
    )
    ap.add_argument("--accept-delay", type=float, default=2.0)
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG, format="%(message)s")
    cfg = SimulatorConfig(
        pin=args.pin,
        require_user_accept=args.require_accept,
        user_accept_delay=args.accept_delay,
        name=args.name,
    )
    with run_in_thread(cfg) as sim:
        print(f"simulator listening on {sim.address[0]}:{sim.address[1]}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":  # pragma: no cover
    _cli()
