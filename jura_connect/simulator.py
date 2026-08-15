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
* Read commands ``@TG:43`` (maintenance counters), ``@TG:C0``
  (maintenance percent), ``@TS:01``/``@TS:00`` (lock/unlock display),
  ``@HU?`` (status request that yields one ``@TF:`` frame),
  ``@HE`` (graceful close).
* Periodic unsolicited ``@TF:<hex>`` status broadcasts on the
  connection so reader code in the client can be exercised.
* The full language-download sequence (``@TS:F1`` lock, ``@TT:00``
  inventory, ``@TT:01`` block select, ``@TT:02`` / ``@TT:08`` chunk
  transfers, ``@TT:03`` finish, ``@TV:81`` / ``@TV:82`` display lines)
  — but only when :attr:`SimulatorConfig.allow_language_download` is
  set, since every mutating step of it is a destructive prefix.

It deliberately refuses to model write/process commands (``@TG:24``
cleaning, ``@TG:25`` descale, etc.) -- it answers ``@an:error`` so
tests that accidentally trigger those during development surface a
clear failure instead of silently "working".
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

from . import language, protocol
from .client import _settings_checksum
from .commands import DESTRUCTIVE_PREFIXES

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
__all__ = [
    "DESTRUCTIVE_PREFIXES",
    "LanguageDownloadState",
    "Simulator",
    "SimulatorConfig",
    "run_in_thread",
]


def _default_language_slots() -> dict[int, str]:
    """Slot table a European machine might ship with (slots 0..13)."""
    return {0: "DE", 1: "EN", 2: "FR", 3: "IT", 4: "ES", 5: "PT"}


@dataclasses.dataclass(slots=True)
class LanguageDownloadState:
    """Live state of a language download; tests assert against it."""

    locked: bool = False
    block: str | None = None
    chunks: list[tuple[int, bytes]] = dataclasses.field(default_factory=list)
    finished: bool = False
    display: list[str] = dataclasses.field(default_factory=lambda: ["", ""])

    @property
    def crc(self) -> int:
        """CRC-16/CCITT-FALSE over everything received for this block.

        The 16-bit field a successful ``@tt:0x`` reply carries is
        **not** understood (see PROTOCOL.md §5.14); a running CRC is the
        reading that fits ``@tt:03,FE = CRC_NOT_MATCHING``, so the
        simulator answers one. Nothing in the client interprets it.
        """
        crc = 0xFFFF
        for _addr, data in self.chunks:
            for byte in data:
                crc ^= byte << 8
                for _ in range(8):
                    crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else crc << 1
                    crc &= 0xFFFF
        return crc


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
    # @TM:50 reply bytes (per-kind slot counts; summed = total slots).
    # Default matches Kaffeebert: 5 kinds × 4 slots = 20 reported.
    pmode_slot_bytes: bytes = bytes.fromhex("0404040404")
    # @TM:42,<slot> → product code at that slot. None entries (or
    # missing slots) cause the simulator to answer "@tm:C2" mirroring
    # the real EF1091 firmware that reports slots but doesn't expose
    # them over WiFi.
    pmode_slots: dict[int, int] = dataclasses.field(default_factory=dict)

    # -- language download (PROTOCOL.md §5.14) -------------------------
    # Off by default: every mutating step (@TS:F1, @TT:01/02/03/08,
    # @TV:81/82) is in DESTRUCTIVE_PREFIXES, so a default simulator
    # answers @an:error exactly like it does for a cleaning cycle. Set
    # this to model a machine that actually supports the feature.
    allow_language_download: bool = False
    # Slot index -> two-letter code for the @TT:00 inventory. Slots not
    # listed (up to LANGUAGE_SLOT_COUNT) report the empty marker FFFF.
    language_slots: dict[int, str] = dataclasses.field(
        default_factory=_default_language_slots
    )
    # The only block @TT:01 accepts; anything else answers FE
    # (COMMON_ERROR_BLOCK_NOT_AVAILABLE).
    language_download_block: str = "0B"
    # Reply to @TM:23. "@tm:23" = supported; "@tm:A3" = not supported;
    # "@tm:00" = checksum false; "@tm:23,0C01" = a language is set.
    max_languages_reply: str = "@tm:23"
    # Answer the first @TT:01 with FC (EXECUTION_IN_PROGRESS) to
    # exercise the finish-and-retry path.
    language_select_busy_once: bool = False
    # 0-based index of a chunk the machine refuses, and with which code.
    language_reject_chunk: int | None = None
    language_reject_code: str = "FE"
    # Make @TT:03 fail with FE (CRC_NOT_MATCHING).
    language_finish_crc_error: bool = False

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
        self.language = LanguageDownloadState()
        self._language_select_seen = False

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
            if frame.startswith(b"@TT:08,"):
                # Binary language transfer: the body is raw escaped bytes,
                # so it must be handled before the ASCII decode mangles it.
                reply = self._handle_binary_language_transfer(frame)
            else:
                reply = self._handle_command(text)
            if reply is None:
                continue  # mimic dongle's silent ignore for unknown commands
            if reply == "@@CLOSE":
                return
            self._send(conn, reply)

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

    # -- language download ----------------------------------------------
    def _handle_language_command(self, cmd: str) -> str | None:
        """Model the language-download sequence (PROTOCOL.md §5.14).

        Only reached when ``allow_language_download`` is set; otherwise
        every mutating verb here falls through to the destructive guard.
        The ordering rules (lock before select, select before transfer)
        are the simulator's own invariants — the real machine's reaction
        to an out-of-order sequence has never been observed.
        """
        state = self.language
        if cmd == language.LOCK_COMMAND:
            state.locked = True
            state.chunks.clear()
            state.block = None
            state.finished = False
            self._language_select_seen = False
            return "@ts"
        if cmd.startswith(language.SELECT_BLOCK_COMMAND + ","):
            block = cmd.split(",", 1)[1].strip().upper()
            if not state.locked:
                return "@tt:01,FB"  # WRONG_CONTENT: not in download mode
            if self.config.language_select_busy_once and not self._language_select_seen:
                self._language_select_seen = True
                return "@tt:01,FC"  # EXECUTION_IN_PROGRESS
            if block != self.config.language_download_block.upper():
                return "@tt:01,FE"  # BLOCK_NOT_AVAILABLE
            state.block = block
            state.chunks.clear()
            state.finished = False
            return "@tt:01,FF"
        if cmd.startswith(language.TRANSFER_ASCII_COMMAND + ","):
            body = cmd.split(",", 1)[1].strip()
            if len(body) < 10 or len(body) % 2:
                return "@tt:02,FD"  # WRONG_SYNTAX
            try:
                address = int(body[:8], 16)
                data = bytes.fromhex(body[8:])
            except ValueError:
                return "@tt:02,FD"
            return self._accept_language_chunk("02", address, data)
        if cmd == language.FINISH_COMMAND:
            if state.block is None:
                return "@tt:03,FE"
            if self.config.language_finish_crc_error:
                return "@tt:03,FE"
            state.finished = True
            return f"@tt:03,FF,{state.crc:04X}"
        for index, verb in enumerate(
            (language.DISPLAY_LINE1_COMMAND, language.DISPLAY_LINE2_COMMAND)
        ):
            if cmd.startswith(verb + ","):
                body = cmd[len(verb) + 1 :]
                text, csum = body[:-2], body[-2:].upper()
                if csum != language.display_checksum(text):
                    log.warning("simulator: bad display checksum for %r", cmd)
                    return "@an:error"
                state.display[index] = text
                return f"@tv:{verb[-2:].lower()}"
        return None

    def _accept_language_chunk(self, verb: str, address: int, data: bytes) -> str:
        state = self.language
        if state.block is None:
            return f"@tt:{verb},FA"  # WRONG_LOGIC: no block selected
        if not data:
            return f"@tt:{verb},FC"  # WRONG_LENGTH
        index = len(state.chunks)
        if index == self.config.language_reject_chunk:
            return f"@tt:{verb},{self.config.language_reject_code.upper()}"
        state.chunks.append((address, data))
        return f"@tt:{verb},FF,{state.crc:04X}"

    def _handle_binary_language_transfer(self, frame: bytes) -> str | None:
        """``@TT:08,<escaped addr><escaped len><escaped data>``."""
        if not self.config.allow_language_download:
            log.warning("simulator: refusing destructive command %r", frame[:16])
            return "@an:error"
        body = frame[len(b"@TT:08,") :]
        try:
            plain = language.unescape_binary(body)
        except ValueError:
            return "@tt:08,FD"  # WRONG_SYNTAX
        if len(plain) < 6:
            return "@tt:08,FD"
        address = int.from_bytes(plain[:4], "big")
        declared = int.from_bytes(plain[4:6], "big")
        data = plain[6:]
        if declared != len(data):
            return "@tt:08,FC"  # WRONG_LENGTH
        return self._accept_language_chunk("08", address, data)

    # -- read commands -------------------------------------------------
    def _handle_command(self, cmd: str) -> str | None:
        b = cmd.encode("ascii")
        if self.config.allow_language_download:
            reply = self._handle_language_command(cmd)
            if reply is not None:
                return reply
        if cmd == language.MAX_LANGUAGES_COMMAND:
            return self.config.max_languages_reply
        if cmd == language.LIST_COMMAND:
            if not self.config.allow_language_download:
                return None  # machine doesn't know the verb: stays silent
            slots = "".join(
                f",{index:02X}"
                + (
                    self.config.language_slots[index].encode("ascii").hex().upper()
                    if index in self.config.language_slots
                    else "FFFF"
                )
                for index in range(language.LANGUAGE_SLOT_COUNT)
            )
            return f"@tt:00{slots}"
        for prefix in DESTRUCTIVE_PREFIXES:
            if b.startswith(prefix):
                log.warning("simulator: refusing destructive command %r", cmd)
                return "@an:error"

        if cmd == "@HE":
            return "@@CLOSE"
        if cmd == "@HB":
            return None
        if cmd in ("@HU?",):
            return f"@TF:{self.config.status_payload.hex().upper()}"
        if cmd == "@TG:43":
            return "@tg:43" + self.config.maint_counters.hex().upper()
        if cmd == "@TG:C0":
            return "@tg:C0" + self.config.maint_percent.hex().upper()
        if cmd == "@TS:01":
            self.config.screen_locked = True
            return "@ts"
        if cmd == "@TS:00":
            self.config.screen_locked = False
            # Same verb releases a language-download lock (@TS:F1).
            self.language.locked = False
            return "@ts"
        if cmd == "@TM:50":
            # Per-kind slot counts. Append a fake checksum byte so the
            # client's parser sees a well-formed reply (the checksum
            # algorithm is opaque; the client doesn't currently verify).
            body = self.config.pmode_slot_bytes.hex().upper()
            return f"@tm:50,{body}7A"
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
        if cmd.startswith("@TR:32,"):
            # Paginated product-counter read. Wire format:
            #   request : @TR:32,<page_hex>
            #   reply   : @tr:32,<page_hex>,<8 hex bytes>
            # Each page covers 4 u16 slots from the configured table.
            page_hex = cmd[len("@TR:32,") :].strip()
            try:
                page = int(page_hex, 16)
            except ValueError:
                return "@tr:00"
            if not 0 <= page < 16:
                return "@tr:00"
            start = page * 4
            slots = self.config.product_counters[start : start + 4]
            while len(slots) < 4:
                slots.append(_PC_UNUSED)
            payload = "".join(f"{s & 0xFFFF:04X}" for s in slots)
            return f"@tr:32,{page:02X},{payload}"
        if cmd.startswith("@TR:33,"):
            # Overflow bank: one byte per slot, 8 slots per page.
            overflow = self.config.product_counter_overflow
            if overflow is None:
                return self.config.overflow_bank_reply
            page_hex = cmd[len("@TR:33,") :].strip()
            try:
                page = int(page_hex, 16)
            except ValueError:
                return "@tr:00"
            if not 0 <= page < 16:
                return "@tr:00"
            start = page * 8
            if start >= len(overflow):
                # Bank shorter than 16 pages — the dongle stops answering
                # with data and falls back to the "no such bank" reply.
                return "@tr:00"
            highs = list(overflow[start : start + 8])
            highs += [0x00] * (8 - len(highs))
            payload = "".join(f"{h & 0xFF:02X}" for h in highs)
            return f"@tr:33,{page:02X},{payload}"
        if cmd.startswith("@TR:"):
            return f"@tr:{cmd[4:6]}00"
        if cmd.startswith("@TG:7E") or cmd.startswith("@TG:FF"):
            return "@an:error"  # destructive guard already caught these
        # Unknown -> dongle stays silent
        return None

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
