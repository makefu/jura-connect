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

from . import protocol
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
    # @TM:50 reply bytes (per-kind slot counts; summed = total slots).
    # Default matches Kaffeebert: 5 kinds × 4 slots = 20 reported.
    pmode_slot_bytes: bytes = bytes.fromhex("0404040404")
    # @TM:42,<slot> → product code at that slot. None entries (or
    # missing slots) cause the simulator to answer "@tm:C2" mirroring
    # the real EF1091 firmware that reports slots but doesn't expose
    # them over WiFi.
    pmode_slots: dict[int, int] = dataclasses.field(default_factory=dict)

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
        # Unknown -> dongle stays silent
        return None

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
