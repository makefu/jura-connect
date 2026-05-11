"""TCP client for the Jura WiFi protocol (unset-PIN flow supported).

Layers:

* :class:`JuraConnection` -- raw framed transport (write/read encoded frames).
* :class:`JuraClient`     -- handshake (`@HP:`) + structured read operations.

Wire framing and crypto live in :mod:`jura_connect.protocol` / :mod:`jura_connect.crypto`
and are shared with the in-tree :mod:`jura_connect.simulator`.

Handshake (matches the J.O.E. Android app's ``WifiCommandConnectionSetup``)::

    -> @HP:<pin>,<conn_id_hex>,<auth_hash>\\r\\n
    <- @hp4                  CORRECT, no new hash
       @hp4:<hash>           CORRECT, persist ``<hash>`` for next time
       @hp5 / @hp5:00        WRONG_PIN  -- machine wants a PIN, none given
       @hp5:01               WRONG_HASH -- conn-id unknown / hash stale
       @hp5:02               ABORTED    -- machine refused

Initial pairing on a machine without a PIN configured:

1. The client opens a TCP session and sends ``@HP:,<conn_id_hex>,``
   (both ``pin`` and ``auth_hash`` empty).
2. The coffee machine pops up a **Connect** dialog on its own display.
3. The user accepts on the machine.
4. The machine replies with ``@hp4:<hash>`` carrying a 64-hex-char auth
   token, which the client surfaces via ``HandshakeResult.new_hash``.

The caller persists ``new_hash`` and passes it as ``auth_hash`` on
subsequent runs to skip the on-machine confirmation.
"""

from __future__ import annotations

import dataclasses
import re
import socket
import threading
import time
import uuid
from collections.abc import Callable, Iterator

from . import protocol
from .profile import MachineProfile

DEFAULT_PORT = 51515
DEFAULT_CONN_ID = "jura-connect"

# 60 seconds is what we observed empirically as a comfortable upper bound:
# the dongle keeps the dialog up roughly that long. The J.O.E. app uses 40 s
# (WifiCommand timeoutAfterSeconds=40L) -- we go a bit higher for humans.
DEFAULT_PAIR_TIMEOUT = 60.0


def _conn_id_hex(conn_id: str) -> str:
    """Hex-encode each character (matches ``ExtensionsKt.c`` in the APK)."""
    return "".join(f"{ord(c) & 0xFF:02X}" for c in conn_id)


class HandshakeError(RuntimeError):
    """Authentication / setup with the coffee machine failed."""


class PairingTimeout(HandshakeError):
    """The machine never sent ``@hp4``/``@hp5`` within the allotted window."""


@dataclasses.dataclass(slots=True)
class HandshakeResult:
    """Outcome of one ``@HP:`` round-trip.

    ``state`` is one of ``CORRECT``, ``WRONG_PIN``, ``WRONG_HASH``,
    ``ABORTED``, or ``REJECTED:<code>`` for unrecognised tails.
    """

    code: str
    state: str
    new_hash: str | None


_HP_RE = re.compile(r"^@hp([45])(?::(.*))?$")


def _classify(reply: str) -> HandshakeResult:
    m = _HP_RE.match(reply.strip())
    if not m:
        raise HandshakeError(f"unexpected handshake reply: {reply!r}")
    major, rest = m.group(1), m.group(2)
    if major == "4":
        return HandshakeResult(reply.strip(), "CORRECT", rest or None)
    code = rest or ""
    if code in ("", "00"):
        state = "WRONG_PIN"
    elif code == "01":
        state = "WRONG_HASH"
    elif code == "02":
        state = "ABORTED"
    else:
        state = f"REJECTED:{code}"
    return HandshakeResult(reply.strip(), state, None)


class JuraConnection:
    """Raw framed TCP connection. One ``send`` / ``recv_frame`` per message."""

    def __init__(
        self,
        address: str,
        port: int = DEFAULT_PORT,
        *,
        connect_timeout: float = 5.0,
        read_timeout: float = 10.0,
    ) -> None:
        self.address = address
        self.port = port
        self._sock: socket.socket | None = None
        self._reader: protocol.FrameReader | None = None
        self._lock = threading.Lock()
        self._read_timeout = read_timeout
        self._connect_timeout = connect_timeout

    def connect(self) -> None:
        if self._sock is not None:
            return
        s = socket.create_connection(
            (self.address, self.port), timeout=self._connect_timeout
        )
        s.settimeout(self._read_timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._sock = s
        self._reader = protocol.FrameReader(s)

    def close(self) -> None:
        s, self._sock = self._sock, None
        self._reader = None
        if s is None:
            return
        try:
            s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        s.close()

    def __enter__(self) -> JuraConnection:
        self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def connected(self) -> bool:
        return self._sock is not None

    def send(self, payload: bytes, *, key: int | None = None) -> None:
        if self._sock is None:
            raise OSError("not connected")
        with self._lock:
            protocol.send_frame(self._sock, payload, key=key)

    def send_str(self, payload: str, *, key: int | None = None) -> None:
        self.send(payload.encode("ascii"), key=key)

    def recv_frame(self, *, timeout: float | None = None) -> bytes:
        if self._reader is None:
            raise OSError("not connected")
        return self._reader.next_frame(timeout=timeout)

    def recv_str(self, *, timeout: float | None = None) -> str:
        return self.recv_frame(timeout=timeout).decode("ascii", errors="replace")


class JuraClient:
    """High-level WiFi client.

    Lifecycle::

        client = JuraClient("192.168.1.42", conn_id="my-host",
                            auth_hash="<persisted-or-empty>")
        result = client.connect()           # short timeout if hash is known
        # OR
        result = client.pair(on_user_prompt=print)  # long wait, user confirms

        client.read_maintenance_counter()   # structured query
        ...
        client.close()

    The handshake step blocks on the TCP receive until either ``@hp4`` /
    ``@hp5`` arrives or the requested timeout expires. Unsolicited
    ``@TF:`` status frames that show up *before* the handshake reply are
    captured into :attr:`status_history`.
    """

    def __init__(
        self,
        address: str,
        port: int = DEFAULT_PORT,
        *,
        pin: str = "",
        conn_id: str = DEFAULT_CONN_ID,
        auth_hash: str = "",
        connect_timeout: float = 5.0,
        read_timeout: float = 10.0,
        profile: MachineProfile | None = None,
    ) -> None:
        self.conn = JuraConnection(
            address,
            port,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
        )
        self.pin = pin
        self.conn_id = conn_id
        self.auth_hash = auth_hash
        self.handshake: HandshakeResult | None = None
        self.status_history: list[str] = []
        # Optional MachineProfile (from jura_connect.profile). When set,
        # status bit names + product names come from the profile's
        # ALERTS / PRODUCTS sections rather than the EF536 baseline.
        self.profile = profile

    # -- lifecycle -----------------------------------------------------
    def connect(self, *, timeout: float = 15.0) -> HandshakeResult:
        """Open the TCP session and run ``@HP:`` with a short timeout.

        Use :meth:`pair` instead when you need the long, user-interactive
        window in which the machine shows its on-screen Connect prompt.
        """
        self.conn.connect()
        return self._do_handshake(timeout=timeout)

    def pair(
        self,
        *,
        timeout: float = DEFAULT_PAIR_TIMEOUT,
        on_user_prompt: Callable[[str], None] | None = None,
    ) -> HandshakeResult:
        """Run the unset-PIN pairing flow.

        Opens the connection, sends ``@HP:,<conn_id_hex>,`` and blocks for
        up to ``timeout`` seconds while the user accepts on the machine.
        Calls ``on_user_prompt`` once with a one-line instruction so the
        UI / CLI can tell the user to press OK on the coffee machine.

        Returns the same :class:`HandshakeResult` as :meth:`connect`. On
        ``CORRECT`` with a new hash, the new hash is captured in
        :attr:`auth_hash` and exposed via ``result.new_hash`` so callers
        can persist it.
        """
        self.auth_hash = ""
        self.pin = ""
        self.conn.connect()
        if on_user_prompt is not None:
            on_user_prompt(
                "Coffee machine should be showing a 'Connect' prompt — "
                "press OK on the machine to accept this device "
                f"(waiting up to {timeout:.0f}s)."
            )
        return self._do_handshake(timeout=timeout)

    def close(self) -> None:
        # Best-effort polite close. Some firmwares accept @HE, others ignore it.
        try:
            self.send_command("@HE")
        except Exception:  # noqa: BLE001
            pass
        self.conn.close()

    def __enter__(self) -> JuraClient:
        self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- handshake -----------------------------------------------------
    def _do_handshake(self, *, timeout: float) -> HandshakeResult:
        cmd = f"@HP:{self.pin},{_conn_id_hex(self.conn_id)},{self.auth_hash}"
        self.conn.send_str(cmd)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PairingTimeout(
                    f"no @hp4/@hp5 reply within {timeout:.1f}s — "
                    "did the user accept on the machine?"
                )
            try:
                reply = self.conn.recv_str(timeout=remaining)
            except (TimeoutError, socket.timeout) as exc:
                raise PairingTimeout(
                    f"no @hp4/@hp5 reply within {timeout:.1f}s"
                ) from exc
            if reply.startswith(("@TF:", "@TV:")):
                self.status_history.append(reply)
                continue
            result = _classify(reply)
            if result.state == "CORRECT" and result.new_hash:
                self.auth_hash = result.new_hash
            self.handshake = result
            return result

    # -- request/response ---------------------------------------------
    def send_command(self, cmd: str) -> None:
        """Fire-and-forget command (no response wait)."""
        self.conn.send_str(cmd)

    def request(
        self,
        cmd: str,
        *,
        match: str | re.Pattern[str] | None = None,
        timeout: float = 6.0,
    ) -> str:
        """Send ``cmd`` and return the first matching reply.

        ``match`` may be a regex source or compiled pattern. When ``None``
        the first reply that isn't an unsolicited ``@TV:``/``@TF:`` status
        frame is returned. Status frames seen along the way are appended
        to :attr:`status_history`.
        """
        if isinstance(match, str):
            pattern: re.Pattern[str] | None = re.compile(match)
        else:
            pattern = match
        self.conn.send_str(cmd)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"no reply to {cmd!r} within {timeout}s")
            try:
                reply = self.conn.recv_str(timeout=remaining)
            except (TimeoutError, socket.timeout) as exc:
                raise TimeoutError(f"no reply to {cmd!r} within {timeout}s") from exc
            if reply.startswith(("@TF:", "@TV:")):
                self.status_history.append(reply)
                if pattern is None:
                    continue
                if not pattern.search(reply):
                    continue
                return reply
            if pattern is None:
                return reply
            if pattern.search(reply):
                return reply

    # -- raw helpers ---------------------------------------------------
    def iter_frames(self, *, until: float | None = None) -> Iterator[str]:
        """Yield every incoming frame as a decoded ASCII string.

        ``until`` is an optional absolute deadline (``time.monotonic()``).
        Useful for watching ``@TF:`` / ``@TV:`` status streams in tests
        and CLI ``--watch`` modes.
        """
        while True:
            if until is not None:
                remaining = until - time.monotonic()
                if remaining <= 0:
                    return
                try:
                    yield self.conn.recv_str(timeout=remaining)
                except (TimeoutError, socket.timeout):
                    return
            else:
                yield self.conn.recv_str()

    # -- structured reads ---------------------------------------------
    def read_maintenance_counter(
        self, *, timeout: float = 6.0
    ) -> "MaintenanceCounters":
        """Read the maintenance counter bank (``@TG:43``)."""
        reply = self.request("@TG:43", match=r"^@tg:43", timeout=timeout)
        return MaintenanceCounters.parse(reply)

    def read_maintenance_percent(self, *, timeout: float = 6.0) -> "MaintenancePercent":
        """Read the maintenance percent bank (``@TG:C0``)."""
        reply = self.request("@TG:C0", match=r"^@tg:C0", timeout=timeout)
        return MaintenancePercent.parse(reply)

    def read_status(self, *, timeout: float = 6.0) -> "MachineStatus":
        """Wait for the next unsolicited ``@TF:`` status frame and parse it."""
        reply = self.request("@HU?", match=r"^@TF:", timeout=timeout)
        return MachineStatus.parse(reply, profile=self.profile)

    def read_product_counters(
        self, *, timeout_per_page: float = 6.0
    ) -> "ProductCounters":
        """Read the per-product brew counter bank (``@TR:32``).

        The wire protocol paginates the response: the client sends
        ``@TR:32,<page>`` for each page ``00..0F`` (16 pages total) and
        reassembles the 8-byte payload of each page into a 64-slot
        table of ``u16`` counts. Slot 0 is the total number of brews;
        slots 1..63 are the per-product counts indexed by product code,
        with ``0xFFFF`` reserved for "this code is not configured on
        this machine". See :class:`ProductCounters` for the slot map.
        """
        slots: list[int] = []
        for page in range(16):
            cmd = f"@TR:32,{page:02X}"
            reply = self.request(
                cmd, match=rf"^@tr:32,{page:02X}", timeout=timeout_per_page
            )
            # "@tr:32,<page>,<8 hex bytes>"
            try:
                _, _, body = reply.split(",", 2)
            except ValueError as exc:
                raise ValueError(
                    f"malformed @TR:32 reply for page {page:02X}: {reply!r}"
                ) from exc
            page_bytes = bytes.fromhex(body)
            for i in range(0, len(page_bytes), 2):
                slots.append(int.from_bytes(page_bytes[i : i + 2], "big"))
        return ProductCounters.from_slots(slots, profile=self.profile)

    def read_machine_info(self, *, timeout: float = 6.0) -> "MachineInfo":
        """Bundle of everything we can passively learn about the machine."""
        return MachineInfo(
            conn_id=self.conn_id,
            auth_hash=self.auth_hash,
            handshake_state=self.handshake.state if self.handshake else "UNKNOWN",
            status=self.read_status(timeout=timeout),
            maintenance_counters=self.read_maintenance_counter(timeout=timeout),
            maintenance_percent=self.read_maintenance_percent(timeout=timeout),
        )

    def read_pmode_slots(self, *, timeout: float = 6.0) -> "ProgramModeSlots":
        """Read the user-programmable recipe slots (``@TM:50`` + ``@TM:42``).

        Older machines expose a "Programmable Mode" where each slot
        holds a saved recipe (variant of a product). The wire protocol
        is two-step:

        * ``@TM:50`` returns the per-product-kind slot count (one byte
          per kind, summed for the total).
        * ``@TM:42,<slot_hex>`` returns the product code and parameters
          for one slot, or the magic ``C2`` prefix when the machine
          doesn't support the requested slot.

        On machines without pmode (e.g. the S8 EB / EF1091), the count
        may be non-zero but every per-slot read returns ``C2``; the
        resulting :class:`ProgramModeSlots` carries an empty
        ``slots`` tuple in that case.
        """
        num_slots_reply = self.request("@TM:50", match=r"^@tm:50", timeout=timeout)
        num_slots = _parse_pmode_num_slots(num_slots_reply)
        entries: list[PModeSlot] = []
        unsupported: list[int] = []
        connection_dropped = False
        for slot in range(num_slots):
            if connection_dropped:
                unsupported.append(slot)
                continue
            cmd = f"@TM:42,{slot:02X}"
            try:
                reply = self.request(cmd, match=r"^@tm", timeout=timeout)
            except TimeoutError:
                # Some slots time out — record and keep iterating.
                unsupported.append(slot)
                continue
            except (ConnectionError, OSError):
                # The real S8 EB drops the TCP session after some
                # @TM:42 reads (observed on slot 0x80). Stop iterating
                # rather than spamming the dongle; mark every remaining
                # slot as unsupported so the caller sees what didn't
                # get answered.
                unsupported.append(slot)
                connection_dropped = True
                continue
            entry = _parse_pmode_slot(slot, reply)
            if entry is None:
                unsupported.append(slot)
            else:
                entries.append(entry)
        return ProgramModeSlots(
            num_slots=num_slots,
            slots=tuple(entries),
            unsupported=tuple(unsupported),
        )

    def read_setting(self, p_argument: str, *, timeout: float = 3.0) -> str:
        """Read one machine setting via ``@TM:<p_argument>``.

        ``p_argument`` is the ``P_Argument`` attribute from the XML
        ``<MACHINESETTINGS>`` block (e.g. ``"02"`` for hardness).

        Returns the raw hex value with the trailing two-char checksum
        stripped. Reply shape on the wire is
        ``@tm:<arg>,<value><checksum>`` — same checksum algorithm as
        the write side (``ByteOperations.d`` over ``"<arg>,<value>"``);
        we verify it before returning. For most settings the value is
        one byte (2 hex chars); for ItemSlider settings it can be 4
        or 6 chars (the AutoOFF table's ``"22021C"`` for 9h).

        Raises :class:`ValueError` when the checksum doesn't match —
        the value would otherwise alias as a too-large integer
        (hardness=13 came back as 3581 in v0.9.0 because the
        checksum byte was lumped in).
        """
        arg = p_argument.upper()
        cmd = f"@TM:{arg}"
        # (?i) — the dongle may echo the argument in either case
        # (observed lowercase for "0a" / "0A" alike), so match
        # case-insensitively on the reply.
        reply = self.request(cmd, match=rf"(?i)^@tm:{arg}", timeout=timeout)
        prefix = f"@tm:{arg.lower()}"
        body = reply[len(prefix) :] if reply.lower().startswith(prefix) else reply
        body = body.lstrip(",").strip()
        if len(body) < 4:
            # Shorter than 2 (value) + 2 (csum). Some firmwares answer
            # plain "@tm:<arg>" when the setting is unknown — surface
            # that as-is rather than synthesising a value.
            return body
        value, csum = body[:-2], body[-2:]
        expected = _settings_checksum(f"{arg},{value}")
        if csum.upper() != expected:
            raise ValueError(
                f"setting read for arg={arg}: checksum mismatch "
                f"(got {csum!r}, expected {expected!r} over "
                f"{arg!r},{value!r}); reply was {reply!r}"
            )
        return value

    def write_setting(
        self,
        p_argument: str,
        value_hex: str,
        *,
        timeout: float = 3.0,
        verify: bool = True,
    ) -> str:
        """Write one setting via ``@TM:<arg>,<value><checksum>``.

        Wire flow on the real dongle (verified against TT237W /
        Kaffeebert and matching the J.O.E. APK's PriorityChannel
        dispatch for ``CommandPriority.PMODE``):

            client → @TS:01                  (lock keypad)
            client ← @ts
            client → @TM:<arg>,<val><csum>   (actual write)
            client ← @tm:<arg>  / @an:error
            client → @TS:00                  (release keypad)
            client ← @ts

        Skipping the lock/unlock wrapper is the bug v0.9.0 - v0.9.1
        shipped: the dongle ACKs the bare ``@TM:`` write with
        ``@tm:<arg>`` so the call looks successful, but the machine
        silently ignores the new value until a future power cycle.
        The APK ALWAYS wraps PMODE-priority commands; we now do the
        same.

        The checksum follows the J.O.E. APK's ``ByteOperations.d``:
        sum every ASCII byte of ``"<arg>,<value>"``, cast
        ``-1 - sum`` to a signed byte, format as two upper-case hex
        chars and append.

        Caller is responsible for validating ``value_hex`` against the
        machine's :class:`~jura_connect.profile.SettingDef`. This
        method takes raw hex strings; see
        :meth:`jura_connect.profile.SettingDef.normalise_value`.

        When ``verify`` is true (default), reads the setting back
        AFTER the unlock and raises :class:`ValueError` if the
        stored value doesn't match — guards against a firmware that
        accepts the wrapped write but still silently drops it.
        Disable via ``verify=False`` if the read-back path is broken
        for a particular setting.
        """
        arg = p_argument.upper()
        value = value_hex.upper()
        checksum = _settings_checksum(f"{arg},{value}")
        cmd = f"@TM:{arg},{value}{checksum}"

        # Wrap in @TS:01 / @TS:00. The unlock runs in `finally` so a
        # mid-write exception can't leave the keypad locked.
        self.lock_screen()
        try:
            reply = self.request(cmd, match=r"^@(tm|an)", timeout=timeout)
        finally:
            try:
                self.unlock_screen()
            except Exception:  # noqa: BLE001
                # Best-effort unlock; failure here mustn't mask the
                # original write error.
                pass

        if reply.lower().startswith("@an:error"):
            return reply
        if verify:
            try:
                stored = self.read_setting(arg, timeout=timeout)
            except (TimeoutError, ValueError):
                # Read-back failed; surface the original reply rather
                # than masking it.
                return reply
            if stored.upper() != value:
                raise ValueError(
                    f"setting write for arg={arg}: dongle ACKed "
                    f"({reply!r}) but the read-back value is "
                    f"{stored!r}, not {value!r}. Even with the "
                    f"@TS:01/@TS:00 lock wrapper the write was "
                    f"silently dropped — this setting may be "
                    f"read-only on your firmware, the value may be "
                    f"outside an undocumented range, or the machine "
                    f"may be in a state that refuses writes."
                )
        return reply

    def lock_screen(self) -> str:
        """Lock the machine's front panel (``@TS:01``)."""
        return self.request("@TS:01", match=r"^@ts")

    def unlock_screen(self) -> str:
        """Unlock the machine's front panel (``@TS:00``)."""
        return self.request("@TS:00", match=r"^@ts")

    @staticmethod
    def random_conn_id() -> str:
        return f"jura-connect-{uuid.uuid4().hex[:8]}"


# --------------------------------------------------------------------- #
# Structured read results
# --------------------------------------------------------------------- #


def _hex_body(reply: str, expected_prefix: str) -> bytes:
    body = reply.strip()
    if not body.lower().startswith(expected_prefix.lower()):
        raise ValueError(f"{expected_prefix!r} reply expected, got {reply!r}")
    return bytes.fromhex(body[len(expected_prefix) :])


def _settings_checksum(payload: str) -> str:
    """Compute the @TM:<arg>,<val> trailing checksum.

    Ported from ``ByteOperations.d`` in the J.O.E. APK::

        sum = sum(c for c in payload)
        return f"{(-1 - sum) & 0xFF:02X}"

    where ``c`` is the codepoint of each character. Empirically the
    dongle requires every settings write to carry this trailing byte;
    omitting it gets you ``@an:error``.
    """
    total = sum(ord(c) for c in payload)
    return f"{(-1 - total) & 0xFF:02X}"


@dataclasses.dataclass(slots=True, frozen=True)
class MaintenanceCounters:
    """Decoded ``@TG:43`` payload.

    Order and meaning are taken from the machine XML ``<BANK Command="@TG:43">``
    section (EF536 / S8). Each counter is a 16-bit big-endian unsigned int.
    """

    cleaning: int
    filter_change: int
    decalc: int
    cappu_rinse: int
    coffee_rinse: int
    cappu_clean: int
    raw: bytes

    @classmethod
    def parse(cls, reply: str) -> MaintenanceCounters:
        data = _hex_body(reply, "@tg:43")
        if len(data) < 12:
            raise ValueError(f"@tg:43 payload too short ({len(data)} bytes): {reply!r}")
        u = [int.from_bytes(data[i : i + 2], "big") for i in range(0, 12, 2)]
        return cls(
            cleaning=u[0],
            filter_change=u[1],
            decalc=u[2],
            cappu_rinse=u[3],
            coffee_rinse=u[4],
            cappu_clean=u[5],
            raw=data,
        )

    def format(self) -> str:
        return (
            f"cleaning={self.cleaning} filter={self.filter_change} "
            f"decalc={self.decalc} cappu_rinse={self.cappu_rinse} "
            f"coffee_rinse={self.coffee_rinse} cappu_clean={self.cappu_clean}"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "cleaning": self.cleaning,
            "filter_change": self.filter_change,
            "decalc": self.decalc,
            "cappu_rinse": self.cappu_rinse,
            "coffee_rinse": self.coffee_rinse,
            "cappu_clean": self.cappu_clean,
            "raw_hex": self.raw.hex().upper(),
        }


@dataclasses.dataclass(slots=True, frozen=True)
class MaintenancePercent:
    """Decoded ``@TG:C0`` payload (one byte per maintenance type, 0..100, or 0xFF if absent)."""

    cleaning: int
    filter_change: int
    decalc: int
    raw: bytes

    @classmethod
    def parse(cls, reply: str) -> MaintenancePercent:
        data = _hex_body(reply, "@tg:C0")
        if len(data) < 3:
            raise ValueError(f"@tg:C0 payload too short ({len(data)} bytes): {reply!r}")
        return cls(
            cleaning=data[0],
            filter_change=data[1],
            decalc=data[2],
            raw=data,
        )

    def format(self) -> str:
        return (
            f"cleaning={self.cleaning} filter={self.filter_change} decalc={self.decalc}"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "cleaning": self.cleaning,
            "filter_change": self.filter_change,
            "decalc": self.decalc,
            "raw_hex": self.raw.hex().upper(),
        }


# Bit-to-alert mapping for the S8 / EF536 (see assets/documents/xml/EF536/1.0.xml).
# Bit index is global: byte_index*8 + bit_within_byte.
#
# Each entry is (name, severity). The XML carries a Type attribute that
# distinguishes blocking errors from informational / in-progress states:
#
#   * "error" -> XML Type="block": the machine is in a state that stops it
#     from operating until the user clears the condition (e.g. fill water,
#     insert tray).
#   * "info"  -> XML Type="info" or missing Type: an informational bit
#     that may or may not block specific products (e.g. "no beans" with
#     Blocked="C" blocks coffee but isn't an error from the user's
#     perspective — the bin just needs refilling).
#   * "process" -> XML Type="ip": an in-process / reminder bit, typically
#     a "schedule maintenance" prompt (decalc / cleaning / filter / cappu
#     rinse) that the user is supposed to action eventually.
_STATUS_BITS: dict[int, tuple[str, str]] = {
    0: ("insert_tray", "error"),
    1: ("fill_water", "error"),
    2: ("empty_grounds", "error"),
    3: ("empty_tray", "error"),
    4: ("insert_coffee_bin", "error"),
    5: ("outlet_missing", "error"),
    6: ("rear_cover_missing", "error"),
    7: ("milk_alert", "info"),
    8: ("fill_system", "error"),
    9: ("system_filling", "info"),
    10: ("no_beans", "info"),
    11: ("welcome", "info"),
    12: ("heating_up", "info"),
    13: ("coffee_ready", "info"),
    14: ("no_milk_sensor", "info"),
    15: ("milk_sensor_error", "info"),
    16: ("milk_sensor_no_signal", "info"),
    17: ("please_wait", "error"),
    18: ("coffee_rinsing", "info"),
    19: ("ventilation_closed", "info"),
    20: ("close_powder_cover", "error"),
    21: ("fill_powder", "error"),
    22: ("system_emptying", "info"),
    23: ("not_enough_powder", "info"),
    24: ("remove_water_tank", "info"),
    25: ("press_rinse", "info"),
    26: ("goodbye", "info"),
    27: ("periphery_alert", "info"),
    28: ("powder_product", "info"),
    29: ("program_mode_status", "error"),
    30: ("error_status", "error"),
    31: ("enjoy_product", "info"),
    32: ("filter_alert", "process"),
    33: ("decalc_alert", "process"),
    34: ("cleaning_alert", "process"),
    35: ("cappu_rinse_alert", "process"),
    36: ("energy_safe", "info"),
    37: ("active_rf_filter", "info"),
    38: ("remote_screen", "info"),
}


@dataclasses.dataclass(slots=True, frozen=True)
class MachineStatus:
    """Decoded ``@TF:<hex>`` status frame.

    The status frame is a bitfield. The codebook above tags every known
    bit with a severity (``error`` / ``info`` / ``process``) lifted from
    the machine XML's ALERT.Type attribute. ``errors`` are the bits the
    user actually needs to action right now; ``info`` covers normal
    state transitions and low-supply reminders (e.g. "no beans" when the
    bean container is low — informational, not an error); ``process``
    holds the periodic maintenance prompts (decalc / cleaning / filter /
    cappu rinse) which the machine surfaces *before* they block brewing.

    ``active_alerts`` is kept as the union of all active named bits for
    backwards compatibility — it's what older callers and the legacy
    ``status`` CLI output have always returned. Prefer ``errors`` to
    decide whether the machine is genuinely stuck.
    """

    raw: bytes
    active_alerts: tuple[str, ...]
    errors: tuple[str, ...]
    info: tuple[str, ...]
    process: tuple[str, ...]

    @classmethod
    def parse(cls, reply: str, profile: MachineProfile | None = None) -> MachineStatus:
        """Parse an ``@TF:`` reply.

        ``profile`` is an optional :class:`jura_connect.profile.MachineProfile`;
        when supplied, its per-machine bit-to-name + severity map is
        used in preference to the hard-coded fallback. Pass it to make
        the parser EF1091-aware (or any other variant) instead of the
        EF536 baseline.
        """
        data = _hex_body(reply, "@TF:")
        active: list[str] = []
        errors: list[str] = []
        info: list[str] = []
        process: list[str] = []
        bits: dict[int, tuple[str, str]]
        if profile is not None and getattr(profile, "alert_by_bit", None):
            bits = {
                bit: (alert.name, alert.severity)
                for bit, alert in profile.alert_by_bit.items()
            }
        else:
            bits = _STATUS_BITS
        for bit_index, (name, severity) in bits.items():
            # MSB-first within each byte, per the J.O.E. APK's
            # `Status.a()`: `(1 << (7 - (i%8))) & bArr[i/8]`.
            byte_i, bit_in_byte = divmod(bit_index, 8)
            if byte_i < len(data) and (data[byte_i] >> (7 - bit_in_byte)) & 1:
                active.append(name)
                if severity == "error":
                    errors.append(name)
                elif severity == "process":
                    process.append(name)
                else:
                    info.append(name)
        return cls(
            raw=data,
            active_alerts=tuple(active),
            errors=tuple(errors),
            info=tuple(info),
            process=tuple(process),
        )

    def format(self) -> str:
        def _fmt(group: tuple[str, ...]) -> str:
            return ", ".join(group) if group else "(none)"

        return (
            f"bits={self.raw.hex().upper()}\n"
            f"  errors  : {_fmt(self.errors)}\n"
            f"  info    : {_fmt(self.info)}\n"
            f"  process : {_fmt(self.process)}"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "bits_hex": self.raw.hex().upper(),
            "active_alerts": list(self.active_alerts),
            "errors": list(self.errors),
            "info": list(self.info),
            "process": list(self.process),
        }


@dataclasses.dataclass(slots=True, frozen=True)
class MachineInfo:
    """Aggregated read-only snapshot returned by :meth:`JuraClient.read_machine_info`."""

    conn_id: str
    auth_hash: str
    handshake_state: str
    status: MachineStatus
    maintenance_counters: MaintenanceCounters
    maintenance_percent: MaintenancePercent

    def format(self) -> str:
        def _fmt(group: tuple[str, ...]) -> str:
            return ", ".join(group) if group else "(none)"

        hash_preview = (self.auth_hash[:16] + "...") if self.auth_hash else "(none)"
        return (
            "== machine info ==\n"
            f"  conn-id        : {self.conn_id}\n"
            f"  handshake state: {self.handshake_state}\n"
            f"  auth-hash      : {hash_preview}\n"
            f"  status bits    : {self.status.raw.hex().upper()}\n"
            f"  errors         : {_fmt(self.status.errors)}\n"
            f"  info flags     : {_fmt(self.status.info)}\n"
            f"  process flags  : {_fmt(self.status.process)}\n"
            f"  maintenance    : {self.maintenance_counters.format()}\n"
            f"  maintenance %  : {self.maintenance_percent.format()}"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "conn_id": self.conn_id,
            "auth_hash": self.auth_hash,
            "handshake_state": self.handshake_state,
            "status": self.status.to_dict(),
            "maintenance_counters": self.maintenance_counters.to_dict(),
            "maintenance_percent": self.maintenance_percent.to_dict(),
        }


# Product code -> human-readable name. Derived from the per-machine
# XML maps under apk/assets/documents/xml/ -- codes are stable across
# machine variants, so a single table covers every TT237W family
# firmware (S8, ENA8, Z8 etc.). 0xFFFF in the wire response means the
# code is not configured on this machine.
PRODUCT_NAMES: dict[int, str] = {
    0x01: "ristretto",
    0x02: "espresso",
    0x03: "coffee",
    0x04: "cappuccino",
    0x05: "milk_coffee",
    0x06: "espresso_macchiato",
    0x07: "latte_macchiato",
    0x08: "milk_foam",
    0x0A: "milk_portion",
    0x0D: "hotwater_portion",
    0x0F: "powder_product",
    0x11: "two_ristretti",
    0x12: "two_espressi",
    0x13: "two_coffees",
    0x28: "americano",
    0x29: "lungo",
    0x2D: "hotwater_green_tea",
    0x2E: "flat_white",
    0x30: "espresso_doppio",
}

# Wire-level sentinel for "this product code is not configured on the
# current machine" inside an @TR:32 page.
PRODUCT_COUNT_UNUSED = 0xFFFF


@dataclasses.dataclass(slots=True, frozen=True)
class ProductCounters:
    """Decoded ``@TR:32`` paginated payload — per-product brew counters.

    The dongle returns 16 pages of 4 ``u16`` slots each (64 slots total),
    indexed by product code:

    * Slot 0 carries the total number of brews ever performed.
    * Slots 1..63 each carry the count for the product whose code matches
      the slot index, or ``0xFFFF`` if that code is not configured on
      the machine.

    The product code -> name mapping in :data:`PRODUCT_NAMES` is shared
    across the TT237W family; unknown codes are surfaced under
    ``by_code`` only.
    """

    total: int
    by_name: dict[str, int]
    by_code: dict[str, int]
    raw_slots: tuple[int, ...]

    @classmethod
    def from_slots(
        cls,
        slots: list[int],
        profile: MachineProfile | None = None,
    ) -> ProductCounters:
        """Decode a 64-slot @TR:32 table.

        ``profile`` is an optional :class:`jura_connect.profile.MachineProfile`
        whose per-product name map is preferred over the package-wide
        :data:`PRODUCT_NAMES` fallback. Unknown codes still surface
        through ``by_code``.
        """
        if len(slots) < 1:
            raise ValueError("product counter table is empty")
        total = slots[0]
        by_name: dict[str, int] = {}
        by_code: dict[str, int] = {}
        code_to_name: dict[int, str]
        if profile is not None and getattr(profile, "product_by_code", None):
            code_to_name = {
                code: product.name for code, product in profile.product_by_code.items()
            }
        else:
            code_to_name = dict(PRODUCT_NAMES)
        for code in range(1, len(slots)):
            value = slots[code]
            if value == PRODUCT_COUNT_UNUSED:
                continue
            code_hex = f"{code:02X}"
            by_code[code_hex] = value
            name = code_to_name.get(code)
            if name is not None:
                by_name[name] = value
        return cls(
            total=total,
            by_name=by_name,
            by_code=by_code,
            raw_slots=tuple(slots),
        )

    def format(self) -> str:
        lines = [f"total brews : {self.total}"]
        for name, count in self.by_name.items():
            lines.append(f"  {name:20s}: {count}")
        # An "unnamed" slot is one that the active code->name map didn't
        # cover at parse time — i.e. by_code has an entry but by_name
        # doesn't. We re-derive this here so both the EF536-baseline
        # case and the profile-aware case are covered without ever
        # double-listing a slot.
        named_counts = list(self.by_name.values())
        unnamed: dict[str, int] = {}
        for code_hex, count in self.by_code.items():
            try:
                named_counts.remove(count)
            except ValueError:
                unnamed[code_hex] = count
        if unnamed:
            lines.append(
                "  (unnamed slots): "
                + ", ".join(f"0x{code}={count}" for code, count in unnamed.items())
            )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        return {
            "total": self.total,
            "by_name": dict(self.by_name),
            "by_code": dict(self.by_code),
        }


# --------------------------------------------------------------------- #
# Programmable mode slots (@TM:50 + @TM:42,<slot>)
# --------------------------------------------------------------------- #
#
# Older Jura machines expose a "Programmable Mode" where each slot
# holds a saved recipe (a variant of a base product code, e.g. "my
# strong espresso"). On newer machines like the S8 EB (EF1091), the
# XML has no ``PROGRAMMODE`` section: ``@TM:50`` returns a non-zero
# slot count but every ``@TM:42,<slot>`` answer is ``@tm:C2``
# (= "slot/product/function not supported by machine"). The
# :class:`ProgramModeSlots` dataclass surfaces both states cleanly so
# callers can tell the difference between "no pmode on this firmware"
# and "pmode present but slot N is empty".


@dataclasses.dataclass(slots=True, frozen=True)
class PModeSlot:
    """One configured slot from ``@TM:42,<slot>``."""

    index: int
    product_code: int  # base product code (e.g. 0x02 for Espresso)
    raw_payload: str  # the hex tail after the slot index in the reply


@dataclasses.dataclass(slots=True, frozen=True)
class ProgramModeSlots:
    """Decoded ``@TM:50`` count + per-slot ``@TM:42`` results."""

    num_slots: int
    slots: tuple[PModeSlot, ...]
    unsupported: tuple[int, ...]  # slot indices that returned C2 / timed out

    def format(self) -> str:
        if not self.num_slots:
            return "pmode: this machine reports no slots"
        if not self.slots:
            return (
                f"pmode: {self.num_slots} slot(s) reported by @TM:50, "
                "but every slot returned C2 (= 'not supported by machine'). "
                "This firmware does not expose pmode entries over WiFi."
            )
        lines = [f"pmode: {self.num_slots} slots, {len(self.slots)} configured"]
        for s in self.slots:
            lines.append(
                f"  slot {s.index:02d}: product=0x{s.product_code:02X}  raw={s.raw_payload}"
            )
        if self.unsupported:
            lines.append(
                "  unsupported slots: "
                + ", ".join(f"{i:02d}" for i in self.unsupported)
            )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        return {
            "num_slots": self.num_slots,
            "slots": [
                {
                    "index": s.index,
                    "product_code": f"{s.product_code:02X}",
                    "raw_payload": s.raw_payload,
                }
                for s in self.slots
            ],
            "unsupported": list(self.unsupported),
        }


def _parse_pmode_num_slots(reply: str) -> int:
    """Parse the reply to ``@TM:50``.

    Wire format (lifted from the APK's ``PModeNumSlotReadParser``):

        @tm:50,<N hex bytes><1-byte checksum>

    The body bytes are summed (each byte parsed as hex) and the total
    is the number of pmode slots. The trailing byte is a checksum that
    we don't currently verify (the APK does but the algorithm is opaque
    and not needed for correctness — wrong counts surface as
    unsupported-slot replies below).
    """
    text = reply.strip()
    if text.lower().startswith("@tm:"):
        text = text[4:]
    if "," in text:
        head, payload = text.split(",", 1)
    else:
        head, payload = text[:2], text[2:]
    if head.lower() != "50":
        return 0
    if len(payload) < 4:
        return 0
    # Drop the trailing checksum byte (last 2 hex chars).
    body = payload[:-2]
    if len(body) % 2:
        return 0
    total = 0
    for i in range(0, len(body), 2):
        try:
            total += int(body[i : i + 2], 16)
        except ValueError:
            return 0
    return total


def _parse_pmode_slot(slot: int, reply: str) -> PModeSlot | None:
    """Parse the reply to ``@TM:42,<slot>``.

    Wire format (success path): ``@tm:42,<slot_hex>,<product_code_hex>
    [<per-product arguments>]<checksum>``. We strip ``@tm:``, the
    ``42`` prefix, and the echoed slot byte, then read the next byte
    as the configured product code.

    Returns ``None`` when the machine answered with the ``C2`` magic
    prefix that the APK's ``PModeSlotProductReadParser`` flags as
    "product code, slot, or function is not supported by machine",
    or when the reply is otherwise malformed.
    """
    text = reply.strip()
    if text.lower().startswith("@tm:"):
        text = text[4:]
    if not text:
        return None
    head = text[:2].upper()
    if head == "C2":
        return None
    if head != "42":
        return None
    # Drop the "42" prefix and any leading comma.
    body = text[2:].lstrip(",")
    # Body starts with the slot byte (echoed back). Strip it.
    if len(body) < 2:
        return None
    body = body[2:].lstrip(",")
    if len(body) < 2:
        return None
    try:
        product_code = int(body[:2], 16)
    except ValueError:
        return None
    return PModeSlot(index=slot, product_code=product_code, raw_payload=body)
