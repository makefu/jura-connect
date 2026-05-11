"""TCP client for the Jura WiFi protocol (unset-PIN flow supported).

Layers:

* :class:`JuraConnection` -- raw framed transport (write/read encoded frames).
* :class:`JuraClient`     -- handshake (`@HP:`) + structured read operations.

Wire framing and crypto live in :mod:`jura_wifi.protocol` / :mod:`jura_wifi.crypto`
and are shared with the in-tree :mod:`jura_wifi.simulator`.

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
                raise TimeoutError(
                    f"no reply to {cmd!r} within {timeout}s"
                ) from exc
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
    def iter_frames(
        self, *, until: float | None = None
    ) -> Iterator[str]:
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
    def read_maintenance_counter(self, *, timeout: float = 6.0) -> "MaintenanceCounters":
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
        return MachineStatus.parse(reply)

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
            raise ValueError(
                f"@tg:43 payload too short ({len(data)} bytes): {reply!r}"
            )
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
            raise ValueError(
                f"@tg:C0 payload too short ({len(data)} bytes): {reply!r}"
            )
        return cls(
            cleaning=data[0],
            filter_change=data[1],
            decalc=data[2],
            raw=data,
        )

    def format(self) -> str:
        return (
            f"cleaning={self.cleaning} filter={self.filter_change} "
            f"decalc={self.decalc}"
        )


# Bit-to-alert mapping for the S8 / EF536 (see assets/documents/xml/EF536/1.0.xml).
# Bit index is global: byte_index*8 + bit_within_byte.
_STATUS_BITS: dict[int, str] = {
    0: "insert_tray",
    1: "fill_water",
    2: "empty_grounds",
    3: "empty_tray",
    4: "insert_coffee_bin",
    5: "outlet_missing",
    6: "rear_cover_missing",
    7: "milk_alert",
    8: "fill_system",
    9: "system_filling",
    10: "no_beans",
    11: "welcome",
    12: "heating_up",
    13: "coffee_ready",
    14: "no_milk_sensor",
    15: "milk_sensor_error",
    16: "milk_sensor_no_signal",
    17: "please_wait",
    18: "coffee_rinsing",
    19: "ventilation_closed",
    20: "close_powder_cover",
}


@dataclasses.dataclass(slots=True, frozen=True)
class MachineStatus:
    """Decoded ``@TF:<hex>`` status frame -- alert / error bit flags."""

    raw: bytes
    active_alerts: tuple[str, ...]

    @classmethod
    def parse(cls, reply: str) -> MachineStatus:
        data = _hex_body(reply, "@TF:")
        active: list[str] = []
        for bit_index, name in _STATUS_BITS.items():
            byte_i, bit_i = divmod(bit_index, 8)
            if byte_i < len(data) and (data[byte_i] >> bit_i) & 1:
                active.append(name)
        return cls(raw=data, active_alerts=tuple(active))

    def format(self) -> str:
        alerts = ", ".join(self.active_alerts) or "(none)"
        return f"bits={self.raw.hex().upper()}  alerts={alerts}"


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
        alerts = ", ".join(self.status.active_alerts) or "(none)"
        hash_preview = (self.auth_hash[:16] + "...") if self.auth_hash else "(none)"
        return (
            "== machine info ==\n"
            f"  conn-id        : {self.conn_id}\n"
            f"  handshake state: {self.handshake_state}\n"
            f"  auth-hash      : {hash_preview}\n"
            f"  status bits    : {self.status.raw.hex().upper()}\n"
            f"  active alerts  : {alerts}\n"
            f"  maintenance    : {self.maintenance_counters.format()}\n"
            f"  maintenance %  : {self.maintenance_percent.format()}"
        )
