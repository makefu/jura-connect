"""Python WiFi interface for Jura coffee machines (S8/EB, TT237W series).

Reverse-engineered from the J.O.E. (Jura Operating Experience) Android
APK. Layered as:

* :mod:`jura_connect.crypto`     -- byte-level WiFi obfuscation cipher
  (port of ``WifiCryptoUtil``); self-inverse, shared client/server.
* :mod:`jura_connect.protocol`   -- frame helpers (``* … \\r\\n``) used by
  both the client and the in-tree simulator.
* :mod:`jura_connect.discovery`  -- UDP/51515 broadcast scan + TCP fallback
  sweep for firmwares that don't answer UDP.
* :mod:`jura_connect.client`     -- ``@HP:`` handshake, unset-PIN pair flow,
  structured read commands.
* :mod:`jura_connect.commands`   -- named-command registry; the entry point
  for "send the *counters* command" without hard-coding ``@TG:43``.
* :mod:`jura_connect.simulator`  -- TCP server speaking the same protocol;
  used by the test-suite to exercise the client end-to-end without a
  physical machine.
* :mod:`jura_connect.credentials` -- JSON file storage of pairing secrets.
"""

__version__ = "0.6.0"

from .client import (
    HandshakeError,
    HandshakeResult,
    JuraClient,
    JuraConnection,
    MachineInfo,
    MachineStatus,
    MaintenanceCounters,
    MaintenancePercent,
    PairingTimeout,
)
from .commands import (
    COMMANDS,
    DESTRUCTIVE_PREFIXES,
    CommandError,
    CommandResult,
    CommandSpec,
    DestructiveCommandError,
    get_command,
    list_commands,
    run_named,
)
from .credentials import CredentialStore, MachineCredentials
from .crypto import decode, encode
from .discovery import Machine, discover, probe, scan_tcp, tcp_probe

__all__ = [
    "COMMANDS",
    "CommandError",
    "CommandResult",
    "CommandSpec",
    "CredentialStore",
    "DESTRUCTIVE_PREFIXES",
    "DestructiveCommandError",
    "HandshakeError",
    "HandshakeResult",
    "JuraClient",
    "JuraConnection",
    "Machine",
    "MachineCredentials",
    "MachineInfo",
    "MachineStatus",
    "MaintenanceCounters",
    "MaintenancePercent",
    "PairingTimeout",
    "__version__",
    "decode",
    "discover",
    "encode",
    "get_command",
    "list_commands",
    "probe",
    "run_named",
    "scan_tcp",
    "tcp_probe",
]
