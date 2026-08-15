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
* :mod:`jura_connect.progress`   -- decoder for the unsolicited ``@TV:``
  product-progress frames ("brewing, 60 %", "empty the grounds").
* :mod:`jura_connect.process`    -- the interactive maintenance-process
  state machine (start a cleaning cycle, confirm each step it asks for).
* :mod:`jura_connect.language`   -- the language-download sequence
  (S-record payloads, capability-gated). Reachable as
  ``jura_connect.language``; only the client entry points are re-exported.
* :mod:`jura_connect.firmware`   -- dongle OTA and the milk cooler.
  Deliberately not re-exported: the OTA sequencer is only safe as a whole
  and a partial transfer needs a service visit to recover.
* :mod:`jura_connect.simulator`  -- TCP server speaking the same protocol;
  used by the test-suite to exercise the client end-to-end without a
  physical machine.
* :mod:`jura_connect.credentials` -- JSON file storage of pairing secrets.
"""

__version__ = "0.13.0"

from .client import (
    PRODUCT_NAMES,
    HandshakeError,
    HandshakeResult,
    JuraClient,
    JuraConnection,
    MachineInfo,
    MachineStatus,
    MaintenanceCounters,
    MaintenancePercent,
    PairingTimeout,
    PModeSlot,
    ProductCounters,
    ProgramModeSlots,
    SettingValue,
)
from .process import (
    ACCEPT_COMMANDS,
    CANCEL_STEP_COMMAND,
    NEXT_STEP_COMMAND,
    PROCESS_FINISH_STATES,
    MachineProcess,
    ProcessAction,
    ProcessCatalogue,
    ProcessError,
    ProcessRun,
    ProcessRunner,
    ProcessStep,
    available_processes,
    resolve_accept_command,
    resolve_process,
    watch_states,
)
from .profile import (
    KIND_BYPASS,
    KIND_COFFEE_STRENGTH,
    KIND_MILK_BREAK,
    KIND_MILK_AMOUNT,
    KIND_MILK_FOAM_AMOUNT,
    KIND_TEMPERATURE,
    KIND_WATER_AMOUNT,
    RECIPE_PARAM_KINDS,
    AlertDef,
    PRODUCT_KINDS,
    MachineCatalogueEntry,
    MachineProfile,
    ProcessDef,
    ProductDef,
    ProductParam,
    SettingDef,
    SettingItem,
    StateDef,
    expand_blocked_kinds,
    iter_profiles,
    known_machine_names,
    list_profile_codes,
    load_profile,
    lookup_by_article_number,
    search_by_friendly_name,
)
from .commands import (
    COMMANDS,
    DESTRUCTIVE_EXACT,
    DESTRUCTIVE_PREFIXES,
    CommandError,
    CommandResult,
    CommandSpec,
    DestructiveCommandError,
    get_command,
    list_commands,
    match_destructive,
    run_named,
)
from .progress import (
    PROCESS_CODES,
    PRODUCT_ARGUMENTS,
    ProductProgress,
    ProductProgressState,
    ProgressLog,
    ProgressState,
    ProgressType,
    is_progress_frame,
)
from .credentials import CredentialStore, MachineCredentials
from .crypto import decode, encode
from .discovery import Machine, discover, probe, scan_tcp, tcp_probe

__all__ = [
    "ACCEPT_COMMANDS",
    "AlertDef",
    "CANCEL_STEP_COMMAND",
    "COMMANDS",
    "KIND_BYPASS",
    "KIND_COFFEE_STRENGTH",
    "KIND_MILK_BREAK",
    "KIND_MILK_AMOUNT",
    "KIND_MILK_FOAM_AMOUNT",
    "KIND_TEMPERATURE",
    "KIND_WATER_AMOUNT",
    "RECIPE_PARAM_KINDS",
    "CommandError",
    "CommandResult",
    "CommandSpec",
    "CredentialStore",
    "DESTRUCTIVE_EXACT",
    "DESTRUCTIVE_PREFIXES",
    "DestructiveCommandError",
    "HandshakeError",
    "HandshakeResult",
    "JuraClient",
    "JuraConnection",
    "Machine",
    "MachineCatalogueEntry",
    "MachineCredentials",
    "MachineInfo",
    "MachineProfile",
    "MachineStatus",
    "MaintenanceCounters",
    "MaintenancePercent",
    "NEXT_STEP_COMMAND",
    "PROCESS_CODES",
    "PROCESS_FINISH_STATES",
    "PRODUCT_ARGUMENTS",
    "PRODUCT_KINDS",
    "PRODUCT_NAMES",
    "PModeSlot",
    "PairingTimeout",
    "MachineProcess",
    "ProcessAction",
    "ProcessCatalogue",
    "ProcessDef",
    "ProcessError",
    "ProcessRun",
    "ProcessRunner",
    "ProcessStep",
    "ProductCounters",
    "ProductDef",
    "ProductParam",
    "ProductProgress",
    "ProductProgressState",
    "ProgramModeSlots",
    "ProgressLog",
    "ProgressState",
    "ProgressType",
    "SettingDef",
    "SettingItem",
    "SettingValue",
    "StateDef",
    "__version__",
    "available_processes",
    "decode",
    "discover",
    "encode",
    "get_command",
    "is_progress_frame",
    "iter_profiles",
    "known_machine_names",
    "list_commands",
    "list_profile_codes",
    "load_profile",
    "lookup_by_article_number",
    "match_destructive",
    "expand_blocked_kinds",
    "probe",
    "resolve_accept_command",
    "resolve_process",
    "run_named",
    "scan_tcp",
    "search_by_friendly_name",
    "tcp_probe",
    "watch_states",
]
