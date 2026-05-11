"""JSON-backed pairing-credential store.

Each coffee machine pairing produces an ``auth_hash`` that must be
preserved verbatim and replayed on every subsequent connection. We
store one entry per ``conn_id`` in a single JSON file so the same
file can hold credentials for multiple machines / phones.

File format (pretty-printed; one entry per machine)::

    {
      "version": 1,
      "machines": {
        "Kaffeebert": {
          "address": "192.168.1.42",
          "conn_id": "jura-connect-7f31a8c2",
          "auth_hash": "13908FE4...C13156C052",
          "paired_at": "2026-05-11T08:42:00Z"
        }
      }
    }

The default path follows the XDG basedir spec
(``$XDG_DATA_HOME/jura-connect/credentials.json``) with a graceful
fall-back to ``~/.local/share/jura-connect/credentials.json``.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import os
import stat
import tempfile
from pathlib import Path

FORMAT_VERSION = 1


def default_path() -> Path:
    """Return the default credential-store path (XDG-compliant)."""
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "share"
    )
    return Path(base) / "jura-connect" / "credentials.json"


@dataclasses.dataclass(slots=True)
class MachineCredentials:
    """One stored pairing entry."""

    name: str
    address: str
    conn_id: str
    auth_hash: str
    paired_at: str | None = None
    # EF code of the machine variant (e.g. "EF1091" for the S8 EB).
    # When None, callers fall through to a generic profile. Populated
    # at pair-time via auto-detect or the explicit --machine-type flag,
    # and updatable after the fact via the ``set-machine-type``
    # subcommand.
    machine_type: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "address": self.address,
            "conn_id": self.conn_id,
            "auth_hash": self.auth_hash,
            "paired_at": self.paired_at,
            "machine_type": self.machine_type,
        }


class CredentialStore:
    """JSON credential store keyed by *machine name* (e.g. ``"Kaffeebert"``).

    Reads are tolerant of a missing or empty file; writes use a
    write-and-rename pattern so the file is never observed half-written.
    File permissions are restricted to the user (0600) since the auth
    hash grants full control over the coffee machine.
    """

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self.path = Path(path) if path is not None else default_path()

    # -- read ----------------------------------------------------------
    def _read(self) -> dict[str, dict[str, str | None]]:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        if not raw.strip():
            return {}
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError(f"{self.path}: malformed credential file")
        machines = data.get("machines", {})
        if not isinstance(machines, dict):
            raise ValueError(f"{self.path}: 'machines' is not an object")
        return machines

    def _entry_to_creds(
        self, name: str, entry: dict[str, str | None]
    ) -> MachineCredentials:
        return MachineCredentials(
            name=name,
            address=str(entry.get("address", "")),
            conn_id=str(entry.get("conn_id", "")),
            auth_hash=str(entry.get("auth_hash", "")),
            paired_at=entry.get("paired_at"),
            machine_type=entry.get("machine_type"),
        )

    def get(self, name: str) -> MachineCredentials | None:
        entries = self._read()
        entry = entries.get(name)
        if entry is None:
            return None
        return self._entry_to_creds(name, entry)

    def entries(self) -> list[MachineCredentials]:
        return [
            self._entry_to_creds(name, entry)
            for name, entry in sorted(self._read().items())
        ]

    def set_machine_type(self, name: str, machine_type: str | None) -> bool:
        """Update the stored machine_type for one paired machine.

        Returns ``True`` on success, ``False`` if no such entry. Used
        by the ``set-machine-type`` CLI subcommand to retro-fit a
        profile onto an existing pairing without re-pairing.
        """
        entries = self._read()
        if name not in entries:
            return False
        entries[name]["machine_type"] = machine_type
        self._write(entries)
        return True

    # -- write ---------------------------------------------------------
    def put(self, creds: MachineCredentials) -> None:
        """Add or replace one credential entry, then flush atomically."""
        entries = self._read()
        if creds.paired_at is None:
            creds.paired_at = (
                _dt.datetime.now(tz=_dt.timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z")
            )
        entries[creds.name] = creds.to_dict()
        self._write(entries)

    def remove(self, name: str) -> bool:
        entries = self._read()
        if name not in entries:
            return False
        del entries[name]
        self._write(entries)
        return True

    def _write(self, machines: dict[str, dict[str, str | None]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": FORMAT_VERSION, "machines": machines}
        # Write to a sibling temp file then rename for crash-safety.
        fd, tmp_name = tempfile.mkstemp(
            prefix=".credentials-", suffix=".json.tmp", dir=str(self.path.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, sort_keys=True)
                fh.write("\n")
            try:
                os.chmod(tmp_name, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
            os.replace(tmp_name, self.path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    # -- convenience ---------------------------------------------------
    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self._read()
