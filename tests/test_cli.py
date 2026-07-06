"""CLI behaviour tests around the new ``command`` subcommand.

The CLI is invoked by calling :func:`jura_connect.__main__.main` directly
with an argv list and capturing stdout via the ``capsys`` fixture, which
keeps the tests fast and avoids spawning subprocesses.
"""

from __future__ import annotations

import json

import pytest

from jura_connect.__main__ import main


def test_command_list_prints_known_names(capsys) -> None:
    rc = main(["--store", "/dev/null", "command", "--list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "info" in out
    assert "counters" in out
    assert "mem-read <addr>" in out


def test_command_without_name_errors(capsys) -> None:
    rc = main(["--store", "/dev/null", "command"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "command name required" in err


def test_command_runs_info_through_simulator(sim, tmp_path, capsys) -> None:
    host, port = sim.address
    store_path = tmp_path / "creds.json"

    # Pair via the CLI's library so we have a stored credential keyed by name.
    from jura_connect.client import JuraClient
    from jura_connect.credentials import CredentialStore, MachineCredentials

    c = JuraClient(host, port=port, conn_id="cli-tests", auth_hash="")
    r = c.pair(timeout=2.0)
    c.close()
    assert r.new_hash
    CredentialStore(store_path).put(
        MachineCredentials(
            name="Sim",
            address=f"{host}:{port}",
            conn_id="cli-tests",
            auth_hash=r.new_hash,
        )
    )

    # Now exercise the CLI against the running simulator. Note: --address
    # overrides the name lookup so we can target the simulator's port.
    rc = main(
        [
            "--store",
            str(store_path),
            "command",
            "--name",
            "Sim",
            "--address",
            f"{host}:{port}",
            "--auth-hash",
            r.new_hash,
            "--conn-id",
            "cli-tests",
            "--handshake-timeout",
            "3",
            "--cmd-timeout",
            "3",
            "info",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "machine info" in out
    # 'no_beans' lives under 'info flags', not 'errors' — it's not a
    # blocking alert.
    assert "info flags" in out
    assert "no_beans" in out


def test_command_missing_credentials_errors(capsys, tmp_path) -> None:
    rc = main(
        [
            "--store",
            str(tmp_path / "empty.json"),
            "command",
            "info",
            "--name",
            "DoesNotExist",
        ]
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "no address" in err or "no auth-hash" in err


def test_version_flag(capsys) -> None:
    from jura_connect import __version__

    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert __version__ in (captured.out + captured.err)


def test_creds_json_output(capsys, tmp_path) -> None:
    from jura_connect.credentials import CredentialStore, MachineCredentials

    p = tmp_path / "creds.json"
    CredentialStore(p).put(MachineCredentials("a", "1.2.3.4", "cid", "h" * 64))
    rc = main(["--store", str(p), "creds", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["name"] == "a"
    assert payload[0]["address"] == "1.2.3.4"


# --------------------------------------------------------------------- #
# Destructive-command CLI behaviour
# --------------------------------------------------------------------- #


def _setup_paired_simulator(sim, tmp_path):
    """Pair against the simulator and return (host, port, store_path, hash)."""
    host, port = sim.address
    from jura_connect.client import JuraClient
    from jura_connect.credentials import CredentialStore, MachineCredentials

    c = JuraClient(host, port=port, conn_id="cli-tests", auth_hash="")
    r = c.pair(timeout=2.0)
    c.close()
    assert r.new_hash
    store_path = tmp_path / "creds.json"
    CredentialStore(store_path).put(
        MachineCredentials(
            name="Sim",
            address=f"{host}:{port}",
            conn_id="cli-tests",
            auth_hash=r.new_hash,
        )
    )
    return host, port, store_path, r.new_hash


def test_command_list_groups_safe_and_destructive(capsys) -> None:
    rc = main(["--store", "/dev/null", "command", "--list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "read-only" in out
    assert "destructive" in out
    # The destructive group must mention how to actually use them.
    assert "--allow-destructive-commands" in out


def test_cli_refuses_destructive_command_without_flag(sim, tmp_path, capsys) -> None:
    host, port, store_path, h = _setup_paired_simulator(sim, tmp_path)
    rc = main(
        [
            "--store",
            str(store_path),
            "command",
            "--name",
            "Sim",
            "--address",
            f"{host}:{port}",
            "--auth-hash",
            h,
            "--conn-id",
            "cli-tests",
            "--handshake-timeout",
            "3",
            "--cmd-timeout",
            "2",
            "clean",
        ]
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "'clean'" in err
    assert "cleaning cycle" in err or "consumes" in err
    assert "--allow-destructive-commands" in err


def test_cli_allows_destructive_command_with_flag(sim, tmp_path, capsys) -> None:
    host, port, store_path, h = _setup_paired_simulator(sim, tmp_path)
    rc = main(
        [
            "--store",
            str(store_path),
            "command",
            "--name",
            "Sim",
            "--address",
            f"{host}:{port}",
            "--auth-hash",
            h,
            "--conn-id",
            "cli-tests",
            "--handshake-timeout",
            "3",
            "--cmd-timeout",
            "2",
            "--allow-destructive-commands",
            "clean",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "@an:error" in out


def test_cli_json_emits_only_json_on_stdout(sim, tmp_path, capsys) -> None:
    """--json: stdout is the JSON CommandResult; the handshake banner moves to stderr."""
    host, port, store_path, h = _setup_paired_simulator(sim, tmp_path)
    rc = main(
        [
            "--store",
            str(store_path),
            "command",
            "--name",
            "Sim",
            "--address",
            f"{host}:{port}",
            "--auth-hash",
            h,
            "--conn-id",
            "cli-tests",
            "--handshake-timeout",
            "3",
            "--cmd-timeout",
            "2",
            "--json",
            "counters",
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()
    # stdout must be parseable as JSON with no other text.
    payload = json.loads(captured.out)
    assert payload["name"] == "counters"
    assert payload["value"]["cleaning"] == 0x0015
    # Handshake banner is on stderr (the "information" stream).
    assert "handshake" in captured.err
    assert "handshake" not in captured.out


def test_cli_json_info_full_nested_shape(sim, tmp_path, capsys) -> None:
    host, port, store_path, h = _setup_paired_simulator(sim, tmp_path)
    rc = main(
        [
            "--store",
            str(store_path),
            "command",
            "--name",
            "Sim",
            "--address",
            f"{host}:{port}",
            "--auth-hash",
            h,
            "--conn-id",
            "cli-tests",
            "--handshake-timeout",
            "3",
            "--cmd-timeout",
            "3",
            "--json",
            "info",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["name"] == "info"
    assert payload["value"]["handshake_state"] == "CORRECT"
    assert "no_beans" in payload["value"]["status"]["active_alerts"]


def test_cli_json_destructive_refusal_stderr(sim, tmp_path, capsys) -> None:
    """A refused destructive command keeps stdout empty under --json."""
    host, port, store_path, h = _setup_paired_simulator(sim, tmp_path)
    rc = main(
        [
            "--store",
            str(store_path),
            "command",
            "--name",
            "Sim",
            "--address",
            f"{host}:{port}",
            "--auth-hash",
            h,
            "--conn-id",
            "cli-tests",
            "--handshake-timeout",
            "3",
            "--cmd-timeout",
            "2",
            "--json",
            "clean",
        ]
    )
    assert rc == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "'clean'" in captured.err
    assert "--allow-destructive-commands" in captured.err


def test_cli_without_json_still_uses_stdout(sim, tmp_path, capsys) -> None:
    """Sanity: without --json, the human-readable output stays on stdout."""
    host, port, store_path, h = _setup_paired_simulator(sim, tmp_path)
    rc = main(
        [
            "--store",
            str(store_path),
            "command",
            "--name",
            "Sim",
            "--address",
            f"{host}:{port}",
            "--auth-hash",
            h,
            "--conn-id",
            "cli-tests",
            "--handshake-timeout",
            "3",
            "--cmd-timeout",
            "2",
            "counters",
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()
    assert "handshake" in captured.out
    assert "cleaning=21" in captured.out


def test_machine_types_lists_friendly_names(capsys) -> None:
    rc = main(["machine-types"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "S8 (EB)" in out
    assert "EF1091" in out


def test_machine_types_filter(capsys) -> None:
    rc = main(["machine-types", "--filter", "S8 (EB)"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "EF1091" in out
    assert "EF1151" in out


def test_machine_types_json_output(capsys) -> None:
    rc = main(["machine-types", "--filter", "S8 (EB)", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    codes = {row["ef_code"] for row in payload}
    assert {"EF1091", "EF1151"} <= codes


def test_set_machine_type_updates_existing_pairing(sim, tmp_path, capsys) -> None:
    host, port, store_path, _h = _setup_paired_simulator(sim, tmp_path)
    rc = main(
        [
            "--store",
            str(store_path),
            "set-machine-type",
            "--name",
            "Sim",
            "EF1091",
        ]
    )
    assert rc == 0
    assert "EF1091" in capsys.readouterr().out
    from jura_connect.credentials import CredentialStore

    creds = CredentialStore(store_path).get("Sim")
    assert creds is not None
    assert creds.machine_type == "EF1091"


def test_set_machine_type_rejects_unknown_code(tmp_path, capsys) -> None:
    rc = main(
        [
            "--store",
            str(tmp_path / "x.json"),
            "set-machine-type",
            "--name",
            "Whatever",
            "EF_NOPE",
        ]
    )
    assert rc == 2
    assert "unknown machine type" in capsys.readouterr().err


def test_cli_refuses_destructive_raw_payload_without_flag(
    sim, tmp_path, capsys
) -> None:
    host, port, store_path, h = _setup_paired_simulator(sim, tmp_path)
    rc = main(
        [
            "--store",
            str(store_path),
            "command",
            "--name",
            "Sim",
            "--address",
            f"{host}:{port}",
            "--auth-hash",
            h,
            "--conn-id",
            "cli-tests",
            "--handshake-timeout",
            "3",
            "--cmd-timeout",
            "2",
            "raw",
            "@TG:24",
        ]
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "@TG:24" in err
    assert "--allow-destructive-commands" in err


def test_pair_without_pin_sends_empty_pin_field(sim, tmp_path, capsys) -> None:
    """Default (no --pin) pairing must send an empty PIN field so machines
    without a configured PIN keep working exactly as before."""
    host, port = sim.address
    store_path = tmp_path / "creds.json"

    rc = main(
        [
            "--store",
            str(store_path),
            "pair",
            f"{host}:{port}",
            "--name",
            "Sim",
            "--conn-id",
            "cli-nopin",
            "--timeout",
            "3",
        ]
    )
    assert rc == 0
    # Simulator records (pin, conn_id_hex, hash) per handshake.
    assert sim.handshakes, "expected one handshake"
    pin, _conn_id_hex, given_hash = sim.handshakes[0]
    assert pin == ""
    assert given_hash == ""


def test_pair_with_pin_succeeds_against_pin_machine(
    sim_factory, tmp_path, capsys
) -> None:
    """A machine with a configured PIN accepts pairing when --pin matches."""
    sim = sim_factory(pin="1234")
    host, port = sim.address
    store_path = tmp_path / "creds.json"

    rc = main(
        [
            "--store",
            str(store_path),
            "pair",
            f"{host}:{port}",
            "--name",
            "Sim",
            "--conn-id",
            "cli-pin",
            "--pin",
            "1234",
            "--timeout",
            "3",
        ]
    )
    assert rc == 0
    assert sim.handshakes[0][0] == "1234"
    out = capsys.readouterr().out
    assert "CORRECT" in out


def test_pair_without_pin_rejected_by_pin_machine(
    sim_factory, tmp_path, capsys
) -> None:
    """Omitting --pin against a PIN-protected machine yields WRONG_PIN, rc 2."""
    sim = sim_factory(pin="1234")
    host, port = sim.address
    store_path = tmp_path / "creds.json"

    rc = main(
        [
            "--store",
            str(store_path),
            "pair",
            f"{host}:{port}",
            "--name",
            "Sim",
            "--conn-id",
            "cli-pin-missing",
            "--timeout",
            "3",
        ]
    )
    assert rc == 2
    out = capsys.readouterr().out
    assert "WRONG_PIN" in out


def test_command_with_pin_runs_against_pin_machine(
    sim_factory, tmp_path, capsys
) -> None:
    """`command --pin` reconnects to a PIN-protected machine and runs a read."""
    from jura_connect.client import JuraClient
    from jura_connect.credentials import CredentialStore, MachineCredentials

    sim = sim_factory(pin="4321")
    host, port = sim.address
    store_path = tmp_path / "creds.json"

    # Pair once (through the library) to obtain a persisted auth hash.
    c = JuraClient(host, port=port, conn_id="cli-pin-cmd", auth_hash="", pin="4321")
    r = c.pair(timeout=2.0)
    c.close()
    assert r.new_hash
    CredentialStore(store_path).put(
        MachineCredentials(
            name="Sim",
            address=f"{host}:{port}",
            conn_id="cli-pin-cmd",
            auth_hash=r.new_hash,
        )
    )

    rc = main(
        [
            "--store",
            str(store_path),
            "command",
            "--name",
            "Sim",
            "--address",
            f"{host}:{port}",
            "--auth-hash",
            r.new_hash,
            "--conn-id",
            "cli-pin-cmd",
            "--pin",
            "4321",
            "--handshake-timeout",
            "3",
            "--cmd-timeout",
            "3",
            "info",
        ]
    )
    assert rc == 0
    # Every @HP: handshake to this PIN machine must carry the PIN.
    assert all(h[0] == "4321" for h in sim.handshakes)
    out = capsys.readouterr().out
    assert "machine info" in out


def test_pair_stores_pin_and_command_reuses_it(sim_factory, tmp_path, capsys) -> None:
    """`pair --pin` persists the PIN so a later `command` reconnects to a
    PIN-protected machine WITHOUT re-passing --pin."""
    from jura_connect.credentials import CredentialStore

    sim = sim_factory(pin="9999")
    host, port = sim.address
    store_path = tmp_path / "creds.json"

    rc = main(
        [
            "--store",
            str(store_path),
            "pair",
            f"{host}:{port}",
            "--name",
            "Sim",
            "--conn-id",
            "cli-pin-store",
            "--pin",
            "9999",
            "--timeout",
            "3",
        ]
    )
    assert rc == 0
    # PIN persisted verbatim in the credential store.
    stored = CredentialStore(store_path).get("Sim")
    assert stored is not None and stored.pin == "9999"
    capsys.readouterr()  # drain pair output

    # Reconnect with NO --pin: the stored PIN must be replayed.
    rc = main(
        [
            "--store",
            str(store_path),
            "command",
            "--name",
            "Sim",
            "--address",
            f"{host}:{port}",
            "--conn-id",
            "cli-pin-store",
            "--handshake-timeout",
            "3",
            "--cmd-timeout",
            "3",
            "info",
        ]
    )
    assert rc == 0
    assert all(h[0] == "9999" for h in sim.handshakes)
    out = capsys.readouterr().out
    assert "machine info" in out


def test_command_missing_stored_pin_hints_to_pass_one(
    sim_factory, tmp_path, capsys
) -> None:
    """A paired credential with no stored PIN against a now-PIN'd machine
    surfaces a helpful WRONG_PIN hint instead of a bare failure."""
    from jura_connect.credentials import CredentialStore, MachineCredentials

    sim = sim_factory(pin="5555")
    host, port = sim.address
    store_path = tmp_path / "creds.json"
    # Credential exists but carries no PIN.
    CredentialStore(store_path).put(
        MachineCredentials(
            name="Sim",
            address=f"{host}:{port}",
            conn_id="cli-nopin-stored",
            auth_hash="h" * 64,
        )
    )

    rc = main(
        [
            "--store",
            str(store_path),
            "command",
            "--name",
            "Sim",
            "--address",
            f"{host}:{port}",
            "--conn-id",
            "cli-nopin-stored",
            "--handshake-timeout",
            "3",
            "--cmd-timeout",
            "3",
            "info",
        ]
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "requires a PIN" in err


def test_creds_json_redacts_pin(capsys, tmp_path) -> None:
    """`creds --json` must expose pin_stored, never the PIN value."""
    from jura_connect.credentials import CredentialStore, MachineCredentials

    p = tmp_path / "creds.json"
    CredentialStore(p).put(
        MachineCredentials("a", "1.2.3.4", "cid", "h" * 64, pin="4711")
    )
    rc = main(["--store", str(p), "creds", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["pin_stored"] is True
    assert "pin" not in payload[0]
    assert "4711" not in json.dumps(payload)
