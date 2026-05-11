# jura_wifi -- Python WiFi interface for Jura coffee machines

Reverse-engineered, dependency-free Python implementation of the WiFi
control protocol spoken by Jura machines fitted with the Smart Connect
WiFi dongle (firmware family **TT237W**, tested against an S8 EB on
`TT237W V06.11`).

The implementation is a direct port of the `joe_android_connector` module
from the official **J.O.E. (Jura Operating Experience)** Android app
(version 4.6.10), with API surface kept compatible with the Bluetooth
flavour documented in [`protocol-bt-cpp`](../protocol-bt-cpp/README.md).

## Layout

| File          | Purpose |
| ------------- | ------- |
| `crypto.py`   | port of `WifiCryptoUtil` (per-byte permutation + escape) |
| `discovery.py`| UDP broadcast discovery + TCP fallback sweep |
| `client.py`   | TCP framed transport + `@HP:` handshake |
| `__main__.py` | small CLI (`discover` / `probe` / `connect` / `pair`) |

## Protocol primer

| Layer      | Port | Notes |
| ---------- | ---- | ----- |
| Discovery  | UDP 51515 broadcast | 16-byte probe `0010A5F300...00`; reply is binary, parsed per `WifiFrog.H()` |
| Status     | UDP 51515 unicast   | 16-byte probe `0010A5F3<ipv4>00..00`; same reply layout |
| Commands   | TCP 51515           | one framed message per command, optional unsolicited status from the machine |

Each TCP frame is wrapped as `b'*' <encoded_body> b'\r\n'`. `<encoded_body>`
starts with a randomly chosen key byte (or `0x1B <key^0x80>` if the key
would clash with a reserved sync byte: `0x00 0x0A 0x0D 0x1B 0x26`). The
inner bytes are obfuscated with a self-inverse nibble permutation using
two 16-entry S-boxes; the same routine is used to encode and decode.

Newer dongles (TT237W) appear to ignore unicast UDP scan probes — the
TCP control port is still reachable, so `discover` falls back to a quick
local TCP sweep when no UDP replies arrive.

## Handshake flow

The first message on a fresh TCP connection must be `@HP:`:

```
@HP:<pin>,<conn_id_hex>,<auth_hash>
```

* `pin`         -- PIN displayed on the machine (empty if none / unknown).
* `conn_id_hex` -- hex-encoded ASCII bytes of an arbitrary device id
  (the J.O.E. app uses the Bluetooth adapter name).
* `auth_hash`   -- 8-char hex token returned by a previous successful
  pairing (empty for a fresh device).

Possible replies (mirrors `ConnectionSetupState` in the APK):

| Reply              | State        | What to do |
| ------------------ | ------------ | ---------- |
| `@hp4`             | `CORRECT`    | proceed; machine doesn't need an explicit hash |
| `@hp4:<new_hash>`  | `CORRECT`    | persist `<new_hash>` and use it next time |
| `@hp5` / `@hp5:00` | `WRONG_PIN`  | PIN field is wrong / required |
| `@hp5:01`          | `WRONG_HASH` | unknown conn-id; trigger pairing on the machine UI |
| `@hp5:02`          | `ABORTED`    | machine rejected -- pick a fresh `conn_id` and retry |

## CLI quickstart

```sh
# discover machines on the LAN (UDP broadcast, TCP sweep fallback)
python -m jura_wifi discover

# probe a known IP via UDP (some dongles answer only to broadcast)
python -m jura_wifi probe 192.168.1.42

# open a TCP session, run the handshake, send commands
python -m jura_wifi connect 192.168.1.42 \
    --conn-id my-host \
    --auth-hash AABBCCDD \
    --cmd '@HU?' --cmd '@TG:43'

# probe pairing state; supply --pin once the machine displays it
python -m jura_wifi pair 192.168.1.42 --conn-id my-host
python -m jura_wifi pair 192.168.1.42 --conn-id my-host --pin 1234
```

## Library use

```python
from jura_wifi import discover, JuraClient

for machine in discover(timeout=4.0):
    print(machine.name, machine.fw, machine.address)

with JuraClient("192.168.1.42",
                conn_id="my-host",
                auth_hash="AABBCCDD") as jura:
    print(jura.handshake.state)              # "CORRECT" if paired
    print(jura.request("@TG:43"))            # maintenance counter
```

## Known commands

A few well-tested commands from the APK (see `CoffeeMachineAdapterWifi`
for the rest):

| Command      | Purpose |
| ------------ | ------- |
| `@HP:p,c,h`  | connection setup / authentication |
| `@HB`        | heartbeat / keep-alive |
| `@HE`        | close session |
| `@HU?`       | request current status |
| `@HW:01,<p>` | set master PIN (requires authenticated session) |
| `@TG:43`     | read maintenance counters |
| `@TF:02`     | restart coffee machine |
| `@TP:<data>` | start a product (recipe payload from machine XML) |
| `@TM:<addr>` | read EEPROM / PMode memory |

Commands the machine sends unsolicited:

| Frame        | Meaning |
| ------------ | ------- |
| `@TV:<hex>`  | progress / brewing in progress |
| `@TF:<hex>`  | full status snapshot |
| `@hu:<kind>` | heartbeat acknowledgement (`ok`/`busy`/`wait`/`error`) |
