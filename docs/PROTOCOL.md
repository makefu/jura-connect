# Jura WiFi protocol — technical reference

Source-of-truth document for the implementation. Captures every detail
that was extracted from the J.O.E. Android APK (`ch.toptronic.joe`
v4.6.10) and validated against a real coffee machine (Jura S8 EB,
firmware `TT237W V06.11`, hostname `espressif.lan`, MAC prefix
`0c:8b:95` = Espressif Inc.).

Numbers, byte values and command codes here are *observed* values, not
guesses — if a behaviour differs from this doc, fix the doc.

---

## 1. Transport

| Layer | Port  | Protocol | Notes |
| ----- | ----- | -------- | ----- |
| Discovery — broadcast  | 51515 | UDP | 16-byte scan probe, dongle replies via broadcast on same port |
| Discovery — unicast    | 51515 | UDP | Probe targeted at one IP; **TT237W ignores unicast** (broadcast-only) |
| Status / commands      | 51515 | TCP | Single long-lived session; one client at a time |

Both UDP and TCP services share the same port. On the TT237W firmware the
dongle does **not** reply to UDP scans at all — the client falls back to
a TCP-port-51515 sweep across the local /24s to locate machines.

### 1.1 TCP frame

Each frame is exactly:

```
b'*'   <encoded_body>   b'\r\n'
```

* `b'*'` (0x2A) is the sync byte that begins every frame.
* `<encoded_body>` starts with the *key byte* used to encode the rest of
  the body, followed by the obfuscated payload (see §2).
* `b'\r\n'` (0x0D 0x0A) terminates the frame.

A `recv` parser should:

1. Drop everything in the buffer up to (but not including) the next `*`.
2. Read until the next un-escaped `\r\n`.
3. Decrypt with the recovered key.

### 1.2 Reserved byte set

Five byte values trigger the escape mechanism inside the encoded body:

```
RESERVED = { 0x00, 0x0A, 0x0D, 0x1B, 0x26 }
```

Any byte that would otherwise sit in `<encoded_body>` and equals one of
these values is emitted as the two-byte sequence `0x1B <byte^0x80>`.
This also applies to the leading key byte itself. On receive, the
escape is undone before the cipher is run.

Note: the leading sync `0x2A` (`*`) is **not** in the reserved set —
once the decoder has past the sync byte it never expects another `*`.

---

## 2. Obfuscation cipher (`WifiCryptoUtil`)

A self-inverse, per-nibble permutation. The exact same routine encrypts
and decrypts; client and simulator both call into
`jura_connect.crypto.encode_payload` and `decode_payload`.

### 2.1 S-boxes

```
SBOX_A = (1, 0, 3, 2, 15, 14, 8, 10, 6, 13, 7, 12, 11, 9, 5, 4)
SBOX_B = (9, 12, 6, 11, 10, 15, 2, 14, 13, 0, 4, 3, 1, 8, 7, 5)
```

### 2.2 Key

For every outgoing frame the client picks a random key byte. Keys
whose low nibble is `0x0E` or `0x0F` are rejected (the J.O.E. app loops
until it gets a valid one); presumably those values would collide with
something else in firmware.

### 2.3 Per-nibble permutation

```
def _a(nibble, pos, key_hi, key_full):
    iB = (nibble + pos + key_hi) % 16
    i11 = pos >> 4
    inner = ((i11 + SBOX_A[iB] + key_full) - pos - key_hi) % 16
    outer = ((SBOX_B[inner] + key_hi + pos - key_full) - i11) % 16
    return (SBOX_A[outer] - pos - key_hi) % 16
```

`pos` is a running nibble counter (starts at 0, increments by 1 per
nibble — i.e. by 2 per byte). For a 100-byte payload `pos` reaches 200.

The function is its own inverse. Verified exhaustively in
`tests/test_crypto.py` for every valid key value plus 500 random
inputs.

### 2.4 Frame composition

```
write '*'
maybe-escape key, then write it
for each input byte b:
    eh = _a((b >> 4) & 0xF, pos,   key_hi, key_full)
    el = _a(b & 0xF,        pos+1, key_hi, key_full)
    enc = (eh << 4) | el
    maybe-escape enc
    pos += 2
write '\r\n'
```

Decoding reverses only the escape handling; the inner `_a` call is the
same.

---

## 3. Discovery

### 3.1 Scan probe

```
0x00 0x10 0xA5 0xF3   0x00 * 12
```

A static 16-byte UDP datagram, sent to the broadcast address of every
local /24. The reply (when one comes — only seen on older firmware than
TT237W) carries the structure below.

### 3.2 Reply layout

| Offset | Size | Field |
| ------ | ---- | ----- |
| 0..2   |  2 | total length (big-endian) |
| 2..4   |  2 | control word: low 12 bits == 1523 (0x5F3); bit-15 set, bit-14 clear (per the APK's odd MSB-from-byte-0 numbering) |
| 4..20  | 16 | firmware version string, ASCII, space-padded (e.g. `TT237W V06.11`) |
| 20..52 | 32 | user-assigned machine name (e.g. `Kaffeebert`) |
| 52..68 | 16 | hardware identifier |
| 68..70 |  2 | article number (BE u16) |
| 70..72 |  2 | machine number (BE u16) |
| 72..74 |  2 | serial number (BE u16) |
| 74..76 |  2 | production date (`((year-1990)<<9) \| (month<<5) \| day`) |
| 76..78 |  2 | UCHI production date (same encoding) |
| 78..108| 30 | reserved / opaque |
| 108..109| 1 | extra byte |
| 109   |   1 | status flags: bit 0 = in-use, bit 4 = ready, bit 7 = standby |
| 110.. |  L | live alert bitfield (re-emitted as `@TF:<hex>` over TCP) |

### 3.3 Unusual bit indexing

The APK's `WifiFrog.G(idx, bArr)` function picks bit `(8*N - idx - 1) %
8` of byte `(8*N - idx - 1) // 8` for an N-byte array. For the 2-byte
control word this means `G(14)` reads bit 1 of the **high** byte (not
bit 14 of the word). Our parser mirrors this exactly; the unit test
`test_discovery.py::test_flag_helpers` covers it.

---

## 4. Handshake (`@HP:`)

### 4.1 Request

```
@HP:<pin>,<conn_id_hex>,<auth_hash>\r\n
```

* `pin` — ASCII PIN if the machine has one set; **empty** when none.
* `conn_id_hex` — `ExtensionsKt.c(SecurityManager.f40668d)` in the
  APK, which is just `''.join(f'{ord(c):02X}' for c in conn_id)`. The
  conn-id is *our* identifier (the J.O.E. app uses the device's
  Bluetooth name). It can be any ASCII string we choose.
* `auth_hash` — 64-hex-char token issued by the dongle on the **first
  successful pair**, or empty for an initial pair.

### 4.2 Responses

| Reply         | `ConnectionSetupState` | Meaning |
| ------------- | ---------------------- | ------- |
| `@hp4`        | CORRECT                | already paired, no fresh hash |
| `@hp4:<hash>` | CORRECT                | first-time pair: persist `<hash>` |
| `@hp5` / `@hp5:00` | WRONG_PIN         | PIN field wrong or required |
| `@hp5:01`     | WRONG_HASH             | conn-id unknown or hash stale |
| `@hp5:02`     | ABORTED                | conn-id known but hash mismatched / refused |

### 4.3 Unset-PIN pairing flow (verified against Kaffeebert)

1. **Client → dongle**: open TCP, send `@HP:,<conn_id_hex>,`
   (both pin and auth_hash empty).
2. **Dongle**: pops up a "Connect" dialog on its own touchscreen.
3. **User**: presses OK on the coffee machine.
4. **Dongle → client**: `@hp4:<64-hex-char-hash>`.
5. **Client**: persists `<hash>` (see §6) and treats the connection
   as authenticated.

On subsequent connections the client sends `@HP:,<conn_id_hex>,<hash>`
and gets back a bare `@hp4` (no on-machine confirmation needed).

The dialog timeout observed in practice is well under 60 s. The J.O.E.
app uses 40 s as its server-side timeout
(`WifiCommand.timeoutAfterSeconds = 40L`); the Python client uses
60 s by default for human comfort.

### 4.4 Failure modes seen in practice

* `@hp5:02 ABORTED` when reconnecting with an empty hash on a conn-id
  that was previously paired — the dongle remembers the slot and won't
  let it be silently re-claimed. **Solution**: pick a fresh `conn_id`
  and run the pair flow again (which trips the on-machine prompt).
* `@hp5:01 WRONG_HASH` when supplying a wrong hash for a known
  conn-id — same recovery: fresh `conn_id` + new pair.
* Empty hash with a *brand-new* conn-id that the dongle has never
  seen, but the dongle's display is asleep / not engaged: the dongle
  silently emits `@TF:` status frames without ever sending
  `@hp4`/`@hp5`. The Python client treats this as a `PairingTimeout`.

---

## 5. Commands

### 5.1 Read-only commands (implemented)

| Send             | Reply prefix      | Decoded type | Notes |
| ---------------- | ----------------- | ------------ | ----- |
| `@HP:p,c,h`      | `@hp4` / `@hp5`   | `HandshakeResult` | authentication |
| `@HE`            | _none_            | —            | polite close |
| `@HU?`           | `@TF:<hex>` (status frame) | `MachineStatus` | status request — the dongle just emits the next status frame |
| `@TG:43`         | `@tg:43<12 bytes hex>` | `MaintenanceCounters` | 6 × big-endian u16 |
| `@TG:C0`         | `@tg:C0<3 bytes hex>` | `MaintenancePercent` | 1 byte per cleaning / filter / decalc (`0xFF` = N/A) |
| `@TS:01`         | `@TB` then `@ts`  | str | lock the front-panel display |
| `@TS:00`         | `@ts`             | str | unlock the display |
| `@TM:<addr>`     | `@tm:<addr>...`   | str | memory / setting read (firmware-specific) |
| `@TR:<bank>`     | `@tr:<bank>...`   | str | bank-register read |

### 5.2 Unsolicited frames (received)

| Prefix     | Meaning |
| ---------- | ------- |
| `@TF:<hex>` | full machine status snapshot — alert bits, same layout as the discovery tail |
| `@TV:<hex>` | brewing-in-progress / product progress |
| `@hu:<code>` | heartbeat acknowledgement: `ok` / `wait` / `busy` / `abort` / `error` |

### 5.3 Maintenance counter layout (`@TG:43`)

12 bytes after the `@tg:43` prefix, 6 × big-endian u16. Order matches
the `<BANK Command="@TG:43">` section of the machine XML
(`assets/documents/xml/EF536/1.0.xml`):

```
[0..2]  cleaning
[2..4]  filter_change
[4..6]  decalc
[6..8]  cappu_rinse
[8..10] coffee_rinse
[10..12] cappu_clean
```

Live example from Kaffeebert:
```
@tg:4300150001000801580E21005B
       └┘└┘└┘└┘└┘└┘
       21  1  8 344 3617 91
```

### 5.4 Status bits (`@TF:`)

Bits are addressed globally: `byte_index * 8 + bit_within_byte`. The
client decodes the well-known S8 alert subset (cf.
`jura_connect.client._STATUS_BITS`). Live frame from Kaffeebert:
`@TF:0004000008000000` → byte 1, bit 2 set → `no_beans`.

### 5.5 **Destructive** commands — kept off the public API

These were observed in the EF536 machine XML or the APK and are
intentionally **not** wrapped by the Python client. The simulator
explicitly returns `@an:error` for them as a test-suite guardrail:

| Command | Effect |
| ------- | ------ |
| `@TG:21` | start `CappuClean` |
| `@TG:23` | start `CappuRinse` |
| `@TG:24` | start `Cleaning` |
| `@TG:25` | start `Decalc` |
| `@TG:26` | start `FilterChange` |
| `@TG:7E` | reset maintenance counters |
| `@TG:FF` | reset (something) |
| `@TF:02` | restart machine |
| `@AN:02` | power off |
| `@TP:<recipe>` | start brewing a product |
| `@HW:01,<pin>` | set machine PIN |
| `@HW:80,<ssid>` | set WiFi SSID |
| `@HW:81,<pwd>` | set WiFi password |
| `@HW:82,<name>` | set dongle name |

Use these only via raw `JuraClient.request()` and only with explicit
intent — running `@TG:24` will start a real cleaning cycle.

---

## 6. Credential persistence

### 6.1 File location

Default: `$XDG_DATA_HOME/jura-connect/credentials.json`
(fall-back `~/.local/share/jura-connect/credentials.json`).

Override with the global CLI flag `--store /path/to.json` or the
`CredentialStore(path=...)` constructor argument.

### 6.2 On-disk format

```json
{
  "version": 1,
  "machines": {
    "Kaffeebert": {
      "address": "192.168.1.42",
      "conn_id": "jura-connect-7f31a8c2",
      "auth_hash": "13908FE4D3EB986B2465ACDB50398D4C1622836A5A1632257FF065C13156C052",
      "paired_at": "2026-05-11T08:42:00Z"
    }
  }
}
```

Writes go through a `mkstemp(dir=…)` + `os.replace` rename, so
mid-write power loss leaves the previous file intact. The file is
`chmod 0600`'d on write since the hash grants full control over the
machine.

### 6.3 End-to-end workflow

```text
┌──────────┐  jura-connect discover           ┌────────────────┐
│          │ ─────────────────────────────►│  finds machine │
│  user    │                               │  at 192.168.…  │
│          │  jura-connect pair <ip>          └────────────────┘
│          │ ──────────────────┐
│          │                   │   open TCP/51515
│          │                   ▼
│          │           ┌─────────────┐  @HP:,<conn_id>,    ┌───────────────┐
│          │           │ JuraClient  │ ───────────────────►│  dongle       │
│          │           │             │                     │  "Connect?"   │
│          │ ◄────────────────── waiting up to 60 s … ─────│  dialog       │
│  presses │                                               └───────┬───────┘
│  OK on   │                   "Connect" prompt shown              │
│  machine │ ────────────────────────────────────────────────► OK pressed
│          │           ┌─────────────┐  @hp4:<64-char hash> ┌───────────────┐
│          │           │ JuraClient  │ ◄────────────────────│  dongle       │
│          │           └──────┬──────┘                      └───────────────┘
│          │                  │ CredentialStore.put(...)
│          │                  ▼
│          │           ┌─────────────────────────┐
│          │           │ credentials.json (0600) │
│          │           └─────────────────────────┘
│          │
│          │  jura-connect connect --name Kaffeebert --read-info
│          │ ──────────────────┐
│          │                   ▼
│          │   CredentialStore.get("Kaffeebert")
│          │           ┌─────────────┐ @HP:,<conn_id>,<hash>┌───────────────┐
│          │           │ JuraClient  │ ───────────────────► │  dongle       │
│          │           │             │ ◄─── @hp4 ──────────│               │
│          │           │             │ @TG:43, @TG:C0, @HU? │               │
│          │           │             │ ◄─── @tg:43..., @tg:C0..., @TF:... ──│
│          │           └─────────────┘                      └───────────────┘
│          │
│ <- output formatted MachineInfo
└──────────┘
```

---

## 7. Code map

| Module                       | Responsibility |
| ---------------------------- | -------------- |
| `jura_connect/crypto.py`        | per-nibble permutation, escape handling |
| `jura_connect/protocol.py`      | frame writer/reader on top of `crypto` |
| `jura_connect/discovery.py`     | UDP scan probe, broadcast-reply parser, TCP fallback sweep |
| `jura_connect/client.py`        | `JuraClient` + structured read results + handshake state machine |
| `jura_connect/commands.py`      | named-command registry (`info` / `counters` / `mem-read` / …) used by CLI and library |
| `jura_connect/credentials.py`   | XDG-located JSON persistence (atomic write, 0600) |
| `jura_connect/simulator.py`     | TCP server speaking the *same* protocol; used by tests |
| `jura_connect/__main__.py`      | CLI (`discover` / `probe` / `pair` / `command` / `creds`) |
| `tests/`                     | pytest suite — driven through the simulator end-to-end |
| `flake.nix`                  | dev shell + package + checks (passthrough pytest) |

Both the client and the simulator depend on the same two modules
(`crypto`, `protocol`) for framing, so a regression on either side
breaks both halves of the test-suite simultaneously.

---

## 8. Known unknowns / next steps

* The `@TR:32` "Product counter for Statistic" command returns nothing
  on TT237W V06.11 — likely needs an additional argument or differs
  between firmwares.
* `@TM:50` (PMode num-slots) and `@TM:42,<slot>` (slot product read)
  are documented in the APK; not yet wrapped because they're highly
  per-machine and depend on parsing the device's XML map.
* `@HU?` returned `@hu:800` in some probes but `@TF:<hex>` in others —
  the dongle may have multiple response code paths for the same input
  depending on internal state. Currently the client just waits for the
  next `@TF:` and treats that as the status answer.
* Locked-screen behaviour: `@TS:01` followed by `@TS:00` works
  cleanly, but issuing `@TS:01` and then disconnecting leaves the
  display locked until power cycle.
