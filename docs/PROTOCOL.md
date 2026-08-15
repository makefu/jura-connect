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

**Inner CRLF (verified against the J.O.E. Android app on TT237W).**
The *cleartext* body — the ASCII command string before the cipher runs
— also ends with a literal `\r\n`. So the bytes the dongle decodes
look like e.g. `@TM:13,211E96\r\n`, not `@TM:13,211E96`. This inner
CRLF is in addition to the outer frame terminator above. Discovered
the hard way: TT237W (Jura S8 EB) silently rejects settings writes
whose body has no inner CRLF, replying `@tm:00` for any
`@TM:<arg>,<val><csum>`. Reads happen to work without it, which made
the asymmetry hard to spot. `jura_connect.protocol.wrap` always
appends the inner CRLF on send (idempotent) and
`jura_connect.protocol.unwrap` / `FrameReader.next_frame` strip it on
receive so callers see clean payloads. Empirically every J.O.E.
phone→dongle and dongle→phone frame in the pcap carries the inner
CRLF, so this appears to be a general protocol rule, not a TT237W
quirk.

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

### 4.4 PIN pairing flow (machines with a setup PIN)

Machines that carry a front-panel setup PIN (e.g. Jura E6 / EF1030)
verify the PIN *before* showing the "Connect" dialog. The flow is
otherwise identical to §4.3, with the PIN filled into the first field:

1. **Client → dongle**: open TCP, send `@HP:<pin>,<conn_id_hex>,`
   (auth_hash empty, `<pin>` the ASCII digits).
2. **Dongle**: rejects with `@hp5` / `@hp5:00` (WRONG_PIN) if the PIN is
   missing or wrong; otherwise pops up the "Connect" dialog.
3. **User**: presses OK on the coffee machine.
4. **Dongle → client**: `@hp4:<64-hex-char-hash>`.
5. **Client**: persists both `<hash>` **and the PIN** (see §6) — the PIN
   is required again on every reconnect, so the client stores it and
   replays `@HP:<pin>,<conn_id_hex>,<hash>` each time.

CLI: pass `--pin <digits>` to `jura-connect pair`; it is written to the
credential store and reused automatically on later `jura-connect
command` runs. Pass `--pin` again only to override a stored PIN. The
PIN itself is never shown by `creds --json` (only `pin_stored: true`).

### 4.5 Failure modes seen in practice

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
* `ConnectionResetError` mid-handshake when **reconnecting too soon
  after closing a session**. Observed on a Z10 (NAA, EF545): the TCP
  connection is accepted, the `@HP:` frame is written, and the dongle
  resets instead of answering. It is session churn the dongle objects
  to, not connections — a socket that connects and then sends nothing
  is held open indefinitely without a reset, and the same credentials
  that fail back-to-back succeed with `@hp4` once left alone. Leaving
  ~20s between sessions was reliable; retrying immediately was not,
  through several consecutive attempts. Worth ruling out before
  suspecting a stale pairing, since the symptom looks identical.

  This may be the same behaviour as the mid-read drops noted for
  `@TM:42` in §5.6 — both are the dongle tearing down a session it has
  decided it is done with, rather than answering.

---

## 5. Commands

### 5.1 Read-only commands (implemented)

| Send             | Reply prefix      | Decoded type | Notes |
| ---------------- | ----------------- | ------------ | ----- |
| `@HP:p,c,h`      | `@hp4` / `@hp5`   | `HandshakeResult` | authentication |
| _(empty frame)_  | _none_            | —            | close the session — what J.O.E.'s `WifiCommandCloseConnection` sends, and what `JuraClient.close()` sends |
| `@HE`            | `@he:ok`          | —            | **OTA end** (`WifiCommandOTAEnd`), not a close verb — see below |
| `@HU?`           | `@hu:<3 hex>` (e.g. `@hu:800`) | — | milk-cooler update status (`WifiCommandMilkCoolerUpdateStatus`) — **not** a status request; see below |
| `@TG:FF`         | `@tg:FF`          | str          | cancel the running product step (`WifiCommandCancelProductStep`) — the "abort this brew" verb |
| `@TG:43`         | `@tg:43<8..12 bytes hex>` | `MaintenanceCounters` | 4..6 × big-endian u16, XML-declared order — see §5.3 |
| `@TG:C0`         | `@tg:C0<2..3 bytes hex>` | `MaintenancePercent` | 1 byte per XML-declared field (`0xFF` = N/A) — see §5.3 |
| `@TS:01`         | `@TB` then `@ts`  | str | lock the front-panel display |
| `@TS:00`         | `@ts`             | str | unlock the display |
| `@TM:<addr>`     | `@tm:<addr>...`   | str | memory / setting read (firmware-specific) |
| `@TR:<bank>`     | `@tr:<bank>...`   | str | bank-register read |
| `@TR:32,<page>`  | `@tr:32,<page>,<8 bytes hex>` | `ProductCounters` (composite) | paginated brew counters — see §5.5 |
| `@TM:50`         | `@tm:50,<num_slots><checksum>` | `int`        | programmable-recipe slot count — see §5.6 |
| `@TM:42,<slot>`  | `@tm:42,<slot><product_code>…<checksum>` | `PModeSlot` | per-slot product code; `@tm:C2` = not supported on this machine — see §5.6 |
| `@TM:41,<code>`  | `@tm:41,<F1..Fn hex><checksum>` | `PModeProduct` | one product's stored PMode settings; `@tm:C1` = not supported — see §5.6 |

#### There is no "read status" command

`@HU?` was long assumed to be a status request because probes that sent
it usually saw a `@TF:` frame right after. The APK settles it: `@HU?` is
`WifiCommandMilkCoolerUpdateStatus` and its matcher is
`@hu:[0-9a-fA-F]{3}` — `@hu:800` *is* the answer to `@HU?`. The `@TF:`
that followed was just the dongle's next periodic broadcast arriving.

J.O.E. never polls for status at all: `TCPReceiveHandler` routes pushed
`@TF:` frames as they land. `JuraClient.read_status()` does the same —
it sends nothing and returns the next broadcast. `read_status(nudge=True)`
still emits `@HU?` first, as an escape hatch for firmwares that want
traffic on the socket, but the status always comes from the pushed
`@TF:` frame.

The same class of mislabel applies to `@HE`: it is `WifiCommandOTAEnd`
(expects `@he:ok`, part of a firmware-update session), not "polite
close". The app closes a session with an **empty frame** — a frame whose
cleartext body is just the inner CRLF. `JuraClient.close()` sends that.

### 5.2 Unsolicited frames (received)

| Prefix     | Meaning |
| ---------- | ------- |
| `@TF:<hex>` | full machine status snapshot — alert bits, same layout as the discovery tail; **pushed periodically, never requested** |
| `@TV:<hex>` | brewing-in-progress / product progress — decoded, see §5.10 |
| `@TV:81,<text>` / `@TV:82,<text>` | language-download display lines — **not** progress |
| `@TV:84,<time>` | coffee-timer clock sync — **not** progress |
| `@TB` | brew started (sent right after an accepted `@TP:`) |
| `@hu:<code>` | milk-cooler / OTA-family acknowledgement code — 3 hex chars (`800` seen on Kaffeebert); also carries `ok` / `wait` / `busy` / `abort` / `error` tails on other verbs |

### 5.3 Maintenance counter layout (`@TG:43`, `@TG:C0`)

Big-endian u16 per counter after the `@tg:43` prefix — **but neither
the number of counters nor their order is universal.** Both are
declared per machine by the `<TEXTITEM Type=…>` children of the XML's
`<BANK Command="@TG:43">` element, and J.O.E. reads them from there:

```xml
<BANK Command="@TG:43" Name="Maintenance Counter">
  <TEXTITEM Type="Cleaning" Text="33"/>
  <TEXTITEM Type="FilterChange" Text="34"/>
  <TEXTITEM Type="Decalc" Text="35"/>
  <TEXTITEM Type="CappuRinse" Text="40"/>
  <TEXTITEM Type="CoffeeRinse" Text="36"/>
  <TEXTITEM Type="CappuClean" Text="41"/>
</BANK>
```

Across the 89 bundled profiles there are four variants (`Decalc` is
this library's `descale`):

| Fields (wire order) | Payload | Profiles |
| ------------------- | ------- | -------- |
| `Cleaning, FilterChange, Decalc, CappuRinse, CoffeeRinse, CappuClean` | 12 B | 68 — incl. EF536 and EF1091 (Kaffeebert) |
| `Cleaning, FilterChange, Decalc, CoffeeRinse` | 8 B | 13 — EF1013, EF1031, EF1089, EF1105, EF1105V2, EF1115, EF1115V2, EF1124, EF1125, EF1128, EF529, EF532COFFEEONLY, EF534 |
| `Cleaning, FilterChange, Decalc, CoffeeRinse, CappuRinse, CappuClean` | 12 B | 7 — EF0000, EF1090, EF1123, EF1143, EF1148, EF1171, EF_MASTER |
| `Cleaning, Decalc, CappuRinse, CoffeeRinse, CappuClean` | 10 B | 1 — EF567_C (no filter) |

`@TG:C0` (one byte per field, `0xFF` = not applicable) is declared the
same way and is `Cleaning, FilterChange, Decalc` on all 89 profiles
except EF567_C, which is `Cleaning, Decalc`.

`MachineProfile.maintenance_counter_fields` /
`.maintenance_percent_fields` carry the parsed order;
`MaintenanceCounters.parse(reply, profile=…)` and
`MaintenancePercent.parse(reply, profile=…)` use it, and
`JuraClient.read_maintenance_counter` / `read_maintenance_percent`
pass the client's profile automatically. Without a profile the first
(EF536 / EF1091) variant is assumed — on any of the other 21 machines
that mislabels the counters, so pass `--machine-type`. Fields the
machine does not report read back as `None` and are omitted from
`format()` / `to_dict()`.

Live example from Kaffeebert (EF1091, baseline order):
```
@tg:4300150001000801580E21005B
       └┘└┘└┘└┘└┘└┘
       21  1  8 344 3617 91
```
The same 12 bytes on an EF1090 mean 344 `coffee_rinse` and 3617
`cappu_rinse` — the tail is swapped.

### 5.4 Status bits (`@TF:`)

Bits are addressed **MSB-first within each byte**, indexed globally
across the frame. The APK's `Status.a()` is the canonical decoder:

```java
return ((1 << (7 - (i % 8))) & bArr[i / 8]) != 0;
```

So bit *N* lives at byte ``N // 8`` with mask ``1 << (7 - (N % 8))``.
This catches everyone who reads the XML and assumes naïve byte-LSB
indexing — prior to v0.9.0 this codebase had the bug and mis-named
every status bit by 7 positions per byte. The `<ALERT Bit="N" …>`
attribute in the machine XML uses the SAME N that the APK decoder
expects; only the byte/bit extraction matters.

The client decodes the well-known S8 alert set (cf.
`jura_connect.client._STATUS_BITS`) and groups each bit by the
*severity* lifted from the XML's `ALERT.Type` attribute:

| XML `Type` | Python severity | Meaning |
| ---------- | --------------- | ------- |
| `block`    | `error`         | the machine is genuinely stuck and needs user action (insert tray, fill water, …) |
| `info` or none | `info`      | informational state or low-supply reminder (`no_beans` with `Blocked="C"`, `heating_up`, `coffee_ready`, …) — not an error, just a flag |
| `ip`       | `process`       | a "schedule maintenance" prompt (descale / cleaning / filter / cappu rinse alerts) shown *before* it actually blocks brewing |

Live frame from Kaffeebert at idle: `@TF:0004000008000000`. Byte 1 =
`0x04` → MSB-position 5 set → global bit 13 = `coffee_ready`
(severity `info`). Byte 4 = `0x08` → MSB-position 4 set → global bit
36 = `energy_safe` (severity `info`). The machine is idle in
energy-save mode and the previous coffee is ready — neither bit is
an error, which matches reality.

The `MachineStatus` dataclass exposes `errors`, `info`, and
`process` as separate tuples plus the unsplit `active_alerts` for
backwards compatibility; only the first should drive "is the machine
broken?" logic.

### 5.5 Product brew counters (`@TR:32,<page>`)

The product counter table is paginated. The client issues 16
requests (`@TR:32,00` through `@TR:32,0F`); each reply has the form

```
@tr:32,<page_hex>,<8 hex bytes>
```

The 8-byte payload is four big-endian `u16` slot values. With 16
pages × 4 slots per page that gives a 64-slot table indexed by
product code:

* **Slot 0** carries the total number of brews ever performed on the
  machine.
* **Slots 1..63** carry the count for the product whose code matches
  the slot index, with `0xFFFF` reserved for "this code is not
  configured on this machine".

The product-code → human-name mapping comes from a `MachineProfile`
loaded by EF code (see §6 below). `jura_connect.client.PRODUCT_NAMES`
is the union map over the TT237W family (S8, ENA8, Z8, …) and is the
fallback when no profile is available. Profile-specific names take
precedence (`from_slots(slots, profile=…)`), so the S8 EB's `0x2B`
brews as `cortado` while the same code on the EF536 baseline is left
under `by_code`. Unknown codes always survive into
`ProductCounters.by_code` so a future firmware variant still surfaces
the raw count rather than dropping it on the floor.

Live first page from Kaffeebert (idle, after a few thousand brews):

```
@tr:32,00,0C9DFFFF004E0253
        └──┘└──┘└──┘└──┘
        3229 ----  78  595
        total       espresso  coffee
```

The second u16 (`FFFF`) is slot 1 = `ristretto` — not configured on
this S8 EB.

#### Counter slot ≠ product code on some machines

A product is normally counted at its own code, but not always: the
**Z10 (EF545) counts its two plain doubles one nibble above their
singles.** Its catalogue lists them at `0x31` ("2 Espressi") and `0x36`
("2 Coffee"), while the counters live at `0x12` and `0x13` and the
catalogue codes read `0xFFFF`.

This is a per-machine quirk, not a family rule. J.O.E. carries exactly
one such remap, built in `CoffeeMachineGenerator` as

```java
coffeeMachine.remap = str.equals("EF545")
        ? mapOf("31" to "12", "36" to "13") : emptyMap()
```

and consumed in `ProductCounterStatisticsParser`, which walks the
machine's *products* and reads each one from `remap[code] ?: code`.
`equals("EF545")` is the only machine-type special case anywhere in the
app, and the quirk is not derivable from the XML — EF545's and EF1091's
`<PRODUCT Code="31" …>` entries are identical down to `PosCSV`.

`jura_connect.client.COUNTER_SLOT_OVERRIDES` mirrors that table (with
one addition: if the override target reads `0xFFFF` on the machine in
front of us, the product's own code is used, so a firmware that counts
at the catalogue code keeps its counts). Machines outside the table are
untouched — an S8 EB (EF1091/EF1151) really does count its doubles at
`0x31`/`0x36`: reading one live gave `2_espressi` = 1 and `2_coffee` =
10, with `0x12`/`0x13` unused.

Both layouts can be cross-checked with the total: the machine bills a
double as two products, so `slot 0` minus the sum over the per-product
slots equals the number of double brews. Z10: 5945 − 5804 = 141 = the
`0x13` count. S8 EB: 3740 − 3729 = 11 = 1 + 10.

#### Other counter banks

`@TR:32` is one of several counter banks a machine's XML may declare
under `<PRODUCTCOUNTER>` (parsed into
`MachineProfile.counter_banks`):

…and, in a second section, under `<DAILYCOUNTER Reset="@TF:05">`
(`MachineProfile.daily_counter_banks` /
`MachineProfile.daily_counter_reset`). The full table, with the page
count and value width the client uses for each
(`jura_connect.client.COUNTER_BANK_SPECS`):

| Bank | Name | Section | Pages | Bytes/value | Profiles | Page count from |
|---|---|---|---|---|---|---|
| `@TR:32` | Product counter | PRODUCTCOUNTER | 16 | 2 | 89 / 89 | APK |
| `@TR:33` | Overflow product counter | PRODUCTCOUNTER | 16 | 1 | 34 | APK |
| `@TR:34` | Barista counter | PRODUCTCOUNTER | 16 | 2 | 4 | assumed |
| `@TR:35` | Overflow barista counter | PRODUCTCOUNTER | 16 | 1 | 3 | assumed |
| `@TR:42` | Daily product counter | DAILYCOUNTER | 16 | 2 | 37 | assumed |
| `@TR:43` | Overflow daily product counter | DAILYCOUNTER | 16 | 1 | 4 | assumed |
| `@TR:44` | Daily barista counter | DAILYCOUNTER | 16 | 2 | 4 | assumed |
| `@TR:45` | Overflow daily barista counter | DAILYCOUNTER | 16 | 1 | 4 | assumed |
| `@TR:52` | Special counter | PRODUCTCOUNTER | 4 | 2 | 14 | APK |
| `@TR:53` | Overflow special counter | PRODUCTCOUNTER | 4 | 1 | 4 | APK (WiFi) |

"APK" means J.O.E. issues exactly that many pages on the WiFi path;
"assumed" means no code path in the app touches the bank at all and the
client uses the product counter's 16 pages because the bank indexes the
same 64-slot product-code space. A machine that serves fewer pages
answers `@tr:00` early, which the reader honours (see below), so the
assumption costs at most one extra round trip.

The two flavours of the app disagree about `@TR:53`: the WiFi adapter
reads it with the 4-page `WifiCommandSpecialCounterStatistics`, the
Bluetooth one with `getStatisticsValues(15, "@TR:53", …, 1)` — 16
pages. This client follows the WiFi side, which is the transport it
speaks.

Only `@TR:32` has a dedicated result type (`ProductCounters`, whose
shape downstream consumers depend on). Every other bank decodes into
`CounterBank`, which carries the bank command alongside the same
`total` / `by_name` / `by_code` / `raw_slots` view. Slot 0 is the
bank's own total everywhere.

Slot naming differs by bank. The product, barista and daily banks index
the catalogue by product code, so profile product names apply (and so do
the `COUNTER_SLOT_OVERRIDES` above). The **special counter** does not:
its slots are fixed functions, per J.O.E.'s
`SpecialCounterStatisticsParser`, which builds a `SpecialCounterEmit`
out of

```
totalCounter    = slot 0
sweetFoam       = slot 3
coldBrew        = slot 4 + slot 5 + slot 6
strongColdBrew  = slot 9
lightBrew       = slot 12 + slot 13 + slot 14
```

(the app also reports `hotBrew` — reading slot 0, i.e. the same value
as the total, which looks like a copy/paste bug and is not reproduced
here). Slots outside that map still surface under `by_code`, so nothing
is dropped. `0xFFFF` counts as "not configured" and is skipped from the
sums, matching the app's `h()` helper.

The overflow banks carry **one byte per slot** holding the high word.
J.O.E. reads them exactly like `@TR:32` — 16 pages, `@TR:33,<page>` —
but with one byte per value instead of two. On the WiFi side
(`CoffeeMachineAdapterWifi.readProductStatistics`) that is literally the
same command class parameterised twice, and the overflow read happens
only when the machine's XML declares the bank:

```java
new WifiCommandProductCounterStatistics(machine, 2, "@TR:32")  // base
// then, iff a Bank with command "@TR:33" is present:
new WifiCommandProductCounterStatistics(machine, 1, "@TR:33")  // overflow
```

Bluetooth does the same through `readOverFlowCounter` →
`getStatisticsValues(15, "@TR:33", …, 1)`. Both flavours combine the two
banks in `StatisticStateEmit` as

```
count = value + (overflow << 16)
```

skipping overflow bytes of `0x00` ("no overflow yet") and `0xFF` (the
not-configured sentinel). Without the high byte a per-product count
wraps at 65535.

`jura_connect` reads an overflow bank when — and only when — the
machine's profile declares it, and folds it into its base bank
(`ProductCounters.from_slots(..., overflow=…)`,
`CounterBank.from_slots(...)`). An overflow bank is never readable on
its own: `JuraClient.read_counter_bank("@TR:33")` raises and points at
`@TR:32`. A machine may also declare the bank and still answer a bare
`@tr:00`; J.O.E.'s reply matcher accepts that shape
(`((@tr:33,<page>,.*)|(@tr:00))`) and so does the client, falling back
to the base table.

The same rule governs the base banks: `JuraClient.read_counter_bank`
sends nothing at all when the profile does not declare the bank, and
returns `None` — not an exception — for both "not declared" and "the
dongle answered `@tr:00` on page 0". Named commands
`special-counters`, `barista-counters`, `daily-brews` and
`daily-barista-counters` wrap the four base banks; `@TR:32` keeps its
own `brews`.

Bank sizes are not uniform: J.O.E.'s WiFi composite asks for 16 pages
of the product counter and its overflow, but only 4 pages of the
special counter (`WifiCommandSpecialCounterStatistics.j()` →
`IntRange(0, 3)`). The client therefore treats a `@tr:00` on a later
page as "bank ends here" and keeps the slots it did read; only a
`@tr:00` on the *first* page means "bank not implemented".

#### The daily banks are a machine capability the app ignores

37 of the 89 profiles carry

```xml
<DAILYCOUNTER Reset="@TF:05">
    <!-- Not available in JOE -->
    <BANK Command="@TR:42" Name="Daily Product counter"/>
    <BANK Command="@TR:43" Name="Daily Product counter overvlow" />
    <BANK Command="@TR:44" Name="Barista Counter Dayli"/>
    <BANK Command="@TR:45" Name="Overflow Barista counter Dayli"/>
</DAILYCOUNTER>
```

The `<!-- Not available in JOE -->` comment is Jura's own, and it holds
up: grepping the decompiled APK for `@TR:4[2-5]` returns nothing —
neither the WiFi nor either Bluetooth adapter ever asks for these
banks, and there is no parser for them. The machine keeps them anyway.
They are the per-product brew counts since the last reset, which is
exactly what a "coffees today" sensor wants, so this client reads them.

`@TF:05` is the XML's own `Reset` verb for the section — all 37
profiles spell it identically. It zeroes the daily banks irreversibly,
so it is in `DESTRUCTIVE_PREFIXES` and exposed only as the gated
`reset-daily-counters` command. Nothing in the app sends it either.

> **Untested against hardware.** No machine available to this project
> declares any bank beyond `@TR:32` — EF545, EF1091 and EF1151 list it
> alone — so all of the decoding above is derived from the app (special
> banks) or from the machine XMLs (barista and daily banks) and
> exercised against the simulator only. For `@TR:33`/`@TR:52`/`@TR:53`
> what the request looks like is settled: it is J.O.E.'s own WiFi path,
> quoted above. For `@TR:34`/`@TR:35` and the four daily banks not even
> that is confirmed — the command form follows the shared
> `@TR:<bank>,<page>` grammar every other bank uses, but no
> implementation has ever been observed sending them, and `@TF:05` has
> never been observed being answered. Treat all of it as APK/XML-derived
> and unverified.
>
> What a real machine *answers* is unknown in every case, so reply
> length is treated as advisory rather than assumed. Anything unexpected
> on an overflow read — a timeout, a reply shape we don't know — is
> logged and degraded to base counts rather than failing the whole read.
> On the WiFi side J.O.E. collects the banks it does read into a
> `StatisticsCollection` alongside the maintenance banks
> (`CoffeeMachineAdapterWifi.readStatistics`).

### 5.6 Programmable-recipe slots (`@TM:50` + `@TM:42,<slot>`)

The dongle's "PMode" interface exposes a small table of user-editable
recipe slots. Reading it is a two-step exchange:

```
client → @TM:50
dongle → @tm:50,<hex bytes ending in a checksum>
```

The body has one byte per recipe **kind** (the number of which is
machine-specific — the J.O.E. APK's PModeRequester does not encode it,
it asks the machine), followed by a single checksum byte equal to the
sum of those kind-bytes. The Python client sums the body modulo 256
and rejects the reply when the checksum doesn't match. The total
number of slots is `sum(per_kind_counts)`.

```
client → @TM:42,<slot_hex>
dongle → @tm:42,<slot_hex><product_code><F2..Fn><checksum>  (configured)
dongle → @tm:C2                                  (slot not exposed here)
```

The reply's trailing byte is the same `ByteOperations.d` checksum the
settings write uses (§5.7), computed over `"42,<slot_hex><payload>"`.
`PModeSlotProductReadParser` verifies it and then indexes the payload
*after* the slot byte as `F1, F2, F3 …` — `F1` is the product code, so
argument `F<n>` lives at payload byte `n-1`, the same offset rule the
`@TP:` recipe blob uses (§5.9).

The S8 EB / EF1091 reports 20 slots via `@TM:50` (`@tm:50,0404040404` +
checksum `7A`) but answers every `@TM:42,<n>` with `@tm:C2`. That is
the "machine reports a PMode table but doesn't make any of it
addressable" branch, and the machine's own XML agrees: EF1091 carries
`<MACHINESETTINGS Productprogramming="false">`.
`ProgramModeSlots.supported_by_machine` flips to `False` in that case,
and the CLI prints ``not supported by machine``.

The real machine also resets the TCP connection on some slot indices
mid-table; the client catches `(ConnectionError, OSError)` and marks
the remaining slots as unsupported rather than blowing up the whole
``pmode`` command.

#### 5.6.1 Where the XML declares PMode

There is **no `<PROGRAMMODE>` element** in Jura's schema. None of the
89 bundled XMLs has one, nor do the documented `EF0000` / `EF_MASTER`
templates. `MachineProfile.has_pmode` used to test for it and was
therefore always `False`. The machine declares product programming on
`<MACHINESETTINGS>` instead — the two attributes the APK's `XMLParser`
reads into `MachineSettings.productProgramming` / `.numberOfSlots`:

```xml
<MACHINESETTINGS Productprogramming="true"
                 NumberOfSlotsForProductProgramming="6">
```

| Declaration | Where | Count | `MachineProfile` |
| ----------- | ----- | ----- | ---------------- |
| `Productprogramming="true\|false"` | `<MACHINESETTINGS>` | 57 profiles (20 true) | `.product_programming`, `.has_pmode` |
| `NumberOfSlotsForProductProgramming` | `<MACHINESETTINGS>` | 5 profiles (all `6`) | `.pmode_slot_count` |
| `ProductSettings="true\|false"` | `<PRODUCT>` | 1679 products | `ProductDef.product_settings` |
| `PModeAdjust="false"` | recipe parameter | 5 profiles | `ProductParam.pmode_adjust` |
| `IntakeF18="true"` | `<MACHINEMANIFEST><CAPABILITIES>` | 23 profiles | `.intake_f18` |

`PModeAdjust="false"` marks a parameter the product-programming UI
hides (EF529 does this for `COFFEE_STRENGTH`); `build_pmode_hex`
refuses to *override* such a parameter but still emits its XML
default. `ProductSettings="false"` marks a product that is not
programmable at all.

#### 5.6.2 The 17-byte PMode product blob

**APK-derived, never sent to a real machine.** From
`ch.toptronic.joe.model.product.AppProduct.d()`:

* 17 bytes pre-filled with `0x00`;
* byte `n-1` for every `Argument="F<n>"` parameter, in the same units
  and 5 ml tick encoding as the `@TP:` blob (§5.9) — the APK's
  `ProductArgument.b()` selects exactly `F4` / `F10` / `Text="94"`,
  which is our `_ML_TICK_KINDS`;
* byte 0 overwritten with the product code, last.

Two differences from the `@TP:` start blob, both deliberate:

* it is 17 bytes, not 16 — `F17` (grinder freeness) needs byte 16, and
  `d()` always allocates it. `@TP:` is this blob truncated to 16 bytes
  (17 when the product has `F17`), which is why §5.9's blob is shorter;
* **byte 8 is not forced to `0x01`.** That "recipe valid" byte belongs
  to `AppProduct.c()`, the `@TP:` path; the PMode write sends the raw
  parameter blob.

#### 5.6.3 Product settings write (`@TM:41`) — APK-derived, untested

`WifiCommandPModeProductWrite` builds `"41," + AppProduct.d()` and
appends `ByteOperations.d` over that same string:

```
client → @TS:01                              (lock, PMODE priority)
client → @TM:41,<34 hex blob><checksum>
dongle → @tm:41                              (stored)
dongle → @tm:C1                              (product programming unsupported)
dongle → @tm:00                              (write rejected)
client → @TS:00                              (unlock)
```

`JuraClient.write_pmode_product` sends this, returns `@an:error`
verbatim (as `write_setting` does) and raises `ValueError` for `C1` /
`00` — a rejection token is never success.

#### 5.6.4 Slot assignment write (`@TM:42`) — APK-derived, untested

From `CoffeeMachineAdapterBle2.sendPmodeProductCommandSlot` plus
`WifiCommandPModeSlotProductWrite.Companion.a`:

```
body = "42," + <slot hex> + <first 14 bytes of the blob> + <tail>
wire = "@TM:" + body + ByteOperations.d(body)
reply matcher: @tm:42,<slot hex>.*      (@tm:C2 = not supported)
```

The tail is where it gets strange:

| Condition | Tail | Body length |
| --------- | ---- | ----------- |
| product has `F17` (grinder freeness) | `00 <F17> 00 00 00 00` | 20 bytes |
| no `F17`, but machine declares `IntakeF18` | `00 00 00 00 00 00` | 20 bytes |
| neither | *(nothing)* | 14 bytes |

Note the asymmetry: `F17` lands at blob index **15** here, not 16 as
in the full 17-byte blob, and the APK splices in the *unscaled*
`getValue("F17")` rather than the scaled byte `d()` computed. That may
well be a bug in J.O.E., but it is what the app puts on the wire, so
`JuraClient.write_pmode_slot` copies it.

#### 5.6.5 Rejection tokens

| Token | Command | APK source | Meaning |
| ----- | ------- | ---------- | ------- |
| `@tm:C1` | `@TM:41` | `PModeProductReadParser` | "Machine does not support Product Programming" |
| `@tm:C2` | `@TM:42` | `PModeSlotProductReadParser` | "Product code, slot, or function is not supported by machine" |
| `@tm:D0` | `@TM:50` | `PModeNumSlotReadParser` | no programmable slots |
| `@tm:00` | either write | dongle generic | write rejected |

None of these is a success reply. Reads map them to `None`; writes
raise. `jura_connect.client._PMODE_NOT_SUPPORTED` is the single table
both paths consult.

> **Nothing in §5.6.2 – §5.6.5 has been observed on hardware.** The
> only PMode traffic ever seen on a real machine is `@TM:50` and the
> `@tm:C2` answers from the S8 EB. The write formats come from the
> decompiled J.O.E. APK; the simulator models both branches so the
> decode path has coverage, but a machine could still disagree.

### 5.7 Machine settings (`@TM:<arg>` read / write)

Every machine XML carries a ``<MACHINESETTINGS>`` block. Each
``SWITCH`` / ``COMBOBOX`` / ``SLIDER`` element has a ``P_Argument``
attribute (e.g. ``"02"`` for hardness on EF1091); reading the setting
is

```
client → @TM:<P_Argument>
dongle → @tm:<P_Argument>,<value_hex><csum>
```

**A read echoes the same trailing checksum a write sends** — it is not
a bare value. `<csum>` is the two hex chars described further down this
section (`(-1 - sum("<P_Argument>,<value_hex>")) & 0xFF`), and
:meth:`jura_connect.client.JuraClient.read_setting` verifies it before
returning the value with it stripped.

Folding the check byte into the value is the obvious failure mode and
it is silent: every setting decodes to a plausible-looking but wrong
number, and short values alias onto other catalogue entries rather than
going out of range. Observed on a Z10 (NAA, EF545) — the fourth column
is what a decoder that keeps the check byte reports:

| Setting | Arg | Reply | Value | Naively decoded as |
| ------- | --- | ----- | ----- | ------------------ |
| Hardness | `02` | `0110` | `01` (1°dH) | 272°dH |
| AutoOFF | `13` | `1EF9` | `1E` (30min) | — |
| Units | `08` | `22010046` | `220100` (oz) | — |
| Language | `09` | `0208` | `02` (english) | `08` = russian |
| Brightness | `0A` | `07FB` | `07` (70%) | 2043% |

The language row is the dangerous one: `0208` ends in `08`, which is
russian's own code, so a decoder that suffix-matches the catalogue
reports a confidently wrong answer instead of an obviously broken one.
(`read_setting`'s docstring records the same class of bug from v0.9.0,
where hardness=13 came back as 3581.)

Writing is the same address with a value and a trailing checksum
byte, **wrapped in @TS:01 / @TS:00**:

```
client → @TS:01                              (lock keypad)
dongle → @ts
client → @TM:<P_Argument>,<value_hex><csum>  (the write)
dongle → @tm:<P_Argument>                    (success — echo of the address)
dongle → @an:error                           (rejected — checksum or value bad)
client → @TS:00                              (release keypad)
dongle → @ts
```

The wrapping is non-optional on TT237W firmware: omit it and the
dongle still ACKs the bare ``@TM:`` write with ``@tm:<arg>``
(looking like success) but the machine silently ignores the new
value until the next power cycle. The J.O.E. APK enforces this by
dispatching every ``CommandPriority.PMODE`` command — which is the
default for ``WifiCommandWritePMode`` — through a
``PriorityChannel`` branch that prepends ``@TS:01`` and appends
``@TS:00``. The Python port now mirrors that wrap in
:meth:`jura_connect.client.JuraClient.write_setting`; releases
0.9.0 - 0.9.1 omitted it, which is why settings appeared to write
successfully but never took effect.

In addition, **the cleartext body must end with `\r\n` before the
cipher runs** (see §1.1). TT237W's failure mode for a missing inner
CRLF is the opposite of the missing lock/unlock wrapper: instead of
ACKing with ``@tm:<arg>``, the dongle ACKs with ``@tm:00`` (the
rejection token) and the value never changes. Releases 0.9.0-0.9.2
hit this on every write. Discovered by pcap-decoding the J.O.E.
Android app's AutoOFF write on Kaffeebert (``192.168.111.192``);
every J.O.E. body carries the trailing CRLF inside the cipher body.

#### ItemSlider value storage (AutoOFF on EF1091)

``ItemSlider`` settings like AutoOFF (``P_Argument="13"``) use a
1-byte *type-tag* prefix on the wire:

* ``21<vv>`` — 1-byte unsigned value ``vv`` follows
  (``211E`` = 30 dec = 30min, ``213C`` = 60 dec = 1h)
* ``22<vvvv>`` — 2-byte unsigned value ``vvvv`` follows
  (``220168`` = 360 dec = 6h, ``22021C`` = 540 dec = 9h)
* ``0F`` — a one-byte literal value with no tag (15min)

The dongle persists only the value bytes for the ``21`` form (so
writing ``211E`` and then reading ``@TM:13`` gives back ``1E``) but
returns the literal value including the ``22`` tag for the
two-byte form (writing ``220168`` reads back ``220168``).
:meth:`jura_connect.client.JuraClient.write_setting` accepts both
shapes when verifying the readback, and the CLI's
``setting auto_off`` lookup falls back to suffix-matching the
ItemSlider catalogue so ``1E`` resolves to ``30min``.

The checksum is two upper-case hex chars computed by the J.O.E. APK's
``ByteOperations.d``: sum the codepoint of every char in
``"<P_Argument>,<value_hex>"``, format ``(-1 - sum) & 0xFF``. The
Python port is in
``jura_connect.client._settings_checksum``.

Each EF code's ``<MACHINESETTINGS>`` block enumerates the user-tunable
settings. On EF1091 (S8 EB) the seven settings are:

| Name | Kind | Arg | Notes |
| ---- | ---- | --- | ----- |
| Hardness | StepSlider | `02` | 1..30°dH, step 1, mask `FF` |
| AutoOFF | ItemSlider | `13` | 15min..9h, 11 named ITEMs (1-byte + 3-byte values mixed) |
| Units | Switch | `08` | `00`=mL / `01`=oz |
| Language | Combobox | `09` | 11 languages, `01`=German .. `0B`=Estonian |
| DisplayBrightnessSetting | Combobox | `0A` | 10..100% in 10% steps, `01`..`0A` |
| MilkRinsing | Combobox | `04` | `00`=Automatic / `01`=Manual |
| Frother Instructions | Switch | `62` | `01`=On / `00`=Off |

``jura_connect.profile.SettingDef`` carries the parsed catalogue;
``SettingDef.normalise_value`` validates user-supplied input (range
+ step for sliders, item name OR raw hex for switches/comboboxes)
before the write is sent. The CLI's ``setting`` command goes through
both validation and the destructive gate.

#### Catalogue shape across all 89 profiles

`<MACHINESETTINGS>` only ever contains four element kinds, all of
which `MachineProfile` parses: `SWITCH` (91 across the bundle),
`COMBOBOX` (122), `SLIDER` with `SliderType="StepSlider"` (46) or
`"ItemSlider"` (44), plus the `BANK` declaration below. Notes from the
survey:

* 32 of the 89 profiles carry **no** `<MACHINESETTINGS>` block at all
  (the older T-protocol families — `EF532`…`EF567`, `EF657`…`EF722`,
  including the synthetic `EF536` fallback baseline). On those, there
  is nothing to read and no settings bank.
* Every `COMBOBOX` carries `Read="TM:<P_Argument>"`, which is
  redundant with `P_Argument` in 121 of 122 cases (the 122nd is an
  empty string). Nothing is parsed from it.
* `Mask` is **not** slider-only: the ESM switch (`P_Argument="07"`)
  in the `EF0000` / `EF_MASTER` templates carries `Mask="01"`.
  `SettingDef.mask` now keeps it for every kind.
* Settings arguments the J.O.E. mock exercises but EF1091 lacks are
  ordinary catalogue entries elsewhere in the bundle and need no
  special handling: `1F` (TimeFormat, a `SWITCH`, 10 profiles) and
  `0A` (DisplayBrightnessSetting, a `COMBOBOX`, present on EF1091).
* A `P_Argument` may legitimately appear twice in one block (`1E` is
  both "Operating instructions" and "Aroma Control Instructions" in
  the template); the first declaration wins, matching J.O.E.

#### Batch settings read (`@TM:00,FC`) — **guessed reply, untested**

57 of the 89 profiles declare, inside `<MACHINESETTINGS>`:

```xml
<BANK Name="Setting" Command="@TM:00,FC" CommandArgument="02080913"/>
```

`CommandArgument` is a concatenation of two-hex-digit `P_Argument`
codes — `02` hardness, `08` units, `09` language, `13` auto-off —
i.e. one round trip instead of four. The declaration is **identical**
in all 57 (same command, same argument list); 16 of them name
arguments their own `<MACHINESETTINGS>` block never declares (e.g.
`EF1096` has neither `02`, `08` nor `13`), so the list is Jura
boilerplate rather than per-machine truth.

What the APK says about it: **nothing**. `XMLParser.e()` parses
`CommandArgument` into the `Bank` model, whose constructor then throws
it away (it keeps only name, command and text items). No
`WifiCommand*` class issues `@TM:00,…`; the WiFi settings path is
`WifiCommandReadPModeComposite`, which fans out into one
`WifiCommandReadPMode` (`@TM:<arg>`) per `SettingElement`. So the app
declares the bank and then never uses it.

`jura_connect` therefore sends the XML's `Command` verbatim, the same
way it treats every other `<BANK Command="…">`, and applies a strict,
guessed decoder modelled on the single-setting read:

```
client → @TM:00,FC
dongle → @tm:00,<v1><v2><v3><v4><csum>   (assumed success)
dongle → @tm:00                          (rejection — no batch read)
```

* values are concatenated in `CommandArgument` order and
  self-delimited by the ItemSlider type tags (`21` = one value byte
  follows, `22` = two, anything else *is* a one-byte value) — the only
  way a concatenated run can be split at all, since AutoOFF alone is
  1, 2 or 3 bytes wide;
* `<csum>` is the usual `ByteOperations.d` over `"00,<values>"`.

Unknowns, spelled out:

* whether the request needs a checksum of its own. `@TM:60,…` and
  every settings write carry one; `@TM:41,…` / `@TM:42,…` reads do
  not. `read_settings_bank(checksum=True)` sends the alternative form
  `@TM:00,FCEA` for probing.
* whether the reply is one frame or several.
* whether the value order follows `CommandArgument` at all.

Because of that, `JuraClient.read_all_settings()` treats the batch
read as an optimisation only: any rejection, checksum failure, or
value-count mismatch is caught and the settings are re-read one
`@TM:<arg>` at a time. The returned `SettingsSnapshot` records which
path was taken (`batch_used`, `batch_error`). **A wrong guess costs a
round trip, never a wrong value.** Verifying this against a real
machine is a read-only, non-destructive experiment: send `@TM:00,FC`
and compare the reply against four individual reads.

#### Limit load (`@TM:60,<product code><csum>`) — APK-derived, untested

`WifiCommandReadLimitLoad` asks the machine for the ranges it will
accept for one product *right now*, which is what J.O.E. bounds its
product sliders with instead of the static XML `Min`/`Max`:

```
client → @TM:60,<product code><csum>       csum = ByteOperations.d("60,<code>")
dongle → @tm:60,<code><5 min/max pairs><csum>
dongle → @tm:C1                            (no product programming on this machine)
```

Decoded by `LimitLoadParser`:

1. strip `@tm:`, require the `60` address (`C1` means "machine does
   not support Product Programming" and aborts the read);
2. the last two chars are a `ByteOperations.d` checksum over
   `"60,<body>"` — same algorithm as the settings read/write;
3. `<body>` is the echoed product code (which must match the request)
   followed by **exactly five min/max byte pairs**, in this fixed
   order regardless of what the product declares:

   | Slot | Arg | Parameter |
   | ---- | --- | --------- |
   | 1 | `F4` | water amount |
   | 2 | `F5` | milk amount |
   | 3 | `F6` | milk foam amount |
   | 4 | `F10` | bypass |
   | 5 | `F11` | milk break |

4. a pair with `FF` for min or max means "not applicable" and is
   dropped, as is any pair for a parameter the product's XML does not
   declare;
5. surviving values are scaled by that parameter's XML `Step` — 5 for
   water/bypass (so the bytes are 5 ml ticks, matching §5.9), 1 for
   the milk parameters (seconds).

Example (EF1091 Cappuccino, `04`): body `04` `0530` `FFFF` `012D`
`FFFF` `FFFF` decodes to water 25..240 ml and milk foam 1..45 s, with
milk / bypass / milk-break not applicable.

`JuraClient.read_limit_load()` returns a `ProductLimits` whose
`allows(kind, value)` bounds a brew against the machine's live limits.
The request form and the decode come straight from the APK; neither
has been exercised on hardware.

### 5.8 **Destructive** commands — gated behind `--allow-destructive-commands`

These were observed in the EF536 machine XML or the APK and are
exposed as named registry commands but gated behind
`--allow-destructive-commands` (or `allow_destructive=True` for
library callers). The simulator returns `@an:error` for them as a
test-suite guardrail; running them via `raw '@TG:24'` is gated by
the same prefix check.

| Command | Effect |
| ------- | ------ |
| `@TG:21` | start `CappuClean` |
| `@TG:23` | start `CappuRinse` |
| `@TG:24` | start `Cleaning` |
| `@TG:25` | start descaling (`descale` command) |
| `@TG:26` | start `FilterChange` |
| `@TG:7E` | skip a quality-assistant step (`WifiCommandCancelQualityAssistantStep`); bare = one step, `@TG:7E,FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF` = all. **Also observed zeroing every maintenance counter on TT237W** — see below |
| `@TF:02` | restart machine |
| `@TF:05` | zero the `<DAILYCOUNTER>` banks (`reset-daily-counters`); XML-declared `Reset` verb, irreversible, never sent by J.O.E. — see §5.5 |
| `@AN:02` | power off |
| `@TP:<recipe blob>` | start brewing a product — see §5.9 |
| `@HW:01,<pin>` | set machine PIN |
| `@HW:80,<ssid>` | set WiFi SSID |
| `@HW:81,<pwd>` | set WiFi password |
| `@HW:82,<name>` | set dongle name |

Use these only via raw `JuraClient.request()` and only with explicit
intent — running `@TG:24` will start a real cleaning cycle.

**`@TG:7E` — two readings, both irreversible.** The APK names it
`WifiCommandCancelQualityAssistantStep`, and that is how the app uses
it. But an accidental `@TG:7E` during this project's early probing
zeroed the maintenance counters on a real TT237W S8 EB, which is why it
was named `reset-counters` here for a long time. Both behaviours may
exist across firmware families; nobody should re-probe this on hardware
to find out. The registry exposes it as `skip-quality-step [one|all]`,
still gated, with a danger string that states both readings.

**`@TG:FF` is not destructive.** It was listed here as "reset
(something)"; the APK shows `WifiCommandCancelProductStep`, i.e. cancel
whatever product step is running. It moved to §5.1 and to the
non-gated `cancel` command.

Two more writes are destructive but are **not** in
`DESTRUCTIVE_PREFIXES`, because the list is matched as a byte prefix
and the same prefixes carry the corresponding *reads*; only the
payload length distinguishes them. They are gated on the
`CommandSpec` instead, exactly like the settings write:

| Wire | Command | Gate |
| ---- | ------- | ---- |
| `@TM:<arg>,<val><csum>` | `setting <name> <value>` | `dynamic_danger` |
| `@TM:41,<blob><csum>` | `pmode-set-product` | `destructive=True` — §5.6.3 |
| `@TM:42,<slot><blob><csum>` | `pmode-set-slot` | `destructive=True` — §5.6.4 |

The simulator applies the same refuse-by-default guardrail to the two
PMode writes via `SimulatorConfig.pmode_writable`.

### 5.9 Product start (`@TP:`) — the recipe blob (verified live)

Verified by **physically brewing** on a **JURA S8 EB / EF1091**
(owner's machine "kaffeebert", 2026-07) and, independently, on an
**E6** (upstream PR author's machine). Brewing works, but **not** with
a bare product code and **not** with the FF-padded blob earlier
versions of this library sent — both are ACKed and then silently
ignored. What the machine executes is a **16-byte recipe blob whose
unused bytes are `0x00` and whose byte 8 is a constant `0x01`**:

```
@TP:28000709000001000109000000000000   (cafe_barista, strength 7, 45 ml, normal, bypass 45 ml)
     │ │ │ │ │ │ │ │ │ └────────────── bytes 10..15: 00 (unused here)
     │ │ │ │ │ │ │ │ └──────────────── byte 9:  bypass, 5 ml ticks (0x09 = 9 = 45 ml)
     │ │ │ │ │ │ │ └────────────────── byte 8:  0x01 — constant "recipe valid" byte
     │ │ │ │ │ │ └──────────────────── byte 7:  00 (unused here)
     │ │ │ │ │ └────────────────────── byte 6:  temperature (00 low / 01 normal / 02 high)
     │ │ │ │ └──────────────────────── byte 5:  milk-foam amount, seconds (unused here)
     │ │ │ └────────────────────────── byte 4:  00 (unused here)
     │ │ └──────────────────────────── byte 3:  water amount, 5 ml ticks (0x09 = 9 = 45 ml)
     │ └────────────────────────────── byte 2:  coffee strength level (0x07 = 7)
     └──────────────────────────────── byte 0:  product code (byte 1 unused = 00)
```

* **Padding is `0x00`, and byte 8 is always `0x01`.** An FF-padded
  blob (`@TP:28FF0709FFFF01FFFF09FF…`) is ACKed `@tp:00` and does
  **nothing** — no `@TB`/`@TV` frames, counter unchanged, tried both
  single- and double-send. The 00-padded, byte-8=01 form brews on the
  first send. Byte 8 is a fixed structural byte: no bundled product
  carries a parameter there (nothing uses `Argument="F9"`).
* **Byte positions come from the machine XML.** Every PRODUCT element
  lists its parameters with an `Argument="F<n>"` attribute
  (COFFEE_STRENGTH at F3, WATER_AMOUNT at F4, MILK_FOAM_AMOUNT at F6,
  TEMPERATURE at F7, BYPASS at F10, MILK_BREAK at F11). The F-numbers
  are the byte offsets of the *Bluetooth* start-product command, which
  carries a leading key byte; the WiFi blob does not, so **blob offset
  = F − 1**.
* **Water and bypass are sent in 5 ml ticks** (`ml / 5`, one byte).
  XML `Value`/`Min`/`Max` attributes are in ml. Milk foam and milk
  break are seconds, sent as-is; strength is the level number;
  temperature is the ITEM value (00/01/02).
* **Live-verified:** water, temperature, strength and bypass, from the
  three cross-model vectors (S8 EB `cafe_barista`, E6 `espresso`, E6
  `coffee`). **Not individually live-verified — may misbrew, verify on
  your hardware:** `milk_foam_amount` / `milk_break` (seconds, as-is).
* **`0x00` means "parameter not set"** — for parameters the product
  doesn't have. A water byte the product *does* have must still be set
  explicitly: with 00-padding an unset water byte is `0x00` = **no
  water** (a dry/short shot), so `build_recipe_hex` refuses to leave it
  unset rather than guess.
* Cross-model verified vectors (all 00-padded, byte 8 = 01):
  `@TP:28000709000001000109000000000000` (S8 EB cafe_barista),
  `@TP:02000809000002000100000000000000` (E6 default espresso),
  `@TP:0300021A000001000100000000000000` (E6 coffee, strength 2,
  130 ml, normal).
* No trailing checksum is needed (unlike `@TM:` writes), and no
  `@TS:01`/`@TS:00` lock wrapper is required.
* Reply behaviour: the dongle ACKs an **accepted** blob with a bare
  `@tp`, then emits `@TB` when the brew starts, `@TV:41<code>…`
  progress frames (byte 4 = current tick, byte 5 = target ticks,
  second-to-last byte = percent 0x00–0x64), and `@TV:3E<code>` on
  completion. A **rejected/ignored** blob gets `@tp:00` and no further
  frames — `@tp:00` is *not* an accept.
* A machine in `energy_safe` wakes on the first `@TP:` but may ignore
  that first command; a retry then brews. `JuraClient.brew(retry=True)`
  opts into resending the blob once if the first reply is not an accept
  (bare `@tp`). With the correct 00-pad/byte-8=01 layout it brews on
  the first send, so the retry is usually moot.
* **Untested variants — verify on your hardware.** Live end-to-end
  verification exists only for single-boiler coffee machines (S8 EB /
  EF1091 by the maintainer, E6 by the upstream PR author). **Twin
  models** (e.g. J8/J10 "twin") and any product carrying a
  `grinder_ratio` parameter are **untested** — their blob layout may
  differ; report back if a brew is ACKed `@tp` but nothing pours.
* The dongle serves **one TCP session at a time**. Back-to-back
  commands may hit a connection refusal for a moment after the previous
  session closes — wait briefly and retry.
* Brew builds the blob from the machine **profile**, so a machine whose
  dongle stays silent on UDP discovery (no auto-detected EF code) must
  have its model set once — `set-machine-type <name> <EF>` (or
  `--machine-type <EF>`) — before `products` / `brew` resolve products
  against the right catalogue instead of the EF536 baseline.

The named `brew` command builds this blob from the machine profile —
`brew hotwater water=220 temp=high` — validating every value against
the XML catalogue (range, step, allowed items) before it goes on the
wire. `JuraClient.brew()` / `ProductDef.build_recipe_hex()` are the
library entry points; a full hex blob is still accepted verbatim as
an escape hatch for firmware variants with a different layout.

The `products` command lists every brewable product on the connected
machine with its resolvable name and each `param=value` key's allowed
values (ranges/steps for water & milk, item choices for strength &
temperature) — built from the same profile, with no extra machine
I/O. Use it to discover exactly what `brew` accepts.

---

### 5.10 Product progress (`@TV:`) — the live state machine

Unsolicited frames the machine pushes while it is doing something:
brewing, running a maintenance process, counting a coffee timer down,
showing an aroma preselection. This is what turns "an alert bit is
set" into "brewing, 60 %".

```
@TV:<hex payload>
```

**Provenance.** The layout below is **APK-derived** — decompiled from
`Progress`, `ProgressParser`, `ProgressState`, `ProductProgressState`
and `ProductArgument` in J.O.E. 4.6.10 — and is **not** hardware
verified as a whole. Two parts *do* match the live S8 EB capture in
§5.9 and are marked **[live]** below; everything else is
**[APK, untested]**.

#### Payload layout

Byte indexes are into the hex payload (`byte(i)` = hex chars
`2i..2i+2`).

| byte | meaning |
| ---- | ------- |
| 0 | progress-state code (table below) |
| 1 | product code (product frames) or process code (process frames) |
| 2 | either the `8F` window marker, or the first value byte |

The **value window** is byte 2 onward, or byte 3 onward when byte 2 is
`8F` *and* the frame is a product/process frame. All indexes below
index the window, not the payload:

| idx | slot (`ProductArgument`) |
| --- | ------------------------ |
| 0 / 1 | actual / max coffee strength |
| 2 / 3 | actual / max water volume |
| 4 / 5 | actual / max milk time |
| 6 / 7 | actual / max milk-foam time — doubles as steam temperature and as bypass water |
| 8 | max water temperature |
| 9 / 10 | actual / max pause time |
| 11 | `INTAKE_PERCENTAGE` (**not** what the app reads) |
| 12 | percentage 0x00–0x64 — J.O.E. reads the percent from **12**, not 11. Mirror the app; do not "fix" it |
| 13 | invalid / padding |

A 16-byte payload (2 head + 14 window) therefore puts the percentage
at payload byte 14, the second-to-last byte — which is exactly where
the live capture in §5.9 saw it, and window slots 2/3 land on payload
bytes 4/5, exactly where §5.9 saw "current tick / target ticks".
**[live]** The frame is decoded defensively: any slot the payload is
too short to reach decodes as `None` rather than raising.

#### Which slots a state reports

Only some states carry a live value pair; for the rest the decoder
falls back to "window slot 0 is the value" (plus slot 1 as the maximum
in an `8F` frame). **[APK, untested]**

| state | reports | actual idx | max idx |
| ----- | ------- | ---------- | ------- |
| `19` | SMART_ALERT_PAUSE | 0 | 1 |
| `31` | MILK_FOAM_BEAN_AMOUNT | 0 | 1 |
| `32` | MILK_FOAM_MILK_VOLUME | 4 | 5 |
| `33` | MILK_FOAM_PAUSE | 9 | 10 |
| `34` | MILK_FOAM_VOLUME | 6 | 7 |
| `37` | MILK_FOAM_WATER_VOLUME | 2 | 3 |
| `39` | COFFEE_BEAN_AMOUNT | 0 | 1 |
| `3C` | COFFEE_WATER_AMOUNT | 2 | 3 |
| `40` | HOTWATER_TEMPERATURE | 8 | 8 |
| `41` | HOTWATER_VOLUME | 2 | 3 |
| `41` | BYPASS_WATER_VOLUME (see below) | 6 | 7 |
| `43` | STEAM_TEMPERATURE | 6 | 7 |

**The `41` disambiguation.** State `41` is overloaded. The app reads
it as `HOTWATER_VOLUME` (slots 2/3) **only when window slot 6 is
`0xFF`**, and as `BYPASS_WATER_VOLUME` (slots 6/7) otherwise —
including when the payload is too short to contain slot 6. Slot 6 is
the bypass-water slot, so `0xFF` reads as "no bypass in this recipe,
the water figure is the real one". The live S8 EB brew in §5.9 showed
tick/target at payload bytes 4/5 — i.e. the `HOTWATER_VOLUME`
reading — so on that firmware slot 6 was `0xFF`. **[live for the
`0xFF` branch, APK-only for the bypass branch]**

#### Frame type

J.O.E. classifies each frame; the order is odd but deliberate and the
decoder mirrors it exactly:

1. state in {`C0`, `C1`, `C4`, `C5`} → `COFFEE_TIMER`;
2. state `7E` → `QUALITY_ASSISTANT`;
3. state ≠ `FE` **and** byte 1 is a known product code → `PRODUCT`;
4. byte 1 is a known process code → `PROCESS`;
5. state `FE` → `AROMA_PRESELECTION`;
6. state `FF` → `P_MODE`;
7. otherwise → `NONE`.

"Known product code" means the loaded `MachineProfile` has it — so
this is profile-dependent: with no profile (or the wrong EF code) a
product frame classifies as `NONE`, while the value window still
decodes. "Known process code" is the tail of a `<PROCESS
ExecuteCommand="@TG:xx">` element; all 89 bundled XMLs use only
`21` CappuClean, `22` CoffeeRinse, `23` CappuRinse, `24` Cleaning,
`25` Decalc, `26` FilterChange, so `jura_connect.progress.PROCESS_CODES`
hard-codes those six.

#### `ProgressState` — all 87 codes **[APK, untested]**

```
01 INSERT_TRAY                  02 FILL_WATERTANK               03 EMPTY_GROUNDS
04 EMPTY_TRAY                   08 INSERT_GROUNDS_BOX           09 CLOSE_NOZZLE_COVER
0A CLOSE_BEAN_COVER             0C CLOSE_TAP                    0D OPEN_TAP
0E ALARM                        0F CLOSE_POWDER_COVER           10 ADD_POWDER_COFFEE
11 FILLING_PROCESS              12 SYSTEM_EMPTYING              13 ADD_BEANS
14 NOT_ENOUGH_POWDER            15 WAITING                      16 REMOVE_WATERTANK
17 MOUNT_SIRUP_CONTAINER        18 REMOVE_SIRUP_CONTAINER       19 SMART_ALERT
1E PLACE_CUP_FOR_COFFEE         1F PLACE_CUP_FOR_CLEANING       20 STARTUP
21 HEATING_UP                   23 RINSE_PROCESS                30 POPUP_WINDOW
31 MILK_FOAM_BEAN_AMOUNT        32 MILK_FOAM_MILK_VOLUME        33 MILK_FOAM_PAUSE
34 MILK_FOAM_VOLUME             37 MILK_FOAM_WATER_VOLUME       38 MILK_FOAM_NO_ADJUSTMENT
39 COFFEE_BEAN_AMOUNT           3C COFFEE_WATER_AMOUNT          3D COFFEE_NO_ADJUSTMENT
3E ENJOY                        40 HOTWATER_TEMPERATURE         41 HOTWATER_VOLUME
42 STEAM_TIME                   43 STEAM_TEMPERATURE            49 LAST_PROGRESS_STATE
4B GRINDER_SETTING_REQUEST      50 DESCALIFY_START              51 DESCALIFY_MATERIALS
52 DESCALIFY_EMPTY_TRAY         53 DESCALIFY_ADD_FLUID          54 DESCALIFY_PROCESS
55 DESCALIFY_RINSE_WATERTANK    56 DESCALIFY_FINISH             5A DESCALIFY_CONNECT_THE_MILK_TUBE
60 FILTER_RINSE_START           61 FILTER_RINSE_MATERIALS       62 FILTER_RINSE_CHANGE
63 FILTER_RINSE_PROCESS         65 FILTER_RINSE_FINISH          66 FILTER_RINSE_REMOVE_FILTER
67 FILTER_RINSE_INSERT          70 CLEANING_START               71 CLEANING_MATERIALS
72 CLEANING_EMPTY_TRAY          73 CLEANING_PRESS_ROTARY        74 CLEANING_PROCESS
75 CLEANING_ADD_TABLET          76 CLEANING_FINISH              7E QUALITY_ASSISTANT
90 CAPPU_CLEAN_START            91 CAPPU_CLEAN_MATERIALS        92 CAPPU_CLEAN_ADD_CLEANER
93 CAPPU_CLEAN_PROCESS          94 CAPPU_CLEAN_ADD_WATER        95 CAPPU_CLEAN_FINISH
9A CAPPU_CLEAN_RINSE_PROCESS    C0 COFFEE_TIMER_SCREEN_SAVER    C1 COFFEE_TIMER_STATUS_SCREEN
C4 COFFEE_TIMER                 C5 COFFEE_TIMER_PMODE_COUNTDOWN E1 WARNING
E2 ACTION                       E3 INFO                         E4 FILTER_ERROR
E5 FILTER_THANKS                E6 TOO_HOT                      EF WIFI_CONFIGURATION
FE AROMA_PRESELECT              FF P_MODE                       00 INVALID
```

`3E` (`ENJOY`) ends a product — the live capture in §5.9 saw exactly
that frame when the cup was done. **[live]**

#### `@TV:` frames that are *not* progress

`@TV:81,<text>` and `@TV:82,<text>` are language-download display
lines and `@TV:84,<time>` is the coffee-timer clock sync. They must
never be fed to the progress decoder;
`jura_connect.progress.is_progress_frame()` rejects them (both the
comma-delimited form and any payload whose head byte is `81`/`82`/`84`)
and `ProductProgress.parse()` raises `ValueError` on them.

#### Library entry points

```python
p = ProductProgress.parse("@TV:41280000091E0000FF00000000003200", profile)
p.state          # ProgressState.HOTWATER_VOLUME (None for unknown codes)
p.progress_type  # ProgressType.PRODUCT
p.product        # "cafe_barista" — resolved via the MachineProfile
p.actual, p.maximum, p.percent, p.fraction
p.is_complete    # True only on the ENJOY frame
p.format(); p.to_dict()

for update in client.iter_progress(timeout=120):   # decoded stream
    ...
client.follow_progress(timeout=120)                 # collect until ENJOY
client.brew("espresso", follow=True)                # brew, then follow
```

The named `progress` command watches the stream and prints the decoded
lines; it is read-only (it sends nothing). The simulator models the
whole chain — `@tp` → `@TB` → rising `@TV:41…` frames → `@TV:3E…` —
behind `SimulatorConfig(allow_brew=True)`, which is off by default so
an accidental `@TP:` in a test still gets refused with `@an:error`.

### 5.11 Maintenance processes and the state machine — **APK/XML-derived, untested**

Starting a cleaning cycle is a conversation, not a command. `@TG:24`
only *opens* it; the machine then drives the client through its
`<STATE>` table and waits for confirmations. Everything in this section
comes from `WifiCommandStartProcess`, `WifiCommandProcessAccept`,
`WiFiCommandNextProductStep` and `StateArgument` in the decompiled app
plus the 89 bundled machine XMLs. **Nothing here has been run against
hardware** — every confirmation advances a real cycle and consumes
supplies, so it was verified against the simulator only.

#### The four verbs

| Wire | J.O.E. class | Reply matcher | Meaning |
| ---- | ------------ | ------------- | ------- |
| `@TG:21/22/23/24/25/26` | `WifiCommandStartProcess` | the command, lower-cased (`@tg:24`) | start the cycle |
| `@TG:10` / `@TG:04` | `WifiCommandProcessAccept` | *(none — the app awaits no reply)* | confirm the state the machine is parked on |
| `@TG:01` | `WiFiCommandNextProductStep` | `@tg:(01\|00)` | advance a step; `@tg:00` = rejected |
| `@TG:FF` | `WifiCommandCancelProductStep` | `@tg:FF` | cancel the current step (§5.8) |

`WifiCommandStartProcess` builds its matcher by lower-casing the
command it was handed, so the acknowledgement is a pure echo. The
accept command sets *no* matcher at all: the app fires it and moves on.
This library still waits for a frame (anything that is not a pushed
`@TF:`/`@TV:`), because a session that sends and never reads cannot tell
a refusal from a success.

#### `<PROCESSES>` — what a machine can run

```xml
<PROCESS Type="Cleaning" ExecuteCommand="@TG:24" Progress="true"
         Title="221" Picture="geraet_reinigen.png"
         PDFURL="…" VideoURL="…"/>
```

Six types exist across all 89 profiles, and each maps 1:1 onto a
command byte — the same table `jura_connect.progress.PROCESS_CODES`
uses to name the process byte of a `@TV:` frame:

| Type | Command | Profiles declaring it | Library name |
| ---- | ------- | --------------------- | ------------ |
| `Cleaning` | `@TG:24` | 89 | `cleaning` |
| `Decalc` | `@TG:25` | 88 | `descale` |
| `FilterChange` | `@TG:26` | 83 | `filter_change` |
| `CappuRinse` | `@TG:23` | 75 | `cappu_rinse` |
| `CappuClean` | `@TG:21` | 74 | `cappu_clean` |
| `CoffeeRinse` | `@TG:22` | 3 | `coffee_rinse` |

`Progress="true"` means the machine pushes `@TV:` frames while the
cycle runs. Every `Cleaning`, `Decalc`, `CappuRinse`, `CappuClean` and
`CoffeeRinse` entry declares it; `FilterChange` declares
`Progress="false"` on 78 of the 83 profiles that have it — those
machines run the filter change entirely on their own front panel, so
following one from here will see no states and simply time out.
`MachineProcess.progress` carries the flag.

#### `<PROGRESS_STATE_INTAKE>` — the state table

83 `<STATE>` entries, identical in value and name across every bundled
profile:

```xml
<STATE Value="26" Name="Press Rinse" Title="193"
       Picture="pflege_druecken.png" AcceptCommand="@TG:10"/>
```

`Value` is **the same byte as `ProgressState`** (§5.10), i.e. the first
byte of a pushed `@TV:` frame, so the frame resolves straight into the
machine's own label for the step.

The XML table is not redundant with the enum: **18 of EF1091's 83
states are missing from `ProgressState` entirely** — among them `22`
"Press Rotary or Next", `24` "Coffee Ready", `2D` "No milk", `9B` "Dock
Cappu Outlet" and, crucially, **`26` "Press Rinse", the state a
cleaning cycle parks on**. Without the profile the decoder reports that
frame as `UNKNOWN(0x26)` and nothing knows a confirmation is due. Load
the machine profile.

Only four states ever carry an `AcceptCommand`:

| State | Name | Accept | Profiles |
| ----- | ---- | ------ | -------- |
| `26` | Press Rinse | `@TG:10` | 78 |
| `92` | Cappu Clean add cleaner | `@TG:04` | 10 |
| `94` | Cappu Clean add water | `@TG:04` | 10 |
| `75` | Cleaning add tablet | `@TG:10` | 9 |

So a profile uses `@TG:10`, `@TG:04`, or both — never anything else
(pinned by a test over all 89 XMLs). Five states end a cycle, again
identically everywhere: `0B` Cappurinse finished, `56` Descale
finished, `65` Filter Rinse finished, `76` Cleaning Process finished,
`95` Cappu Clean finish. `jura_connect.process.PROCESS_FINISH_STATES`
maps each process to its own; `TERMINAL_STATE_CODES` is the union plus
`3E` (`ENJOY`).

#### The conversation

```
-> @TG:24
<- @tg:24
<- @TV:7024…            state 70  "Cleaning Start"
<- @TV:7224…            state 72  "Cleaning empty tray"
<- @TV:7524…            state 75  "Cleaning add tablet"
<- @TV:2624…            state 26  "Press Rinse"  -> AcceptCommand="@TG:10"
-> @TG:10
<- @tg:10
<- @TV:7424…            state 74  "Cleaning Process"
<- @TV:7624…            state 76  "Cleaning Process finished"
```

The frames are ordinary progress frames (§5.10): byte 0 the state, byte
1 the **process** code, then the value window — which is why
`ProductProgress.progress_type` comes out as `PROCESS`. No bundled
profile assigns a product the codes `0x21`..`0x26`, so a process frame
can never be mistaken for a product one.

The *ordering* of the states inside a cycle is the one thing the XMLs
do not say. The sequences in `SimulatorConfig.process_sequences` are a
plausible reconstruction, not an observation.

#### Alert metadata: what is blocked, and what clears it

The same XML says which products an active alert stops and which
process makes it go away:

```xml
<ALERT Bit="10" Name="no beans" … Blocked="C" Type="info"/>
<ALERT Bit="34" Name="cleaning alert" … Type="ip"
       ProcessButton="206" Process="Cleaning" CancelButton="72"/>
```

* `Type="block"` blocks **every** product kind; `info` / `ip` block only
  what `Blocked` names (and `Blocked` is absent on most of them).
* `Blocked` is a single `Product.ProductGroup` token — `C`, `M`, `CM`,
  `T`, `TM`, `P`. Jura's own comment only says that `CM` "block[s]
  products of Coffe, Milk and Coffe + Milk", and the app code that
  consumes the field did not survive obfuscation, so
  `profile.expand_blocked_kinds()` implements the reading that matches
  that example and the machine's behaviour: **a token blocks every kind
  that shares a letter with it**. `Blocked="M"` therefore blocks `M`,
  `CM` and `TM` — no milk, no cappuccino.
* `Process` names the maintenance process that clears the alert, in the
  same vocabulary as the table above (`Decalc` → `descale`).
  **13 of the 89 profiles point at a process they never declare** —
  milk-free machines that kept the boilerplate cappu-rinse/cappu-clean
  alerts. Treat the field as a hint; `resolve_process()` refuses an
  undeclared one rather than sending a verb the machine has no use for.
* `Disabled="0406070A2E"` is a list of individual product codes (the app
  chops it into two-character substrings); watch-only in J.O.E.

`MachineStatus` surfaces all of this **only when a profile is loaded** —
the hard-coded EF536 fallback codebook has no such metadata:

```python
st = client.read_status()          # client built with profile=load_profile("EF1091")
st.blocked_kinds                   # ("C", "CM") — no beans
st.blocked_products                # ("espresso", "coffee", "cappuccino", …)
st.blocking_alerts                 # ("no_beans",)
st.alert_processes                 # (("cleaning_alert", "cleaning"),)
st.can_brew_kind("T")              # True — hot water is still fine
st.can_brew("espresso")            # False
```

Every pre-existing field and `to_dict()` key is unchanged; the four new
keys (`blocked_kinds`, `blocked_products`, `blocking_alerts`,
`alert_processes`) are additive.

#### Library entry points

```python
client.process_runner("cleaning")      # bind, send nothing
client.run_process("cleaning", auto_accept=True, timeout=900)
client.watch_process(timeout=60)       # read-only: decode a cycle someone else started

runner = client.process_runner("cleaning")
runner.start()                         # @TG:24, raises ProcessError if refused
step = runner.wait_step(timeout=120)   # ProcessStep: name, accept_command, percent
if step.needs_confirmation:
    runner.accept()                    # the state's own @TG:10 / @TG:04
runner.next_step(); runner.cancel()    # @TG:01 / @TG:FF
run = runner.follow(auto_accept=True)  # ProcessRun.format() / .to_dict()
```

`follow(on_step=…)` takes a decision callback returning a
`ProcessAction` (`WAIT` / `ACCEPT` / `NEXT` / `CANCEL`), which is how a
UI drives the cycle without blocking on `auto_accept`.

Named commands: `processes` (list, no I/O) and `process-watch`
(listen-only) are ungated; `process-start`, `process-run`,
`process-accept` and `process-next` are **gated** — `@TG:01`, `@TG:04`
and `@TG:10` joined `DESTRUCTIVE_PREFIXES` because confirming a step
advances a physical cycle and burns the tablet or descaler that step
uses. The simulator models the whole walk behind
`SimulatorConfig(allow_process=True)` and refuses the verbs with
`@an:error` without it.

---

## 6. Machine variants (`MachineProfile`)

The 88 machine XML files extracted from the J.O.E. APK
(`assets/documents/xml/<EF_code>/<version>.xml`) are vendored under
`jura_connect/data/xml/` and loaded on demand by
`jura_connect.profile.load_profile(code)`. They provide:

* the **alert bitmap** — bit index → name → severity
  (`block`/`info`/`ip` in the XML, mapped to `error`/`info`/`process`
  in Python);
* the **product code → name** map for the brew-counter table;
* (where present) the `<PROGRAMMODE>` section, currently exposed only
  as the kind-count vector consumed by `@TM:50`.

### 6.1 EF code lookup

`jura_connect/data/JOE_MACHINES.TXT` (vendored verbatim from the APK)
is a `;`-separated table of
``<article_number>;<friendly_name>;<EF_code>;<type>`` rows. Example
rows around the S8 EB:

```
15480;S8 (EB);EF1091;tt237w
15533;S8 (EB);EF1151;tt237w
```

The CLI's pair flow reads the article number from a UDP discovery
reply (offset 68..70, BE u16) and looks the EF code up in this table.
On firmwares that don't answer unicast UDP (notably TT237W) the
lookup fails — pass `--machine-type EF1091` explicitly, or retro-fit
later with ``jura-connect set-machine-type --name … EF1091``.

`jura_connect.profile.iter_profiles()` parses every bundled XML once
and caches the result via `lru_cache`. Loading a single profile is
roughly an `ElementTree.parse` + a couple of `findall(".//{*}TAG")`
sweeps — wildcard namespace traversal is used because each XML
declares the same `xmlns="http://www.top-tronic.com"` default
namespace.

### 6.2 EF536 fallback

Credentials without a `machine_type` field fall through to the
synthetic ``EF536`` baseline (the only profile the codebase hard-coded
before v0.8.0). The fallback covers the alert names and the
common product codes for the S8 / ENA8 / Z8 lineage; it doesn't know
about the S8 EB's `cortado` (`0x2B`) and friends. That's why
EF1091-paired machines should explicitly carry `machine_type = EF1091`
in their credential.

---

## 7. Credential persistence

### 7.1 File location

Default: `$XDG_DATA_HOME/jura-connect/credentials.json`
(fall-back `~/.local/share/jura-connect/credentials.json`).

Override with the global CLI flag `--store /path/to.json` or the
`CredentialStore(path=...)` constructor argument.

### 7.2 On-disk format

```json
{
  "version": 1,
  "machines": {
    "Kaffeebert": {
      "address": "192.168.1.42",
      "conn_id": "jura-connect-7f31a8c2",
      "auth_hash": "13908FE4D3EB986B2465ACDB50398D4C1622836A5A1632257FF065C13156C052",
      "pin": "1234",
      "machine_type": "EF1091",
      "paired_at": "2026-05-11T08:42:00Z"
    }
  }
}
```

`pin` is optional — present only for machines that require a setup PIN
on every reconnect (see §4.4). It is stored verbatim so reconnects
replay it, but `creds --json` redacts it to `pin_stored: true`.

`machine_type` is optional — omitted entries silently fall through to
the EF536 baseline. `CredentialStore.set_machine_type(name, code)`
retro-fits the field onto an existing entry without forcing a re-pair.

Writes go through a `mkstemp(dir=…)` + `os.replace` rename, so
mid-write power loss leaves the previous file intact. The file is
`chmod 0600`'d on write since the hash grants full control over the
machine.

### 7.3 End-to-end workflow

```text
┌──────────┐  jura-connect discover           ┌────────────────┐
│          │ ─────────────────────────────►│  finds machine │
│  user    │                               │  at 192.168.…  │
│          │  jura-connect pair <ip>          └────────────────┘
│          │ ──────────────────┐
│          │                   │   open TCP/51515
│          │                   ▼
│          │           ┌─────────────┐ @HP:<pin>,<conn_id>, ┌───────────────┐
│          │           │ JuraClient  │ ───────────────────►│  dongle       │
│          │           │             │  (pin empty if none)│  "Connect?"   │
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
│          │           ┌─────────────┐@HP:<pin>,<conn_id>,<hash>┌───────────┐
│          │           │ JuraClient  │ ───────────────────► │  dongle       │
│          │           │             │ ◄─── @hp4 ──────────│               │
│          │           │             │ @TG:43, @TG:C0       │               │
│          │           │             │ ◄─ @tg:43…, @tg:C0…, pushed @TF:… ───│
│          │           └─────────────┘                      └───────────────┘
│          │
│ <- output formatted MachineInfo
└──────────┘
```

---

## 8. Code map

| Module                       | Responsibility |
| ---------------------------- | -------------- |
| `jura_connect/crypto.py`        | per-nibble permutation, escape handling |
| `jura_connect/protocol.py`      | frame writer/reader on top of `crypto` |
| `jura_connect/discovery.py`     | UDP scan probe, broadcast-reply parser, TCP fallback sweep |
| `jura_connect/profile.py`       | per-machine `MachineProfile` registry built from the 88 bundled XMLs + `JOE_MACHINES.TXT` |
| `jura_connect/data/`            | vendored XMLs + `JOE_MACHINES.TXT`; shipped as `package-data` so installed wheels load profiles via `importlib.resources` |
| `jura_connect/client.py`        | `JuraClient` + structured read results + handshake state machine; profile-aware status / brew / pmode parsers |
| `jura_connect/commands.py`      | named-command registry (`info` / `counters` / `brews` / `pmode` / `mem-read` / `progress` / …) used by CLI and library |
| `jura_connect/progress.py`      | `@TV:` product-progress decoder — `ProgressState` / `ProgressType` / `ProductProgress` (§5.10) |
| `jura_connect/credentials.py`   | XDG-located JSON persistence (atomic write, 0600); `machine_type` field |
| `jura_connect/simulator.py`     | TCP server speaking the *same* protocol; used by tests |
| `jura_connect/__main__.py`      | CLI (`discover` / `probe` / `pair` / `command` / `creds` / `machine-types` / `set-machine-type`) |
| `tests/`                     | pytest suite — driven through the simulator end-to-end |
| `flake.nix`                  | dev shell + package + checks (passthrough pytest) |

Both the client and the simulator depend on the same two modules
(`crypto`, `protocol`) for framing, so a regression on either side
breaks both halves of the test-suite simultaneously.

---

## 9. Known unknowns / next steps

* `@TG:7E` means "skip a quality-assistant step" in the APK but zeroed
  the maintenance counters on a TT237W S8 EB. Whether that is a
  firmware difference or a side effect of the skip is unresolved, and
  **must not** be resolved by probing hardware — the counters cannot be
  restored. See §5.8.
* Locked-screen behaviour: `@TS:01` followed by `@TS:00` works
  cleanly, but issuing `@TS:01` and then disconnecting leaves the
  display locked until power cycle.
* `@TM:42` returning data on a machine that *does* expose programmable
  slots has still not been observed live — the S8 EB / EF1091 reports
  a slot count via `@TM:50` but answers `@tm:C2` for every index. The
  configured-slot decode path is now **covered by simulation** (the
  simulator serves populated slots with real checksums, and
  `tests/test_pmode.py` round-trips a slot write through it), but it
  remains unobserved on hardware. Same for the `@TM:41` / `@TM:42`
  **writes** in §5.6.3 / §5.6.4: APK-derived, simulator-verified,
  never sent to a machine. A machine whose XML carries
  `Productprogramming="true"` (20 of the 89 bundled profiles, e.g.
  EF1143 / EF529) is what's needed to confirm them.
* `@TV:` decoding (§5.10) is APK-derived and verified only against the
  simulator plus the two live observations recorded in §5.9. Wanted
  from real hardware: a full raw capture of a brew (to pin the frame
  *length* and confirm the percentage really sits at window slot 12
  rather than 11), a milk drink (states `31`–`37`), a `41` frame from
  a recipe with bypass (to confirm the `BYPASS_WATER_VOLUME` branch),
  and any `8F` extended-window frame — we have never seen one.
