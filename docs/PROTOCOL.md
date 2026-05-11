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
| `@TR:32,<page>`  | `@tr:32,<page>,<8 bytes hex>` | `ProductCounters` (composite) | paginated brew counters — see §5.5 |
| `@TM:50`         | `@tm:50,<num_slots><checksum>` | `int`        | programmable-recipe slot count — see §5.6 |
| `@TM:42,<slot>`  | `@tm:42,<slot>,<product_code>...` | `PModeSlot` | per-slot product code; `@tm:C2` = not supported on this machine — see §5.6 |

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
| `ip`       | `process`       | a "schedule maintenance" prompt (decalc / cleaning / filter / cappu rinse alerts) shown *before* it actually blocks brewing |

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
client → @TM:42,<slot_dec>
dongle → @tm:42,<slot_dec>,<product_code_hex>...   (slot is configured)
dongle → @tm:C2                                    (slot not exposed on this machine)
```

The S8 EB / EF1091 reports 20 slots via `@TM:50` (`@tm:50,0404040404` +
checksum `7A`) but answers every `@TM:42,<n>` with `@tm:C2`. That is
the "machine reports a PMode table but doesn't make any of it
addressable" branch — the EF1091 XML omits the `<PROGRAMMODE>` section
entirely. `ProgramModeSlots.supported_by_machine` flips to `False` in
that case, and the CLI prints ``not supported by machine``.

The real machine also resets the TCP connection on some slot indices
mid-table; the client catches `(ConnectionError, OSError)` and marks
the remaining slots as unsupported rather than blowing up the whole
``pmode`` command.

### 5.7 Machine settings (`@TM:<arg>` read / write)

Every machine XML carries a ``<MACHINESETTINGS>`` block. Each
``SWITCH`` / ``COMBOBOX`` / ``SLIDER`` element has a ``P_Argument``
attribute (e.g. ``"02"`` for hardness on EF1091); reading the setting
is

```
client → @TM:<P_Argument>
dongle → @tm:<P_Argument>,<value_hex>
```

Writing has TWO wire forms depending on whether the setting is part
of a ``<BANK>``. Each machine XML may declare one bank inside
``<MACHINESETTINGS>``:

```xml
<BANK Name="Setting" Command="@TM:00,FC" CommandArgument="02080913" />
```

On EF1091 the bank covers hardness (02), units (08), language (09)
and auto_off (13). Brightness (0A), milk_rinsing (04) and frother
(62) are **not** in the bank.

### Bank settings — bulk write @TM:00,FC

```
client → @TS:01                                      (lock keypad)
dongle ← @ts
client → @TM:00,FC,<arg1><val1>...<argN><valN><csum> (bulk write)
dongle ← @tm:00                                      (success)
dongle ← @an:error                                   (rejected)
client → @TS:00                                      (release keypad)
dongle ← @ts
```

The bulk payload is the concatenation of (arg, value) pairs in the
order given by ``CommandArgument``. Values are **variable-length**;
for AutoOFF specifically, the leading byte encodes the field
width:

| Lead byte | Total width | Example                |
| --------- | ----------- | ---------------------- |
| ``0F``    | 1 byte      | ``0F``           = 15min |
| ``21``    | 2 bytes     | ``211E``         = 30min |
| ``22``    | 3 bytes     | ``220168``       = 6h    |

The dongle parses each value's width by inspecting its leading
byte. The Python client constructs the payload by reading the
current values for any bank arg the user isn't changing and
substituting only the targeted arg.

Writing a bank arg via the **individual** ``@TM:<arg>,<val><csum>``
form is silently dropped by TT237W firmware — the dongle ACKs with
``@tm:00`` (the bank reply signature) but the machine ignores the
write. v0.9.0-v0.9.2 sent only individual writes which is why
settings appeared to write successfully but never took effect.

### Non-bank settings — individual write @TM:<arg>,<val>

```
client → @TS:01
dongle ← @ts
client → @TM:<P_Argument>,<value_hex><csum>          (individual write)
dongle ← @tm:<P_Argument>                            (success)
dongle ← @an:error                                   (rejected)
client → @TS:00
dongle ← @ts
```

Used for args that are NOT listed in any ``<BANK CommandArgument>``.
On EF1091: brightness (0A), milk_rinsing (04), frother (62). The
J.O.E. APK's language-download flow also uses this individual form
(it writes args 24, 25, 09 with z2=true / CommandPriority.COMMAND,
bypassing the PMODE lock wrap entirely).

### The @TS:01/@TS:00 lock wrap

Both write forms run inside a ``@TS:01`` … ``@TS:00`` pair. The
J.O.E. APK's PriorityChannel dispatch
(``apk_unpacked/smali_classes2/k8/c.smali:367``) does this
automatically for any command sent with
``CommandPriority.PMODE`` — which is the default for
``WifiCommandWritePMode``. Skipping the wrap leaves the keypad
"live" and writes are silently rejected.

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
      "machine_type": "EF1091",
      "paired_at": "2026-05-11T08:42:00Z"
    }
  }
}
```

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

## 8. Code map

| Module                       | Responsibility |
| ---------------------------- | -------------- |
| `jura_connect/crypto.py`        | per-nibble permutation, escape handling |
| `jura_connect/protocol.py`      | frame writer/reader on top of `crypto` |
| `jura_connect/discovery.py`     | UDP scan probe, broadcast-reply parser, TCP fallback sweep |
| `jura_connect/profile.py`       | per-machine `MachineProfile` registry built from the 88 bundled XMLs + `JOE_MACHINES.TXT` |
| `jura_connect/data/`            | vendored XMLs + `JOE_MACHINES.TXT`; shipped as `package-data` so installed wheels load profiles via `importlib.resources` |
| `jura_connect/client.py`        | `JuraClient` + structured read results + handshake state machine; profile-aware status / brew / pmode parsers |
| `jura_connect/commands.py`      | named-command registry (`info` / `counters` / `brews` / `pmode` / `mem-read` / …) used by CLI and library |
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

* `@HU?` returned `@hu:800` in some probes but `@TF:<hex>` in others —
  the dongle may have multiple response code paths for the same input
  depending on internal state. Currently the client just waits for the
  next `@TF:` and treats that as the status answer.
* Locked-screen behaviour: `@TS:01` followed by `@TS:00` works
  cleanly, but issuing `@TS:01` and then disconnecting leaves the
  display locked until power cycle.
* `@TM:42` returning data on a machine that *does* expose programmable
  slots has not been observed live — the S8 EB / EF1091 reports a
  slot count via `@TM:50` but answers `@tm:C2` for every index. A
  TT237W variant with a populated `<PROGRAMMODE>` XML section is
  needed to validate the configured-slot decode path.
