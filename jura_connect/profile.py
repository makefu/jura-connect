"""Per-machine profile loader (alerts, products, pmode capabilities).

The J.O.E. Android APK ships 88 XML files under
``apk/assets/documents/xml/<EF_code>/<version>.xml`` describing each
machine variant: which alert bits exist, which product codes the
machine knows, whether pmode slots are configurable, etc. The codes
differ meaningfully across machines — e.g. on the EF536 (legacy S8)
``0x12`` is "2 Espressi" but on the EF1091 (S8 EB) "2 Espressi"
lives at ``0x31``. Hard-coding any single map is wrong.

This module loads the XMLs lazily, parses the relevant sections
(``ALERTS``, ``PRODUCTS``, optional ``PROGRAMMODE``) into a
:class:`MachineProfile`, and offers lookup helpers — including a
mapping from a machine's article-number (read from the discovery
reply) to the matching EF code via the bundled ``JOE_MACHINES.TXT``.

Profiles are cached in-process after first load. The loader uses
:mod:`importlib.resources` so it works inside a wheel, in a Nix
store path, or against a local checkout without any path tricks.
"""

from __future__ import annotations

import dataclasses
import importlib.resources
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from functools import lru_cache

# Anchor for importlib.resources.files() so the loader works whether
# we're running from a wheel, a Nix store path, or a source checkout.
# __package__ is Optional[str] which trips type checkers; pin it down.
_PACKAGE = "jura_connect"

# Per-XML alert Type -> internal severity. Mirrors the categorisation
# in :mod:`jura_connect.client._STATUS_BITS` but is now sourced from
# the XML rather than hard-coded.
_XML_TYPE_TO_SEVERITY = {
    "block": "error",
    "info": "info",
    "ip": "process",
}

#: Wire commands of the two maintenance banks whose field order the XML
#: declares. Used as the ``<BANK Command=…>`` lookup key.
MAINTENANCE_COUNTER_BANK = "@TG:43"
MAINTENANCE_PERCENT_BANK = "@TG:C0"


@dataclasses.dataclass(slots=True, frozen=True)
class AlertDef:
    """One ALERT entry from the machine XML."""

    bit: int
    name: str  # snake_case, derived from XML Name attribute
    severity: str  # "error" / "info" / "process"
    raw_name: str  # the original XML Name (with spaces)


def _snake(name: str) -> str:
    """Normalise an XML ``Name`` attribute to a snake_case identifier.

    Splits CamelCase ("AutoOFF" → "auto_off",
    "DisplayBrightnessSetting" → "display_brightness_setting") and
    flattens runs of non-alphanumerics to single underscores.
    """
    s = name.strip()
    # Split lower→upper boundaries: "fooBar" → "foo Bar"
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", s)
    # Split runs of uppercase followed by a lowercase letter:
    # "HTMLParser" → "HTML Parser", "AutoOFFTimer" → "Auto OFF Timer".
    s = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", s)
    s = s.lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    s = s.strip("_")
    return s or "unnamed"


def _validate_ranged(
    value: int, lo: int | None, hi: int | None, step: int | None, name: str
) -> None:
    """Validate an integer against an XML Min/Max/Step range.

    Shared by :meth:`ProductParam.encode` and
    :meth:`SettingDef.normalise_value`. When ``Min`` is absent in the
    XML it defaults to ``0`` — never to "unbounded" — so an off-step or
    out-of-range water amount can't slip through a profile that happens
    to omit ``Min``. Raises :class:`ValueError` on any violation.
    """
    lo = 0 if lo is None else lo
    hi = 0xFF if hi is None else hi
    if not lo <= value <= hi:
        raise ValueError(f"{name}: {value} is outside [{lo}, {hi}]")
    if step and step > 1 and (value - lo) % step != 0:
        raise ValueError(f"{name}: {value} is not aligned to the step ({step})")


@dataclasses.dataclass(slots=True, frozen=True)
class SettingItem:
    """One ITEM child of a SWITCH / COMBOBOX / ItemSlider setting."""

    name: str  # snake_case form for the CLI
    raw_name: str  # original XML Name (may have spaces / mixed case)
    value: str  # hex string, uppercase, e.g. "0F" or "22021C"


@dataclasses.dataclass(slots=True, frozen=True)
class SettingDef:
    """One machine setting from <MACHINESETTINGS>.

    ``kind`` distinguishes the input type:

    * ``"switch"`` — two-position toggle (Units, Frother Instructions);
      values are ITEM-driven (typically ``"00"``/``"01"``).
    * ``"combobox"`` — pick-one from N values (Language, Brightness,
      MilkRinsing); values are ITEM-driven.
    * ``"step_slider"`` — integer-valued slider (Hardness): Min..Max
      with Step granularity.
    * ``"item_slider"`` — pick-one from named ITEMs but laid out as a
      slider in the J.O.E. UI (AutoOFF / switch-off-delay).
    """

    name: str  # snake_case identifier for CLI, e.g. "hardness"
    raw_name: str  # original XML Name, e.g. "Hardness"
    p_argument: str  # hex byte(s), e.g. "02" — the @TM:<arg> code
    kind: str  # "switch" | "combobox" | "step_slider" | "item_slider"
    default: str | None  # hex default, e.g. "10" for hardness=16
    items: tuple[SettingItem, ...]  # may be empty for step_slider
    minimum: int | None  # step_slider only
    maximum: int | None  # step_slider only
    step: int | None  # step_slider only
    mask: str | None  # step_slider only ("FF", "FFFF" …)

    def item_by_name(self, name: str) -> SettingItem | None:
        target = _snake(name)
        for it in self.items:
            if it.name == target:
                return it
        return None

    def item_from_hex(self, raw_hex: str) -> SettingItem | None:
        """Resolve a read-back hex value to its catalogue ITEM.

        Exact-match first, then suffix-match — AutoOFF (P_Argument=13)
        writes ``211E`` but reads back the dongle's stored value
        ``1E`` (the length-tag byte ``21`` is dropped); we want both
        to resolve to the same ``30min`` item. Returns ``None`` when
        the value is not in the catalogue.
        """
        cleaned = raw_hex.strip().lstrip(",").upper()
        for it in self.items:
            if it.value.upper() == cleaned:
                return it
        for it in self.items:
            if it.value.upper().endswith(cleaned):
                return it
        return None

    def validate_wire_hex(self, raw: str) -> str:
        """Validate a wire-format hex value (the form
        :meth:`JuraClient.write_setting` sends).

        Differs from :meth:`normalise_value` in that step-slider input
        is parsed as **hex**, not decimal — write_setting's contract is
        hex-format end-to-end. ITEM names are still accepted as a
        convenience (so library callers can write
        ``write_setting("13", "30min")``).

        Returns the canonical upper-case hex form, or raises
        :class:`ValueError` if the input is neither a known ITEM name
        nor a valid in-range / in-catalogue hex value.
        """
        raw = raw.strip()
        # ITEM-name match (covers switch / combobox / item_slider).
        item = self.item_by_name(raw)
        if item is not None:
            return item.value.upper()
        candidate = raw.upper()
        if self.kind == "step_slider":
            try:
                n = int(candidate, 16)
            except ValueError as exc:
                raise ValueError(
                    f"{self.raw_name}: expected a hex value or item name, got {raw!r}"
                ) from exc
            lo = self.minimum if self.minimum is not None else 0
            hi = self.maximum if self.maximum is not None else 0xFF
            if not lo <= n <= hi:
                raise ValueError(
                    f"{self.raw_name}: 0x{candidate} (={n}) is outside [{lo}, {hi}]"
                )
            if self.step and self.step > 1 and (n - lo) % self.step != 0:
                raise ValueError(
                    f"{self.raw_name}: {n} is not aligned to the step ({self.step})"
                )
            width = len(self.mask) if self.mask else 2
            return f"{n:0{width}X}"
        # ITEM-driven kinds: hex must exactly match a catalogue entry.
        for it in self.items:
            if it.value.upper() == candidate:
                return candidate
        allowed = ", ".join(f"{it.name}={it.value}" for it in self.items)
        raise ValueError(
            f"{self.raw_name}: {raw!r} is not a recognised value. "
            f"Allowed: {allowed or '(no options known)'}"
        )

    def normalise_value(self, raw: str) -> str:
        """Turn a user-supplied value into the wire-format hex string.

        - For switches / comboboxes / item-sliders: accept either an
          ITEM name (``"on"``, ``"english"``, ``"15min"``) or the hex
          value itself (``"01"``).
        - For step sliders: accept a decimal integer in [min, max]
          honouring the step; return a hex string of the right width.

        Raises ``ValueError`` with a helpful message if the value is
        invalid.
        """
        raw = raw.strip()
        if self.kind == "step_slider":
            try:
                n = int(raw, 0)
            except ValueError as exc:
                raise ValueError(
                    f"{self.raw_name}: expected an integer, got {raw!r}"
                ) from exc
            _validate_ranged(n, self.minimum, self.maximum, self.step, self.raw_name)
            width = len(self.mask) if self.mask else 2
            return f"{n:0{width}X}"
        # SWITCH / COMBOBOX / ItemSlider — match against ITEM names or
        # raw hex values.
        item = self.item_by_name(raw)
        if item is not None:
            return item.value.upper()
        # Allow raw hex too (must match one of the catalogue values).
        candidate = raw.upper()
        for it in self.items:
            if it.value.upper() == candidate:
                return candidate
        allowed = ", ".join(f"{it.name}={it.value}" for it in self.items)
        raise ValueError(
            f"{self.raw_name}: {raw!r} is not a recognised value. "
            f"Allowed: {allowed or '(no options known)'}"
        )


#: Total length of the ``@TP:`` recipe blob in bytes. Live-verified by
#: physically brewing on a JURA S8 EB (EF1091) and, independently, an
#: E6: the machine ACKs and brews a 16-byte payload whose *unused*
#: bytes are ``0x00`` (see :meth:`ProductDef.build_recipe_hex`); a
#: bare product code, or an FF-padded blob, is ACKed ``@tp:00`` and
#: silently ignored.
RECIPE_BLOB_BYTES = 16

#: Blob byte index that must always be ``0x01`` for the machine to
#: accept and brew the recipe. Observed constant across every
#: hardware-verified vector (S8 EB cafe_barista, E6 espresso, E6
#: coffee); no bundled product carries a parameter at this index
#: (nothing uses ``Argument="F9"``), so it is a fixed structural byte.
_RECIPE_VALID_BYTE_INDEX = 8
_RECIPE_VALID_BYTE = "01"

#: Recipe-parameter kinds whose XML values are millilitres encoded on
#: the wire as 5 ml ticks (one byte). WATER_AMOUNT is live-verified on
#: the S8 EB (EF1091): water at 45 ml lands as 0x09 (9 ticks). BYPASS
#: shares WATER_AMOUNT's ml semantics in the XML (ml-ranged, Step=5)
#: and is live-verified on the S8 EB (cafe_barista bypass 45 ml -> 0x09).
_ML_TICK_KINDS = frozenset({"water_amount", "bypass"})

#: 5 ml per wire tick for the kinds above (matches the Bluetooth
#: protocol's "1 second = 5 ml" documented by Jutta-Proto).
_ML_PER_TICK = 5

# --- Public recipe-parameter kind identifiers --------------------------
# These are the stable snake_case strings used as :attr:`ProductParam.kind`
# and as the keys of the ``overrides`` dict accepted by
# :meth:`ProductDef.build_recipe_hex`. Downstream consumers (the Home
# Assistant component) should import these instead of hard-coding the
# literal strings, so a future rename stays in one place.
KIND_WATER_AMOUNT = "water_amount"
KIND_COFFEE_STRENGTH = "coffee_strength"
KIND_TEMPERATURE = "temperature"
KIND_MILK_AMOUNT = "milk_amount"
KIND_MILK_FOAM_AMOUNT = "milk_foam_amount"
KIND_MILK_BREAK = "milk_break"
KIND_BYPASS = "bypass"

#: All recipe-parameter kinds this library knows how to encode, in a
#: stable order suitable for building UI (product code first is implicit).
RECIPE_PARAM_KINDS: tuple[str, ...] = (
    KIND_COFFEE_STRENGTH,
    KIND_WATER_AMOUNT,
    KIND_TEMPERATURE,
    KIND_MILK_AMOUNT,
    KIND_MILK_FOAM_AMOUNT,
    KIND_MILK_BREAK,
    KIND_BYPASS,
)


@dataclasses.dataclass(slots=True, frozen=True)
class ProductParam:
    """One recipe parameter of a PRODUCT entry (WATER_AMOUNT, …).

    Public/stable attributes (UI-render contract): :attr:`kind` (stable
    identifier — compare against the ``KIND_*`` constants),
    :attr:`default` (XML default in XML units, or ``None``),
    :attr:`minimum` / :attr:`maximum` / :attr:`step` (ranged/ml params),
    and :attr:`items` (ordered choices for enumerated params such as
    strength/temperature; each has ``.name``, ``.raw_name``, ``.value``).

    ``argument`` is the XML ``Argument`` attribute's F-number
    (``Argument="F4"`` → 4). The F-numbers are byte positions in the
    Bluetooth start-product command *including* its leading key byte;
    the WiFi ``@TP:`` blob carries no key byte, so the byte offset
    inside the blob is ``argument - 1`` (:attr:`offset`). Verified
    live on an E8 (EB) / EF538 — water at F4 lands on blob byte 3.
    """

    kind: str  # snake_case XML tag, e.g. "water_amount"
    argument: int  # F-number from the XML, e.g. 4 for Argument="F4"
    default: int | None  # XML Value/Default in XML units (ml / level / s)
    minimum: int | None
    maximum: int | None
    step: int | None
    items: tuple[SettingItem, ...]  # TEMPERATURE only

    @property
    def offset(self) -> int:
        """Byte offset of this parameter inside the recipe blob."""
        return self.argument - 1

    def encode(self, value: int | str) -> int:
        """Validate ``value`` (in XML units) and return the wire byte.

        * ml-ranged kinds (water, bypass): validated against Min/Max/
          Step, then divided into 5 ml ticks;
        * ITEM-driven kinds (temperature): accepts an ITEM name
          (``"normal"``) or a hex value from the catalogue (``"01"``);
        * everything else (strength level, milk seconds): validated
          against Min/Max/Step and sent as-is.
        """
        if self.items:
            if isinstance(value, str):
                item = next((it for it in self.items if it.name == _snake(value)), None)
                if item is None:
                    # Allow the raw catalogue hex too ("01").
                    candidate = value.strip().upper()
                    item = next(
                        (it for it in self.items if it.value == candidate), None
                    )
                if item is None:
                    allowed = ", ".join(f"{it.name}={it.value}" for it in self.items)
                    raise ValueError(
                        f"{self.kind}: {value!r} is not a recognised value. "
                        f"Allowed: {allowed}"
                    )
                return int(item.value, 16)
            if not any(int(it.value, 16) == value for it in self.items):
                allowed = ", ".join(f"{it.name}={it.value}" for it in self.items)
                raise ValueError(
                    f"{self.kind}: {value} is not in the catalogue. Allowed: {allowed}"
                )
            return value
        if isinstance(value, str):
            try:
                value = int(value, 10)
            except ValueError as exc:
                raise ValueError(
                    f"{self.kind}: expected an integer, got {value!r}"
                ) from exc
        _validate_ranged(value, self.minimum, self.maximum, self.step, self.kind)
        wire = value // _ML_PER_TICK if self.kind in _ML_TICK_KINDS else value
        if not 0 <= wire <= 0xFF:  # single unsigned byte
            raise ValueError(f"{self.kind}: {value} does not fit the wire byte")
        return wire


@dataclasses.dataclass(slots=True, frozen=True)
class ProductDef:
    """One PRODUCT entry from the machine XML.

    Public/stable attributes for building UI: :attr:`code` (int product
    code), :attr:`name` (snake_case), :attr:`raw_name` (original XML
    label), :attr:`active` (whether to offer it as brewable),
    :attr:`params` (iterable of :class:`ProductParam`), and the
    :meth:`param` lookup. :meth:`build_recipe_hex` turns a chosen recipe
    into the wire blob.
    """

    code: int  # product code, e.g. 0x02
    name: str  # snake_case, e.g. "espresso"
    raw_name: str  # original XML Name
    params: tuple[ProductParam, ...] = ()  # recipe parameters, may be empty
    # Whether J.O.E. shows this product in the brew menu. Defaults to
    # True (XMLParser.java sets Active true unless the XML says
    # Active="false"). Products flagged inactive — the internal
    # Powderproduct, and the double-shot slots on some models — are kept
    # in the catalogue (the machine still reports counters for them) but
    # a UI should not offer them as brewable.
    active: bool = True

    def param(self, kind: str) -> ProductParam | None:
        """Find a recipe parameter by kind (e.g. ``"water_amount"``)."""
        for p in self.params:
            if p.kind == kind:
                return p
        return None

    def build_recipe_hex(self, overrides: dict[str, int | str] | None = None) -> str:
        """Build the 16-byte ``@TP:`` recipe blob for this product.

        Blob layout — **live-verified by physically brewing** on a JURA
        S8 EB (EF1091) and, independently, an E6:

        * byte 0 — the product code;
        * byte ``F-1`` for every XML parameter (strength at F3 → byte 2,
          water at F4 → byte 3 in 5 ml ticks, milk at F5 → byte 4 in
          seconds, milk foam at F6 → byte 5 in seconds, temperature at
          F7 → byte 6 as 00/01/02, bypass at F10 → byte 9 in 5 ml
          ticks, milk break at F11 → byte 10);
        * **byte 8 → ``0x01``** always (a fixed structural / "recipe
          valid" byte; no bundled product uses ``F9``);
        * **``0x00`` everywhere else** ("parameter not set").

        The earlier FF-padded layout was never physically brewed and is
        wrong: the machine ACKs an FF-padded blob with ``@tp:00`` and
        silently does nothing (no ``@TB`` / ``@TV`` frames, counters
        unchanged). The 00-padded, byte-8=01 form brews on the first
        send. See PROTOCOL.md §5.9.

        ``overrides`` maps parameter kinds to values in XML units,
        e.g. ``{"water_amount": 220, "temperature": "high"}``. Use the
        ``KIND_*`` constants for the keys. Parameters not overridden
        fall back to the XML default. Values are validated against the
        XML catalogue *before* anything goes on the wire.

        **Not live-verified — may misbrew, verify on your hardware:**
        the ``milk_break`` encoding is inferred from the XML (seconds,
        sent as-is), not individually confirmed. Water, temperature,
        strength and bypass are live-verified on the S8 EB;
        ``milk_amount`` and ``milk_foam_amount`` are live-verified on a
        Z10 (EA) / EF545 (Milkcoffee blob
        ``05000812030202000100000000000000`` — milk 3 s, foam 2 s —
        brewed with the physical pour matching both phases).

        Raises :class:`ValueError` on unknown override kinds, on
        out-of-range values, and when a millilitre parameter the product
        *has* would be left unset (no override and no XML default):
        with 00-padding that byte would be ``0x00`` = **no water**, so
        rather than silently brew a dry/short shot this is refused —
        pass an explicit amount.
        """
        overrides = dict(overrides or {})
        blob = ["00"] * RECIPE_BLOB_BYTES
        blob[0] = f"{self.code:02X}"
        # Fixed structural byte required for the machine to brew; set
        # before the param loop so a (hypothetical, currently
        # non-existent) F9 param would take precedence rather than be
        # clobbered.
        blob[_RECIPE_VALID_BYTE_INDEX] = _RECIPE_VALID_BYTE
        for p in self.params:
            if not 0 < p.offset < RECIPE_BLOB_BYTES:
                raise ValueError(
                    f"{self.name}: parameter {p.kind} has offset {p.offset} "
                    f"outside the {RECIPE_BLOB_BYTES}-byte recipe blob"
                )
            value = overrides.pop(p.kind, p.default)
            if value is None:
                if p.kind in _ML_TICK_KINDS:
                    raise ValueError(
                        f"{self.name}: water-amount parameter {p.kind!r} has no "
                        f"value and no XML default; refusing to leave its byte at "
                        f"0x00 (= no water). Pass an explicit amount."
                    )
                continue
            blob[p.offset] = f"{p.encode(value):02X}"
        if overrides:
            known = ", ".join(p.kind for p in self.params) or "(none)"
            raise ValueError(
                f"{self.name}: unknown recipe parameter(s) "
                f"{', '.join(sorted(overrides))}. This product accepts: {known}"
            )
        return "".join(blob)


@dataclasses.dataclass(slots=True, frozen=True)
class MachineProfile:
    """Static description of one machine variant.

    Keyed by the EF code that names the directory in the APK
    (e.g. ``EF1091`` for the S8 EB, ``EF536`` for the legacy S8).
    """

    code: str  # EF code, e.g. "EF1091"
    version: str  # XML schema version, e.g. "1.6"
    alerts: tuple[AlertDef, ...]
    products: tuple[ProductDef, ...]
    settings: tuple[SettingDef, ...]
    has_pmode: bool  # whether the XML carries a PROGRAMMODE section
    # Bank commands the XML declares under <STATISTIC><PRODUCTCOUNTER>,
    # in document order, e.g. ("@TR:32", "@TR:33"). Every machine
    # declares "@TR:32"; a subset also declares overflow / special /
    # barista banks. See docs/PROTOCOL.md §5.5.
    counter_banks: tuple[str, ...] = ()
    # Bank commands the XML declares under <STATISTIC><DAILYCOUNTER>,
    # in document order, e.g. ("@TR:42", "@TR:43"). Kept apart from
    # ``counter_banks`` because the two sections mean different things:
    # the daily banks count since the last reset and are zeroed with
    # ``daily_counter_reset``. 37 of the 89 bundled profiles declare at
    # least one. See docs/PROTOCOL.md §5.5.
    daily_counter_banks: tuple[str, ...] = ()
    # <DAILYCOUNTER Reset="@TF:05"> — the command that zeroes the daily
    # banks. ``None`` when the machine declares no daily section.
    daily_counter_reset: str | None = None
    # Field names of the maintenance banks, in the order the machine
    # answers them — the <TEXTITEM Type=…> children of
    # <BANK Command="@TG:43"> and <BANK Command="@TG:C0">. Per-machine:
    # 21 of the 89 bundled profiles disagree with the EF536/EF1091
    # baseline (four-field machines, a swapped rinse/clean tail, one
    # profile without FilterChange). See docs/PROTOCOL.md §5.3.
    maintenance_counter_fields: tuple[str, ...] = ()
    maintenance_percent_fields: tuple[str, ...] = ()

    # Derived lookup tables, populated in __post_init__. The default
    # factories keep ty happy with the declared dict types; frozen=True
    # forces __post_init__ to use object.__setattr__ to overwrite them.
    alert_by_bit: dict[int, AlertDef] = dataclasses.field(
        repr=False, default_factory=dict
    )
    product_by_code: dict[int, ProductDef] = dataclasses.field(
        repr=False, default_factory=dict
    )
    setting_by_name: dict[str, SettingDef] = dataclasses.field(
        repr=False, default_factory=dict
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "alert_by_bit", {a.bit: a for a in self.alerts})
        object.__setattr__(self, "product_by_code", {p.code: p for p in self.products})
        object.__setattr__(self, "setting_by_name", {s.name: s for s in self.settings})

    def declares_counter_bank(self, command: str) -> bool:
        """Whether the XML declares ``command`` as a counter bank.

        Covers both the ``<PRODUCTCOUNTER>`` and the ``<DAILYCOUNTER>``
        sections — a caller asking "may I read ``@TR:42`` here?" does
        not care which section it came from. Reading a bank the machine
        never declared is what the check exists to prevent.
        """
        target = command.strip().upper()
        return target in self.counter_banks or target in self.daily_counter_banks

    def setting_by_arg(self, p_argument: str) -> SettingDef | None:
        """Find the :class:`SettingDef` for a ``P_Argument`` hex code
        (e.g. ``"13"`` for AutoOFF). Returns ``None`` if no setting in
        the profile carries that P_Argument."""
        target = p_argument.strip().upper()
        for s in self.settings:
            if s.p_argument.upper() == target:
                return s
        return None


# --------------------------------------------------------------------- #
# XML loading
# --------------------------------------------------------------------- #


def _parse_xml(text: str, code: str, version: str) -> MachineProfile:
    """Parse a single machine XML into a :class:`MachineProfile`."""
    root = ET.fromstring(text)

    alerts: list[AlertDef] = []
    for alert in root.findall(".//{*}ALERT"):
        bit_str = alert.get("Bit")
        raw_name = alert.get("Name") or ""
        if bit_str is None or not raw_name:
            continue
        try:
            bit = int(bit_str)
        except ValueError:
            continue
        xml_type = alert.get("Type")
        severity = _XML_TYPE_TO_SEVERITY.get(xml_type or "", "info")
        # The Jura XMLs spell the descaling alert "decalc alert"; expose
        # it under the consistent "descale" key the rest of the API uses.
        name = _snake(raw_name).replace("decalc", "descale")
        alerts.append(
            AlertDef(
                bit=bit,
                name=name,
                severity=severity,
                raw_name=raw_name,
            )
        )

    products: list[ProductDef] = []
    seen_codes: set[int] = set()
    for product in root.findall(".//{*}PRODUCT"):
        code_str = product.get("Code")
        raw_name = product.get("Name") or ""
        if not code_str or not raw_name:
            continue
        try:
            code_int = int(code_str, 16)
        except ValueError:
            continue
        if code_int in seen_codes:
            # Some XMLs list a code twice; keep the first definition,
            # which matches J.O.E.'s parsing order.
            continue
        seen_codes.add(code_int)
        # J.O.E. (XMLParser.java) defaults the Active flag to true and
        # only hides products explicitly marked Active="false". Products
        # with no Active attribute — Milk Foam, Cafe Barista, Barista
        # Lungo, and dozens of other models' menu items — stay brewable.
        # Inactive products are kept in the catalogue (the machine still
        # reports their counters) but flagged so a UI can hide them.
        active = (product.get("Active") or "").strip().lower() != "false"
        products.append(
            ProductDef(
                code=code_int,
                name=_snake(raw_name),
                raw_name=raw_name,
                params=_parse_product_params(product),
                active=active,
            )
        )

    has_pmode = root.find(".//{*}PROGRAMMODE") is not None

    counter_banks = tuple(
        command
        for bank in root.findall(".//{*}PRODUCTCOUNTER/{*}BANK")
        if (command := (bank.get("Command") or "").strip())
    )

    daily = root.find(".//{*}DAILYCOUNTER")
    daily_counter_banks = tuple(
        command
        for bank in root.findall(".//{*}DAILYCOUNTER/{*}BANK")
        if (command := (bank.get("Command") or "").strip())
    )
    daily_counter_reset = (
        (daily.get("Reset") or "").strip() or None if daily is not None else None
    )

    settings = _parse_machine_settings(root)

    return MachineProfile(
        code=code,
        version=version,
        alerts=tuple(alerts),
        products=tuple(products),
        settings=settings,
        has_pmode=has_pmode,
        counter_banks=counter_banks,
        daily_counter_banks=daily_counter_banks,
        daily_counter_reset=daily_counter_reset,
        maintenance_counter_fields=_bank_fields(root, MAINTENANCE_COUNTER_BANK),
        maintenance_percent_fields=_bank_fields(root, MAINTENANCE_PERCENT_BANK),
    )


def _bank_fields(root: ET.Element, command: str) -> tuple[str, ...]:
    """Ordered field names of one ``<BANK Command=…>`` element.

    The bank's ``<TEXTITEM Type=…>`` children name the values the
    machine returns, in wire order — this is what makes the ``@TG:43``
    payload self-describing per machine. ``Type`` is normalised the
    same way alert names are, so the XML's "Decalc" becomes the
    "descale" key the rest of the API uses. Returns an empty tuple when
    the machine declares no such bank.
    """
    for bank in root.findall(".//{*}BANK"):
        if (bank.get("Command") or "").strip() != command:
            continue
        return tuple(
            _snake(kind).replace("decalc", "descale")
            for item in bank.findall("{*}TEXTITEM")
            if (kind := (item.get("Type") or "").strip())
        )
    return ()


def _int_attr(el: ET.Element, name: str) -> int | None:
    """Read a decimal integer XML attribute, or ``None`` if absent/bad."""
    raw = el.get(name)
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _parse_product_params(product: ET.Element) -> tuple[ProductParam, ...]:
    """Parse a PRODUCT element's recipe parameters.

    Every direct child carrying an ``Argument="F<n>"`` attribute is a
    recipe parameter (WATER_AMOUNT, COFFEE_STRENGTH, TEMPERATURE,
    MILK_FOAM_AMOUNT, BYPASS, MILK_BREAK, …). Children without an
    F-numbered Argument (e.g. PRESELECTION) are skipped.
    """
    params: list[ProductParam] = []
    for el in product:
        arg = el.get("Argument") or ""
        if not arg.startswith("F"):
            continue
        # Strictly digits only: sub-indexed arguments like MILK_FOAM_TEMP's
        # ``Argument="F14_1"`` would otherwise parse as int("14_1") == 141
        # (PEP 515 underscore separators!) and blow build_recipe_hex up with
        # an offset far outside the blob. Their wire semantics are unknown,
        # so they are skipped rather than encoded.
        if not arg[1:].isdigit():
            continue
        argument = int(arg[1:])
        tag = el.tag.split("}", 1)[-1]
        items: list[SettingItem] = []
        for item in el.findall("{*}ITEM"):
            iname = item.get("Name") or ""
            ivalue = item.get("Value") or ""
            if not iname or not ivalue:
                continue
            items.append(
                SettingItem(name=_snake(iname), raw_name=iname, value=ivalue.upper())
            )
        # Defaults: ranged parameters carry Value (XML units, decimal);
        # ITEM-driven parameters (TEMPERATURE) carry Default (hex,
        # matching an ITEM Value).
        default: int | None = None
        raw_value = el.get("Value")
        raw_default = el.get("Default")
        try:
            if raw_value is not None:
                default = int(raw_value)
            elif raw_default is not None:
                default = int(raw_default, 16)
        except ValueError:
            default = None

        params.append(
            ProductParam(
                kind=_snake(tag),
                argument=argument,
                default=default,
                minimum=_int_attr(el, "Min"),
                maximum=_int_attr(el, "Max"),
                step=_int_attr(el, "Step"),
                items=tuple(items),
            )
        )
    return tuple(params)


# Map XML element tag (local-name) and SliderType attribute -> kind.
# Order matters when a SLIDER has SliderType="ItemSlider".
_SETTING_TAG_TO_KIND = {
    "SWITCH": "switch",
    "COMBOBOX": "combobox",
}


def _setting_kind(tag: str, slider_type: str | None) -> str | None:
    """Return the canonical kind string for one settings element."""
    if tag == "SLIDER":
        if slider_type == "ItemSlider":
            return "item_slider"
        return "step_slider"
    return _SETTING_TAG_TO_KIND.get(tag)


def _parse_machine_settings(root: ET.Element) -> tuple[SettingDef, ...]:
    """Parse <MACHINESETTINGS> into a tuple of :class:`SettingDef`.

    Recognised element tags: ``SWITCH``, ``COMBOBOX``, ``SLIDER``
    (with ``SliderType`` = ``"StepSlider"`` or ``"ItemSlider"``). Each
    must carry ``Name`` and ``P_Argument``; entries lacking either
    are skipped silently.
    """
    container = root.find(".//{*}MACHINESETTINGS")
    if container is None:
        return ()
    settings: list[SettingDef] = []
    seen_args: set[str] = set()
    for el in container:
        # ElementTree returns Clark-notation tags like
        # "{http://www.top-tronic.com}SWITCH"; strip the namespace.
        tag = el.tag.split("}", 1)[-1]
        kind = _setting_kind(tag, el.get("SliderType"))
        if kind is None:
            continue
        raw_name = el.get("Name") or ""
        p_arg = el.get("P_Argument") or ""
        if not raw_name or not p_arg:
            continue
        p_arg = p_arg.upper()
        if p_arg in seen_args:
            # First occurrence wins, matching ElementTree iteration order
            # and the J.O.E. UI which only renders one widget per arg.
            continue
        seen_args.add(p_arg)
        items: list[SettingItem] = []
        for item in el.findall("{*}ITEM"):
            iname = item.get("Name") or ""
            ivalue = item.get("Value") or ""
            if not iname or not ivalue:
                continue
            items.append(
                SettingItem(
                    name=_snake(iname),
                    raw_name=iname,
                    value=ivalue.upper(),
                )
            )
        default = el.get("Default")
        if default is not None:
            default = default.upper()
        minimum: int | None = None
        maximum: int | None = None
        step: int | None = None
        mask: str | None = None
        if kind == "step_slider":
            try:
                minimum = int(el.get("Min", "")) if el.get("Min") else None
                maximum = int(el.get("Max", "")) if el.get("Max") else None
                step = int(el.get("Step", "")) if el.get("Step") else None
            except ValueError:
                pass
            mask = el.get("Mask")
            if mask is not None:
                mask = mask.upper()
        settings.append(
            SettingDef(
                name=_snake(raw_name),
                raw_name=raw_name,
                p_argument=p_arg,
                kind=kind,
                default=default,
                items=tuple(items),
                minimum=minimum,
                maximum=maximum,
                step=step,
                mask=mask,
            )
        )
    return tuple(settings)


@lru_cache(maxsize=None)
def load_profile(code: str) -> MachineProfile:
    """Load the profile for one EF code, e.g. ``"EF1091"``.

    The XMLs ship with the package; this picks the highest version
    available under ``data/xml/<code>/``. Raises :class:`KeyError` if
    the code is unknown.
    """
    base = importlib.resources.files(_PACKAGE).joinpath("data/xml").joinpath(code)
    if not base.is_dir():
        raise KeyError(f"no profile for machine code {code!r}")
    versions = sorted(
        (f.name for f in base.iterdir() if f.name.endswith(".xml")),
        key=lambda n: _version_key(n.removesuffix(".xml")),
    )
    if not versions:
        raise KeyError(f"no XML files under data/xml/{code}/")
    chosen = versions[-1]  # highest version wins
    text = base.joinpath(chosen).read_text(encoding="utf-8")
    return _parse_xml(text, code=code, version=chosen.removesuffix(".xml"))


def _version_key(version: str) -> tuple[int, ...]:
    """Sort key for XML version strings like ``"1.6"`` or ``"3.9"``."""
    parts: list[int] = []
    for p in version.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def list_profile_codes() -> list[str]:
    """Every EF code shipped with the package, sorted lexicographically."""
    base = importlib.resources.files(_PACKAGE).joinpath("data/xml")
    return sorted(f.name for f in base.iterdir() if f.is_dir())


def iter_profiles() -> Iterator[MachineProfile]:
    """Yield every bundled profile (lazy; loads as it iterates)."""
    for code in list_profile_codes():
        try:
            yield load_profile(code)
        except (ET.ParseError, KeyError):
            # Skip malformed entries rather than crash callers iterating.
            continue


# --------------------------------------------------------------------- #
# JOE_MACHINES.TXT lookup
# --------------------------------------------------------------------- #


@dataclasses.dataclass(slots=True, frozen=True)
class MachineCatalogueEntry:
    """One row of ``JOE_MACHINES.TXT``."""

    article_number: int
    friendly_name: str  # e.g. "S8 (EB)"
    ef_code: str  # e.g. "EF1091"
    type_id: int  # opaque, internal to J.O.E.


@lru_cache(maxsize=1)
def _catalogue() -> tuple[MachineCatalogueEntry, ...]:
    text = (
        importlib.resources.files(_PACKAGE)
        .joinpath("data/JOE_MACHINES.TXT")
        .read_text(encoding="utf-8")
    )
    entries: list[MachineCatalogueEntry] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or ";" not in line:
            continue
        parts = line.split(";")
        if len(parts) < 4:
            continue
        try:
            article = int(parts[0])
            type_id = int(parts[3])
        except ValueError:
            continue
        entries.append(
            MachineCatalogueEntry(
                article_number=article,
                friendly_name=parts[1].strip(),
                ef_code=parts[2].strip(),
                type_id=type_id,
            )
        )
    return tuple(entries)


def lookup_by_article_number(article: int) -> MachineCatalogueEntry | None:
    """Find the catalogue entry for one article number."""
    for entry in _catalogue():
        if entry.article_number == article:
            return entry
    return None


def search_by_friendly_name(query: str) -> list[MachineCatalogueEntry]:
    """Case-insensitive substring search over the friendly-name column.

    Returns one row per unique (friendly_name, ef_code) pair so callers
    don't see the same machine listed 30 times because every regional
    variant has its own article number.
    """
    q = query.casefold()
    seen: set[tuple[str, str]] = set()
    out: list[MachineCatalogueEntry] = []
    for entry in _catalogue():
        if q not in entry.friendly_name.casefold():
            continue
        key = (entry.friendly_name, entry.ef_code)
        if key in seen:
            continue
        seen.add(key)
        out.append(entry)
    return out


def known_machine_names() -> list[tuple[str, str]]:
    """``[(friendly_name, ef_code), ...]`` for every unique machine.

    Sorted by friendly name. Useful for ``jura-connect machine-types``
    output and for shell completion.
    """
    seen: set[tuple[str, str]] = set()
    for entry in _catalogue():
        seen.add((entry.friendly_name, entry.ef_code))
    return sorted(seen)
