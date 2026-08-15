"""Per-machine profile loader (alerts, products, pmode capabilities).

The J.O.E. Android APK ships 88 XML files under
``apk/assets/documents/xml/<EF_code>/<version>.xml`` describing each
machine variant: which alert bits exist, which product codes the
machine knows, whether pmode slots are configurable, etc. The codes
differ meaningfully across machines — e.g. on the EF536 (legacy S8)
``0x12`` is "2 Espressi" but on the EF1091 (S8 EB) "2 Espressi"
lives at ``0x31``. Hard-coding any single map is wrong.

This module loads the XMLs lazily, parses the relevant sections
(``ALERTS``, ``PRODUCTS``, ``MACHINESETTINGS``) into a
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
from collections.abc import Iterable, Iterator
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

#: Every product kind (J.O.E.'s ``Product.ProductGroup``) an ``<ALERT
#: Blocked=…>`` token or a ``<PRODUCT P_Kind=…>`` attribute can name.
#: ``A`` and ``NONE`` exist in the app's enum but appear in no bundled
#: XML; the five kinds actually used are ``C``, ``M``, ``CM``, ``T``,
#: ``P``.
PRODUCT_KINDS: tuple[str, ...] = ("C", "M", "CM", "T", "TM", "P")


def expand_blocked_kinds(token: str | None) -> tuple[str, ...]:
    """Product kinds blocked by an ``<ALERT Blocked="…">`` token.

    Jura's own XML comment (see ``EF0000/3.8.xml``) says only that
    ``Blocked="CM"`` "block[s] products of Coffe, Milk and Coffe + Milk".
    The app models the attribute as a single ``ProductGroup`` enum value
    and the code that consumes it did not survive obfuscation, so the
    expansion rule here is **our reading** of that comment: a token
    blocks every kind that shares at least one letter with it. That makes
    ``Blocked="M"`` (no milk) block ``M``, ``CM`` and ``TM`` — i.e. a
    cappuccino is unbrewable when the milk runs out, which is what the
    machine actually does. Returns ``()`` for ``None`` or an unknown
    token.
    """
    if not token:
        return ()
    letters = {c for c in token.strip().upper() if c.isalpha()}
    if not letters:
        return ()
    return tuple(kind for kind in PRODUCT_KINDS if letters & set(kind))


@dataclasses.dataclass(slots=True, frozen=True)
class AlertDef:
    """One ALERT entry from the machine XML.

    Beyond the bit and its name the XML carries what the alert *does*:
    ``Type``/``Blocked`` say which products it stops (see
    :attr:`blocked_kinds`) and ``Process`` names the maintenance process
    that clears it (:attr:`process`, e.g. ``"cleaning"`` — the same
    vocabulary as :data:`jura_connect.progress.PROCESS_CODES`). Every
    field after ``raw_name`` defaults, so a profile that omits them still
    constructs.
    """

    bit: int
    name: str  # snake_case, derived from XML Name attribute
    severity: str  # "error" / "info" / "process"
    raw_name: str  # the original XML Name (with spaces)
    # The raw XML Type: "block" (stops everything), "info", "ip"
    # (in-process reminder), or None for a purely cosmetic alert.
    raw_type: str | None = None
    # The raw XML Blocked token ("C", "M", "CM", "TM", "P"), or None.
    blocked: str | None = None
    # Product kinds this alert blocks *right now* when it is active. For
    # Type="block" that is every kind in PRODUCT_KINDS regardless of the
    # Blocked attribute; otherwise it is expand_blocked_kinds(blocked).
    blocked_kinds: tuple[str, ...] = ()
    # Maintenance process that clears the alert, snake_case and
    # normalised the same way ProcessDef.name is ("descale", not
    # "Decalc"). None when the XML declares no Process.
    process: str | None = None
    process_button: str | None = None  # translation key of the button
    title: str | None = None  # translation key (integer as a string)
    message: str | None = None  # translation key
    picture: str | None = None  # icon file name shipped with the app
    cancel_button: str | None = None  # translation key, always "72"
    # <ALERT Disabled="0406070A2E"> — individual product codes the alert
    # disables, as opposed to whole kinds. Watch-only in J.O.E.
    disabled_products: tuple[int, ...] = ()

    @property
    def blocks_everything(self) -> bool:
        """True for ``Type="block"`` — no product can be started."""
        return self.raw_type == "block"


@dataclasses.dataclass(slots=True, frozen=True)
class ProcessDef:
    """One ``<PROCESS>`` entry: a maintenance cycle the machine can run.

    ``execute_command`` is the wire verb J.O.E.'s
    ``WifiCommandStartProcess`` sends (``@TG:24`` for cleaning); the
    machine answers with the lower-cased echo. ``name`` is the XML
    ``Type`` normalised to snake_case with ``Decalc`` renamed
    ``descale``, which makes it identical to the value
    :data:`jura_connect.progress.PROCESS_CODES` gives for the same
    command byte.
    """

    name: str  # "cleaning", "descale", "filter_change", …
    raw_type: str  # the XML Type verbatim: "Cleaning", "Decalc", …
    execute_command: str  # "@TG:24"
    progress: bool  # Progress="true": the machine pushes @TV: frames
    title: str | None = None  # translation key
    picture: str | None = None
    pdf_url: str | None = None
    video_url: str | None = None

    @property
    def code(self) -> int:
        """Command byte of :attr:`execute_command` (``0x24`` for cleaning)."""
        return int(self.execute_command.rsplit(":", 1)[-1], 16)


@dataclasses.dataclass(slots=True, frozen=True)
class StateDef:
    """One ``<STATE>`` entry: a step the machine can drive the client to.

    Mirrors the app's ``StateArgument`` (value, name, title, hasProgress,
    message, picture, acceptCommand). :attr:`value` is the same byte as
    :attr:`jura_connect.progress.ProductProgress.state_code`, so a pushed
    ``@TV:`` frame resolves against this table.
    """

    value: int  # state code, e.g. 0x26
    name: str  # snake_case, e.g. "press_rinse"
    raw_name: str  # the XML Name verbatim, e.g. "Press Rinse"
    accept_command: str | None = None  # "@TG:10" / "@TG:04"
    title: str | None = None  # translation key
    message: str | None = None  # translation key
    picture: str | None = None
    progress: bool = False  # Progress="true"

    @property
    def needs_confirmation(self) -> bool:
        """True when the machine waits for an explicit accept here."""
        return self.accept_command is not None


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
    mask: str | None  # value mask when declared ("FF", "FFFF", "01" …)

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


@dataclasses.dataclass(slots=True, frozen=True)
class SettingsBank:
    """The ``<MACHINESETTINGS><BANK Name="Setting">`` declaration.

    ``<BANK Name="Setting" Command="@TM:00,FC" CommandArgument="02080913"/>``
    describes a *batch* settings read: one round trip that answers with
    the values of several ``P_Argument`` settings at once (here ``02``
    hardness, ``08`` units, ``09`` language, ``13`` auto-off) instead of
    one ``@TM:<arg>`` request per setting.

    All 57 profiles that declare the bank declare exactly this command
    and this argument list; the remaining 32 carry no
    ``<MACHINESETTINGS>`` block at all. The list is boilerplate rather
    than machine truth — 16 profiles name arguments their own catalogue
    never declares — so consumers must tolerate a bank argument with no
    matching :class:`SettingDef`.

    See :meth:`jura_connect.client.JuraClient.read_settings_bank`: the
    reply layout is **not** APK-derived (no J.O.E. code path issues the
    command) and is untested on hardware.
    """

    name: str  # the XML Name attribute, always "Setting" so far
    command: str  # wire command, e.g. "@TM:00,FC"
    arguments: tuple[str, ...]  # P_Arguments in reply order, e.g. ("02", …)


#: Total length of the ``@TP:`` recipe blob in bytes. Live-verified by
#: physically brewing on a JURA S8 EB (EF1091) and, independently, an
#: E6: the machine ACKs and brews a 16-byte payload whose *unused*
#: bytes are ``0x00`` (see :meth:`ProductDef.build_recipe_hex`); a
#: bare product code, or an FF-padded blob, is ACKed ``@tp:00`` and
#: silently ignored.
RECIPE_BLOB_BYTES = 16

#: Total length of the PMode (programmable-recipe) product blob in
#: bytes. Derived from the J.O.E. APK's ``AppProduct.d()``, which
#: allocates exactly 17 slots and fills byte ``F-1`` for every
#: ``Argument="F<n>"`` — so ``F17`` (grinder freeness) lands on the
#: last byte. The ``@TP:`` start blob is the same layout truncated to
#: 16 (or 17, on machines with F17) bytes. **APK-derived, never sent
#: to a real machine.**
PMODE_BLOB_BYTES = 17

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


# --- Preselections -----------------------------------------------------
# A "preselection" is the extra-shot / double / powder / cold-brew /
# light-brew / sweet-foam toggle J.O.E. offers next to a product. The
# machine XML declares them per product as
#   <PRESELECTION xtrashot="false" double="31" powder="true" .../>
# and declares which of them may be combined machine-wide as
#   <MULTIPLE_PRESELECTS><COMBINATION powder="true" sweetfoam="true"/></…>
#
# Every attribute is a plain "true"/"false" flag **except** ``double``,
# which carries the *product code of the double product* (old
# T-protocol) or ``"00"``. Quoting Jura's own documentation in the
# EF0000 template XML:
#
#   "All preselections are either true or false - except the double.
#    The double preselect contains the Product Code of the Double
#    Product (old T-Protocol) or just 00 for the new T-Protocol with
#    F18 support (<CAPABILITIES IntakeF18="true"/> in the
#    MACHINEMANIFEST)."

#: Every ``<PRESELECTION>`` attribute name that occurs across the 89
#: bundled machine XMLs, lower-cased. These are the canonical
#: preselection names this library accepts. ``pmodeadjust`` is included
#: because the XMLs carry it, but it is never ``"true"`` anywhere.
PRESELECTION_NAMES: tuple[str, ...] = (
    "xtrashot",
    "double",
    "powder",
    "coldbrew",
    "strongcoldbrew",
    "lightbrew",
    "sweetfoam",
    "fakesweetfoam",
    "chocolate",
    "xl",
    "pmodeadjust",
)

#: Friendly spellings accepted for :func:`canonical_preselection`, so
#: ``brew espresso extra_shot`` works as well as ``brew espresso
#: xtrashot``.
PRESELECTION_ALIASES: dict[str, str] = {
    "extra_shot": "xtrashot",
    "extrashot": "xtrashot",
    "xtra_shot": "xtrashot",
    "double_shot": "double",
    "cold_brew": "coldbrew",
    "strong_cold_brew": "strongcoldbrew",
    "light_brew": "lightbrew",
    "sweet_foam": "sweetfoam",
    "fake_sweet_foam": "fakesweetfoam",
    "p_mode_adjust": "pmodeadjust",
    "pmode_adjust": "pmodeadjust",
}

#: Blob offset of the preselection **mask** byte on machines that
#: declare ``<CAPABILITIES IntakeF18="true"/>``, and the length such a
#: blob has. Both are read straight out of the J.O.E. APK's single
#: product-start encoder, ``ch.toptronic.joe.model.product.AppProduct.c``
#: (jadx line 151-184, cross-checked against
#: ``smali/…/AppProduct.smali:400-806``)::
#:
#:     String s = join(bytes).substring(0, (hasF17 ? 17 : 16) * 2);
#:     if (!startData.f18Enabled) return s;              // 16/17 bytes
#:     mask = Σ bits;                                    // table below
#:     return hasF17 ? s + "0000" + hex(mask)            // 20 bytes
#:                   : s + "000000" + hex(mask);         // 20 bytes
#:
#: i.e. the blob is padded to exactly 20 bytes and the mask is the
#: **last** one, at offset 19 — *not* at 17 as the ``IntakeF18``
#: capability name suggests. No bundled XML declares ``Argument="F18"``,
#: ``F19`` or ``F20``, and the string ``"F18"`` does not occur in the
#: APK's smali outside the capability name, so the name looks
#: historical. **APK-derived, never seen on a wire.**
PRESELECT_MASK_OFFSET = 19
PRESELECT_BLOB_BYTES = 20

#: Mask bit each preselection contributes on an ``IntakeF18`` machine.
#: From the ``Pair`` table in ``AppProduct.c``. ``fakesweetfoam`` is
#: deliberately absent — it is in the enum but not in that table, so it
#: contributes nothing (and ``0x20`` is unused). **APK-derived,
#: untested.**
PRESELECT_MASK_BITS: dict[str, int] = {
    "powder": 0x01,
    "xtrashot": 0x02,
    "sweetfoam": 0x04,
    "lightbrew": 0x08,
    "coldbrew": 0x10,
    "double": 0x40,
    "strongcoldbrew": 0x80,
}

#: Old-T-protocol encoding: preselections that are **not** a mask bit but
#: a fixed byte written over the recipe blob, ``name -> (offset, value)``.
#: These are the ``(a, b)`` payloads of the ``PreselectArgument`` enum
#: (``…/shared_model/interfaces/PreselectArgument.java:76-96``), applied
#: by ``AppProduct.c`` *after* the recipe parameters and therefore
#: overwriting them: powder blanks the coffee-strength byte (F3),
#: cold/light brew replace the temperature byte (F7) with an
#: out-of-band value, extra shot writes the stroke byte (F8).
#: **APK-derived, untested.**
PRESELECT_LEGACY_BYTES: dict[str, tuple[int, int]] = {
    "powder": (2, 0x00),
    "coldbrew": (6, 0x80),
    "lightbrew": (6, 0x81),
    "xtrashot": (7, 0x02),
}

# Anything in neither table has **no wire representation** for that
# machine generation and is refused rather than silently dropped:
# sweetfoam / fakesweetfoam / strongcoldbrew on an old-T-protocol
# machine (J.O.E. shows them and then sends nothing), and
# fakesweetfoam / chocolate / xl / pmodeadjust on an IntakeF18 one.


def canonical_preselection(name: str) -> str:
    """Normalise a user-supplied preselection name.

    Accepts the XML spelling (``"xtrashot"``) and the friendly aliases
    in :data:`PRESELECTION_ALIASES` (``"extra_shot"``). Raises
    :class:`ValueError` for anything else.
    """
    key = name.strip().lower().replace("-", "_")
    key = PRESELECTION_ALIASES.get(key, key.replace("_", ""))
    if key not in PRESELECTION_NAMES:
        raise ValueError(
            f"unknown preselection {name!r}. Known: {', '.join(PRESELECTION_NAMES)}"
        )
    return key


def _parse_preselection(product: ET.Element) -> tuple[frozenset[str], int | None]:
    """Parse a PRODUCT's ``<PRESELECTION>`` child.

    Returns ``(supported, double_code)`` where ``supported`` holds the
    preselection names the product declares — the ``"true"`` flags, plus
    ``"double"`` when the product names a double product code — and
    ``double_code`` is that code (``None`` when the attribute is absent
    or ``"00"``).

    ``double="00"`` is read as **"this product has no double"**: every
    bundled XML that uses it does so for products that cannot sensibly
    be doubled (milk foam, hot water, pot), *including* machines with
    ``IntakeF18="true"``. Jura's own comment allows ``00`` to also mean
    "double via the F18 argument" on new-protocol machines, but no
    bundled profile demonstrates that, so we do not guess it.
    """
    el = product.find("{*}PRESELECTION")
    if el is None:
        return frozenset(), None
    supported: set[str] = set()
    double_code: int | None = None
    for raw_key, raw_value in el.attrib.items():
        key = raw_key.strip().lower()
        if key not in PRESELECTION_NAMES:
            continue
        value = raw_value.strip()
        if key == "double":
            try:
                code = int(value, 16)
            except ValueError:
                continue
            if code:
                double_code = code
                supported.add(key)
            continue
        if value.lower() == "true":
            supported.add(key)
    return frozenset(supported), double_code


def _parse_combinations(root: ET.Element) -> tuple[frozenset[str], ...]:
    """Parse ``<MULTIPLE_PRESELECTS><COMBINATION …/></…>`` rows.

    Each row lists preselections that may be active **at the same
    time**; attributes explicitly set ``"false"`` are not part of the
    row. Rows with fewer than two members carry no information (a lone
    preselection is always allowed) and are dropped, as are duplicates.
    A machine with no ``MULTIPLE_PRESELECTS`` section allows no
    combinations at all — one preselection at a time.
    """
    rows: list[frozenset[str]] = []
    for el in root.findall(".//{*}COMBINATION"):
        members = frozenset(
            key
            for raw_key, raw_value in el.attrib.items()
            if (key := raw_key.strip().lower()) in PRESELECTION_NAMES
            and raw_value.strip().lower() == "true"
        )
        if len(members) >= 2 and members not in rows:
            rows.append(members)
    return tuple(rows)


@dataclasses.dataclass(slots=True, frozen=True)
class PreselectionPlan:
    """How a set of requested preselections reaches the machine.

    Produced by :meth:`MachineProfile.plan_preselections`; feed it to
    :meth:`build_recipe_hex` to get the wire blob.

    * :attr:`product` — the product to actually brew. On an
      old-T-protocol machine a ``double`` **swaps the product** for the
      catalogue's double product (``espresso`` → ``2 Espressi``, code
      ``0x31`` on the S8 EB) rather than touching the blob.
    * :attr:`mask` — the preselection mask byte for an ``IntakeF18``
      machine (blob offset :data:`PRESELECT_MASK_OFFSET`), or ``None``
      when this machine does not use one.
    * :attr:`byte_overwrites` — ``(offset, value)`` pairs written over
      the recipe blob on an old-T-protocol machine.
    """

    product: ProductDef
    requested: tuple[str, ...]
    mask: int | None = None
    byte_overwrites: tuple[tuple[int, int], ...] = ()

    def build_recipe_hex(self, overrides: dict[str, int | str] | None = None) -> str:
        """The ``@TP:`` blob for this plan (see
        :meth:`ProductDef.build_recipe_hex`)."""
        return self.product.build_recipe_hex(
            overrides,
            preselect_mask=self.mask,
            preselect_bytes=self.byte_overwrites,
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
    # The XML ``PModeAdjust`` attribute: False marks a parameter the
    # machine will not let you change through the programmable-recipe
    # interface (J.O.E. hides the slider). ``None`` means the attribute
    # is absent, i.e. unconstrained. Only five bundled profiles set it.
    # See :meth:`ProductDef.build_pmode_hex`.
    pmode_adjust: bool | None = None

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
    # The XML ``ProductSettings`` attribute. False means the machine
    # does not expose this product in the product-programming (PMode)
    # UI at all — J.O.E. never sends a ``@TM:41`` for it.
    product_settings: bool = True
    # <PRODUCT P_Kind="…">: the product's kind, one of PRODUCT_KINDS
    # ("C" coffee, "M" milk, "CM" coffee+milk, "T" tea/water, "P"
    # powder). Empty when the XML omits it. What an active alert's
    # AlertDef.blocked_kinds is matched against.
    kind: str = ""
    # Preselections this product declares in <PRESELECTION> (the "true"
    # flags, plus "double" when the product names a double product).
    # See :data:`PRESELECTION_NAMES`.
    preselections: frozenset[str] = frozenset()
    # Product code of this product's double (old T-protocol), or None.
    double_code: int | None = None
    # Whether the machine XML lets this product be scheduled through the
    # coffee timer (``Coffeetimer="false"`` on the PRODUCT element).
    # J.O.E.'s ``Product`` model stores the attribute as a *nullable*
    # Boolean and defaults a missing one to true
    # (``shouldBeShownInCoffeeTimer = bool ?: true``), so only an
    # explicit "false" makes a product ineligible. Six of the 89
    # bundled profiles carry the attribute at all. See PROTOCOL.md §5.12.
    coffee_timer: bool = True

    def param(self, kind: str) -> ProductParam | None:
        """Find a recipe parameter by kind (e.g. ``"water_amount"``)."""
        for p in self.params:
            if p.kind == kind:
                return p
        return None

    def supports_preselection(self, name: str) -> bool:
        """Whether the XML declares ``name`` for this product.

        ``name`` is normalised via :func:`canonical_preselection`, so
        both ``"extra_shot"`` and ``"xtrashot"`` work.
        """
        return canonical_preselection(name) in self.preselections

    def build_recipe_hex(
        self,
        overrides: dict[str, int | str] | None = None,
        *,
        preselect_mask: int | None = None,
        preselect_bytes: tuple[tuple[int, int], ...] = (),
    ) -> str:
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

        ``preselect_mask`` / ``preselect_bytes`` carry preselections and
        normally come from a :class:`PreselectionPlan` — use
        :meth:`MachineProfile.plan_preselections` rather than passing
        them by hand. A mask grows the blob to
        :data:`PRESELECT_BLOB_BYTES` with the mask as its last byte;
        ``preselect_bytes`` overwrite recipe bytes in place. **Both are
        APK-derived and have never been seen on a wire** — see
        PROTOCOL.md §5.13.

        A preselection that would overwrite a parameter the caller set
        explicitly is refused: on an old-T-protocol machine ``powder``
        blanks the coffee-strength byte and ``coldbrew`` replaces the
        temperature byte, so ``powder`` + ``strength=7`` is a
        contradiction rather than something to silently resolve.
        """
        explicit = set(overrides or ())
        overrides = dict(overrides or {})
        size = RECIPE_BLOB_BYTES
        if preselect_mask is not None:
            if not 0 <= preselect_mask <= 0xFF:
                raise ValueError(
                    f"preselect_mask: {preselect_mask} does not fit a wire byte"
                )
            size = max(size, PRESELECT_BLOB_BYTES)
        blob = ["00"] * size
        blob[0] = f"{self.code:02X}"
        # Fixed structural byte required for the machine to brew; set
        # before the param loop so a (hypothetical, currently
        # non-existent) F9 param would take precedence rather than be
        # clobbered.
        blob[_RECIPE_VALID_BYTE_INDEX] = _RECIPE_VALID_BYTE
        if preselect_mask is not None:
            blob[PRESELECT_MASK_OFFSET] = f"{preselect_mask:02X}"
        for p in self.params:
            # Bound against the *actual* blob length: a preselection mask
            # grows it to 20 bytes, which is exactly the window J.O.E.
            # uses for such machines (it keeps the F17 grinder-freeness
            # byte at offset 16 when the product has one).
            if not 0 < p.offset < size:
                raise ValueError(
                    f"{self.name}: parameter {p.kind} has offset {p.offset} "
                    f"outside the {size}-byte recipe blob"
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
        # Preselection byte overwrites land last — J.O.E. applies them
        # after the recipe parameters — but never silently over a value
        # the caller asked for.
        for offset, value in preselect_bytes:
            clash = next(
                (p for p in self.params if p.offset == offset and p.kind in explicit),
                None,
            )
            if clash is not None:
                raise ValueError(
                    f"{self.name}: this preselection forces blob byte {offset} "
                    f"to 0x{value:02X}, which is the {clash.kind!r} you set "
                    f"explicitly. Drop one of the two."
                )
            blob[offset] = f"{value:02X}"
        return "".join(blob)

    def build_pmode_hex(self, overrides: dict[str, int | str] | None = None) -> str:
        """Build the 17-byte PMode product blob for this product.

        **APK-derived, hardware-untested.** Ported from the J.O.E.
        app's ``ch.toptronic.joe.model.product.AppProduct.d()``:

        * a 17-byte array pre-filled with ``0x00``;
        * byte ``F-1`` for every ``Argument="F<n>"`` parameter, using
          the same units and 5 ml tick encoding as
          :meth:`build_recipe_hex` (``ProductArgument.b()`` in the APK
          selects exactly the F4 / F10 / ``Text="94"`` parameters our
          ``_ML_TICK_KINDS`` covers);
        * byte 0 overwritten with the product code, last.

        Two deliberate differences from :meth:`build_recipe_hex`:

        * the blob is 17 bytes, not 16 — ``F17`` (grinder freeness)
          needs byte 16, and ``AppProduct.d()`` always allocates it;
        * byte 8 is **not** forced to ``0x01``. That "recipe valid"
          byte belongs to the ``@TP:`` start command (``AppProduct.c()``
          sets it after calling ``d()``); the PMode write sends the
          raw parameter blob.

        ``overrides`` works exactly as for :meth:`build_recipe_hex`.
        A parameter the XML marks ``PModeAdjust="false"`` cannot be
        overridden — J.O.E. hides its slider in the product-programming
        UI, so a value written there would at best be ignored. Its XML
        default still occupies its byte.
        """
        overrides = dict(overrides or {})
        blob = ["00"] * PMODE_BLOB_BYTES
        for p in self.params:
            if not 0 < p.offset < PMODE_BLOB_BYTES:
                raise ValueError(
                    f"{self.name}: parameter {p.kind} has offset {p.offset} "
                    f"outside the {PMODE_BLOB_BYTES}-byte pmode blob"
                )
            if p.kind in overrides and p.pmode_adjust is False:
                raise ValueError(
                    f"{self.name}: parameter {p.kind!r} is marked "
                    f'PModeAdjust="false" in this machine\'s XML and cannot '
                    f"be changed through the programmable-recipe interface."
                )
            value = overrides.pop(p.kind, p.default)
            if value is None:
                if p.kind in _ML_TICK_KINDS:
                    raise ValueError(
                        f"{self.name}: water-amount parameter {p.kind!r} has no "
                        f"value and no XML default; refusing to store a recipe "
                        f"whose byte would be 0x00 (= no water). Pass an "
                        f"explicit amount."
                    )
                continue
            blob[p.offset] = f"{p.encode(value):02X}"
        if overrides:
            known = ", ".join(p.kind for p in self.params) or "(none)"
            raise ValueError(
                f"{self.name}: unknown recipe parameter(s) "
                f"{', '.join(sorted(overrides))}. This product accepts: {known}"
            )
        blob[0] = f"{self.code:02X}"
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
    # Whether this machine exposes the programmable-recipe ("PMode")
    # interface at all. See :func:`_parse_programmode` — the XML says
    # so on <MACHINESETTINGS Productprogramming="…">, not via a
    # <PROGRAMMODE> element (no bundled XML has one).
    has_pmode: bool
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
    # The <MACHINESETTINGS><BANK Name="Setting"> declaration, when the
    # XML carries one (57 of the 89 bundled profiles). See
    # :class:`SettingsBank` and docs/PROTOCOL.md §5.7.
    settings_bank: SettingsBank | None = None
    # <PROCESSES><PROCESS> — the maintenance cycles this machine can run,
    # in document order. Every bundled profile declares between four and
    # six. See docs/PROTOCOL.md §5.11.
    processes: tuple[ProcessDef, ...] = ()
    # <PROGRESS_STATE_INTAKE><STATE> — the machine's step table (83
    # entries in every bundled profile), keyed by the same byte the
    # ``@TV:`` progress frames carry. See docs/PROTOCOL.md §5.11.
    states: tuple[StateDef, ...] = ()

    # --- programmable-recipe (PMode) declarations ---------------------
    # ``<MACHINESETTINGS Productprogramming="true|false">``: the
    # machine's own statement about whether it accepts ``@TM:41`` /
    # ``@TM:42`` writes. 20 of the 89 bundled profiles say true;
    # EF1091 (S8 EB) says false, which is why it answers ``@tm:C2``.
    product_programming: bool = False
    # ``<MACHINESETTINGS NumberOfSlotsForProductProgramming="6">``, when
    # declared (5 profiles). ``None`` = not declared; ask the machine
    # via ``@TM:50`` instead.
    pmode_slot_count: int | None = None
    # <MACHINEMANIFEST><CAPABILITIES …/> attributes verbatim (keys keep
    # the XML's CamelCase: "IntakeF18", "LanguageDownload", …). Empty for
    # the 66 profiles with no manifest — every old T-protocol machine,
    # the maintainer's EF1091 among them.
    capabilities: dict[str, str] = dataclasses.field(default_factory=dict)
    # Sets of preselections the machine allows simultaneously, from
    # <MULTIPLE_PRESELECTS>. Empty means "one preselection at a time".
    preselect_combinations: tuple[frozenset[str], ...] = ()

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
    process_by_name: dict[str, ProcessDef] = dataclasses.field(
        repr=False, default_factory=dict
    )
    state_by_value: dict[int, StateDef] = dataclasses.field(
        repr=False, default_factory=dict
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "alert_by_bit", {a.bit: a for a in self.alerts})
        object.__setattr__(self, "product_by_code", {p.code: p for p in self.products})
        object.__setattr__(self, "setting_by_name", {s.name: s for s in self.settings})
        object.__setattr__(self, "process_by_name", {p.name: p for p in self.processes})
        object.__setattr__(self, "state_by_value", {s.value: s for s in self.states})

    def declares_counter_bank(self, command: str) -> bool:
        """Whether the XML declares ``command`` as a counter bank.

        Covers both the ``<PRODUCTCOUNTER>`` and the ``<DAILYCOUNTER>``
        sections — a caller asking "may I read ``@TR:42`` here?" does
        not care which section it came from. Reading a bank the machine
        never declared is what the check exists to prevent.
        """
        target = command.strip().upper()
        return target in self.counter_banks or target in self.daily_counter_banks

    @property
    def intake_f18(self) -> bool:
        """Whether the manifest declares ``<CAPABILITIES IntakeF18="true"/>``.

        23 of the 89 bundled profiles do. On those machines J.O.E.
        carries preselections in the ``F18`` blob argument instead of
        (or in addition to) swapping in a double product code — but see
        :meth:`plan_preselections`: that encoding is unresolved here.
        The ``@TM:42`` PMode slot write also keys off it: J.O.E. appends
        six zero bytes to the blob on IntakeF18 machines even when the
        product declares no F17.
        """
        return (self.capabilities.get("IntakeF18") or "").strip().lower() == "true"

    def combination_allowed(self, names: Iterable[str]) -> bool:
        """Whether ``names`` may be preselected at the same time.

        Zero or one preselection is always allowed. Two or more must fit
        inside one ``<COMBINATION>`` row (a subset of a legal row is
        legal: if three may be active together, so may any two of them).
        Names are normalised via :func:`canonical_preselection`.
        """
        wanted = {canonical_preselection(n) for n in names}
        if len(wanted) < 2:
            return True
        return any(wanted <= row for row in self.preselect_combinations)

    def plan_preselections(
        self,
        product: ProductDef,
        names: Iterable[str] = (),
        *,
        mask: int | None = None,
    ) -> PreselectionPlan:
        """Work out how to apply ``names`` to ``product``.

        Validates, in order, that every name is a known preselection,
        that the product's ``<PRESELECTION>`` element declares it, that
        the requested set is a legal ``<COMBINATION>``, and that this
        machine generation can actually express it. All of that happens
        **before** anything goes on the wire.

        The two machine generations encode preselections differently.
        J.O.E. picks between them on the ``IntakeF18`` capability alone
        (``AppProduct.c``), and so does this method:

        * **Old T-protocol** (no ``<MACHINEMANIFEST>``; the maintainer's
          S8 EB / EF1091 is one). A ``double`` is a *different product*:
          the XML's ``<PRESELECTION double="31"/>`` names its code, so
          the plan swaps :attr:`~PreselectionPlan.product` for that
          catalogue entry — consistent with §5.5 of PROTOCOL.md, where
          the S8 EB counts its doubles at the separate slots ``0x31`` /
          ``0x36``. ``powder``, ``coldbrew``, ``lightbrew`` and
          ``xtrashot`` overwrite one recipe byte each
          (:data:`PRESELECT_LEGACY_BYTES`). Everything else —
          ``sweetfoam``, ``fakesweetfoam``, ``strongcoldbrew`` — has no
          wire representation at all: J.O.E. offers those toggles on
          such machines and then sends nothing for them, so they are
          refused here rather than silently dropped.
        * **New protocol** (``IntakeF18="true"``). Nothing is
          overwritten and no product swap happens; every preselection is
          one bit of a **mask byte appended to the blob**
          (:data:`PRESELECT_MASK_BITS`, offset
          :data:`PRESELECT_MASK_OFFSET`). ``double`` is bit ``0x40``
          there, not a product code.

        Note that a ``double`` product is usually marked
        ``Active="false"`` in the XML (it is not a menu entry), and that
        it carries its *own* recipe parameters — often none at all — so
        overrides valid for the single product may not be valid for its
        double.

        ``mask`` overrides the computed mask byte verbatim (an escape
        hatch for firmware that numbers the bits differently); it is
        only meaningful on an ``IntakeF18`` machine.

        **None of the encoding is hardware-verified.** It is transcribed
        from the APK — see PROTOCOL.md §5.13, and check a real machine
        before trusting it. Raises :class:`ValueError` on every
        rejection.
        """
        requested: list[str] = []
        for raw in names:
            name = canonical_preselection(raw)
            if name not in requested:
                requested.append(name)
        for name in requested:
            if name not in product.preselections:
                supported = ", ".join(sorted(product.preselections)) or "(none)"
                raise ValueError(
                    f"{product.name}: preselection {name!r} is not supported on "
                    f"{self.code}. This product supports: {supported}"
                )
        if not self.combination_allowed(requested):
            rows = (
                "; ".join("+".join(sorted(row)) for row in self.preselect_combinations)
                or "(none — one preselection at a time)"
            )
            raise ValueError(
                f"{self.code}: {' + '.join(requested)} is not a legal preselection "
                f"combination. Allowed combinations: {rows}"
            )

        if self.intake_f18:
            bits = 0
            for name in requested:
                bit = PRESELECT_MASK_BITS.get(name)
                if bit is None:
                    raise ValueError(
                        f"{self.code}: preselection {name!r} has no bit in the "
                        f"preselection mask this machine uses, so it cannot be "
                        f"sent. Encodable here: "
                        f"{', '.join(sorted(PRESELECT_MASK_BITS))}"
                    )
                bits |= bit
            return PreselectionPlan(
                product=product,
                requested=tuple(requested),
                mask=bits if mask is None else mask,
            )

        target = product
        overwrites: list[tuple[int, int]] = []
        for name in requested:
            if name == "double":
                if product.double_code is None:
                    raise ValueError(
                        f"{product.name}: {self.code} declares no double product "
                        f"code, so a double cannot be started on this machine."
                    )
                double = self.product_by_code.get(product.double_code)
                if double is None:
                    raise ValueError(
                        f"{product.name}: the {self.code} XML declares double "
                        f"product 0x{product.double_code:02X} but no such product "
                        f"is in its catalogue — the double cannot be brewed."
                    )
                target = double
                continue
            legacy = PRESELECT_LEGACY_BYTES.get(name)
            if legacy is None:
                raise ValueError(
                    f"{self.code}: preselection {name!r} has no wire encoding on "
                    f"this machine generation — J.O.E. shows it and sends nothing. "
                    f"Encodable here: double, "
                    f"{', '.join(sorted(PRESELECT_LEGACY_BYTES))}"
                )
            overwrites.append(legacy)
        return PreselectionPlan(
            product=target,
            requested=tuple(requested),
            mask=mask,
            byte_overwrites=tuple(overwrites),
        )

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
        blocked = alert.get("Blocked")
        # Type="block" stops every product regardless of Blocked (which
        # such alerts never carry); info/ip block only what Blocked names.
        blocked_kinds = (
            PRODUCT_KINDS if xml_type == "block" else expand_blocked_kinds(blocked)
        )
        raw_process = alert.get("Process")
        alerts.append(
            AlertDef(
                bit=bit,
                name=name,
                severity=severity,
                raw_name=raw_name,
                raw_type=xml_type,
                blocked=blocked,
                blocked_kinds=blocked_kinds,
                process=_process_name(raw_process),
                process_button=alert.get("ProcessButton"),
                title=alert.get("Title"),
                message=alert.get("Message"),
                picture=alert.get("Picture"),
                cancel_button=alert.get("CancelButton"),
                disabled_products=_hex_byte_list(alert.get("Disabled")),
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
        preselections, double_code = _parse_preselection(product)
        # Same "absent means allowed" rule J.O.E. applies to
        # shouldBeShownInCoffeeTimer.
        coffee_timer = (product.get("Coffeetimer") or "").strip().lower() != "false"
        products.append(
            ProductDef(
                code=code_int,
                name=_snake(raw_name),
                raw_name=raw_name,
                params=_parse_product_params(product),
                active=active,
                product_settings=_xml_bool(
                    product.get("ProductSettings"), default=True
                ),
                kind=(product.get("P_Kind") or "").strip().upper(),
                preselections=preselections,
                double_code=double_code,
                coffee_timer=coffee_timer,
            )
        )

    product_programming, pmode_slot_count = _parse_programmode(root)

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
    settings_bank = _parse_settings_bank(root)

    capabilities_el = root.find(".//{*}MACHINEMANIFEST/{*}CAPABILITIES")
    capabilities = {} if capabilities_el is None else dict(capabilities_el.attrib)

    return MachineProfile(
        code=code,
        version=version,
        alerts=tuple(alerts),
        products=tuple(products),
        settings=settings,
        has_pmode=product_programming,
        counter_banks=counter_banks,
        daily_counter_banks=daily_counter_banks,
        daily_counter_reset=daily_counter_reset,
        maintenance_counter_fields=_bank_fields(root, MAINTENANCE_COUNTER_BANK),
        maintenance_percent_fields=_bank_fields(root, MAINTENANCE_PERCENT_BANK),
        settings_bank=settings_bank,
        product_programming=product_programming,
        pmode_slot_count=pmode_slot_count,
        processes=_parse_processes(root),
        states=_parse_states(root),
        capabilities=capabilities,
        preselect_combinations=_parse_combinations(root),
    )


def _process_name(raw_type: str | None) -> str | None:
    """Normalise an XML process ``Type`` to the library's process name.

    ``"Decalc"`` becomes ``"descale"`` for the same reason the alert
    names do — the rest of the API (counters, percent bank, named
    commands, :data:`jura_connect.progress.PROCESS_CODES`) says
    "descale". Returns ``None`` for a missing/empty attribute.
    """
    if not raw_type or not raw_type.strip():
        return None
    return _snake(raw_type).replace("decalc", "descale")


def _hex_byte_list(raw: str | None) -> tuple[int, ...]:
    """Split a concatenated hex-byte attribute into ints.

    ``Disabled="0406070A2E"`` names five product codes, exactly the way
    the app's ``Alert`` constructor chops the string into two-character
    substrings. A malformed value yields ``()`` rather than raising.
    """
    text = (raw or "").strip()
    if not text or len(text) % 2:
        return ()
    try:
        return tuple(bytes.fromhex(text))
    except ValueError:
        return ()


def _parse_processes(root: ET.Element) -> tuple[ProcessDef, ...]:
    """Parse ``<PROCESSES><PROCESS>`` into :class:`ProcessDef` entries.

    Elements without a ``Type`` or an ``ExecuteCommand`` are skipped:
    without the wire verb there is nothing to start. ``Progress="true"``
    means the machine pushes ``@TV:`` frames while the cycle runs.
    """
    processes: list[ProcessDef] = []
    seen: set[str] = set()
    for el in root.findall(".//{*}PROCESS"):
        name = _process_name(el.get("Type"))
        command = (el.get("ExecuteCommand") or "").strip().upper()
        if name is None or not command:
            continue
        if name in seen:
            continue
        seen.add(name)
        processes.append(
            ProcessDef(
                name=name,
                raw_type=(el.get("Type") or "").strip(),
                execute_command=command,
                progress=(el.get("Progress") or "").strip().lower() == "true",
                title=el.get("Title"),
                picture=el.get("Picture"),
                pdf_url=el.get("PDFURL"),
                video_url=el.get("VideoURL"),
            )
        )
    return tuple(processes)


def _parse_states(root: ET.Element) -> tuple[StateDef, ...]:
    """Parse ``<PROGRESS_STATE_INTAKE><STATE>`` into :class:`StateDef`.

    ``Value`` is a hex byte; entries with a missing/unparsable value or
    an empty name are skipped. Note the XMLs contain ``<STATE Value="0E"
    Name ="Alert"/>`` — a space before the ``=`` — which ElementTree
    handles, so the attribute names here are the plain ones.
    """
    states: list[StateDef] = []
    seen: set[int] = set()
    for el in root.findall(".//{*}STATE"):
        raw_name = (el.get("Name") or "").strip()
        raw_value = (el.get("Value") or "").strip()
        if not raw_name or not raw_value:
            continue
        try:
            value = int(raw_value, 16)
        except ValueError:
            continue
        if value in seen:
            continue
        seen.add(value)
        accept = (el.get("AcceptCommand") or "").strip().upper() or None
        states.append(
            StateDef(
                value=value,
                name=_snake(raw_name),
                raw_name=raw_name,
                accept_command=accept,
                title=el.get("Title"),
                message=el.get("Message"),
                picture=el.get("Picture"),
                progress=(el.get("Progress") or "").strip().lower() == "true",
            )
        )
    return tuple(states)


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


def _xml_bool(raw: str | None, *, default: bool) -> bool:
    """XML boolean attribute, parsed the way ``Boolean.parseBoolean``
    does in the APK: only the literal string ``"true"`` (any case) is
    true, anything else — including garbage — is false."""
    if raw is None:
        return default
    return raw.strip().lower() == "true"


def _parse_programmode(root: ET.Element) -> tuple[bool, int | None]:
    """Parse the machine's programmable-recipe (PMode) declarations.

    There is **no ``<PROGRAMMODE>`` element** in Jura's schema — none
    of the 89 bundled XMLs (nor the documented ``EF_MASTER`` /
    ``EF0000`` templates) has one. The machine declares product
    programming on ``<MACHINESETTINGS>`` instead, exactly the two
    attributes the APK's ``XMLParser`` reads into
    ``MachineSettings.productProgramming`` / ``.numberOfSlots``:

    ```xml
    <MACHINESETTINGS Productprogramming="false"
                     NumberOfSlotsForProductProgramming="6">
    ```

    ``Productprogramming`` appears on 57 profiles (20 true), the slot
    count on 5. A ``<PROGRAMMODE>`` element is still honoured as
    "supports pmode" so a future firmware XML that grows one does not
    silently regress.

    Returns ``(product_programming, declared_slot_count)``.
    """
    supported = root.find(".//{*}PROGRAMMODE") is not None
    slot_count: int | None = None
    for el in root.findall(".//{*}MACHINESETTINGS"):
        raw = el.get("Productprogramming")
        if raw is not None:
            supported = supported or _xml_bool(raw, default=False)
        declared = _int_attr(el, "NumberOfSlotsForProductProgramming")
        if declared is not None:
            slot_count = declared
    return supported, slot_count


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
    F-numbered Argument are skipped; PRESELECTION is one of those and is
    parsed separately by :func:`_parse_preselection`.
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
                pmode_adjust=(
                    None
                    if el.get("PModeAdjust") is None
                    else _xml_bool(el.get("PModeAdjust"), default=False)
                ),
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


def _parse_settings_bank(root: ET.Element) -> SettingsBank | None:
    """Parse ``<MACHINESETTINGS><BANK Name="Setting" …>``.

    ``CommandArgument`` is a concatenation of two-hex-digit
    ``P_Argument`` codes (``"02080913"`` → ``("02", "08", "09", "13")``)
    naming the settings the batch read answers with, in reply order.
    Returns ``None`` when the XML declares no settings bank, and drops
    a bank whose ``CommandArgument`` is missing or not a whole number of
    hex bytes rather than guessing at a partial list.
    """
    container = root.find(".//{*}MACHINESETTINGS")
    if container is None:
        return None
    for el in container:
        if el.tag.split("}", 1)[-1] != "BANK":
            continue
        command = (el.get("Command") or "").strip()
        raw_args = (el.get("CommandArgument") or "").strip().upper()
        if not command or not raw_args or len(raw_args) % 2:
            continue
        try:
            int(raw_args, 16)
        except ValueError:
            continue
        arguments = tuple(raw_args[i : i + 2] for i in range(0, len(raw_args), 2))
        return SettingsBank(
            name=el.get("Name") or "Setting",
            command=command,
            arguments=arguments,
        )
    return None


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
        # Mask is not slider-only: the ESM switch (P_Argument="07")
        # carries Mask="01". Keep whatever the XML declares for every
        # kind so the catalogue mirrors the source.
        mask = el.get("Mask")
        if mask is not None:
            mask = mask.upper()
        if kind == "step_slider":
            try:
                minimum = int(el.get("Min", "")) if el.get("Min") else None
                maximum = int(el.get("Max", "")) if el.get("Max") else None
                step = int(el.get("Step", "")) if el.get("Step") else None
            except ValueError:
                pass
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
