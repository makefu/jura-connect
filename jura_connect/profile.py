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


@dataclasses.dataclass(slots=True, frozen=True)
class AlertDef:
    """One ALERT entry from the machine XML."""

    bit: int
    name: str  # snake_case, derived from XML Name attribute
    severity: str  # "error" / "info" / "process"
    raw_name: str  # the original XML Name (with spaces)


@dataclasses.dataclass(slots=True, frozen=True)
class ProductDef:
    """One PRODUCT entry from the machine XML."""

    code: int  # product code, e.g. 0x02
    name: str  # snake_case, e.g. "espresso"
    raw_name: str  # original XML Name


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
            lo = self.minimum if self.minimum is not None else 0
            hi = self.maximum if self.maximum is not None else 0xFF
            if not lo <= n <= hi:
                raise ValueError(f"{self.raw_name}: {n} is outside [{lo}, {hi}]")
            if self.step and self.step > 1 and (n - lo) % self.step != 0:
                raise ValueError(
                    f"{self.raw_name}: {n} is not aligned to the step "
                    f"({self.step}); allowed values are "
                    f"{lo}, {lo + self.step}, {lo + 2 * self.step}, …, {hi}"
                )
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


# --------------------------------------------------------------------- #
# XML loading
# --------------------------------------------------------------------- #


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
        alerts.append(
            AlertDef(
                bit=bit,
                name=_snake(raw_name),
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
        products.append(
            ProductDef(
                code=code_int,
                name=_snake(raw_name),
                raw_name=raw_name,
            )
        )

    has_pmode = root.find(".//{*}PROGRAMMODE") is not None

    settings = _parse_machine_settings(root)

    return MachineProfile(
        code=code,
        version=version,
        alerts=tuple(alerts),
        products=tuple(products),
        settings=settings,
        has_pmode=has_pmode,
    )


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
