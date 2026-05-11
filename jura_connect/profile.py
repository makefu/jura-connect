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
class MachineProfile:
    """Static description of one machine variant.

    Keyed by the EF code that names the directory in the APK
    (e.g. ``EF1091`` for the S8 EB, ``EF536`` for the legacy S8).
    """

    code: str  # EF code, e.g. "EF1091"
    version: str  # XML schema version, e.g. "1.6"
    alerts: tuple[AlertDef, ...]
    products: tuple[ProductDef, ...]
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

    def __post_init__(self) -> None:
        object.__setattr__(self, "alert_by_bit", {a.bit: a for a in self.alerts})
        object.__setattr__(self, "product_by_code", {p.code: p for p in self.products})


# --------------------------------------------------------------------- #
# XML loading
# --------------------------------------------------------------------- #


def _snake(name: str) -> str:
    """Normalise an XML ``Name`` attribute to a snake_case identifier."""
    s = name.strip().lower()
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

    return MachineProfile(
        code=code,
        version=version,
        alerts=tuple(alerts),
        products=tuple(products),
        has_pmode=has_pmode,
    )


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
