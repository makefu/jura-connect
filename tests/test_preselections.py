"""Preselections: XML parsing and the two ways they reach the machine.

Preselections are the extra-shot / double / powder / cold-brew /
light-brew / sweet-foam toggles J.O.E. shows next to a product. Two
mechanisms exist, and J.O.E. picks between them purely on the
``IntakeF18`` capability:

* old T-protocol machines (no ``<MACHINEMANIFEST>``, e.g. the
  maintainer's S8 EB / EF1091) express a *double* as a **different
  product code** — ``<PRESELECTION double="31"/>`` — and powder /
  cold brew / light brew / extra shot as **fixed bytes overwritten**
  onto the recipe blob;
* ``IntakeF18`` machines never swap the product and never overwrite:
  every preselection is one bit of a **mask byte appended to the
  blob**.

The encodings are transcribed from the J.O.E. APK
(``AppProduct.c`` / ``PreselectArgument``); see PROTOCOL.md §5.13. No
hardware was available when these tests were written, so **no assertion
below claims a hardware-verified wire format** — they pin the
transcription down, not the machine's behaviour.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from jura_connect import profile as profile_mod
from jura_connect.client import JuraClient
from jura_connect.commands import CommandError, run_named
from jura_connect.profile import (
    PRESELECT_BLOB_BYTES,
    PRESELECT_MASK_OFFSET,
    PRESELECTION_NAMES,
    canonical_preselection,
    iter_profiles,
    list_profile_codes,
    load_profile,
)

# The one bundled XML that breaks Jura's own rule ("if the double
# contains a Product Code other than 00, the Product should exist in
# this List of Products too"): EF1143's Espresso Doppio (0x30) points at
# a double 0x31 that its own catalogue does not define.
_DANGLING_DOUBLE = {("EF1143", 0x30, 0x31)}


def _paired(sim, code: str | None = None) -> JuraClient:
    host, port = sim.address
    c = JuraClient(
        host,
        port=port,
        conn_id="preselect-tests",
        auth_hash="",
        profile=None if code is None else load_profile(code),
    )
    assert c.pair(timeout=2.0).state == "CORRECT"
    return c


# --------------------------------------------------------------------- #
# XML parsing
# --------------------------------------------------------------------- #


def test_ef1091_preselections_parsed_old_t_protocol() -> None:
    """EF1091 (S8 EB) has no manifest: doubles are product codes."""
    prof = load_profile("EF1091")
    assert prof.capabilities == {}
    assert prof.intake_f18 is False

    espresso = prof.product_by_code[0x02]
    # <PRESELECTION xtrashot="false" double="31" powder="true"
    #               coldbrew="false" sweetfoam="false"/>
    assert espresso.preselections == frozenset({"double", "powder"})
    assert espresso.double_code == 0x31
    assert prof.product_by_code[0x31].raw_name == "2 Espressi"
    assert espresso.supports_preselection("powder") is True
    assert espresso.supports_preselection("cold_brew") is False

    coffee = prof.product_by_code[0x03]
    assert coffee.double_code == 0x36

    cappuccino = prof.product_by_code[0x04]
    # double="00" -> no double, but xtrashot/powder/sweetfoam are true.
    assert cappuccino.double_code is None
    assert cappuccino.preselections == frozenset({"xtrashot", "powder", "sweetfoam"})

    hotwater = prof.product_by_code[0x0D]
    assert hotwater.preselections == frozenset()

    # <MULTIPLE_PRESELECTS> declares which may be combined.
    assert prof.preselect_combinations == (
        frozenset({"powder", "sweetfoam"}),
        frozenset({"xtrashot", "sweetfoam"}),
    )


def test_ef1120_intake_f18_capability_parsed() -> None:
    """An IntakeF18 machine exposes the capability *and* still names a
    double product code — the two mechanisms are not exclusive in the
    bundled XMLs."""
    prof = load_profile("EF1120")
    assert prof.capabilities == {"IntakeF18": "true"}
    assert prof.intake_f18 is True

    espresso = prof.product_by_code[0x02]
    # <PRESELECTION double="31" powder="false" lightbrew="true" sweetfoam="false"/>
    assert espresso.preselections == frozenset({"double", "lightbrew"})
    assert espresso.double_code == 0x31
    assert prof.preselect_combinations == (frozenset({"lightbrew", "sweetfoam"}),)


def test_combination_row_false_attributes_are_not_members() -> None:
    """EF1123 writes <COMBINATION powder="false" sweetfoam="true"/>; only
    the "true" attributes are part of a row, so that row degenerates to a
    single preselection and is dropped as carrying no information."""
    prof = load_profile("EF1123")
    for row in prof.preselect_combinations:
        assert len(row) >= 2
        assert "powder" not in row or row != frozenset({"powder", "sweetfoam"})
    assert prof.combination_allowed(["coldbrew", "strongcoldbrew"]) is True
    assert prof.combination_allowed(["coldbrew", "powder"]) is False


def test_all_profiles_preselection_attributes_are_documented() -> None:
    """Walk all 89 bundled profiles: the raw XML attribute set must be
    exactly PRESELECTION_NAMES (a new attribute in a future APK drop
    breaks this test rather than being silently ignored), and every
    declared double code must resolve to a product in the same
    catalogue."""
    import importlib.resources

    base = importlib.resources.files("jura_connect").joinpath("data/xml")
    seen_attrs: set[str] = set()
    seen_true: set[str] = set()
    dangling: set[tuple[str, int, int]] = set()

    codes = list_profile_codes()
    assert len(codes) >= 89
    for code in codes:
        folder = base.joinpath(code)
        newest = max(
            (f.name for f in folder.iterdir() if f.name.endswith(".xml")),
            key=lambda n: profile_mod._version_key(n.removesuffix(".xml")),
        )
        root = ET.fromstring(folder.joinpath(newest).read_text(encoding="utf-8"))
        for el in root.findall(".//{*}PRESELECTION"):
            for key, value in el.attrib.items():
                seen_attrs.add(key.lower())
                if value.strip().lower() == "true":
                    seen_true.add(key.lower())

        prof = load_profile(code)
        for product in prof.products:
            if product.double_code is None:
                continue
            assert "double" in product.preselections
            if product.double_code not in prof.product_by_code:
                dangling.add((code, product.code, product.double_code))

    assert seen_attrs == set(PRESELECTION_NAMES)
    # PModeAdjust is declared but never actually enabled anywhere, so it
    # never lands in a product's supported set.
    assert "pmodeadjust" not in seen_true
    assert dangling == _DANGLING_DOUBLE


def test_dangling_double_is_refused_not_crashed() -> None:
    """A double code with no matching product must fail loudly at plan
    time, not produce a blob for a product the machine lacks.

    No bundled old-T-protocol XML has that defect (EF1143 does, but it
    is an IntakeF18 machine and never looks the code up), so the profile
    here is assembled from the real dataclasses.
    """
    from jura_connect.profile import MachineProfile, ProductDef

    espresso = ProductDef(
        code=0x02,
        name="espresso",
        raw_name="Espresso",
        preselections=frozenset({"double"}),
        double_code=0x31,
    )
    prof = MachineProfile(
        code="EF_TEST",
        version="1.0",
        alerts=(),
        products=(espresso,),
        settings=(),
        has_pmode=False,
    )
    with pytest.raises(ValueError, match="no such product"):
        prof.plan_preselections(espresso, ["double"])

    # EF1143 is the one bundled XML with a dangling double. It is an
    # IntakeF18 machine, so the code is never dereferenced and the
    # double is sent as a mask bit instead.
    real = load_profile("EF1143")
    doppio = real.product_by_code[0x30]
    assert doppio.double_code == 0x31
    assert 0x31 not in real.product_by_code
    assert real.plan_preselections(doppio, ["double"]).mask == 0x40


def test_capability_parsing_covers_every_manifest_machine() -> None:
    """23 of the bundled profiles carry <CAPABILITIES>; all of them set
    IntakeF18 and the property agrees with the raw attribute."""
    with_caps = [p for p in iter_profiles() if p.capabilities]
    assert len(with_caps) == 23
    for prof in with_caps:
        assert prof.intake_f18 == (prof.capabilities.get("IntakeF18") == "true")
        assert prof.intake_f18 is True


def test_canonical_preselection_aliases() -> None:
    assert canonical_preselection("extra_shot") == "xtrashot"
    assert canonical_preselection("Cold-Brew") == "coldbrew"
    assert canonical_preselection("sweet_foam") == "sweetfoam"
    assert canonical_preselection("DOUBLE") == "double"
    with pytest.raises(ValueError, match="unknown preselection"):
        canonical_preselection("decaf")


# --------------------------------------------------------------------- #
# Resolution: old T-protocol double = a different product
# --------------------------------------------------------------------- #


def test_double_on_ef1091_resolves_to_the_double_product_code() -> None:
    """`brew espresso double` must brew product 0x31, not a modified
    espresso blob."""
    prof = load_profile("EF1091")
    espresso = prof.product_by_code[0x02]
    plan = prof.plan_preselections(espresso, ["double"])
    assert plan.product.code == 0x31
    assert plan.product.raw_name == "2 Espressi"
    assert plan.mask is None  # no mask byte on an old-T-protocol machine
    assert plan.byte_overwrites == ()
    blob = plan.build_recipe_hex()
    assert blob.startswith("31")
    # Untouched apart from product code and the constant byte-8 marker.
    assert blob == "31000000000000000100000000000000"
    # The single-shot blob is unchanged by comparison — no blob-level
    # doubling happens on this machine.
    assert espresso.build_recipe_hex().startswith("02")


def test_unsupported_preselection_is_rejected_before_the_wire(sim) -> None:
    """Hot water declares no preselections at all; asking for one must
    fail client-side with nothing sent."""
    c = _paired(sim, "EF1091")
    try:
        with pytest.raises(CommandError, match="not supported"):
            run_named(
                c,
                "brew",
                ["hotwater", "double"],
                timeout=1.0,
                allow_destructive=True,
            )
    finally:
        c.close()
    assert not [f for f in sim.sent_commands if f.startswith(b"@TP:")]


def test_illegal_combination_is_rejected_before_the_wire(sim) -> None:
    """EF1091 allows powder+sweetfoam and xtrashot+sweetfoam only, so
    double+powder — both individually supported by Espresso — must be
    refused."""
    prof = load_profile("EF1091")
    espresso = prof.product_by_code[0x02]
    assert {"double", "powder"} <= espresso.preselections
    assert prof.combination_allowed(["double", "powder"]) is False

    c = _paired(sim, "EF1091")
    try:
        with pytest.raises(CommandError, match="combination"):
            run_named(
                c,
                "brew",
                ["espresso", "double", "powder"],
                timeout=1.0,
                allow_destructive=True,
            )
    finally:
        c.close()
    assert not [f for f in sim.sent_commands if f.startswith(b"@TP:")]


def test_legacy_byte_overwrites_on_an_old_t_protocol_machine() -> None:
    """powder / coldbrew / lightbrew / xtrashot are single fixed bytes
    written over the recipe on a machine without IntakeF18. Values from
    PreselectArgument's (index, value) payloads — APK-derived, untested.
    """
    prof = load_profile("EF1091")
    cappuccino = prof.product_by_code[0x04]
    plan = prof.plan_preselections(cappuccino, ["powder"])
    assert plan.product is cappuccino
    assert plan.mask is None
    assert plan.byte_overwrites == ((2, 0x00),)
    blob = plan.build_recipe_hex()
    # 16 bytes, unchanged length: powder only blanks the strength byte.
    assert len(blob) == 32
    assert blob[2 * 2 : 2 * 2 + 2] == "00"
    assert blob.startswith("04")
    # Coffee strength normally carries the XML default, so the
    # overwrite is a real change.
    assert cappuccino.build_recipe_hex()[2 * 2 : 2 * 2 + 2] != "00"

    # Extra shot writes 0x02 at byte 7 (F8, stroke).
    xtra = prof.plan_preselections(cappuccino, ["xtrashot"])
    assert xtra.byte_overwrites == ((7, 0x02),)
    assert xtra.build_recipe_hex()[7 * 2 : 7 * 2 + 2] == "02"


def test_preselection_conflicting_with_an_explicit_override_is_refused() -> None:
    """powder blanks the coffee-strength byte, so asking for both is a
    contradiction — refuse rather than silently drop the user's value."""
    prof = load_profile("EF1091")
    cappuccino = prof.product_by_code[0x04]
    plan = prof.plan_preselections(cappuccino, ["powder"])
    with pytest.raises(ValueError, match="coffee_strength"):
        plan.build_recipe_hex({"coffee_strength": 5})
    # A non-clashing override still works.
    assert plan.build_recipe_hex({"water_amount": 45})[3 * 2 : 3 * 2 + 2] == "09"


def test_preselection_without_wire_encoding_is_refused(sim) -> None:
    """EF1091's Cappuccino declares sweetfoam, but an old-T-protocol
    machine has no way to send it (J.O.E. shows the toggle and sends
    nothing). Refuse instead of silently brewing a plain cappuccino."""
    prof = load_profile("EF1091")
    cappuccino = prof.product_by_code[0x04]
    assert "sweetfoam" in cappuccino.preselections
    with pytest.raises(ValueError, match="no wire encoding"):
        prof.plan_preselections(cappuccino, ["sweet_foam"])

    c = _paired(sim, "EF1091")
    try:
        with pytest.raises(CommandError, match="no wire encoding"):
            run_named(
                c,
                "brew",
                ["cappuccino", "sweet_foam"],
                timeout=1.0,
                allow_destructive=True,
            )
    finally:
        c.close()
    assert not [f for f in sim.sent_commands if f.startswith(b"@TP:")]


def test_intake_f18_machine_uses_a_mask_byte_not_a_product_swap() -> None:
    """On an IntakeF18 machine J.O.E. never swaps the product code and
    never overwrites recipe bytes: every preselection is one bit of a
    mask byte appended as the 20th blob byte. APK-derived, untested."""
    prof = load_profile("EF1123")
    espresso = prof.product_by_code[0x02]
    assert prof.intake_f18 is True
    assert espresso.double_code == 0x31  # declared, but unused on this path

    plan = prof.plan_preselections(espresso, ["double"])
    assert plan.product is espresso  # no swap
    assert plan.byte_overwrites == ()
    assert plan.mask == 0x40
    blob = plan.build_recipe_hex()
    assert len(blob) == PRESELECT_BLOB_BYTES * 2 == 40
    assert blob.startswith("02")
    assert blob[PRESELECT_MASK_OFFSET * 2 :] == "40"
    # Bytes 17..18 are padding; byte 16 is this product's F17
    # grinder-freeness default, which the 20-byte window includes.
    assert blob[16 * 2 : 16 * 2 + 2] == "02"
    assert blob[17 * 2 : PRESELECT_MASK_OFFSET * 2] == "0000"

    # Bits OR together; lightbrew is 0x08 and lightbrew+double is one of
    # this machine's legal <COMBINATION> rows.
    combo = prof.plan_preselections(espresso, ["double", "lightbrew"])
    assert combo.mask == 0x48
    assert (
        prof.plan_preselections(espresso, ["coldbrew", "strongcoldbrew"]).mask == 0x90
    )


def test_mask_escape_hatch_overrides_the_computed_byte() -> None:
    prof = load_profile("EF1123")
    espresso = prof.product_by_code[0x02]
    plan = prof.plan_preselections(espresso, ["double"], mask=0x41)
    assert plan.mask == 0x41
    assert plan.build_recipe_hex()[PRESELECT_MASK_OFFSET * 2 :] == "41"
    with pytest.raises(ValueError, match="wire byte"):
        espresso.build_recipe_hex(preselect_mask=0x1FF)


# --------------------------------------------------------------------- #
# End-to-end through the simulator
# --------------------------------------------------------------------- #


def test_simulator_round_trip_double_sends_the_double_products_blob(sim) -> None:
    """The bytes that actually leave the client for `brew espresso
    double` are the double product's blob."""
    c = _paired(sim, "EF1091")
    try:
        result = run_named(
            c,
            "brew",
            ["espresso", "double"],
            timeout=2.0,
            allow_destructive=True,
        )
    finally:
        c.close()
    # The simulator refuses @TP: by design (destructive guardrail); what
    # matters is the payload it saw.
    assert result.value.startswith("@an:error")
    sent = [f for f in sim.sent_commands if f.startswith(b"@TP:")]
    assert sent == [b"@TP:31000000000000000100000000000000"]


def test_simulator_round_trip_legacy_overwrite(sim) -> None:
    """A legacy byte overwrite reaches the wire in the 16-byte blob."""
    c = _paired(sim, "EF1091")
    try:
        run_named(
            c,
            "brew",
            ["cappuccino", "powder"],
            timeout=2.0,
            allow_destructive=True,
        )
    finally:
        c.close()
    sent = [f for f in sim.sent_commands if f.startswith(b"@TP:")]
    assert len(sent) == 1
    blob = sent[0].removeprefix(b"@TP:").decode()
    assert len(blob) == 32
    assert blob.startswith("04")
    assert blob[2 * 2 : 2 * 2 + 2] == "00"


def test_simulator_round_trip_intake_f18_mask(sim) -> None:
    """The mask byte reaches the wire as the 20th blob byte."""
    c = _paired(sim, "EF1123")
    try:
        run_named(
            c,
            "brew",
            ["espresso", "double"],
            timeout=2.0,
            allow_destructive=True,
        )
    finally:
        c.close()
    sent = [f for f in sim.sent_commands if f.startswith(b"@TP:")]
    assert len(sent) == 1
    blob = sent[0].removeprefix(b"@TP:").decode()
    assert len(blob) == PRESELECT_BLOB_BYTES * 2
    assert blob.startswith("02")
    assert blob[PRESELECT_MASK_OFFSET * 2 :] == "40"


def test_client_brew_preselection_kwarg(sim) -> None:
    """The library entry point takes the same preselections the CLI does."""
    c = _paired(sim, "EF1091")
    try:
        reply = c.brew("espresso", preselections=["double"])
    finally:
        c.close()
    assert reply.startswith("@an:error")
    sent = [f for f in sim.sent_commands if f.startswith(b"@TP:")]
    assert sent == [b"@TP:31000000000000000100000000000000"]


# --------------------------------------------------------------------- #
# products output
# --------------------------------------------------------------------- #


def test_products_lists_preselections_per_product(sim) -> None:
    """`products` exists to tell users what `brew` accepts, so it must
    show the preselections too — including where a double lands."""
    from jura_connect.commands import ProductCatalogue

    c = _paired(sim, "EF1091")
    try:
        result = run_named(c, "products", [], timeout=1.0)
    finally:
        c.close()
    cat = result.value
    assert isinstance(cat, ProductCatalogue)
    espresso = next(p for p in cat.products if p.name == "espresso")
    assert espresso.preselections == ("double", "powder")
    assert espresso.unsendable == ()
    assert espresso.double_product == "2_espressi"
    assert espresso.double_code == 0x31
    text = espresso.format()
    assert "double" in text and "powder" in text
    assert "2_espressi" in text

    hotwater = next(p for p in cat.products if p.name.startswith("hotwater"))
    assert hotwater.preselections == ()
    assert "preselections: (none)" in hotwater.format()

    # sweetfoam is declared on the Cappuccino but cannot be sent on an
    # old-T-protocol machine, and `products` must say so rather than
    # advertise something `brew` refuses.
    cappuccino = next(p for p in cat.products if p.name == "cappuccino")
    assert "sweetfoam" in cappuccino.preselections
    assert cappuccino.unsendable == ("sweetfoam",)
    assert "not sendable" in cappuccino.format()

    d = espresso.to_dict()
    assert d["preselections"] == ["double", "powder"]
    assert d["double_product"] == "2_espressi"
    assert d["unsendable_preselections"] == []
    assert cat.to_dict()["preselect_combinations"] == [
        ["powder", "sweetfoam"],
        ["sweetfoam", "xtrashot"],
    ]
