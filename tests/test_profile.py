"""Tests for the bundled MachineProfile registry."""

from __future__ import annotations

import pytest

from jura_connect.profile import (
    _parse_xml,
    iter_profiles,
    known_machine_names,
    list_profile_codes,
    load_profile,
    lookup_by_article_number,
    search_by_friendly_name,
)


def test_list_profile_codes_returns_89_machines():
    codes = list_profile_codes()
    # The vendored APK ships 88 machine XMLs; EF1125 (S10) was added on
    # top, so 89.
    assert len(codes) == 89
    # Must include the S8 EB (EF1091), the legacy S8 (EF536), and the
    # S10 (EF1125).
    assert "EF1091" in codes
    assert "EF536" in codes
    assert "EF1125" in codes


def test_ef1091_has_s8_eb_specific_products():
    """The S8 EB's product map differs from the legacy S8 — verify the
    codes the J.O.E. app actually shows for this machine."""
    p = load_profile("EF1091")
    # Smoke check: alert + product counts match the v1.6 XML.
    assert len(p.alerts) >= 50
    assert len(p.products) >= 17
    # Per-EF code differences from the EF536 baseline.
    assert p.product_by_code[0x2B].name == "cortado"
    assert p.product_by_code[0x2C].name == "sweet_latte"
    assert p.product_by_code[0x2E].name == "flat_white"
    assert p.product_by_code[0x30].name == "espresso_doppio"
    # The S8 EB uses 0x31/0x36 for the doubles (vs 0x12/0x13 on EF536).
    assert p.product_by_code[0x31].name == "2_espressi"
    assert p.product_by_code[0x36].name == "2_coffee"
    # No PROGRAMMODE in the EF1091 XML.
    assert p.has_pmode is False


def test_alert_severity_lifted_from_xml_type_attribute():
    p = load_profile("EF1091")
    # 'no beans' is Type="info" => severity "info".
    assert p.alert_by_bit[10].name == "no_beans"
    assert p.alert_by_bit[10].severity == "info"
    # 'fill water' is Type="block" => severity "error".
    assert p.alert_by_bit[1].name == "fill_water"
    assert p.alert_by_bit[1].severity == "error"
    # 'cappu rinse alert' is Type="ip" => severity "process".
    assert p.alert_by_bit[35].name == "cappu_rinse_alert"
    assert p.alert_by_bit[35].severity == "process"


def test_ef1069_maps_high_byte7_status_bits():
    """The J8 (SAS / EF1069) status frame carries bits in byte 7 that the
    EF536 baseline codebook (which stops at bit 38) doesn't know about.
    These are what the J8's @TF: frame actually exercises, so the profile
    must define them. See makefu/jura-connect-hass#3."""
    p = load_profile("EF1069")
    # bit 54 is set in every J8 frame at idle ("ML/OZ status").
    assert p.alert_by_bit[54].name == "ml_oz_status"
    assert p.alert_by_bit[54].severity == "info"
    # bit 56 toggles when a cup is placed under the coffee eye.
    assert p.alert_by_bit[56].name == "coffee_eye_cup_detected"
    assert p.alert_by_bit[56].severity == "info"


def test_unknown_profile_code_raises():
    with pytest.raises(KeyError):
        load_profile("EF_NOT_A_REAL_MACHINE")


def test_iter_profiles_covers_everything_without_crashing():
    """Every bundled XML must parse without an exception."""
    seen = list(iter_profiles())
    # 88 codes; at least the parseable subset must be non-trivial.
    assert len(seen) >= 80
    assert any(p.code == "EF1091" for p in seen)


def test_lookup_by_article_number_finds_s8_eb():
    entry = lookup_by_article_number(15480)
    assert entry is not None
    assert entry.friendly_name == "S8 (EB)"
    assert entry.ef_code == "EF1091"


def test_search_by_friendly_name_substring_match():
    rows = search_by_friendly_name("S8 (EB)")
    # 15480 (EF1091) and 15482 (EF1151) are both badged "S8 (EB)".
    codes = {r.ef_code for r in rows}
    assert "EF1091" in codes
    assert "EF1151" in codes
    # The result deduplicates per (friendly_name, ef_code) pair.
    assert len(rows) == 2


def test_known_machine_names_is_sorted_and_unique():
    names = known_machine_names()
    assert names == sorted(names)
    assert len(names) == len(set(names))


def test_ef538_product_params_parsed_from_xml():
    """The E8 (EB)'s recipe parameters must survive parsing — they
    drive the @TP recipe-blob builder."""
    p = load_profile("EF538")
    hot_water = p.product_by_code[0x0D]
    water = hot_water.param("water_amount")
    assert water is not None
    assert (water.argument, water.offset) == (4, 3)
    assert (water.default, water.minimum, water.maximum, water.step) == (
        220,
        25,
        450,
        5,
    )
    temp = hot_water.param("temperature")
    assert temp is not None
    assert (temp.argument, temp.offset) == (7, 6)
    assert {it.name for it in temp.items} == {"low", "normal", "high"}
    # Espresso carries a strength parameter at F3 -> blob byte 2.
    espresso = p.product_by_code[0x02]
    strength = espresso.param("coffee_strength")
    assert strength is not None
    assert strength.offset == 2
    # PRESELECTION has no F-argument and must not become a parameter.
    assert hot_water.param("preselection") is None


def test_build_recipe_hex_uses_00_padding_and_byte8_flag():
    """The hardware-verified layout is 00-padded with byte 8 = 0x01.

    Water at 220 ml -> 0x2C (44 ticks) at byte 3, temperature normal
    (default) -> 0x01 at byte 6, byte 8 = 0x01, everything else 0x00."""
    p = load_profile("EF538")
    hot_water = p.product_by_code[0x0D]
    assert (
        hot_water.build_recipe_hex({"water_amount": 220})
        == "0D00002C000001000100000000000000"
    )
    # XML defaults only — same blob, since 220 ml is the XML default.
    assert hot_water.build_recipe_hex() == "0D00002C000001000100000000000000"
    # Temperature accepts ITEM names and lands on byte 6.
    assert (
        hot_water.build_recipe_hex({"temperature": "high"})
        == "0D00002C000002000100000000000000"
    )
    # Padding is 0x00 and byte 8 is the constant 0x01.
    blob = hot_water.build_recipe_hex()
    assert blob[1 * 2 : 1 * 2 + 2] == "00"  # unused byte
    assert blob[8 * 2 : 8 * 2 + 2] == "01"  # structural "recipe valid" byte


def test_build_recipe_hex_validates_against_catalogue():
    p = load_profile("EF538")
    hot_water = p.product_by_code[0x0D]
    with pytest.raises(ValueError, match="outside"):
        hot_water.build_recipe_hex({"water_amount": 9999})
    with pytest.raises(ValueError, match="step"):
        hot_water.build_recipe_hex({"water_amount": 33})
    with pytest.raises(ValueError, match="not a recognised value"):
        hot_water.build_recipe_hex({"temperature": "lukewarm"})
    with pytest.raises(ValueError, match="unknown recipe parameter"):
        hot_water.build_recipe_hex({"coffee_strength": 5})  # no grounds in water


def test_active_default_true_keeps_products_without_active_attribute():
    """J.O.E. defaults Active to true; only Active="false" is hidden.

    On the EF538 (E8 (EB)) Milk Foam, Cafe Barista and Barista Lungo
    carry no Active attribute and must stay brewable. Products flagged
    Active="false" (internal Powderproduct) stay in the catalogue — the
    machine still reports their counters — but are marked inactive so a
    UI can hide them."""
    p = load_profile("EF538")
    assert p.product_by_code[0x08].name == "milk_foam"  # no Active attr
    assert p.product_by_code[0x08].active is True
    assert p.product_by_code[0x28].name == "cafe_barista"  # no Active attr
    assert p.product_by_code[0x28].active is True
    assert p.product_by_code[0x29].name == "barista_lungo"  # no Active attr
    assert p.product_by_code[0x29].active is True
    # Powderproduct is Active="false": present for counters, but inactive.
    assert p.product_by_code[0x0F].name == "powderproduct"
    assert p.product_by_code[0x0F].active is False


def test_build_recipe_hex_flood_guard_on_missing_ml_value():
    """A water/ml parameter with no override and no XML default must be
    refused: with 00-padding its byte would be 0x00 (= no water), so
    rather than silently brew a dry shot the builder raises."""
    from jura_connect.profile import ProductDef, ProductParam

    # Synthetic product with a WATER_AMOUNT param that has NO default.
    water = ProductParam(
        kind="water_amount",
        argument=4,
        default=None,
        minimum=25,
        maximum=450,
        step=5,
        items=(),
    )
    prod = ProductDef(
        code=0x02, name="synthetic", raw_name="Synthetic", params=(water,)
    )
    with pytest.raises(ValueError, match="refusing to leave"):
        prod.build_recipe_hex()
    # An explicit amount is fine.
    assert prod.build_recipe_hex({"water_amount": 100}).startswith("02")


def test_build_recipe_hex_encodes_milk_foam_and_milk_break_overrides():
    """Milk-foam (F6, seconds) and milk-break (F11, seconds) overrides
    land on their F-1 byte, sent as-is (NOT live-verified). Latte
    Macchiato on the EF538 carries both parameters."""
    p = load_profile("EF538")
    latte = p.product_by_code[0x07]
    assert latte.param("milk_foam_amount").offset == 5  # F6
    assert latte.param("milk_break").offset == 10  # F11
    blob = latte.build_recipe_hex({"milk_foam_amount": 30, "milk_break": 45})
    # Seconds are sent as-is: 30 -> 0x1E at byte 5, 45 -> 0x2D at byte 10.
    assert blob[5 * 2 : 5 * 2 + 2] == "1E"
    assert blob[10 * 2 : 10 * 2 + 2] == "2D"
    # A milk_foam_amount override on a product that only has foam
    # (Cappuccino) also lands correctly.
    cappuccino = p.product_by_code[0x04]
    assert cappuccino.param("milk_break") is None
    assert cappuccino.build_recipe_hex({"milk_foam_amount": 40})[5 * 2 : 5 * 2 + 2] == (
        "28"
    )
    # Out-of-range milk values are refused before the wire.
    with pytest.raises(ValueError, match="outside"):
        latte.build_recipe_hex({"milk_break": 99})  # Max=60


def test_build_recipe_hex_encodes_bypass_and_milk_foam_defaults():
    """Bypass (F10, ml ÷5 ticks) and milk-foam (F6, seconds) defaults
    from the XML are baked into the blob (NOT live-verified)."""
    p = load_profile("EF538")
    # Cafe Barista: BYPASS F10 (offset 9) default 45 ml -> 9 ticks = 0x09.
    barista = p.product_by_code[0x28]
    blob = barista.build_recipe_hex()
    assert blob[9 * 2 : 9 * 2 + 2] == "09"
    # Override in ml is validated + divided into 5 ml ticks.
    assert barista.build_recipe_hex({"bypass": 30})[9 * 2 : 9 * 2 + 2] == "06"
    # Milk Foam: MILK_FOAM_AMOUNT F6 (offset 5) default 22 s -> 0x16.
    milk_foam = p.product_by_code[0x08]
    assert milk_foam.build_recipe_hex()[5 * 2 : 5 * 2 + 2] == "16"


def test_build_recipe_hex_matches_e6_live_verified_coffee_vector():
    """The builder now reproduces the E6 author's hardware-verified
    Coffee vector exactly: 0300021A000001000100000000000000 (strength
    2, 130 ml, Normal). 00-padded, byte 8 = 01, params at F-1 offsets
    (strength@2, water 130ml/5=0x1A@3, temperature Normal=01@6)."""
    from jura_connect.profile import ProductDef, ProductParam, SettingItem

    strength = ProductParam(
        kind="coffee_strength",
        argument=3,
        default=2,
        minimum=None,
        maximum=None,
        step=None,
        items=(
            SettingItem(name="1", raw_name="1", value="01"),
            SettingItem(name="2", raw_name="2", value="02"),
        ),
    )
    water = ProductParam(
        kind="water_amount",
        argument=4,
        default=130,
        minimum=15,
        maximum=250,
        step=5,
        items=(),
    )
    temp = ProductParam(
        kind="temperature",
        argument=7,
        default=1,
        minimum=None,
        maximum=None,
        step=None,
        items=(
            SettingItem(name="normal", raw_name="Normal", value="01"),
            SettingItem(name="high", raw_name="High", value="02"),
        ),
    )
    coffee = ProductDef(
        code=0x03,
        name="coffee",
        raw_name="Coffee",
        params=(strength, water, temp),
    )
    blob = coffee.build_recipe_hex(
        {"coffee_strength": 2, "water_amount": 130, "temperature": "normal"}
    )
    assert blob == "0300021A000001000100000000000000"


def test_build_recipe_hex_matches_s8eb_live_verified_cafe_barista():
    """Owner's machine (JURA S8 EB / EF1091, 'kaffeebert') physically
    brewed this exact blob on the first send: cafe_barista (0x28),
    strength 7 (byte2=07), water 45 ml -> 0x09 (byte3), temperature
    normal -> 0x01 (byte6), byte8=01, bypass 45 ml -> 0x09 (byte9),
    everything else 0x00."""
    p = load_profile("EF1091")
    cafe_barista = p.product_by_code[0x28]
    blob = cafe_barista.build_recipe_hex(
        {
            "coffee_strength": 7,
            "water_amount": 45,
            "temperature": "normal",
            "bypass": 45,
        }
    )
    assert blob == "28000709000001000109000000000000"
    # Unused bytes are 0x00 (not 0xFF) and byte 8 is the constant 0x01.
    assert blob[1 * 2 : 1 * 2 + 2] == "00"
    assert blob[7 * 2 : 7 * 2 + 2] == "00"
    assert blob[8 * 2 : 8 * 2 + 2] == "01"
    assert blob.endswith("000000000000")


def test_build_recipe_hex_matches_e6_live_verified_espresso_vector():
    """The EF538 Espresso defaults reproduce the E6 author's second
    hardware-verified vector: 02000809000002000100000000000000."""
    p = load_profile("EF538")
    espresso = p.product_by_code[0x02]
    assert espresso.build_recipe_hex() == "02000809000002000100000000000000"


# --------------------------------------------------------------------- #
# F17 (grinder freeness) — the 17-byte blob
# --------------------------------------------------------------------- #


def test_build_recipe_hex_grows_to_17_bytes_for_an_f17_product():
    """A product declaring ``Argument="F17"`` (grinder freeness) puts a
    byte at offset 16, one past the 16-byte blob. J.O.E.'s
    ``AppProduct.c`` builds ``(hasF17 ? 17 : 16)`` bytes for exactly
    this reason; before the fix this raised ValueError and the product
    could not be brewed at all."""
    p = load_profile("EF1119")
    espresso = p.product_by_code[0x02]
    blob = espresso.build_recipe_hex()
    # 17 bytes = 34 hex chars, not 32.
    assert len(blob) == 34
    # Product code, strength F3 -> byte 2, water F4 -> byte 3 (45 ml =
    # 9 ticks), temperature F7 -> byte 6, the constant byte 8, and the
    # grinder freeness F17 -> byte 16 (XML default 2).
    assert blob == "02000809000002000100000000000000" + "02"
    assert blob[16 * 2 : 16 * 2 + 2] == "02"


def test_build_recipe_hex_f17_override_lands_on_byte_16():
    p = load_profile("EF1119")
    coffee = p.product_by_code[0x03]
    # The XML default for this product is 1; ask for the other catalogue
    # value so the assertion proves the override reached byte 16.
    assert coffee.param("grinder_freeness").default == 1
    blob = coffee.build_recipe_hex({"grinder_freeness": 2})
    assert len(blob) == 34
    assert blob[16 * 2 : 16 * 2 + 2] == "02"
    # Out-of-catalogue values are still refused, at byte 16 like anywhere.
    with pytest.raises(ValueError, match="not in the catalogue"):
        coffee.build_recipe_hex({"grinder_freeness": 9})


def test_build_recipe_hex_stays_16_bytes_without_f17():
    """The live-verified layout must not grow for the 83 profiles whose
    products declare no F17 — the machine ACKs and ignores a blob of the
    wrong length."""
    for code, product_code in (("EF1091", 0x28), ("EF538", 0x02)):
        product = load_profile(code).product_by_code[product_code]
        assert len(product.build_recipe_hex()) == 32


def test_every_f17_product_builds_a_blob():
    """Regression guard across the whole catalogue: no product may raise
    'offset outside the recipe blob' for a parameter its own XML
    declares."""
    built = 0
    for profile in iter_profiles():
        for product in profile.products:
            has_f17 = any(param.argument == 17 for param in product.params)
            if not has_f17:
                continue
            # Millilitre parameters with no XML default are refused by
            # design (they would brew dry); skip only those.
            if any(
                param.kind in ("water_amount", "bypass") and param.default is None
                for param in product.params
            ):
                continue
            blob = product.build_recipe_hex()
            assert len(blob) == 34, (profile.code, product.name, blob)
            built += 1
    # Six bundled profiles declare F17 products; make sure the sweep
    # actually exercised them rather than skipping everything.
    assert built > 0


def test_parse_xml_handles_default_namespace():
    """The Jura XMLs use a default namespace; the loader must strip it."""
    text = """<?xml version="1.0"?>
<JOE Version="2" Group="TEST" xmlns="http://www.top-tronic.com">
  <PRODUCTS>
    <PRODUCT Code="02" Name="Espresso"/>
  </PRODUCTS>
  <ALERTS>
    <ALERT Bit="0" Name="insert tray" Type="block"/>
    <ALERT Bit="10" Name="no beans" Type="info"/>
  </ALERTS>
</JOE>
"""
    p = _parse_xml(text, code="TEST", version="1.0")
    assert len(p.alerts) == 2
    assert p.alert_by_bit[0].severity == "error"
    assert p.alert_by_bit[10].severity == "info"
    assert p.product_by_code[0x02].name == "espresso"


def test_milk_amount_f5_parsed_and_encoded():
    """MILK_AMOUNT (F5 -> blob byte 4) — the milk *liquid* phase.

    Z10-class machines split milk into MILK_AMOUNT (F5) and
    MILK_FOAM_AMOUNT (F6). EF545 Milkcoffee: milk default 7 s,
    range 1..45 step 1."""
    p = load_profile("EF545")
    milkcoffee = p.product_by_code[0x05]
    milk = milkcoffee.param("milk_amount")
    assert milk is not None
    assert milk.offset == 4
    assert (milk.default, milk.minimum, milk.maximum, milk.step) == (7, 1, 45, 1)


def test_build_recipe_hex_z10_live_verified_milk_vector():
    """Live-verified on a Z10 (EA) / EF545: this exact blob was brewed and
    the physical pour matched — milk ran ~3 s (byte 4) and foam ~2 s
    (byte 5), water 90 ml, strength 8, temperature high."""
    p = load_profile("EF545")
    milkcoffee = p.product_by_code[0x05]
    blob = milkcoffee.build_recipe_hex(
        {
            "coffee_strength": 8,
            "water_amount": 90,
            "milk_amount": 3,
            "milk_foam_amount": 2,
            "temperature": "high",
        }
    )
    assert blob == "05000812030202000100000000000000"


def test_sub_indexed_arguments_are_skipped():
    """``Argument="F14_1"`` (MILK_FOAM_TEMP) must not become a parameter.

    Regression: int("14_1") == 141 (PEP 515 underscore separators), which
    used to yield offset 140 and made build_recipe_hex raise for every
    product carrying milk-temperature parameters — i.e. every Z10 milk
    drink. Sub-indexed arguments have unknown wire semantics and are
    skipped entirely."""
    p = load_profile("EF545")
    milkcoffee = p.product_by_code[0x05]
    assert milkcoffee.param("milk_foam_temp") is None
    assert milkcoffee.param("milk_temp") is None
    # And the defaults blob builds instead of raising.
    blob = milkcoffee.build_recipe_hex()
    assert blob == "05000512070301000100000000000000"
