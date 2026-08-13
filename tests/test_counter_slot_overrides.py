"""@TR:32 slot overrides — a product counted away from its own code."""

from jura_connect.client import ProductCounters
from jura_connect.profile import load_profile
from jura_connect.simulator import _default_product_counters

# 64-slot @TR:32 table read off a real Z10 (NAA, article 15361, EF545)
# and cross-checked against the J.O.E. statistics CSV export for the same
# machine (issue #9). Every slot not listed reads 0xFFFF.
Z10_TABLE = {
    0: 5945, 2: 610, 3: 8, 4: 1, 5: 2957, 6: 0, 7: 6, 8: 116, 10: 24,
    12: 0, 13: 1192, 15: 554, 18: 0, 19: 141, 40: 0, 41: 2, 43: 0,
    45: 192, 46: 1, 48: 0, 56: 0, 57: 0,
}  # fmt: skip


def _z10_slots() -> list[int]:
    return [Z10_TABLE.get(i, 0xFFFF) for i in range(64)]


def test_z10_counts_its_doubles_one_nibble_above_the_single():
    """EF545 counts "2 Coffee" (code 0x36) at slot 0x13, and 0x36 itself
    reads 0xFFFF. The J.O.E. CSV for this machine lists "2 x Coffee,141".
    """
    counters = ProductCounters.from_slots(_z10_slots(), profile=load_profile("EF545"))

    assert counters.by_name["2_coffee"] == 141
    assert counters.by_name["2_espressi"] == 0
    # The catalogue's own codes for those doubles carry nothing.
    assert "31" not in counters.by_code
    assert "36" not in counters.by_code
    # Every product the machine's CSV lists is now named, and no slot is
    # left over unnamed.
    assert len(counters.by_name) == 21
    assert set(counters.by_code) == {f"{c:02X}" for c in Z10_TABLE if c}
    # The machine bills a double as two products, so the residual between
    # the reported total and the per-slot sum is exactly the 141 doubles.
    assert counters.total - sum(counters.by_name.values()) == 141


def test_barista_pair_is_not_remapped_on_the_z10():
    """Only 0x31/0x36 move; 0x38/0x39 are counted at their own codes."""
    counters = ProductCounters.from_slots(_z10_slots(), profile=load_profile("EF545"))
    assert counters.by_name["2_cafe_barista"] == 0
    assert counters.by_name["2_barista_lungo"] == 0


def test_s8_eb_is_untouched_by_the_override_table():
    """EF1091/EF1151 count every product at its own code — 0x31 and 0x36
    hold the double counts, and slots 0x12/0x13 are unused. Decoding must
    be identical to the no-override behaviour.
    """
    slots = _default_product_counters()  # real S8 EB table
    for ef in ("EF1091", "EF1151"):
        counters = ProductCounters.from_slots(list(slots), profile=load_profile(ef))
        assert counters.by_name["2_espressi"] == 1
        assert counters.by_name["2_coffee"] == 10
        assert counters.by_code["31"] == 1
        assert counters.by_code["36"] == 10
        assert "12" not in counters.by_code
        assert "13" not in counters.by_code
        # Nothing invented: every name comes from the machine's catalogue.
        catalogue = {p.name for p in load_profile(ef).product_by_code.values()}
        assert set(counters.by_name) <= catalogue


def test_override_falls_back_when_the_target_slot_is_unused():
    """A firmware that counts EF545's doubles at their own codes must not
    lose them to an override pointing at an empty slot.
    """
    slots = [0xFFFF] * 64
    slots[0] = 50
    slots[0x02] = 30
    slots[0x31] = 7  # counted at the catalogue code, not at 0x12
    counters = ProductCounters.from_slots(slots, profile=load_profile("EF545"))
    assert counters.by_name["2_espressi"] == 7
