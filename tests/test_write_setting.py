"""Validation tests for :meth:`JuraClient.write_setting` and the
name-based settings API (:meth:`get_setting` / :meth:`set_setting` /
:meth:`list_settings`).

The library used to accept any hex string and forward it to the dongle,
so a caller could mean ``auto_off=30min`` but pass the raw string
``"30"`` (= byte ``0x30`` = 48 dec) which is not in the AutoOFF
catalogue. The dongle would silently apply the bogus byte. We now
validate against the loaded :class:`MachineProfile` before sending.
"""

from __future__ import annotations

import pytest

from jura_connect.client import JuraClient, SettingValue
from jura_connect.profile import load_profile


def _paired(sim, *, with_profile: bool) -> JuraClient:
    host, port = sim.address
    profile = load_profile("EF1091") if with_profile else None
    c = JuraClient(host, port=port, conn_id="writer", auth_hash="", profile=profile)
    r = c.pair(timeout=2.0)
    assert r.state == "CORRECT"
    return c


def test_write_setting_rejects_raw_hex_not_in_catalogue(sim) -> None:
    """``auto_off`` value ``"30"`` means byte 0x30 (48 dec). Not in the
    EF1091 ItemSlider catalogue — write_setting must refuse before the
    request hits the wire."""
    c = _paired(sim, with_profile=True)
    try:
        with pytest.raises(ValueError, match="not a recognised value"):
            c.write_setting("13", "30")
    finally:
        c.close()


def test_write_setting_rejects_other_garbage(sim) -> None:
    c = _paired(sim, with_profile=True)
    try:
        with pytest.raises(ValueError, match="not a recognised value"):
            c.write_setting("13", "deadbeef")
    finally:
        c.close()


def test_write_setting_accepts_catalogue_hex(sim) -> None:
    """``"211E"`` is the wire-format hex for 30min — must pass."""
    c = _paired(sim, with_profile=True)
    try:
        reply = c.write_setting("13", "211E")
        assert reply.lower().startswith("@tm:13")
    finally:
        c.close()


def test_write_setting_accepts_item_name(sim) -> None:
    """Library callers can pass the friendly ITEM name too — saves the
    caller from looking up the hex."""
    c = _paired(sim, with_profile=True)
    try:
        reply = c.write_setting("13", "30min")
        assert reply.lower().startswith("@tm:13")
        # Round-trip: simulator stores what was actually written, so
        # this proves the ITEM name was resolved to the wire hex.
        stored = c.read_setting("13", timeout=2.0)
        assert stored.upper() == "211E"
    finally:
        c.close()


def test_write_setting_no_profile_skips_validation(sim) -> None:
    """Without a profile, anything goes — preserves the v0.9.x library
    contract for adventurous callers writing to raw P_Arguments."""
    c = _paired(sim, with_profile=False)
    try:
        # "30" is bogus, but with no profile we can't know — pass-through.
        reply = c.write_setting("13", "30", verify=False)
        assert reply.lower().startswith("@tm:13")
    finally:
        c.close()


def test_write_setting_rejects_step_slider_out_of_range(sim) -> None:
    """Hardness is a step_slider over 1..50; ``"99"`` parses as hex
    0x99 = 153 which is well outside the range."""
    c = _paired(sim, with_profile=True)
    try:
        with pytest.raises(ValueError, match="outside"):
            c.write_setting("02", "99")
    finally:
        c.close()


def test_write_setting_accepts_step_slider_in_range(sim) -> None:
    """write_setting's contract is hex-format: ``"0D"`` means byte
    0x0D = 13°dH, which is in the [1, 50] hardness range."""
    c = _paired(sim, with_profile=True)
    try:
        reply = c.write_setting("02", "0D")
        assert reply.lower().startswith("@tm:02")
        stored = c.read_setting("02", timeout=2.0)
        assert stored.upper() == "0D"
    finally:
        c.close()


# --------------------------------------------------------------------- #
# Name-based settings API: get_setting / set_setting / list_settings
# --------------------------------------------------------------------- #


def test_set_setting_by_item_name(sim) -> None:
    """``set_setting("auto_off", "30min")`` resolves the ITEM name to
    the wire-format hex via the profile and writes successfully."""
    c = _paired(sim, with_profile=True)
    try:
        reply = c.set_setting("auto_off", "30min")
        assert reply.lower().startswith("@tm:13")
        stored = c.read_setting("13", timeout=2.0)
        assert stored.upper() == "211E"
    finally:
        c.close()


def test_set_setting_by_hex(sim) -> None:
    c = _paired(sim, with_profile=True)
    try:
        reply = c.set_setting("auto_off", "220168")
        assert reply.lower().startswith("@tm:13")
        stored = c.read_setting("13", timeout=2.0)
        assert stored.upper() == "220168"
    finally:
        c.close()


def test_set_setting_rejects_unknown_name(sim) -> None:
    c = _paired(sim, with_profile=True)
    try:
        with pytest.raises(ValueError, match="not in the EF1091 catalogue"):
            c.set_setting("frobnicate", "on")
    finally:
        c.close()


def test_set_setting_rejects_invalid_value(sim) -> None:
    c = _paired(sim, with_profile=True)
    try:
        with pytest.raises(ValueError, match="not a recognised value"):
            c.set_setting("auto_off", "30")
    finally:
        c.close()


def test_set_setting_without_profile_raises(sim) -> None:
    c = _paired(sim, with_profile=False)
    try:
        with pytest.raises(RuntimeError, match="no MachineProfile"):
            c.set_setting("auto_off", "30min")
    finally:
        c.close()


def test_get_setting_resolves_item_name(sim) -> None:
    """After writing 30min, get_setting resolves the dongle's stored
    ``1E`` back to the ``30min`` ITEM via the AutoOFF length-tag
    suffix-match fallback in SettingDef.item_from_hex."""
    sim.config.settings["13"] = "1E"  # dongle's stored form for 30min
    c = _paired(sim, with_profile=True)
    try:
        result = c.get_setting("auto_off")
    finally:
        c.close()
    assert isinstance(result, SettingValue)
    assert result.name == "auto_off"
    assert result.raw == "1E"
    assert result.item == "30min"
    assert result.definition.p_argument == "13"
    assert "30min" in str(result)


def test_get_setting_unknown_value(sim) -> None:
    sim.config.settings["13"] = "AA"  # nothing in the catalogue ends in AA
    c = _paired(sim, with_profile=True)
    try:
        result = c.get_setting("auto_off")
    finally:
        c.close()
    assert result.raw == "AA"
    assert result.item is None
    assert "0x" in str(result)


def test_list_settings_returns_catalogue(sim) -> None:
    c = _paired(sim, with_profile=True)
    try:
        settings = c.list_settings()
    finally:
        c.close()
    names = {s.name for s in settings}
    assert {"auto_off", "hardness", "language"} <= names


def test_list_settings_without_profile_raises(sim) -> None:
    c = _paired(sim, with_profile=False)
    try:
        with pytest.raises(RuntimeError, match="no MachineProfile"):
            c.list_settings()
    finally:
        c.close()
