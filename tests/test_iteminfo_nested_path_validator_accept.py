"""Iteminfo nested-path intents must pass validation cleanly.

Bug 2026-05-09 (helmysaini, niyaruza, cajae on Nexus): kliff_Wears
_Damiane_Armor_Update_1.05.01.json fails to import on v3.2.13 with:

    field 'prefab_data_list[0].tribe_gender_list' has no field_schema
    entry and isn't in the PABGB record schema. Author needs to add
    a field_schema/iteminfo.json entry mapping ...

Root cause: the v3.2.11 fix added an iteminfo nested-path early
return inside ``_diagnose_unsupported_intent`` so those paths are
not rejected as "nested writes not implemented". But the validator
in ``validate_intents`` only consults that helper to suppress the
nested-write rejection; it then continues to field_specs lookup
(via the candidate-name probe), which fails for nested paths
because flat field schemas don't contain dotted paths. Result:
the validator falls through to the "no field_schema entry" reject
path even though the apply-time writer's path-walker handles these
intents correctly.

Fix: mirror the buffinfo nested-path early-accept (line 636-638
of format3_handler.py) for iteminfo. After ``_diagnose_unsupported
_intent`` returns None for ``prefab_data_list[N].x`` /
``drop_default_data.x`` / ``gimmick_visual_prefab_data_list[N].x``
on iteminfo, the validator must also short-circuit-accept those
intents so they reach the apply-time path-walker.
"""
from __future__ import annotations

import pytest


def _make_intent(field: str):
    from cdumm.engine.format3_handler import Format3Intent
    return Format3Intent(
        entry="Marni_Devotee_PlateArmor_Helm",
        key=14510,
        field=field,
        op="set",
        new=[4184612308, 3215062603],
    )


def test_validate_accepts_prefab_data_list_nested_path():
    """The exact path that helmysaini's diagnostic flagged must
    validate cleanly so the writer can resolve it at apply time."""
    from cdumm.engine.format3_handler import validate_intents

    intent = _make_intent("prefab_data_list[0].tribe_gender_list")
    result = validate_intents("iteminfo.pabgb", [intent])

    assert intent in result.supported, (
        f"prefab_data_list[0].tribe_gender_list was rejected by "
        f"the validator. Skipped reasons: {result.skipped!r}. "
        f"Expected acceptance because the apply-time writer's "
        f"path-walker handles this layout."
    )
    assert intent not in [s[0] for s in result.skipped], (
        f"intent appeared in skipped list: "
        f"{[s for s in result.skipped if s[0] is intent]}"
    )


def test_validate_accepts_drop_default_data_nested_path():
    """floozo's cloak case: drop_default_data.x subfields."""
    from cdumm.engine.format3_handler import validate_intents

    intent = _make_intent("drop_default_data.add_socket_material_item_list")
    result = validate_intents("iteminfo.pabgb", [intent])

    assert intent in result.supported, (
        f"drop_default_data.add_socket_material_item_list was "
        f"rejected. Skipped reasons: {result.skipped!r}"
    )


def test_validate_accepts_gimmick_visual_prefab_data_list_nested_path():
    """Third whitelisted nested-path family for iteminfo."""
    from cdumm.engine.format3_handler import validate_intents

    intent = _make_intent("gimmick_visual_prefab_data_list[2].tribe_gender_list")
    result = validate_intents("iteminfo.pabgb", [intent])

    assert intent in result.supported, (
        f"gimmick_visual_prefab_data_list[N].x was rejected. "
        f"Skipped reasons: {result.skipped!r}"
    )


def test_validate_still_rejects_truly_unknown_iteminfo_nested_path():
    """Sanity: a nested path that ISN'T in the iteminfo whitelist
    (and isn't supported by the writer) must still be rejected so
    the user gets a clear message."""
    from cdumm.engine.format3_handler import validate_intents

    intent = _make_intent("totally_made_up_field.subfield")
    result = validate_intents("iteminfo.pabgb", [intent])

    # This path doesn't match prefab_data_list[ / drop_default_data.
    # / gimmick_visual_prefab_data_list[. The diagnose helper should
    # reject it as a "nested struct sub-field" not implemented case.
    assert intent not in result.supported, (
        "an unknown nested path must NOT be accepted; the validator's "
        "iteminfo nested-path whitelist must be path-prefix scoped"
    )
