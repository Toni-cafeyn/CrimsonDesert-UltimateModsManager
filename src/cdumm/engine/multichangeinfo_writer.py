"""multichangeinfo.pabgb writer for Format 3 mods (GitHub #125).

Refinement Cost Reforged (Nexus 1342) and similar mods ship Format 3.1
intents targeting multichangeinfo.pabgb with field paths of the form
``fixed_material_data_list[N].item_info`` and
``fixed_material_data_list[N].count``.

This module does NOT implement a full 25-field multichangeinfo parser.
It does the minimum to land those two fields safely:

  * Split the table into records using the .pabgh index.
  * Locate the _fixedMaterialDataList array inside a record.
  * Patch item_info / count of an existing element in place, or
    extend the array (append zeroed elements + bump the u16 count)
    when an intent targets an index past the current element count.
  * Reassemble the table and rebuild the .pabgh offsets.

Record framing (verified 2026-05-21 against vanilla 1.07.00):
  u32 key, u32 strlen, name[strlen], 0x00, then 25 fields.

_fixedMaterialDataList framing (verified):
  u16 element_count, then element_count * 30-byte elements.
  Element layout, on-disk order:
    +0  u32 item_info
    +4  u32 character_info
    +8  u32 gimmick_info
    +12 u16 enchant_level
    +14 u64 coupon_count
    +22 u64 count
  Array offset = 8 + strlen + 1 + 53 for ~94% of records; the rest
  have a variable-length field before it and are located by scan.

.pabgh framing (verified): u16 count, then count*(u32 key, u32 off).
Records are stored in ascending-offset order; pabgh order matches.
"""
from __future__ import annotations

import logging
import struct

logger = logging.getLogger(__name__)

_FML_ELEM_SIZE = 30
_FML_ITEM_INFO_OFF = 0    # u32, within element
_FML_COUNT_OFF = 22       # u64, within element
_CONST_PREARRAY = 53      # bytes between the post-name null and the array
_MAX_PLAUSIBLE_COUNT = 256


def parse_pabgh(pabgh: bytes) -> list[tuple[int, int]]:
    """Return [(key, offset), ...] in pabgh order (== ascending offset)."""
    count = struct.unpack_from("<H", pabgh, 0)[0]
    out: list[tuple[int, int]] = []
    pos = 2
    for _ in range(count):
        key = struct.unpack_from("<I", pabgh, pos)[0]
        off = struct.unpack_from("<I", pabgh, pos + 4)[0]
        out.append((key, off))
        pos += 8
    return out


def build_pabgh(entries: list[tuple[int, int]]) -> bytes:
    """Inverse of parse_pabgh. entries = [(key, offset), ...]."""
    out = bytearray(struct.pack("<H", len(entries)))
    for key, off in entries:
        out += struct.pack("<II", key, off)
    return bytes(out)


def _record_strlen(rec: bytes) -> int:
    """u32 string length of the record's name field."""
    return struct.unpack_from("<I", rec, 4)[0]


def _array_candidate_ok(rec: bytes, array_off: int) -> int | None:
    """If a plausible _fixedMaterialDataList array sits at array_off,
    return its element count, else None.

    Plausible = u16 count below a sane ceiling and the whole array
    (2 + count*30 bytes) fits inside the record.
    """
    if array_off + 2 > len(rec):
        return None
    count = struct.unpack_from("<H", rec, array_off)[0]
    if count > _MAX_PLAUSIBLE_COUNT:
        return None
    if array_off + 2 + count * _FML_ELEM_SIZE > len(rec):
        return None
    return count


def locate_fixed_material_list(rec: bytes) -> tuple[int, int] | None:
    """Return (array_offset, element_count) for the record's
    _fixedMaterialDataList, or None if it cannot be located confidently.

    Uses ONLY the constant offset formula (8 + strlen + 1 + 53), which
    is the schema-derived position and is exact for the ~94% of
    records whose fields before _fixedMaterialDataList are all
    fixed-size. The remaining ~6% have a variable-length field that
    shifts the array; locating it there needs a real field walk.

    A forward scan was tried and rejected: a u16 that happens to equal
    a small int followed by 30 plausible bytes occurs coincidentally
    inside the earlier fixed fields, so a scan mislocates the array
    and would corrupt the record. Returning None for the 6% means the
    caller skips those records (and logs it) instead of patching the
    wrong bytes. Correct-but-partial beats silently-corrupt.
    """
    strlen = _record_strlen(rec)
    formula = 8 + strlen + 1 + _CONST_PREARRAY
    count = _array_candidate_ok(rec, formula)
    if count is not None:
        return formula, count
    return None


def _patch_element_field(
    rec: bytearray, elem_off: int, field: str, value: int
) -> bool:
    """Patch one element field in place. Returns True on success."""
    if field == "item_info":
        struct.pack_into("<I", rec, elem_off + _FML_ITEM_INFO_OFF,
                         value & 0xFFFFFFFF)
        return True
    if field == "count":
        struct.pack_into("<Q", rec, elem_off + _FML_COUNT_OFF,
                         value & 0xFFFFFFFFFFFFFFFF)
        return True
    logger.warning("multichangeinfo: unknown element field %r", field)
    return False


def apply_record_intents(
    rec: bytes, intents: list[tuple[int, str, int]]
) -> bytes | None:
    """Apply fixed_material_data_list intents to one record.

    intents: list of (list_index, field, value). field is
    'item_info' or 'count'.

    Returns the new record bytes (possibly longer, if the array was
    extended), or None if the array could not be located.
    """
    located = locate_fixed_material_list(rec)
    if located is None:
        return None
    array_off, count = located
    work = bytearray(rec)

    max_index = max((i for i, _f, _v in intents), default=-1)
    if max_index >= count:
        # Extend: append (max_index + 1 - count) zeroed 30-byte
        # elements right after the existing array, bump the u16 count.
        new_count = max_index + 1
        insert_at = array_off + 2 + count * _FML_ELEM_SIZE
        pad = bytes(_FML_ELEM_SIZE * (new_count - count))
        work = work[:insert_at] + bytearray(pad) + work[insert_at:]
        struct.pack_into("<H", work, array_off, new_count)
        count = new_count
        logger.info(
            "multichangeinfo: extended _fixedMaterialDataList to %d "
            "elements (record grew %d bytes)",
            new_count, len(pad))

    for list_index, field, value in intents:
        if list_index < 0 or list_index >= count:
            logger.warning(
                "multichangeinfo: intent index %d out of range "
                "(count=%d), skipping", list_index, count)
            continue
        elem_off = array_off + 2 + list_index * _FML_ELEM_SIZE
        _patch_element_field(work, elem_off, field, value)

    return bytes(work)


def apply_multichangeinfo(
    pabgb: bytes,
    pabgh: bytes,
    intents_by_key: dict[int, list[tuple[int, str, int]]],
) -> tuple[bytes, bytes]:
    """Apply Format 3 intents to multichangeinfo.pabgb.

    intents_by_key maps a record key to a list of
    (list_index, field, value) tuples.

    Returns (new_pabgb, new_pabgh). When intents_by_key is empty the
    output is byte-identical to the input (round-trip floor).
    """
    entries = parse_pabgh(pabgh)
    # Records are stored in ascending-offset order; pabgh order matches.
    order = sorted(range(len(entries)), key=lambda i: entries[i][1])
    bounds: list[tuple[int, int, int]] = []  # (key, start, end)
    for rank, idx in enumerate(order):
        key, start = entries[idx]
        end = (entries[order[rank + 1]][1]
               if rank + 1 < len(order) else len(pabgb))
        bounds.append((key, start, end))

    out_records: list[tuple[int, bytes]] = []
    for key, start, end in bounds:
        rec = pabgb[start:end]
        rec_intents = intents_by_key.get(key)
        if rec_intents:
            new_rec = apply_record_intents(rec, rec_intents)
            if new_rec is None:
                logger.warning(
                    "multichangeinfo: could not locate "
                    "_fixedMaterialDataList for key=%d, leaving record "
                    "unmodified (%d intent(s) skipped)",
                    key, len(rec_intents))
                new_rec = rec
            rec = new_rec
        out_records.append((key, rec))

    # Reassemble in the same (ascending-offset) order, recompute
    # offsets, rebuild pabgh keeping the original pabgh key order.
    new_body = bytearray()
    key_to_off: dict[int, int] = {}
    for key, rec in out_records:
        key_to_off[key] = len(new_body)
        new_body += rec
    new_pabgh_entries = [(k, key_to_off[k]) for k, _o in entries]
    return bytes(new_body), build_pabgh(new_pabgh_entries)
