# buffinfo.pabgb reverse-engineering notes

Working notes for the multi-session task of building a Phase 3+
buffinfo body decoder so NattKh-dialect Format 3 mods (e.g. Adfaz
Double Resource Buff, Nexus 2276) that target
``buff_data_list[i].data.base.{...}`` can apply.

## Verified so far (Phases 1 + 2, shipped)

```
[0..3]            entry_key                 (u32 LE)
[4..7]            slen                      (u32 LE)
[8..7+slen]       name                      (UTF-8)
[prefix_end]      _isBlocked tag/value      (1 byte; always 0 in v1.05)
[prefix_end+1..]  _buffDataList count       (u32; 1..200 observed)
[body_start..]    _buffDataList items       (NOT decoded yet)
```

Source: 280 entries from CD v1.05 vanilla buffinfo.pabgb (extracted
via pycrimson's BinaryGameBlob + the matching .pabgh header).

## Unverified (next session)

The bytes from ``body_start`` onward look like a sequence of
tagged-primitive blocks. From inspection of single-item
(``_buffDataList`` count = 1) entries, the apparent shape is:

```
body_start +0..+14   (15 bytes)   _isBlocked-like field:
                                   (u32, byte, u32, byte, u32, byte)
                                   where the u32s vary across entries
                                   and the bytes are always 0x00.
                                   Engine schema lists this as
                                   direct_15B which matches.

body_start +15..+18  (4 bytes)    _maxLevel  (u32 LE)
body_start +19..+22  (4 bytes)    _minLevel  (u32 LE)

body_start +23..+37  (15 bytes)   _buffLevelCalculateType
                                   direct_15B, same shape as
                                   _isBlocked

body_start +38?..    ??           Cross-check failed: in the
                                   BuffLevel_Comma_Symptom oracle,
                                   the next field's u32 length
                                   prefix lands at offset 75 within
                                   the entry (body_start + 39, NOT
                                   +38). One byte off vs the schema
                                   sum of 15+4+4+15 = 38. Could be:
                                   * A trailing 0x00 separator byte
                                     after _buffLevelCalculateType
                                   * Or _isBlocked is actually 16
                                     bytes not 15
                                   * Or there's a hidden field
                                     between _buffLevelCalculateType
                                     and _sequencerFileName that the
                                     engine schema doesn't list.

                                   Need an oracle (run NattKh's tool
                                   on a known input, observe which
                                   bytes change) to disambiguate.
```

## Open question: are buff_data items here at all?

Hypothesis A: buff_data items begin AT ``body_start``, with what
I'm reading as ``_isBlocked / _maxLevel / _minLevel`` actually being
the FIRST item's per-item fields (e.g. ``absent_flag`` /
``some_count`` / ``level_id``).

Hypothesis B: buff_data items begin AFTER the
``_isBlocked..._sequencerFileName`` fields, somewhere in the 100+
remaining bytes.

The path ``buff_data_list[0].data.base.absent_flag`` from Adfaz's
mod targets ``absent_flag`` of the first item. Once we can produce
a parser that emits the offset of a known field for a known entry,
running Adfaz's mod through CDUMM's apply path with verbose logging
on a SINGLE intent should let us reverse the offset.

## Tooling already in place

* ``BuffinfoEntryHeader`` returns offsets for ``is_blocked_offset``,
  ``buff_data_count_offset``, and ``body_start``. Future fields
  should also expose ``_offset`` annotations the same way NattKh's
  ``characterinfo_full_parser.py`` does.

* ``locate_buff_field(entry_bytes, field_path)`` is the eventual
  public API. Currently returns ``None`` for everything. Each new
  field decoded should add a branch returning
  ``(offset, width, dtype)``.

## How to resume

```bash
# 1. Extract a fresh copy of vanilla buffinfo.pabgb
py -3 -c "
import sys; sys.path.insert(0, 'src')
from pathlib import Path
from cdumm.engine.json_patch_handler import (
    _find_pamt_entry, _extract_from_paz)
vanilla = Path(r'E:/SteamLibrary/steamapps/common/Crimson Desert/CDMods/vanilla')
entry = _find_pamt_entry('buffinfo.pabgb', vanilla)
Path(r'C:/temp/buffinfo.pabgb').write_bytes(_extract_from_paz(entry))
"

# 2. Inspect single-item entries with known semantics
py -3 -c "
from pycrimson._files import BinaryGameBlob
from cdumm._vendor.buffinfo_parser import parse_entry_prefix
from pathlib import Path
b = BinaryGameBlob.from_file(Path(r'C:/temp/buffinfo.pabgb'))
for off, payload in list(b.entries.items())[:5]:
    h = parse_entry_prefix(payload)
    print(h)
    print(payload[h.body_start:h.body_start+80].hex())
"

# 3. Run Adfaz's mod on a controlled scratch buffinfo with verbose
#    logging so you can observe which exact bytes change , gives
#    you the field-to-offset mapping for free without speculation.
```
