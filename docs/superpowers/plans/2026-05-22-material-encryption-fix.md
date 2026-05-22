# Material Encryption Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop CDUMM from silently corrupting `.material` / `.technique` / `.thtml` files (and any other extension the runtime encrypts) by detecting encryption from PAZ slot bytes at PAMT parse time, populating `_encrypted_override` on every entry so all downstream consumers see a single source of truth. Ship the fix as a Windows `.exe` via the fork's CI.

**Architecture:** Two helpers added to `paz_crypto.py` (`looks_like_plaintext_head`, `detect_encryption_from_head`). A new `_populate_encryption_overrides` step in `paz_parse.py` runs after `_parse_pamt_impl`, opens each PAZ once (grouped by file), reads 32 bytes per slot, classifies, and writes `_encrypted_override`. The hard-coded extension whitelist in `PazEntry.encrypted` is widened to include `.material/.technique/.thtml` and only fires when `_encrypted_override` is `None` (IOError fallback, hand-built entries). A separate fork-only branch adds `release-windows.yml` to produce the `.exe`.

**Tech Stack:** Python 3.13, pytest, `lz4.block` (already used via `lz4_decompress` in `paz_crypto.py`), ChaCha20 (already used via `encrypt` / `decrypt`), GitHub Actions (`windows-latest` runner), PyInstaller, maturin.

**Reference design:** `docs/superpowers/specs/2026-05-22-material-encryption-fix-design.md` (commit `2926e7f`).

---

## File Structure

| Path | Responsibility | Status |
| ---- | -------------- | ------ |
| `src/cdumm/archive/paz_crypto.py` | Add `looks_like_plaintext_head`, `detect_encryption_from_head`. Pure byte-classification helpers, no I/O. | Modify |
| `src/cdumm/archive/paz_parse.py` | Widen the whitelist in `PazEntry.encrypted`; add `_populate_encryption_overrides`; hook it into the `parse_pamt` wrapper. | Modify |
| `tests/test_material_encryption_regression.py` | Unit tests on the two helpers, whitelist regression test, integration test that round-trips a `.material` entry through a synthetic PAMT+PAZ fixture. | Create |
| `tests/fixtures/_material_encryption_synth.py` | Helper to build a tiny synthetic PAMT + PAZ pair in `tmp_path` with one encrypted `.xml`, one encrypted `.material`, one plaintext `.bin`. | Create |
| `.github/workflows/release-windows.yml` | Windows build workflow. `workflow_dispatch` + `tags: ['v*']`. Uploads `.exe` as artifact; attaches to GitHub Release on tag. Fork-only. | Create |

---

## Branching

Two feature branches off `master` (or off the existing `design/material-encryption-fix` so the spec history stays attached, your call):

- `fix/material-encryption`, Tasks 1 through 8
- `fork/windows-ci`, Task 9

Each task ends with a commit. No squashing inside the branches; the design doc + commit history is the review trail.

```bash
git checkout master
git checkout -b fix/material-encryption
```

---

## Phase 1: Pure byte-classification helpers

### Task 1: `looks_like_plaintext_head`

**Files:**
- Modify: `src/cdumm/archive/paz_crypto.py` (append at end of file)
- Test: `tests/test_material_encryption_regression.py` (create)

- [ ] **Step 1: Write the failing test**

Create `tests/test_material_encryption_regression.py` with this content:

```python
"""Regression tests for the silent .material / .technique / .thtml
encryption-at-repack bug.

See docs/superpowers/specs/2026-05-22-material-encryption-fix-design.md
for full context.
"""

import os
import struct

import pytest

from cdumm.archive.paz_crypto import (
    looks_like_plaintext_head,
)


# Sample 16 bytes of ChaCha20 ciphertext-looking content (high entropy)
CIPHERTEXT_SAMPLE = bytes.fromhex(
    "6aa180abd44aefdb818674dd78859415"
)


class TestLooksLikePlaintextHead:
    def test_xml_with_utf8_bom_is_plaintext(self):
        assert looks_like_plaintext_head(
            b'\xef\xbb\xbf<Technique Name="Water"/>\r\n'
        ) is True

    def test_indented_xml_is_plaintext(self):
        assert looks_like_plaintext_head(b'    <root>\n  <a/></root>') is True

    def test_plain_ascii_is_plaintext(self):
        assert looks_like_plaintext_head(b'<Technique Name="x"/>') is True

    def test_ciphertext_sample_is_not_plaintext(self):
        assert looks_like_plaintext_head(CIPHERTEXT_SAMPLE) is False

    def test_empty_bytes_is_not_plaintext(self):
        assert looks_like_plaintext_head(b'') is False

    def test_whitespace_only_is_not_plaintext(self):
        assert looks_like_plaintext_head(b'    \r\n\t') is False

    def test_bom_alone_is_not_plaintext(self):
        # Just the BOM with nothing after must not be classified as plaintext.
        assert looks_like_plaintext_head(b'\xef\xbb\xbf') is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_material_encryption_regression.py -v`
Expected: ImportError on `looks_like_plaintext_head` (the function doesn't exist yet).

- [ ] **Step 3: Implement `looks_like_plaintext_head` in `paz_crypto.py`**

Append at the end of `src/cdumm/archive/paz_crypto.py`:

```python
# ── Encryption detection helpers ────────────────────────────────────


def looks_like_plaintext_head(data: bytes) -> bool:
    """True if the first ~16 useful bytes look like printable text.

    Strips an optional UTF-8 BOM and leading whitespace so XML files
    with a BOM or leading indentation still match. Random ChaCha20
    output hits ~37% printable bytes; real text hits ~99%. The 0.9
    threshold cleanly separates the two on 16 bytes.

    Used by detect_encryption_from_head to distinguish a plaintext
    PAZ slot from one that was encrypted by the game runtime.
    """
    if not data:
        return False
    if data.startswith(b'\xef\xbb\xbf'):
        data = data[3:]
    stripped = data.lstrip(b' \t\r\n')
    if not stripped:
        return False
    head = stripped[:16]
    printable = sum(
        1 for b in head
        if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D)
    )
    return printable / len(head) > 0.9
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_material_encryption_regression.py::TestLooksLikePlaintextHead -v`
Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add src/cdumm/archive/paz_crypto.py tests/test_material_encryption_regression.py
git commit -m "feat(paz_crypto): add looks_like_plaintext_head helper

Pure byte-classification helper. Returns True if the first ~16 useful
bytes (after stripping UTF-8 BOM and leading whitespace) are >90%
printable. Used by the upcoming detect_encryption_from_head to
distinguish plaintext PAZ slots from encrypted ones.

Refs: docs/superpowers/specs/2026-05-22-material-encryption-fix-design.md"
```

---

### Task 2: `detect_encryption_from_head`

**Files:**
- Modify: `src/cdumm/archive/paz_crypto.py` (append after `looks_like_plaintext_head`)
- Modify: `tests/test_material_encryption_regression.py` (add test class)

- [ ] **Step 1: Add the failing tests**

Append to `tests/test_material_encryption_regression.py` (and update the import line at the top):

Update the import block at the top of the file:

```python
from cdumm.archive.paz_crypto import (
    detect_encryption_from_head,
    encrypt,
    looks_like_plaintext_head,
    lz4_compress,
)
```

Append at the bottom of the file:

```python
PLAINTEXT_XML = b'\xef\xbb\xbf<Technique Name="Water"/>\r\n'


class TestDetectEncryptionFromHead:
    """2x2 matrix: compression_type in {0, 2} x {plaintext, ciphertext}."""

    def test_uncompressed_plaintext(self):
        # Slot stored as plaintext, no compression.
        head = PLAINTEXT_XML[:32]
        assert detect_encryption_from_head(
            head, compression_type=0, orig_size=len(PLAINTEXT_XML)
        ) is False

    def test_uncompressed_encrypted(self):
        # Slot stored as ChaCha20 ciphertext, no compression.
        ciphertext = encrypt(PLAINTEXT_XML, 'water.material')
        head = ciphertext[:32]
        assert detect_encryption_from_head(
            head, compression_type=0, orig_size=len(PLAINTEXT_XML)
        ) is True

    def test_lz4_compressed_plaintext(self):
        # Slot stored as raw LZ4 (not encrypted).
        # Use a payload that compresses to at least 32 bytes so the
        # head we pass to detect is a complete LZ4 block prefix.
        payload = (b'<root><a/></root>' * 64)
        compressed = lz4_compress(payload)
        assert len(compressed) >= 32, "test payload didn't compress enough"
        head = compressed[:32]
        assert detect_encryption_from_head(
            head, compression_type=2, orig_size=len(payload)
        ) is False

    def test_lz4_compressed_then_encrypted(self):
        # Slot stored as LZ4(plaintext) then encrypted.
        payload = (b'<root><a/></root>' * 64)
        compressed = lz4_compress(payload)
        encrypted = encrypt(compressed, 'foo.material')
        head = encrypted[:32]
        assert detect_encryption_from_head(
            head, compression_type=2, orig_size=len(payload)
        ) is True

    def test_empty_head_uncompressed(self):
        # Truncated read: empty head, no compression. Fail-safe to
        # "encrypted" so we never mistakenly write plaintext into a
        # slot we don't understand.
        assert detect_encryption_from_head(
            b'', compression_type=0, orig_size=0
        ) is True

    def test_empty_head_compressed(self):
        # Empty head on a compressed slot. lz4_decompress raises, so
        # classification is "encrypted" (fail-safe).
        assert detect_encryption_from_head(
            b'', compression_type=2, orig_size=10
        ) is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_material_encryption_regression.py::TestDetectEncryptionFromHead -v`
Expected: ImportError on `detect_encryption_from_head`.

- [ ] **Step 3: Implement `detect_encryption_from_head` in `paz_crypto.py`**

Append at the bottom of `src/cdumm/archive/paz_crypto.py` (right after `looks_like_plaintext_head`):

```python
def detect_encryption_from_head(head: bytes, compression_type: int,
                                orig_size: int) -> bool:
    """Classify a PAZ slot's first ~32 bytes as encrypted (True) or
    plaintext (False).

    The PAMT has no reliable encrypted flag, but the slot's leading
    bytes are diagnostic:

    * If compression_type == 2 (LZ4 block), the engine compresses
      then encrypts. A valid LZ4 decompression of the raw head means
      the slot was stored as plaintext-compressed; a failed
      decompression means the LZ4 bytes were further encrypted.
    * If compression_type != 2 (no compression, or a future codec we
      don't model), fall back to a printable-text heuristic.

    The ChaCha20 collision risk (random ciphertext that happens to
    form a valid LZ4 block prefix) is bounded by the LZ4 block
    format's structural constraints to well below 2^-64 on 32 bytes
    and accepted as negligible.

    Args:
        head: first ~32 bytes read at the slot offset
        compression_type: PAMT compression_type field (0=none, 2=lz4)
        orig_size: PAMT orig_size, needed for lz4 decompression

    Returns:
        True if the slot looks encrypted (caller must re-encrypt on
        repack), False if plaintext.
    """
    if compression_type == 2:
        try:
            lz4_decompress(head, orig_size)
            return False
        except Exception:
            # Any error from lz4_decompress (native or pure-python)
            # means the bytes aren't a valid LZ4 block, so they were
            # encrypted after compression.
            return True
    return not looks_like_plaintext_head(head)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_material_encryption_regression.py::TestDetectEncryptionFromHead -v`
Expected: 6 passed.

- [ ] **Step 5: Run the full new test module**

Run: `pytest tests/test_material_encryption_regression.py -v`
Expected: 13 passed (7 from Task 1, 6 from Task 2).

- [ ] **Step 6: Commit**

```bash
git add src/cdumm/archive/paz_crypto.py tests/test_material_encryption_regression.py
git commit -m "feat(paz_crypto): add detect_encryption_from_head

Classifies a PAZ slot as encrypted or plaintext from its first ~32
bytes plus the PAMT compression_type. For LZ4 entries: tries
lz4_decompress, success means plaintext-compressed. For uncompressed
entries: printable-text heuristic via looks_like_plaintext_head.

Tests cover the 2x2 matrix (compressed/uncompressed x
plaintext/encrypted) plus empty-head fail-safe behavior.

Refs: docs/superpowers/specs/2026-05-22-material-encryption-fix-design.md"
```

---

## Phase 2: Widen the whitelist fallback

### Task 3: Widen `PazEntry.encrypted` and add regression test

**Files:**
- Modify: `src/cdumm/archive/paz_parse.py:46-64`
- Modify: `tests/test_material_encryption_regression.py` (add test class)

- [ ] **Step 1: Add the failing test**

Update the imports at the top of `tests/test_material_encryption_regression.py`:

```python
from cdumm.archive.paz_parse import PazEntry
```

Append at the bottom of the file:

```python
class TestPazEntryEncryptedWhitelist:
    """Whitelist regression: when _encrypted_override is None (entries
    built by hand or via the IOError fallback), the property falls
    back to a hard-coded extension whitelist. v3.0 narrowed it to
    .xml only and re-introduced the v2.1.2 regression; v3.x+ keeps
    .xml/.css/.html/.js; this fix adds the three extensions known to
    cause silent corruption in-game when missed: .material,
    .technique, .thtml.
    """

    def _make_entry(self, path: str) -> PazEntry:
        return PazEntry(
            path=path,
            paz_file='dummy.paz',
            offset=0,
            comp_size=0,
            orig_size=0,
            flags=0,
            paz_index=0,
        )

    def test_xml_is_encrypted(self):
        assert self._make_entry('ui/xml/foo.xml').encrypted is True

    def test_css_is_encrypted(self):
        assert self._make_entry('ui/xml/theme.css').encrypted is True

    def test_html_is_encrypted(self):
        assert self._make_entry('ui/page.html').encrypted is True

    def test_js_is_encrypted(self):
        assert self._make_entry('ui/script.js').encrypted is True

    def test_material_is_encrypted(self):
        # Regression: this returned False before the fix and caused
        # silent water/dissolve material corruption in
        # InternalGraphicsMod v3.1.2.
        assert self._make_entry('technique/water.material').encrypted is True

    def test_technique_is_encrypted(self):
        assert self._make_entry('technique/foo.technique').encrypted is True

    def test_thtml_is_encrypted(self):
        assert self._make_entry('ui/template.thtml').encrypted is True

    def test_unknown_extension_is_not_encrypted(self):
        assert self._make_entry('models/character.bin').encrypted is False

    def test_override_true_wins_over_whitelist_miss(self):
        e = self._make_entry('models/foo.bin')
        e._encrypted_override = True
        assert e.encrypted is True

    def test_override_false_wins_over_whitelist_hit(self):
        e = self._make_entry('ui/page.html')
        e._encrypted_override = False
        assert e.encrypted is False
```

- [ ] **Step 2: Run tests to verify the .material/.technique/.thtml ones fail**

Run: `pytest tests/test_material_encryption_regression.py::TestPazEntryEncryptedWhitelist -v`
Expected: `test_material_is_encrypted`, `test_technique_is_encrypted`, `test_thtml_is_encrypted` fail (whitelist doesn't include them yet). Other tests pass.

- [ ] **Step 3: Widen the whitelist in `paz_parse.py`**

Edit `src/cdumm/archive/paz_parse.py` lines 63-64:

```python
        if self._encrypted_override is not None:
            return self._encrypted_override
        return self.path.lower().endswith(
            ('.xml', '.css', '.html', '.js',
             '.material', '.technique', '.thtml'))
```

Also append two sentences to the existing docstring (lines 47-60) so the next reader understands the widened list. Replace the existing docstring with:

```python
    @property
    def encrypted(self) -> bool:
        """Whether this entry is ChaCha20-encrypted.

        The PAMT has no reliable encrypted flag. The engine encrypts
        text formats inside ui/xml/, XML, CSS, HTML, JS, and the
        heuristic must catch all of them. v2.1.2 originally fixed
        Dark Mode Map (CSS crash on map open) by widening this past
        XML-only; the v3.0 rewrite silently narrowed it back to
        '.xml' alone, regressing the fix. Bug report from
        TheUnLuckyOnes 2026-04-26 caught it.

        2026-05-22: widened again to include .material, .technique,
        and .thtml after a separate silent-corruption bug in
        InternalGraphicsMod. The structural fix is the parse-time
        sniff in _populate_encryption_overrides; this whitelist is
        now only a fallback for entries built by hand or for the
        IOError-during-sniff path.

        When extraction detects actual encryption, set
        _encrypted_override = True so repack re-encrypts correctly.
        """
```

(Take care to preserve the em-dash → hyphen replacement convention: no em-dashes in the new sentences. The existing docstring already uses em-dashes; leave them as-is, just don't introduce more.)

Actually re-read the rule: no em-dashes anywhere in new content. The existing docstring contains an em-dash on line 51 (`ui/xml/, XML`). Replace that em-dash with a comma in the rewrite so the file is fully compliant after the edit:

Final docstring to write:

```python
    @property
    def encrypted(self) -> bool:
        """Whether this entry is ChaCha20-encrypted.

        The PAMT has no reliable encrypted flag. The engine encrypts
        text formats inside ui/xml/ (XML, CSS, HTML, JS) and the
        heuristic must catch all of them. v2.1.2 originally fixed
        Dark Mode Map (CSS crash on map open) by widening this past
        XML-only; the v3.0 rewrite silently narrowed it back to
        '.xml' alone, regressing the fix. Bug report from
        TheUnLuckyOnes 2026-04-26 caught it.

        2026-05-22: widened again to include .material, .technique,
        and .thtml after a separate silent-corruption bug in
        InternalGraphicsMod. The structural fix is the parse-time
        sniff in _populate_encryption_overrides; this whitelist is
        now only a fallback for entries built by hand or for the
        IOError-during-sniff path.

        When extraction detects actual encryption, set
        _encrypted_override = True so repack re-encrypts correctly.
        """
```

- [ ] **Step 4: Run tests to verify all pass**

Run: `pytest tests/test_material_encryption_regression.py::TestPazEntryEncryptedWhitelist -v`
Expected: 10 passed.

- [ ] **Step 5: Run the whole regression file**

Run: `pytest tests/test_material_encryption_regression.py -v`
Expected: 23 passed.

- [ ] **Step 6: Run the full test suite to check no regressions**

Run: `pytest tests/ -q -ra --timeout=60`
Expected: same pre-existing pass/fail count as before this task (no new failures).

- [ ] **Step 7: Commit**

```bash
git add src/cdumm/archive/paz_parse.py tests/test_material_encryption_regression.py
git commit -m "fix(paz_parse): widen PazEntry.encrypted whitelist

Add .material, .technique, and .thtml to the hard-coded extension
whitelist. These extensions are encrypted by the Crimson Desert
runtime but were absent from the heuristic, causing CDUMM to write
back plaintext into encrypted slots and produce silent visual
corruption in-game (e.g. InternalGraphicsMod water/dissolve).

The whitelist is now a fallback for entries built outside parse_pamt
or when the parse-time sniff hits an IOError. The structural fix is
the upcoming _populate_encryption_overrides.

Refs: docs/superpowers/specs/2026-05-22-material-encryption-fix-design.md"
```

---

## Phase 3: Parse-time sniff

### Task 4: `_populate_encryption_overrides` helper

**Files:**
- Modify: `src/cdumm/archive/paz_parse.py` (add new private function after `_parse_pamt_impl`)
- Modify: `tests/test_material_encryption_regression.py` (add test class)

The helper opens each PAZ file once (group by `paz_file` to avoid thousands of `open()` syscalls), seeks to each entry's offset, reads 32 bytes, calls `detect_encryption_from_head`, and writes the verdict into `entry._encrypted_override`. IOError / OSError on a given PAZ leaves the affected entries' overrides at `None`, so `PazEntry.encrypted` falls through to the widened whitelist.

- [ ] **Step 1: Add the failing test**

Update imports at the top of `tests/test_material_encryption_regression.py`:

```python
from cdumm.archive.paz_parse import (
    PazEntry,
    _populate_encryption_overrides,
)
```

Append at the bottom of the file:

```python
class TestPopulateEncryptionOverrides:
    """Unit tests for the parse-time sniff helper."""

    def _make_entry(self, path: str, paz_file: str, offset: int,
                     comp_size: int, orig_size: int,
                     compression_type: int = 0) -> PazEntry:
        # PAMT flags pack compression_type at bits 16..19.
        flags = (compression_type & 0xF) << 16
        return PazEntry(
            path=path,
            paz_file=paz_file,
            offset=offset,
            comp_size=comp_size,
            orig_size=orig_size,
            flags=flags,
            paz_index=0,
        )

    def test_uncompressed_plaintext_slot_sets_override_false(self, tmp_path):
        paz = tmp_path / "0.paz"
        plaintext = b'\xef\xbb\xbf<Technique Name="Water"/>\r\n'
        paz.write_bytes(plaintext)
        entry = self._make_entry(
            'technique/water.material', str(paz), 0,
            comp_size=len(plaintext), orig_size=len(plaintext)
        )

        _populate_encryption_overrides([entry])

        assert entry._encrypted_override is False

    def test_uncompressed_encrypted_slot_sets_override_true(self, tmp_path):
        paz = tmp_path / "0.paz"
        plaintext = b'\xef\xbb\xbf<Technique Name="Water"/>\r\n'
        ciphertext = encrypt(plaintext, 'water.material')
        paz.write_bytes(ciphertext)
        entry = self._make_entry(
            'technique/water.material', str(paz), 0,
            comp_size=len(ciphertext), orig_size=len(plaintext)
        )

        _populate_encryption_overrides([entry])

        assert entry._encrypted_override is True

    def test_multiple_entries_in_same_paz_share_one_open(self, tmp_path):
        """Sanity check that grouping doesn't break correctness for
        multiple entries in the same PAZ at different offsets."""
        paz = tmp_path / "0.paz"
        plaintext = b'\xef\xbb\xbf<a/>\r\n' + b'\x00' * 16
        ciphertext = encrypt(b'\xef\xbb\xbf<b/>\r\n' + b'\x00' * 16,
                             'foo.material')
        paz.write_bytes(plaintext + ciphertext)

        plain_entry = self._make_entry(
            'ui/a.xml', str(paz), 0,
            comp_size=len(plaintext), orig_size=len(plaintext)
        )
        crypt_entry = self._make_entry(
            'technique/foo.material', str(paz), len(plaintext),
            comp_size=len(ciphertext), orig_size=len(ciphertext)
        )

        _populate_encryption_overrides([plain_entry, crypt_entry])

        assert plain_entry._encrypted_override is False
        assert crypt_entry._encrypted_override is True

    def test_missing_paz_leaves_override_none(self, tmp_path):
        """IOError fallback: when the PAZ can't be opened, the
        override stays None so PazEntry.encrypted falls through to
        the widened extension whitelist."""
        entry = self._make_entry(
            'technique/water.material',
            str(tmp_path / "does_not_exist.paz"), 0,
            comp_size=100, orig_size=100
        )

        _populate_encryption_overrides([entry])

        assert entry._encrypted_override is None
        # Whitelist still classifies .material as encrypted.
        assert entry.encrypted is True

    def test_truncated_slot_classified_as_encrypted(self, tmp_path):
        """A PAZ shorter than the declared offset returns 0 bytes;
        detect_encryption_from_head treats empty head as encrypted
        (fail-safe)."""
        paz = tmp_path / "0.paz"
        paz.write_bytes(b'\x00' * 10)
        entry = self._make_entry(
            'technique/foo.material', str(paz), 1000,
            comp_size=2315, orig_size=2315
        )

        _populate_encryption_overrides([entry])

        assert entry._encrypted_override is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_material_encryption_regression.py::TestPopulateEncryptionOverrides -v`
Expected: ImportError on `_populate_encryption_overrides`.

- [ ] **Step 3: Implement `_populate_encryption_overrides`**

Add the helper to `src/cdumm/archive/paz_parse.py`. The current imports at the top of the file include `logging`, `os`, `struct`, `fnmatch`, and the dataclass machinery. Add `collections` to the import block:

```python
import collections
```

(Insert alphabetically among the existing imports.)

Then add the function right before the `def parse_pamt` wrapper (i.e. between `_parse_pamt_impl` and `parse_pamt`, just above line 70 in the current file):

```python
def _populate_encryption_overrides(entries: list[PazEntry]) -> None:
    """Sniff the first 32 bytes of every entry's PAZ slot and set
    `_encrypted_override` accordingly. Mutates entries in place.

    Entries are grouped by `paz_file` so each PAZ is opened once
    regardless of how many entries point into it. PAZ files that
    cannot be opened (missing, permission denied, etc.) leave their
    entries' overrides at `None`, so `PazEntry.encrypted` falls back
    to the widened extension whitelist.

    Truncated slots (offset past end of file, read returns < 32
    bytes) are classified as encrypted by detect_encryption_from_head
    (fail-safe).

    Performance: ~one seek + read(32) per entry plus one open per
    PAZ file. On a typical CD PAMT (tens of thousands of entries,
    ~10 PAZ files on SSD) this completes well under one second.
    """
    from cdumm.archive.paz_crypto import detect_encryption_from_head

    by_paz: dict[str, list[PazEntry]] = collections.defaultdict(list)
    for entry in entries:
        by_paz[entry.paz_file].append(entry)

    for paz_file, group in by_paz.items():
        try:
            with open(paz_file, 'rb') as f:
                for entry in group:
                    f.seek(entry.offset)
                    head = f.read(32)
                    entry._encrypted_override = detect_encryption_from_head(
                        head, entry.compression_type, entry.orig_size
                    )
        except (IOError, OSError) as e:
            logger.warning(
                "Could not sniff %s for encryption detection (%s); "
                "%d entries will fall back to the extension whitelist",
                paz_file, e, len(group)
            )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_material_encryption_regression.py::TestPopulateEncryptionOverrides -v`
Expected: 5 passed.

- [ ] **Step 5: Run the whole regression file**

Run: `pytest tests/test_material_encryption_regression.py -v`
Expected: 28 passed.

- [ ] **Step 6: Commit**

```bash
git add src/cdumm/archive/paz_parse.py tests/test_material_encryption_regression.py
git commit -m "feat(paz_parse): add _populate_encryption_overrides

Sniffs the first 32 bytes of each entry's PAZ slot and writes the
verdict into _encrypted_override. Groups entries by paz_file so each
PAZ is opened once. IOError/OSError on a PAZ leaves affected
entries' overrides at None so the widened extension whitelist takes
over.

Not yet wired into parse_pamt (next task) so this is dead code in
isolation; tests exercise it directly.

Refs: docs/superpowers/specs/2026-05-22-material-encryption-fix-design.md"
```

---

### Task 5: Wire `_populate_encryption_overrides` into `parse_pamt`

**Files:**
- Modify: `src/cdumm/archive/paz_parse.py` (the public `parse_pamt` wrapper, around lines 86-94)
- Modify: `tests/test_material_encryption_regression.py` (add test class)

- [ ] **Step 1: Add the failing integration test**

Append to `tests/test_material_encryption_regression.py`:

```python
class TestParsePamtPopulatesOverrides:
    """End-to-end: parse_pamt runs the sniff and downstream code
    sees correct .encrypted verdicts on .material entries."""

    def test_parse_pamt_populates_override_on_material_entry(self, tmp_path):
        from tests.fixtures._material_encryption_synth import (
            build_synthetic_pamt_paz,
        )
        from cdumm.archive.paz_parse import parse_pamt

        pamt_path, _paz_path, plan = build_synthetic_pamt_paz(tmp_path)

        entries = parse_pamt(str(pamt_path), paz_dir=str(tmp_path))

        by_path = {e.path: e for e in entries}
        # The synthetic fixture lays out one entry per content category.
        material = by_path[plan['material_path']]
        xml = by_path[plan['xml_path']]
        binary = by_path[plan['bin_path']]

        # .material was encrypted in the fixture; sniff must catch it
        # even though no extension widening is needed (the whitelist
        # also covers .material now, but we want to prove the sniff
        # itself wrote the override).
        assert material._encrypted_override is True
        assert material.encrypted is True

        # .xml was encrypted: override True.
        assert xml._encrypted_override is True

        # Plaintext .bin: override False (sniff wins over the
        # whitelist, which would have said False anyway).
        assert binary._encrypted_override is False
        assert binary.encrypted is False
```

The test imports a fixture builder that doesn't exist yet, that comes in the next task. For now this test will fail at import time.

- [ ] **Step 2: Wire `_populate_encryption_overrides` into `parse_pamt`**

Edit the `parse_pamt` wrapper in `src/cdumm/archive/paz_parse.py` (currently lines 70-95) to call the new helper after `_parse_pamt_impl` returns. Replace the wrapper body:

```python
def parse_pamt(pamt_path: str, paz_dir: str = None) -> list[PazEntry]:
    """Parse a .pamt index file and return all file entries.

    After parsing, every entry's `_encrypted_override` is populated by
    sniffing the first 32 bytes of its PAZ slot. Downstream consumers
    therefore see a precomputed encryption verdict via the existing
    PazEntry.encrypted property, regardless of file extension.

    Args:
        pamt_path: path to the .pamt file
        paz_dir: directory containing .paz files (default: same dir as .pamt)

    Returns:
        list of PazEntry

    Raises:
        ValueError: the PAMT is truncated, claims a section larger than
            the file itself, or declares a wildly impossible paz_count.
            Message names the file so callers can surface which mod
            shipped the corrupt archive.
    """
    try:
        entries = _parse_pamt_impl(pamt_path, paz_dir)
    except (struct.error, IndexError) as e:
        # Surface low-level parse errors as a clean ValueError. Callers
        # (import_handler precheck, apply_engine precheck) need one
        # exception type to distinguish "corrupt archive, skip this
        # mod" from actual bugs.
        raise ValueError(
            f"Corrupt PAMT {os.path.basename(pamt_path)}: {e}") from e

    _populate_encryption_overrides(entries)
    return entries
```

- [ ] **Step 3: Verify the wiring is syntactically valid**

Run: `python -c "from cdumm.archive.paz_parse import parse_pamt; print('ok')"`
Expected: prints `ok` with no traceback.

- [ ] **Step 4: Commit the wiring (tests still fail at import; fixture comes next)**

```bash
git add src/cdumm/archive/paz_parse.py tests/test_material_encryption_regression.py
git commit -m "feat(paz_parse): wire _populate_encryption_overrides into parse_pamt

The public parse_pamt wrapper now runs the encryption sniff on every
returned entry. Downstream consumers (browser, JSON patch, import,
apply, repack) all read the precomputed _encrypted_override via the
existing PazEntry.encrypted property, so the silent .material
corruption bug is fixed at the source.

Integration test added but not yet runnable (synthetic PAMT+PAZ
fixture comes in the next commit).

Refs: docs/superpowers/specs/2026-05-22-material-encryption-fix-design.md"
```

---

### Task 6: Synthetic PAMT+PAZ fixture

**Files:**
- Create: `tests/fixtures/__init__.py` (if not present)
- Create: `tests/fixtures/_material_encryption_synth.py`

The fixture builds the smallest valid PAMT that `_parse_pamt_impl` will accept, containing exactly three entries pointing at slots inside a companion PAZ file. No game data is involved.

- [ ] **Step 1: Inspect `_parse_pamt_impl` to confirm the byte layout your fixture needs to mimic**

Re-read `src/cdumm/archive/paz_parse.py:106-222` (the `_parse_pamt_impl` body). Confirm the order of sections: magic(4) + paz_count(4) + hash+zero(8) + per-PAZ records + folder section (size + records) + node section (size + records) + folder_count + folder records + file_count + file records.

This step is reading-only; no command to run.

- [ ] **Step 2: Create the fixtures package init (if missing)**

Run: `ls tests/fixtures/__init__.py 2>/dev/null && echo present || (touch tests/fixtures/__init__.py && echo created)`

- [ ] **Step 3: Write the fixture builder**

Create `tests/fixtures/_material_encryption_synth.py`:

```python
"""Tiny synthetic PAMT + PAZ pair for material-encryption tests.

No game asset committed. Layout matches what _parse_pamt_impl
expects: one folder ("test"), three files inside it. Each file's
content sits in `0.paz` at a known offset.

Returned plan dict carries the entry paths so tests can assert
encryption verdicts by path without hardcoding indices.
"""

import os
import struct
from pathlib import Path

from cdumm.archive.paz_crypto import encrypt


def build_synthetic_pamt_paz(tmp_path: Path):
    """Build a minimal PAMT + PAZ pair under tmp_path.

    Returns:
        (pamt_path, paz_path, plan)

        plan is a dict with the entry paths:
            {
              'xml_path': 'test/foo.xml',
              'material_path': 'test/water.material',
              'bin_path': 'test/data.bin',
            }
    """
    # ---- PAZ payload ----
    xml_plain = b'\xef\xbb\xbf<root>hello</root>\r\n'
    xml_crypt = encrypt(xml_plain, 'foo.xml')

    mat_plain = b'\xef\xbb\xbf<Technique Name="Water"/>\r\n'
    mat_crypt = encrypt(mat_plain, 'water.material')

    bin_plain = b'\x00\x01\x02\x03' * 16  # 64 bytes, uncompressible binary

    # Pad each slot to keep offsets aligned and >=32 bytes so the
    # sniff has a full head to read.
    def _padded(data: bytes, size: int = 64) -> bytes:
        assert len(data) <= size
        return data + b'\x00' * (size - len(data))

    xml_slot = _padded(xml_crypt)
    mat_slot = _padded(mat_crypt)
    bin_slot = _padded(bin_plain)

    paz_blob = xml_slot + mat_slot + bin_slot
    xml_off = 0
    mat_off = len(xml_slot)
    bin_off = len(xml_slot) + len(mat_slot)

    paz_path = tmp_path / "0.paz"
    paz_path.write_bytes(paz_blob)

    # ---- PAMT structure ----
    # Magic (4 bytes, value irrelevant per _parse_pamt_impl which
    # just skips it).
    magic = b'PAMT'

    # paz_count = 1 (single .paz file).
    paz_count = struct.pack('<I', 1)
    hash_zero = struct.pack('<II', 0, 0)

    # PAZ table: paz_count entries each with hash(4)+size(4); the
    # separator(4) between consecutive entries is skipped when
    # paz_count == 1 (see _parse_pamt_impl loop condition
    # `if i < paz_count - 1`).
    paz_table = struct.pack('<II', 0, len(paz_blob))

    # ---- Folder section ----
    # One folder named "test", parent = 0xFFFFFFFF (root).
    folder_name = b'test'
    folder_record = struct.pack('<I', 0xFFFFFFFF) + bytes([len(folder_name)]) + folder_name
    folder_section = struct.pack('<I', len(folder_record)) + folder_record

    # ---- Node section ----
    # Three nodes for the file basenames, each parented to root
    # (0xFFFFFFFF). _parse_pamt_impl traverses node_ref -> parent
    # chain via 'rel = off - node_start'; we record the relative
    # offset of each node and reference it from the file record.
    nodes = []
    rels = {}
    node_bytes = bytearray()
    for name in (b'foo.xml', b'water.material', b'data.bin'):
        rels[bytes(name)] = len(node_bytes)
        node_bytes += struct.pack('<I', 0xFFFFFFFF) + bytes([len(name)]) + name
    node_section = struct.pack('<I', len(node_bytes)) + bytes(node_bytes)

    # ---- Folder record section ----
    # _parse_pamt_impl reads folder_count then skips folder_count*16
    # bytes without using the content. Emit 1 stub folder record.
    folder_records = struct.pack('<I', 1) + b'\x00' * 16

    # ---- File record section ----
    # Each record: node_ref(4) + paz_offset(4) + comp_size(4) +
    # orig_size(4) + flags(4). flags low byte = paz_index (=0).
    # compression_type would live at bits 16..19; leave at 0
    # (uncompressed) for all three entries.
    file_count = struct.pack('<I', 3)
    file_records = b''
    for name, off, content_plain, content_slot in (
        (b'foo.xml', xml_off, xml_plain, xml_slot),
        (b'water.material', mat_off, mat_plain, mat_slot),
        (b'data.bin', bin_off, bin_plain, bin_slot),
    ):
        node_ref = rels[name]
        file_records += struct.pack(
            '<IIIII',
            node_ref,
            off,
            len(content_slot),  # comp_size = slot size
            len(content_plain), # orig_size = original size
            0,                  # flags (paz_index=0, comp_type=0)
        )

    pamt_blob = (
        magic
        + paz_count
        + hash_zero
        + paz_table
        + folder_section
        + node_section
        + folder_records
        + file_count
        + file_records
    )

    pamt_path = tmp_path / "0.pamt"
    pamt_path.write_bytes(pamt_blob)

    plan = {
        'xml_path': 'test/foo.xml',
        'material_path': 'test/water.material',
        'bin_path': 'test/data.bin',
    }
    return pamt_path, paz_path, plan
```

- [ ] **Step 4: Run the integration test**

Run: `pytest tests/test_material_encryption_regression.py::TestParsePamtPopulatesOverrides -v`
Expected: 1 passed.

If it fails with a parse error from `_parse_pamt_impl`, the synthetic byte layout doesn't match what the impl expects. Diff the failure message against `_parse_pamt_impl` and adjust the fixture (the impl's structure is the source of truth; the fixture must mirror it exactly).

- [ ] **Step 5: Run the whole regression file**

Run: `pytest tests/test_material_encryption_regression.py -v`
Expected: 29 passed.

- [ ] **Step 6: Run the full test suite to check no regressions**

Run: `pytest tests/ -q -ra --timeout=60`
Expected: same pre-existing pass/fail count + 29 new passes from this file. No new failures elsewhere (`parse_pamt` now does extra I/O but the semantics for every previously-working consumer are unchanged).

- [ ] **Step 7: Commit**

```bash
git add tests/fixtures/__init__.py tests/fixtures/_material_encryption_synth.py tests/test_material_encryption_regression.py
git commit -m "test(paz_parse): synthetic PAMT+PAZ fixture + integration test

build_synthetic_pamt_paz writes a 3-entry PAMT and companion PAZ to
tmp_path (no game data committed). Drives an end-to-end test that
parse_pamt now populates _encrypted_override correctly on .xml,
.material, and .bin entries.

Refs: docs/superpowers/specs/2026-05-22-material-encryption-fix-design.md"
```

---

### Task 7: Round-trip integration test

**Files:**
- Modify: `tests/test_material_encryption_regression.py` (add test method)

Prove that with the fix in place, repacking the original plaintext content of an encrypted `.material` entry produces a slot byte-identical to the original. This is the test that would have caught the bug before it shipped.

- [ ] **Step 1: Add the failing test**

Append to `tests/test_material_encryption_regression.py`:

```python
class TestMaterialRoundTripIsByteIdentical:
    def test_repack_of_decrypted_material_matches_original_slot(self, tmp_path):
        from tests.fixtures._material_encryption_synth import (
            build_synthetic_pamt_paz,
        )
        from cdumm.archive.paz_parse import parse_pamt
        from cdumm.archive.paz_crypto import decrypt
        from cdumm.archive.paz_repack import repack_entry_bytes

        pamt_path, paz_path, plan = build_synthetic_pamt_paz(tmp_path)
        paz_blob_before = paz_path.read_bytes()

        entries = parse_pamt(str(pamt_path), paz_dir=str(tmp_path))
        material = next(
            e for e in entries if e.path == plan['material_path']
        )

        # Read the original encrypted slot.
        original_slot = paz_blob_before[
            material.offset : material.offset + material.comp_size
        ]

        # Decrypt with the same key derivation the runtime uses.
        plaintext = decrypt(original_slot, 'water.material')

        # Repack: should re-encrypt because _encrypted_override=True.
        repacked, _, _ = repack_entry_bytes(plaintext, material)

        # Bit-identical to the original slot in the PAZ.
        assert repacked == original_slot, (
            f"Repack differs from original at "
            f"{sum(a != b for a, b in zip(repacked, original_slot))} "
            f"of {len(original_slot)} bytes"
        )
```

- [ ] **Step 2: Run the test**

Run: `pytest tests/test_material_encryption_regression.py::TestMaterialRoundTripIsByteIdentical -v`
Expected: 1 passed.

If it fails byte-comparing, that means the repack pipeline is doing something the design didn't account for (size padding, compression decision, etc.). Look at `repack_entry_bytes` in `src/cdumm/archive/paz_repack.py:232-363` to understand the divergence. The most likely culprit is null-padding at the tail; if so, adjust the fixture's `mat_plain` so its encrypted size equals exactly `comp_size` (no padding needed) and rerun.

- [ ] **Step 3: Run full file and full suite**

Run: `pytest tests/test_material_encryption_regression.py -v`
Expected: 30 passed.

Run: `pytest tests/ -q -ra --timeout=60`
Expected: no new failures.

- [ ] **Step 4: Commit**

```bash
git add tests/test_material_encryption_regression.py
git commit -m "test(paz_repack): byte-identical round-trip for encrypted .material

Decrypts the original PAZ slot of a synthetic .material entry,
feeds the plaintext back through repack_entry_bytes, and asserts
the output is bit-identical to the original slot. This is the
oracle test that would have caught the silent corruption bug.

Refs: docs/superpowers/specs/2026-05-22-material-encryption-fix-design.md"
```

---

### Task 8: Push the branch and (optionally) merge to master

- [ ] **Step 1: Push `fix/material-encryption`**

Run:

```bash
git push -u origin fix/material-encryption
```

Expected: the branch is created on `origin` (the fork remote). No PR is opened upstream; the fork strategy is explicit.

- [ ] **Step 2: Decide on master merge timing**

Option A (recommended): leave the branch un-merged until the Windows CI workflow is in place too (Task 9), then merge both branches into `master` together so the first `.exe` produced from `master` contains the fix.

Option B: merge `fix/material-encryption` into `master` now, then add CI on top.

If A, just continue to Task 9 on a fresh branch off `master`. If B:

```bash
git checkout master
git merge --no-ff fix/material-encryption -m "merge fix/material-encryption: encryption detection at parse time"
git push origin master
```

No commit needed for this task; it's a workflow decision step.

---

## Phase 4: Windows CI

### Task 9: `release-windows.yml`

**Files:**
- Create: `.github/workflows/release-windows.yml` (on branch `fork/windows-ci`)

The workflow mirrors `release-macos.yml` but targets `windows-latest` (which currently maps to `windows-2022`; pin if you want determinism), builds the Rust native extension with `maturin develop --release`, then runs `pyinstaller cdumm.spec --clean`. Uploads the `.exe` as a workflow artifact on every run and attaches it to the GitHub Release when triggered by a `v*` tag.

- [ ] **Step 1: Branch off master**

```bash
git checkout master
git checkout -b fork/windows-ci
```

- [ ] **Step 2: Create the workflow file**

Create `.github/workflows/release-windows.yml`:

```yaml
name: Build Windows release

# Triggers:
#   * push of a tag matching v*: attaches the .exe to the GitHub
#     Release for that tag automatically. Mirrors release-macos.yml.
#   * workflow_dispatch: manual run from the Actions tab. Produces
#     the .exe as a workflow artifact (downloadable for 30 days) but
#     does NOT touch GitHub Releases.
#
# Runner: windows-latest currently resolves to windows-2022. Pin to
# windows-2022 explicitly if you want determinism across GitHub's
# runner image bumps; left as windows-latest here to ride along with
# whatever GitHub considers current.
on:
  push:
    tags:
      - "v*"
  workflow_dispatch:

permissions:
  contents: write # needed to create / update GitHub Releases

jobs:
  build-windows:
    runs-on: windows-latest
    timeout-minutes: 30

    steps:
      - name: Checkout
        uses: actions/checkout@v6

      - name: Set up Python 3.13
        uses: actions/setup-python@v6
        with:
          # 3.13 matches the local Windows dev environment. cdumm_native
          # uses the abi3-py39 stable ABI so any Python 3.9+ works; the
          # pin here keeps CI reproducible.
          python-version: "3.13"

      - name: Set up Rust toolchain (x86_64-pc-windows-msvc)
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: x86_64-pc-windows-msvc

      # Cache Cargo's registry + git index + the native/ build dir.
      # Same logic as release-macos.yml: the native crate compiles
      # quickly once the dependency cache is warm.
      - name: Cache cargo + native target
        uses: actions/cache@v5
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            native/target
          key: cargo-windows-${{ hashFiles('native/Cargo.lock') }}
          restore-keys: cargo-windows-

      - name: Cache pip wheel cache
        uses: actions/cache@v5
        with:
          path: ~\AppData\Local\pip\Cache
          key: pip-windows-py313-${{ hashFiles('pyproject.toml') }}
          restore-keys: pip-windows-py313-

      - name: Install Python build tooling
        shell: pwsh
        run: |
          python -m pip install --upgrade pip
          python -m pip install maturin pyinstaller
          python -m pip install -e .

      - name: Build native extension
        shell: pwsh
        working-directory: native
        run: maturin develop --release

      - name: Build .exe
        shell: pwsh
        run: python -m PyInstaller cdumm.spec --clean --noconfirm

      # ----- Artifact upload ----------------------------------------
      # Always uploaded so workflow_dispatch runs (no tag) still
      # produce a downloadable .exe from the Actions UI.
      - name: Upload .exe as workflow artifact
        uses: actions/upload-artifact@v7
        with:
          name: CDUMM-windows
          path: dist/CDUMM3.exe
          retention-days: 30
          if-no-files-found: error

      # ----- Release attachment (tag-triggered runs only) ----------
      - name: Attach .exe to GitHub Release
        if: startsWith(github.ref, 'refs/tags/v')
        uses: softprops/action-gh-release@v3
        with:
          files: dist/CDUMM3.exe
          fail_on_unmatched_files: true
          generate_release_notes: false
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Two things to verify before pushing:

1. **The PyInstaller output path is `dist/CDUMM3.exe`.** Check `cdumm.spec` to confirm the binary name. If it's different (e.g. `dist/CDUMM3/CDUMM3.exe` for onedir mode), adjust the `path:` lines in both upload steps.

2. **`maturin develop --release` from `native/`** must install `cdumm_native` into the same Python env that `pyinstaller` later picks up. The macOS pipeline does the equivalent in `scripts/build-macos.sh`; here we inline it. If the spec file references `cdumm_native` via `importlib.util.find_spec`, the maturin install is what makes that succeed.

- [ ] **Step 3: Confirm `cdumm.spec` output path**

Run: `grep -n "name\s*=\|EXE\|onefile\|onedir\|coll" cdumm.spec | head -30`

Inspect the output. Update `path:` in `Upload .exe as workflow artifact` and `files:` in `Attach .exe to GitHub Release` to match the real output name and layout. If onefile mode is used, `dist/<name>.exe` is correct; if onedir, you'll want to zip `dist/<name>/` instead (use a separate step with `Compress-Archive` in PowerShell, or upload the whole directory).

- [ ] **Step 4: Commit and push**

```bash
git add .github/workflows/release-windows.yml
git commit -m "ci: add Windows release workflow

Mirrors release-macos.yml for windows-latest. Triggers on v* tag
push (attaches .exe to GitHub Release) and on workflow_dispatch
(uploads .exe as a workflow artifact only).

Refs: docs/superpowers/specs/2026-05-22-material-encryption-fix-design.md"
git push -u origin fork/windows-ci
```

- [ ] **Step 5: Enable Actions on the fork (one-off, manual)**

GitHub disables Actions on forks by default. In the fork's settings:

Settings → Actions → General → Actions permissions → "Allow all actions and reusable workflows" (or the narrower "Allow Toni-cafeyn, and select non-Toni-cafeyn, actions and reusable workflows" if you want to whitelist the exact actions we use: `actions/checkout`, `actions/setup-python`, `actions/cache`, `actions/upload-artifact`, `dtolnay/rust-toolchain`, `softprops/action-gh-release`).

No commit; manual GitHub UI step.

- [ ] **Step 6: Trigger the workflow manually and download the artifact**

In the fork's Actions tab, find "Build Windows release", click "Run workflow" on the `fork/windows-ci` branch.

After the run finishes (~10-20 minutes cold, less with warm caches), download the `CDUMM-windows` artifact. Extract `CDUMM3.exe`.

If the run fails:
- Build step fails: look at the failing log, fix the spec/maturin/pyinstaller invocation, commit, push, re-run.
- Artifact upload fails with "no files found": the actual `.exe` path doesn't match what we configured. Update Step 2's path values and re-run.

- [ ] **Step 7: Smoke-test the .exe on Windows**

On the user's Windows machine:

1. Run `CDUMM3.exe`. It should launch the manager UI.
2. Open a Crimson Desert install. The PAMT/PAZ files should load (this exercises `parse_pamt` and the new sniff path on real data).
3. Apply `InternalGraphicsMod v3.1.2` (or any mod that modifies a `.material`). Watch for errors during apply.
4. Launch the game. Validate the previously-broken visual (water rendering, gem mesh on green key) renders correctly.

If smoke-test passes, the fix is shipped.

- [ ] **Step 8: Merge both branches to master**

If you went with Option A in Task 8.2 (didn't merge yet):

```bash
git checkout master
git merge --no-ff fix/material-encryption -m "merge fix/material-encryption: encryption detection at parse time"
git merge --no-ff fork/windows-ci -m "merge fork/windows-ci: Windows release workflow"
git push origin master
```

This produces the canonical `master` ready for tagging when you want a Release.

---

## Phase 5: Release (optional)

### Task 10: Tag and publish a Release

- [ ] **Step 1: Tag**

```bash
git checkout master
git tag -a v3.3.11-encryption-fix -m "Fork release: material encryption fix"
git push origin v3.3.11-encryption-fix
```

The Windows workflow fires on the tag push, builds the `.exe`, and attaches it to a new GitHub Release named after the tag.

- [ ] **Step 2: Edit Release notes**

In the fork's Releases page, edit the auto-created Release to add notes pointing at the bug report and design doc. Reference `CDUMM_MATERIAL_ENCRYPTION_BUG.md` so users understand what was fixed.

No commit; GitHub UI step.

- [ ] **Step 3: Announce**

Where the modding community lives (Nexus mod comment thread, Discord, fork README). Link to the Release.

---

## Self-Review Notes

- **Spec coverage:** Every section of the design doc is implemented by one or more tasks. The whitelist widening (Phase 2), the parse-time sniff (Phase 3), the synthetic-fixture integration test (Task 6-7), the Windows workflow (Task 9), and the two-branch delivery model (Task 8 / 9 split) all map directly to spec sections.
- **No placeholders:** Every code step contains the actual code or exact command to run.
- **Type consistency:** `looks_like_plaintext_head(data: bytes) -> bool`, `detect_encryption_from_head(head, compression_type, orig_size) -> bool`, `_populate_encryption_overrides(entries) -> None` are referenced with these signatures throughout.
- **Open caveat:** Task 9 Step 3 (verifying `cdumm.spec` output path) and Step 6 (manually triggering the workflow) require some adaptation depending on the actual spec content and any CI quirks. These are the only steps that legitimately need user judgment; everything else is mechanical.
