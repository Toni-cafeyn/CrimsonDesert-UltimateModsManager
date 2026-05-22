# Design: fix silent corruption of `.material` (and similar) files at repack

Date: 2026-05-22
Related bug report: `~/crimson-desert/CDUMM_MATERIAL_ENCRYPTION_BUG.md`

## Goal

Make CDUMM detect encryption state from the actual PAZ slot bytes at parse time, so that any file the game runtime encrypts (regardless of extension) is correctly re-encrypted on repack. Eliminate the silent corruption of `.material`, `.technique`, `.thtml` (and unknown future extensions).

Priority order:
1. Ship a usable fix on the fork (`Toni-cafeyn/CrimsonDesert-UltimateModsManager`) as a Windows `.exe` artifact.
2. Best-effort upstream PRs to `faisalkindi/CrimsonDesert-UltimateModsManager`, split by logical change.

## Non-goals

- Exhaustive enumeration of every encrypted extension. The sniff covers them.
- Automated in-game regression testing. Manual validation on a real Windows + Crimson Desert install is the final oracle.
- Refactoring the wider encryption flow beyond what serves this fix.
- Parallelizing PAZ slot reads. YAGNI until measured.

## Root cause recap

`src/cdumm/archive/paz_parse.py:46-64`, `PazEntry.encrypted` returns True only for paths ending in `.xml`, `.css`, `.html`, `.js`. The PAMT carries no reliable encrypted flag, so CDUMM guesses by extension. The runtime encrypts more than that (confirmed: `.material`, `.technique`, `.thtml`). Files with these extensions are written back as plaintext into encrypted slots; the runtime decrypts plaintext, producing pseudo-random buffer fed to the material parser, producing visual artifacts in-game.

The existing `_encrypted_override` mechanism only fires on specific code paths (browser GUI, JSON patch, import_handler, apply_engine mod metadata). The plain "drop a file into the mod folder and apply" path bypasses it entirely.

## Approach: sniff at parse time, populate `_encrypted_override` for all entries

Make `parse_pamt` the single source of truth. After parsing each entry, peek at the first 32 bytes of its slot in the corresponding PAZ file, classify, and set `_encrypted_override`. Every downstream consumer (browser, JSON patch, import, apply, repack) then sees the correct verdict via the existing override read path.

The extension whitelist in `PazEntry.encrypted` becomes a fallback that only fires when the sniff cannot read the PAZ (IOError, missing file, etc.). It is widened to `.material`, `.technique`, `.thtml` so the fallback path is correct for the common modded files.

## Detection algorithm

```python
def detect_encryption_from_head(head: bytes, compression_type: int,
                                orig_size: int) -> bool:
    """Classify a slot as encrypted (True) or plaintext (False).

    head: first ~32 bytes read at the slot offset
    compression_type: PAMT compression_type field (0=none, 2=lz4)
    orig_size: PAMT orig_size, needed for lz4.block.decompress
    """
    if compression_type == 2:  # lz4 block
        try:
            lz4.block.decompress(head, uncompressed_size=orig_size)
            return False  # valid lz4 → was plaintext-compressed
        except (lz4.block.LZ4BlockError, ValueError):
            return True   # invalid lz4 → was encrypted (then compressed)
    return not looks_like_plaintext_head(head)


def looks_like_plaintext_head(data: bytes) -> bool:
    """True if first ~16 useful bytes look like printable text.

    Strips optional UTF-8 BOM and leading whitespace so XML with BOM
    or indentation still matches. >90% printable in 16 bytes is a
    strong signal: random ChaCha20 output hits ~37% printable.
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

Both helpers live in `src/cdumm/archive/paz_crypto.py` (closer to the codec/crypto domain than to PAMT parsing).

### Risk acknowledged

Random ChaCha20 output that happens to form a valid lz4 block is theoretically possible (probability < 2^-64 on 32 bytes given lz4's strict block format). Accepted as negligible; documented in the helper docstring.

### Edge cases

- Empty / truncated slot: `looks_like_plaintext_head` returns False, `lz4.decompress` raises → classified as encrypted (fail-safe; these slots are not consumable as plaintext anyway).
- All-zero slot: `looks_like_plaintext_head` returns False → classified as encrypted (acceptable; unused slot).
- `compression_type` other than 0 or 2 (custom codec, value 3): falls through to `looks_like_plaintext_head`. If a future codec produces high-entropy output, it would be mis-classified as encrypted. Mitigation: add a branch when such a codec appears; no known mod exercises this today.

## Integration in `parse_pamt`

```python
def parse_pamt(pamt_path, paz_dir=None):
    entries = _parse_pamt_entries(pamt_path, paz_dir)  # existing logic
    _populate_encryption_overrides(entries)
    return entries


def _populate_encryption_overrides(entries):
    # Group by paz_file to minimize open() syscalls.
    by_paz = collections.defaultdict(list)
    for e in entries:
        by_paz[e.paz_file].append(e)

    for paz_file, group in by_paz.items():
        try:
            with open(paz_file, 'rb') as f:
                for entry in group:
                    f.seek(entry.offset)
                    head = f.read(32)
                    entry._encrypted_override = detect_encryption_from_head(
                        head, entry.compression_type, entry.orig_size
                    )
        except (IOError, OSError):
            # Leave _encrypted_override = None; PazEntry.encrypted
            # will fall back to the widened extension whitelist.
            logger.warning(
                "Could not sniff %s for encryption detection; "
                "falling back to extension whitelist", paz_file
            )
```

Performance: for a typical CD PAMT (~tens of thousands of entries across ~10 PAZ files), this adds one `open()` per PAZ plus one `seek+read(32)` per entry. Expected total: well under 1s on SSD. Acceptable at manager startup / project open.

## Whitelist change

`PazEntry.encrypted` keeps its docstring (it documents the v2.1.2 → v3.0 regression history and remains valid) but widens the fallback list:

```python
return self.path.lower().endswith(
    ('.xml', '.css', '.html', '.js',
     '.material', '.technique', '.thtml'))
```

This list is now used only when `_encrypted_override` is `None`, which after `parse_pamt` only happens on:
- Entries constructed by hand (tests, debug scripts)
- Entries whose PAZ could not be read (IOError fallback)

## Files touched

| Path | Change |
| ---- | ------ |
| `src/cdumm/archive/paz_crypto.py` | Add `looks_like_plaintext_head`, `detect_encryption_from_head` |
| `src/cdumm/archive/paz_parse.py` | Widen whitelist in `PazEntry.encrypted`; add `_populate_encryption_overrides` step in `parse_pamt` |
| `tests/test_material_encryption_regression.py` | New: unit + integration tests |
| `.github/workflows/release-windows.yml` | New: Windows build workflow (fork-only, both `tags: ['v*']` and `workflow_dispatch`) |

## Tests

Unit tests on the helpers:

1. `looks_like_plaintext_head`: XML+BOM → True, plain XML → True, ChaCha20 sample → False, lz4 block bytes → False, empty → False, whitespace-only → False.
2. `detect_encryption_from_head`: 2x2 matrix (compression_type ∈ {0, 2}) × (plaintext vs ciphertext).

Whitelist regression:

3. `PazEntry(path='technique/water.material', _encrypted_override=None).encrypted is True`
4. Same for `.css`, `.technique`, `.thtml`. Unknown extension `.bin` → False.
5. Override beats whitelist: `_encrypted_override=False` on `.xml` → encrypted is False.

Integration test:

6. Build a synthetic PAMT + PAZ in a pytest fixture (no copyrighted game asset committed):
   - one `.xml` entry, encrypted with `encrypt()` from the codebase
   - one `.material` entry, encrypted (the bug case)
   - one binary `.bin` entry, plaintext (uncompressed)
   - the lz4-compressed-plaintext case is covered by the unit test on `detect_encryption_from_head`; not required here
7. Call `parse_pamt(fixture.pamt)`.
8. Assert each entry's `_encrypted_override` matches the construction.
9. For the `.material` entry: decrypt, repack via `repack_entry_bytes`, assert byte-identical to the original slot.

Fixture generation lives in `tests/conftest.py`, uses only public helpers from `paz_crypto`. No game data committed.

## Acceptance criteria

- `pytest tests/ -q -ra` passes locally and in CI.
- The Windows workflow produces a `.exe` artifact.
- Manual test on real Windows + Crimson Desert install: a mod modifying a `.material` file (e.g., `InternalGraphicsMod.v.3.1.2` water/dissolve materials) applies correctly, no visual artifact.
- No regression on the previously-working cases: mod that only modifies `.xml`, mod with no encrypted files.

## Delivery plan

**Branch 1, `fix/material-encryption-whitelist`** (upstream PR #1, autonomous, minimal patch)
- `paz_parse.py`: widen the whitelist in `PazEntry.encrypted` to include `.material`, `.technique`, `.thtml`
- `tests/test_material_encryption_regression.py`: whitelist regression test (`PazEntry(...).encrypted` cases)
- Rationale: smallest possible patch, mergeable on its own. Resolves the bug for the three currently-known extensions without touching any other code. Friendly to a maintainer who wants a quick fix.

**Branch 2, `fix/material-encryption-parse-sniff`** (upstream PR #2, depends on #1, structural fix)
- `paz_crypto.py`: add `looks_like_plaintext_head` and `detect_encryption_from_head`
- `paz_parse.py`: `_populate_encryption_overrides` + integration in `parse_pamt`
- `tests/`: unit tests on the two helpers + integration test with synthetic fixture
- Open as draft until PR #1 merges, then rebase and request review.
- Rationale: structural fix so future encrypted extensions are auto-detected and the whitelist becomes an IOError fallback only.

**Branch 3, `fork/windows-ci`** (fork-only, not upstreamed)
- `.github/workflows/release-windows.yml`
- Triggers: `workflow_dispatch` + `tags: ['v*']`
- Steps: setup-python 3.13, Rust toolchain (windows-msvc), cache cargo + native target, `maturin develop --release`, `pyinstaller cdumm.spec --clean`, upload artifact, attach to Release if tag-triggered.
- Independent of branches 1 and 2 (can be developed in parallel).

**Release branch, `release/encryption-fix`** (fork)
- Merges branches 1, 2, 3 on top of `master`.
- Trigger `workflow_dispatch` manually on this branch to produce the `.exe`.
- Distribute the artifact link (Nexus comment, fork README) to users.

## Open items confirmed during brainstorm

- Detection layer: parse-time only. No belt-and-suspenders at repack.
- Compression handling: `lz4.block.decompress` attempt for `compression_type == 2`; printable heuristic otherwise. LZ4 collision risk accepted.
- Whitelist: kept as IOError fallback only, widened to include `.material`, `.technique`, `.thtml`.
- PR strategy: two separate upstream PRs, split by logical change.
- Fork release: dedicated `release/encryption-fix` branch, `.exe` as workflow artifact, optional Release on tag push.
- Test fixture: synthetic generation in `conftest.py`, no game data committed.

## References

- Bug report and proof: `~/crimson-desert/CDUMM_MATERIAL_ENCRYPTION_BUG.md`
- Buggy heuristic: `src/cdumm/archive/paz_parse.py:46-64`
- Repack follows the flag: `src/cdumm/archive/paz_repack.py:195-196`, `:360-361`
- Existing override mechanism touched at:
  - `src/cdumm/archive/paz_parse.py:35`
  - `src/cdumm/engine/crimson_browser_handler.py:437,443`
  - `src/cdumm/engine/json_patch_handler.py:346,379,382,391,394,407,410`
  - `src/cdumm/engine/apply_engine.py:4073`
  - `src/cdumm/engine/import_handler.py:1176`
- Crypto primitives: `src/cdumm/archive/paz_crypto.py` (`derive_key_iv`, `encrypt`, `decrypt`)
- PyInstaller spec (reused for Windows): `cdumm.spec`
- Workflow reference (macOS): `.github/workflows/release-macos.yml`
