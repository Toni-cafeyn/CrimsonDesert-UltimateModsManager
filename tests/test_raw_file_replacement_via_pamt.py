"""Manifest-less loose-file replacement mods that ship raw game files
at the engine's internal path layout must import cleanly.

Bug 2026-05-09 (Faisal verified via diagnostic, mods 1299
'Aeserion Dragonslayer Greatsword V3' and 2406 'Healthbar Always On'):
CDUMM rejects mods that consist of replacement files dropped at the
game's true internal paths (e.g. ``character/.../cd_phm_02_sword_0042.pac``,
``gamedata/binary__/client/bin/skill.pabgb``) without a manifest.

Why it fails: ``_match_game_files`` only knows how to match files
against the snapshot's PAZ-archive index (the 209 ``NNNN/N.paz`` /
``NNNN/N.pamt`` entries) or the ``_GAME_FILE_RE`` regex which is
limited to that same shape. Inner-archive paths like
``character/...`` never match either, so the import falls through
to the generic "no recognized format" rejection.

Fix: when the existing detectors find nothing, try a PAMT entry
lookup for each file the user dropped. ``_find_pamt_entry`` already
resolves an inner-game path to its PazEntry. Each match becomes an
ENTR-style delta with the file's contents as the new bytes,
reusing the same delta machinery JSON byte-patch mods already use.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest


@dataclass
class _FakePazEntry:
    path: str
    paz_file: str
    offset: int = 0
    comp_size: int = 100
    orig_size: int = 100
    compression_type: int = 0
    flags: int = 0
    paz_index: int = 0
    encrypted: bool = False


def _make_mod_tree(tmp_path: Path,
                   relpaths: list[str]) -> Path:
    """Materialise a folder of replacement files at internal paths.

    Each ``relpath`` is a forward-slash game-internal path. The
    file content is just the bytes of that path so the test can
    distinguish files later."""
    root = tmp_path / "synthetic_mod"
    root.mkdir()
    for rel in relpaths:
        out = root / rel.replace("/", "/")
        # On Windows tmp paths, build via Path operations to avoid
        # POSIX vs Windows separator confusion at file-creation time.
        out_path = root
        for piece in rel.split("/"):
            out_path = out_path / piece
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(rel.encode("utf-8"))
    return root


def test_detect_returns_matches_for_inner_path_replacements(
        tmp_path, monkeypatch):
    """The detector walks every file, asks _find_pamt_entry to
    resolve each candidate path, and returns one (rel_path,
    source_file, PazEntry) per file that resolves."""
    from cdumm.engine import import_handler as ih

    rel = "character/model/1_pc/foo/cd_phm_02_sword_0042.pac"
    mod_dir = _make_mod_tree(tmp_path, [rel])

    fake_entry = _FakePazEntry(
        path=rel,
        paz_file=str(tmp_path / "fake_game" / "0009" / "1.paz"))

    def fake_find_pamt_entry(game_file, game_dir):
        return fake_entry if game_file == rel else None

    monkeypatch.setattr(ih, "_find_pamt_entry", fake_find_pamt_entry,
                        raising=False)
    # If the symbol is imported lazily inside the function, patch the
    # source module too.
    from cdumm.engine import json_patch_handler as jph
    monkeypatch.setattr(jph, "_find_pamt_entry", fake_find_pamt_entry)

    fake_game_dir = tmp_path / "fake_game"
    fake_game_dir.mkdir()

    matches = ih._detect_raw_file_replacements_via_pamt(
        mod_dir, fake_game_dir)

    assert len(matches) == 1, (
        f"expected 1 match for the .pac file, got {len(matches)}: "
        f"{matches}"
    )
    matched_rel, src, entry = matches[0]
    assert matched_rel == rel
    assert src.read_bytes() == rel.encode("utf-8")
    assert entry.path == rel


def test_detect_skips_readme_and_other_non_game_files(
        tmp_path, monkeypatch):
    """Readmes, license files, screenshots, etc. live alongside
    the actual replacement files and must NOT be force-imported.
    Anything that doesn't resolve via PAMT is silently dropped."""
    from cdumm.engine import import_handler as ih
    from cdumm.engine import json_patch_handler as jph

    real_rel = "gamedata/binary__/client/bin/skill.pabgb"
    mod_dir = _make_mod_tree(tmp_path, [
        real_rel,
        "Readme.txt",
        "screenshots/preview.png",
    ])

    def fake_find_pamt_entry(game_file, game_dir):
        if game_file == real_rel:
            return _FakePazEntry(path=real_rel, paz_file="x")
        return None

    monkeypatch.setattr(ih, "_find_pamt_entry", fake_find_pamt_entry,
                        raising=False)
    monkeypatch.setattr(jph, "_find_pamt_entry", fake_find_pamt_entry)

    matches = ih._detect_raw_file_replacements_via_pamt(
        mod_dir, tmp_path / "fake_game")

    assert len(matches) == 1
    assert matches[0][0] == real_rel


def test_detect_tries_progressively_shorter_relative_paths(
        tmp_path, monkeypatch):
    """Mod authors often nest the game tree under an outer folder
    (e.g. ``MyMod/character/...`` instead of ``character/...``).
    The detector must try each suffix of the relative path so the
    PAMT lookup can succeed regardless of nesting depth."""
    from cdumm.engine import import_handler as ih
    from cdumm.engine import json_patch_handler as jph

    inner_rel = "character/model/1_pc/foo.pac"
    mod_dir = _make_mod_tree(tmp_path, ["MyModName/" + inner_rel])

    def fake_find_pamt_entry(game_file, game_dir):
        if game_file == inner_rel:
            return _FakePazEntry(path=inner_rel, paz_file="x")
        return None

    monkeypatch.setattr(ih, "_find_pamt_entry", fake_find_pamt_entry,
                        raising=False)
    monkeypatch.setattr(jph, "_find_pamt_entry", fake_find_pamt_entry)

    matches = ih._detect_raw_file_replacements_via_pamt(
        mod_dir, tmp_path / "fake_game")

    assert len(matches) == 1
    assert matches[0][0] == inner_rel


def test_detect_returns_empty_when_no_files_resolve(
        tmp_path, monkeypatch):
    """If no file in the mod folder resolves via PAMT, return an
    empty list so the caller can fall through to the existing
    'no recognized format' error path."""
    from cdumm.engine import import_handler as ih
    from cdumm.engine import json_patch_handler as jph

    mod_dir = _make_mod_tree(tmp_path, [
        "Readme.txt",
        "config/settings.json",
    ])

    def fake_find_pamt_entry(game_file, game_dir):
        return None

    monkeypatch.setattr(ih, "_find_pamt_entry", fake_find_pamt_entry,
                        raising=False)
    monkeypatch.setattr(jph, "_find_pamt_entry", fake_find_pamt_entry)

    matches = ih._detect_raw_file_replacements_via_pamt(
        mod_dir, tmp_path / "fake_game")

    assert matches == []
