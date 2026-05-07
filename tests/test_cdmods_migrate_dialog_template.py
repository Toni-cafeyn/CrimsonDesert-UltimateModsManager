"""Regression: the migrate-confirmation dialog template must
substitute its {old} / {new} placeholders (I2).

Before, settings_page called
    tr("settings.cdmods_path_migrate_confirm_text")
with no kwargs, so the placeholders printed literally as '{old}' and
'{new}'. The actual paths were shown in a separate
``setInformativeText`` block, which made the template body dead text.

After, the call passes ``old=...`` and ``new=...`` and the informative-
text block is gone , the user sees the resolved paths inline.
"""
from __future__ import annotations

import pytest

from cdumm.i18n import load as load_translations, tr

load_translations("en")


def test_template_substitutes_old_and_new():
    """tr() with old/new kwargs returns a string containing both
    paths and no remaining placeholders."""
    rendered = tr(
        "settings.cdmods_path_migrate_confirm_text",
        old="C:/old/CDMods",
        new="D:/big/CDMods",
    )
    assert "C:/old/CDMods" in rendered
    assert "D:/big/CDMods" in rendered
    assert "{old}" not in rendered
    assert "{new}" not in rendered


def test_template_without_kwargs_does_not_swallow_braces():
    """When called without kwargs (defensive: legacy callers), tr()
    must not crash; placeholders may remain literal but the call
    completes."""
    # tr() is permissive with missing kwargs; we just check it
    # doesn't raise.
    out = tr("settings.cdmods_path_migrate_confirm_text")
    assert isinstance(out, str)
    assert len(out) > 0
