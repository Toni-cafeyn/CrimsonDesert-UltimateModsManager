"""Widget tests for the preset selector radio row."""
from __future__ import annotations

import pytest


@pytest.fixture
def app(qtbot):
    """Returns the QApplication via pytest-qt."""
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    return app


def test_preset_selector_inserted_for_tagged_patches(qtbot, app):
    from cdumm.gui.components.config_panel import ConfigPanel

    panel = ConfigPanel()
    qtbot.addWidget(panel)
    patches = [
        {"label": "[0%] foo", "enabled": True},
        {"label": "[100%] foo", "enabled": False},
        {"label": "[0%] bar", "enabled": True},
        {"label": "[100%] bar", "enabled": False},
    ]
    panel.show_mod(
        mod_id=1, name="t", author="x", version="1",
        status="active", file_count=1, patches=patches, conflicts=[],
    )
    assert panel._preset_radio_group is not None
    # 2 preset tags + 1 Custom = 3 radios
    assert len(panel._preset_radio_group.buttons()) == 3
    labels = sorted(b.text() for b in panel._preset_radio_group.buttons())
    assert "0%" in labels
    assert "100%" in labels
    assert "Custom" in labels


def test_no_preset_selector_for_flat_patches(qtbot, app):
    from cdumm.gui.components.config_panel import ConfigPanel

    panel = ConfigPanel()
    qtbot.addWidget(panel)
    patches = [
        {"label": "Patch one", "enabled": True},
        {"label": "Patch two", "enabled": False},
    ]
    panel.show_mod(
        mod_id=1, name="t", author="x", version="1",
        status="active", file_count=1, patches=patches, conflicts=[],
    )
    assert panel._preset_radio_group is None


def test_custom_selected_by_default_when_no_current_preset(qtbot, app):
    from cdumm.gui.components.config_panel import ConfigPanel

    panel = ConfigPanel()
    qtbot.addWidget(panel)
    patches = [
        {"label": "[0%] foo", "enabled": True},
        {"label": "[100%] foo", "enabled": False},
    ]
    panel.show_mod(
        mod_id=1, name="t", author="x", version="1",
        status="active", file_count=1, patches=patches, conflicts=[],
    )
    checked = [b for b in panel._preset_radio_group.buttons() if b.isChecked()]
    assert len(checked) == 1
    assert checked[0].text() == "Custom"
