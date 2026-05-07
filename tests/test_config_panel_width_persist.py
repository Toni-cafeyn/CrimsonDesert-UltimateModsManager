"""Tests for ConfigPanel width persistence (Task 2.2)."""
from __future__ import annotations

import pytest


@pytest.fixture
def app(qtbot):
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture
def db(tmp_path):
    from cdumm.storage.database import Database
    db = Database(tmp_path / "test.db")
    db.initialize()
    return db


def _show_simple_mod(panel):
    panel.show_mod(
        mod_id=1, name="t", author="x", version="1",
        status="active", file_count=1,
        patches=[{"label": "p", "enabled": True}], conflicts=[],
    )


def test_set_panel_width_persist_true_saves_to_config(qtbot, app, db):
    """Explicit persist=True commits the width to the DB."""
    from cdumm.gui.components.config_panel import ConfigPanel
    from cdumm.storage.config import Config

    panel = ConfigPanel()
    panel.set_db(db)
    qtbot.addWidget(panel)
    panel.set_panel_width(800, persist=True)
    assert Config(db).get("config_panel_width") == "800"


def test_set_panel_width_default_does_not_persist(qtbot, app, db):
    """Default set_panel_width call (no persist kwarg) must NOT write
    to the DB. The drag handle relies on this — without it, every
    pixel of mouse motion would issue a SQLite commit."""
    from cdumm.gui.components.config_panel import ConfigPanel
    from cdumm.storage.config import Config

    panel = ConfigPanel()
    panel.set_db(db)
    qtbot.addWidget(panel)
    panel.set_panel_width(800)
    # Width applied to the widget but the DB key is unset.
    assert panel._PANEL_WIDTH == 800
    assert Config(db).get("config_panel_width") is None


def test_persist_panel_width_writes_current_value(qtbot, app, db):
    """persist_panel_width() commits whatever _PANEL_WIDTH is now."""
    from cdumm.gui.components.config_panel import ConfigPanel
    from cdumm.storage.config import Config

    panel = ConfigPanel()
    panel.set_db(db)
    qtbot.addWidget(panel)
    panel.set_panel_width(750)
    panel.persist_panel_width()
    assert Config(db).get("config_panel_width") == "750"


def test_drag_simulation_writes_db_once_on_release(qtbot, app, db):
    """50 mid-drag set_panel_width() calls + 1 persist (release)
    must produce exactly ONE row in the DB, not 50.

    Wraps ``db.connection`` in a counting proxy so every
    ``execute(INSERT ... config_panel_width ...)`` increments a
    counter. Drag-time set_panel_width() calls must NOT call execute;
    the single persist on release must produce exactly one increment.
    """
    from cdumm.gui.components.config_panel import ConfigPanel

    panel = ConfigPanel()
    panel.set_db(db)
    qtbot.addWidget(panel)

    write_count = {"n": 0}
    real_conn = db.connection

    class _CountingConn:
        """Pass-through proxy around sqlite3.Connection that counts
        INSERT/REPLACE/UPDATE statements touching the
        config_panel_width key.

        sqlite3.Connection.execute is a read-only C method so we can't
        monkey-patch it directly; this proxy intercepts the call.
        """
        def execute(self, sql, params=()):
            sql_upper = sql.upper().lstrip()
            if (sql_upper.startswith("INSERT")
                    or sql_upper.startswith("REPLACE")
                    or sql_upper.startswith("UPDATE")):
                try:
                    if "config_panel_width" in tuple(params):
                        write_count["n"] += 1
                except TypeError:
                    pass
            return real_conn.execute(sql, params)

        def __getattr__(self, name):
            return getattr(real_conn, name)

    # Database.connection is a read-only @property; swap the underlying
    # _connection slot the property reads from.
    db._connection = _CountingConn()
    try:
        # Simulate 50 mid-drag width updates (no persist).
        for i in range(50):
            panel.set_panel_width(500 + i)
        # Single release-time persist.
        panel.persist_panel_width()
    finally:
        db._connection = real_conn

    assert write_count["n"] == 1, (
        f"Expected exactly 1 SQLite write on release, got "
        f"{write_count['n']} (mid-drag calls leaking writes)"
    )


def test_set_panel_width_no_db_no_crash(qtbot, app):
    """Backward compat: panels without set_db() shouldn't crash on resize."""
    from cdumm.gui.components.config_panel import ConfigPanel

    panel = ConfigPanel()
    qtbot.addWidget(panel)
    panel.set_panel_width(800)  # must not raise
    panel.set_panel_width(800, persist=True)  # also must not raise
    panel.persist_panel_width()  # also must not raise
    assert panel._PANEL_WIDTH == 800


def test_set_db_restores_saved_width(qtbot, app, db):
    """When set_db is called and the DB has a saved width, the
    panel should adopt that width."""
    from cdumm.gui.components.config_panel import ConfigPanel
    from cdumm.storage.config import Config

    Config(db).set("config_panel_width", "900")
    panel = ConfigPanel()
    qtbot.addWidget(panel)
    panel.set_db(db)
    assert panel._PANEL_WIDTH == 900


def test_saved_width_is_clamped_on_restore(qtbot, app, db):
    """A garbage / out-of-range saved value should be clamped, not used raw."""
    from cdumm.gui.components.config_panel import ConfigPanel
    from cdumm.storage.config import Config

    Config(db).set("config_panel_width", "5000")
    panel = ConfigPanel()
    qtbot.addWidget(panel)
    panel.set_db(db)
    assert panel._PANEL_WIDTH == 1200  # clamped to max


def test_invalid_saved_width_falls_back_to_default(qtbot, app, db):
    """Non-integer saved value falls back to default (640)."""
    from cdumm.gui.components.config_panel import ConfigPanel
    from cdumm.storage.config import Config

    Config(db).set("config_panel_width", "not_a_number")
    panel = ConfigPanel()
    qtbot.addWidget(panel)
    panel.set_db(db)
    assert panel._PANEL_WIDTH == 640  # default


def test_empty_string_saved_width_falls_back_to_default(qtbot, app, db):
    """An empty-string saved value (e.g. from a stray Config.set with
    empty arg) must fall back to the default rather than skip
    restoration silently. The old code used ``if saved:`` which
    short-circuits on '' — so a corrupted empty value was treated the
    same as missing, masking the bug. The new ``if saved is not None``
    forces int() conversion which raises ValueError and lands in the
    fallback branch."""
    from cdumm.gui.components.config_panel import ConfigPanel
    from cdumm.storage.config import Config

    Config(db).set("config_panel_width", "")
    panel = ConfigPanel()
    qtbot.addWidget(panel)
    panel.set_db(db)
    assert panel._PANEL_WIDTH == 640  # default, no crash
