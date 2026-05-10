"""GitHub #88 (zvitko-hue, CDUMM v3.3.1): Crimson Desert won't
start when launched through CDUMM but works fine from Steam.

Root cause: ``_on_launch_game`` in ``src/cdumm/gui/fluent_window.py``
hands off to ``open_path("steam://rungameid/...")`` for Steam
installs so the Steam DRM bootstrap initialises and the overlay
attaches. If that hand-off raises (Steam client not running, URI
handler refusing the request, etc.), the blanket ``except`` clause
silently falls back to ``subprocess.Popen([str(exe)])`` against
the bare game exe. Crimson Desert is Themida + Denuvo protected:
launching the bare exe without Steam's DRM bootstrap "succeeds"
from Python's perspective (the process spawns) but the game
exits within a fraction of a second. CDUMM still shows a
green "Game launched!" toast because Popen did not raise. To
the user it looks like CDUMM is the one failing.

Fix: do not fall back to bare exe for Steam (or Xbox) installs.
Surface a clear "Could not reach Steam — make sure the Steam
client is running" error instead. Bare-exe fallback is still
appropriate for the "unknown install layout" case where the
user pointed CDUMM at a copy of the game outside any storefront.
"""
from __future__ import annotations

from pathlib import Path


def _launch_source() -> str:
    src_path = (Path(__file__).parent.parent
                / "src" / "cdumm" / "gui" / "fluent_window.py")
    return src_path.read_text(encoding="utf-8")


def _slice_launch_function(src: str) -> str:
    """Return the body of ``_on_launch_game`` from the next def
    onwards. The body is large; slice up to the next top-level
    method def so the test reasons only about the launch path."""
    anchor = src.find("def _on_launch_game(self)")
    assert anchor != -1, "_on_launch_game not found"
    after = src.find("\n    def ", anchor + 5)
    assert after != -1, "could not locate end of _on_launch_game body"
    return src[anchor:after]


def test_bare_exe_fallback_does_not_fire_for_steam_installs():
    """The Steam-URI failure path must NOT fall through to a
    bare-exe ``subprocess.Popen``. Crimson Desert is Themida +
    Denuvo protected; the bare exe spawns then exits within a
    fraction of a second, and the prior code emitted a green
    'Game launched' toast anyway. Franci GitHub #88 was hitting
    this exact path.

    The fix may restructure the error handling in several ways
    (separate try/except per branch, an install-type check at
    the top of the except, removing the fallback entirely), but
    the invariant we enforce is the same: a Steam install that
    fails the URI hand-off must NOT silently spawn the bare exe.
    """
    body = _slice_launch_function(_launch_source())

    # Locate every bare-exe Popen call inside _on_launch_game.
    # For each one, walk backward in the source to find the
    # nearest enclosing conditional / except / branch and require
    # SOMETHING upstream of the Popen explicitly handles the
    # Steam install path differently (either skips this Popen,
    # or the Popen lives inside an `else` of an `is_steam_install`
    # check).
    popen_pat = "Popen([str(exe)]"
    pos = 0
    indices = []
    while True:
        i = body.find(popen_pat, pos)
        if i == -1:
            break
        indices.append(i)
        pos = i + len(popen_pat)

    assert indices, (
        "no Popen([str(exe)] in _on_launch_game; the test needs "
        "updating if the launcher no longer uses this exact "
        "spawn shape")

    for i in indices:
        # Look at the 3000-char window BEFORE this Popen call.
        # The Steam-aware code may live either as the explicit
        # `is_steam_install` call high in the function, or as a
        # short local boolean used in conditional gates near the
        # Popen site. Either is fine -- the invariant is just
        # that the code knows about Steam at this site and the
        # Popen lives in a non-Steam branch.
        window = body[max(0, i - 3000):i]
        has_install_check = (
            "is_steam_install" in window
            or "if steam" in window
            or "if not steam" in window
            or "elif" in window  # an `elif xbox` or `elif not steam` etc
        )
        assert has_install_check, (
            f"Bare-exe Popen at offset {i} in _on_launch_game has "
            f"no Steam/Xbox install gate upstream. On Steam "
            f"installs this silently bypasses DRM bootstrap. "
            f"GitHub #88. Window before Popen:\n{window[-500:]}"
        )


def test_steam_uri_failure_surfaces_a_specific_error_message():
    """When the Steam URI hand-off fails, the user must see a
    message that explicitly mentions Steam (so they know to start
    it), not a generic 'launch failed: <exception>' that gives
    them nothing to act on."""
    body = _slice_launch_function(_launch_source())
    # Either translation-key or literal-string — any one is fine,
    # as long as the user-facing copy hints at Steam being the
    # likely cause when the Steam-URI branch fails.
    hints = (
        "steam_not_running",
        "steam_client",
        "Make sure the Steam client",
        "Could not reach Steam",
        "launch_failed_steam",
    )
    assert any(h in body for h in hints), (
        "Expected the launch error handler to surface a Steam-"
        "specific message when the Steam URI hand-off fails. None "
        "of the expected hints found in _on_launch_game:\n  "
        + "\n  ".join(hints))
