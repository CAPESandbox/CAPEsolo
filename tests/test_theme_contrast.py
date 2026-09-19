"""Contrast audit of the theme palettes.

The original UI failed here in a way that is easy to reintroduce: grey-on-grey disabled
text, a warning amber that disappeared into the card, and selection fills that swallowed
the text drawn on them. These are arithmetic properties of the palette, so they are checked
directly against the token tables rather than by looking at a screenshot.

Thresholds are WCAG 2.1: 4.5:1 for body text, 3:1 for large text and for non-text elements
that carry meaning (borders, fills, the countdown bar).

No display and no wx.App needed - only the RGB tables are read:

    ./.venv/Scripts/python.exe -m pytest tests/test_theme_contrast.py
"""

import pytest

from CAPEsolo.classes.theme import DARK, LIGHT, _PALETTES

TEXT_RATIO = 4.5
NON_TEXT_RATIO = 3.0

MODES = (DARK, LIGHT)


def luminance(rgb):
    """Relative luminance, WCAG 2.1 definition."""
    channels = []
    for value in rgb:
        value /= 255
        channels.append(
            value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4
        )
    red, green, blue = channels
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def ratio(first, second):
    lighter, darker = sorted((luminance(first), luminance(second)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def contrast(mode, foreground, background):
    palette = _PALETTES[mode]
    return ratio(palette[foreground], palette[background])


# (foreground, background) pairs that carry text.
TEXT_PAIRS = [
    ("FG_PRIMARY", "BG_MAIN"),
    ("FG_PRIMARY", "BG_CARD"),
    ("FG_PRIMARY", "BG_INPUT"),
    ("FG_PRIMARY", "BG_SURFACE"),
    ("FG_PRIMARY", "GRID_ROW_ALT"),
    ("FG_SECONDARY", "BG_MAIN"),
    ("FG_SECONDARY", "BG_CARD"),
    ("FG_SELECT", "BG_SELECT"),
    ("FG_RED_ALERT", "BG_RED_ALERT"),
    ("FG_RED_ALERT", "BG_CARD"),
    ("FG_ON_ACCENT", "ACCENT"),
    ("FG_ON_ACCENT", "ACCENT_HOVER"),
    ("FG_ON_DANGER", "DANGER"),
    ("FG_ON_SUCCESS", "SUCCESS"),
]

# Elements that are read as shapes rather than as text: fills, borders, indicators.
NON_TEXT_PAIRS = [
    ("ACCENT", "BG_CARD"),
    ("FOCUS_RING", "BG_CARD"),
    ("FOCUS_RING", "BG_INPUT"),
    ("BORDER_STRONG", "BG_CARD"),
    ("TIMER_WARN", "BG_CARD"),
    ("ACCENT_RED", "BG_CARD"),
    ("ACCENT_CYAN", "BG_CARD"),
]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("foreground,background", TEXT_PAIRS)
def test_text_contrast(mode, foreground, background):
    measured = contrast(mode, foreground, background)
    assert measured >= TEXT_RATIO, (
        f"{mode}: {foreground} on {background} is {measured:.2f}:1, needs {TEXT_RATIO}:1"
    )


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("foreground,background", NON_TEXT_PAIRS)
def test_non_text_contrast(mode, foreground, background):
    measured = contrast(mode, foreground, background)
    assert measured >= NON_TEXT_RATIO, (
        f"{mode}: {foreground} on {background} is {measured:.2f}:1, needs {NON_TEXT_RATIO}:1"
    )


@pytest.mark.parametrize("mode", MODES)
def test_disabled_text_is_dim_but_legible(mode):
    """Disabled text is allowed to fall under the body threshold - that is the point of it -
    but not to vanish. The native controls this replaced rendered disabled labels at roughly
    1.5:1, which is what made the old UI unreadable."""
    measured = contrast(mode, "FG_DISABLED", "BG_DISABLED")
    assert measured >= NON_TEXT_RATIO, (
        f"{mode}: disabled text is {measured:.2f}:1, needs {NON_TEXT_RATIO}:1"
    )
    assert measured < TEXT_RATIO, (
        f"{mode}: disabled text is {measured:.2f}:1, which is not visibly disabled"
    )


@pytest.mark.parametrize("mode", MODES)
def test_surfaces_are_distinguishable(mode):
    """Cards have to read as sitting on the window, and inputs as wells inside the cards.
    The separation is small by design, so this only checks the ordering holds and that no
    two adjacent surfaces collapse into the same colour."""
    palette = _PALETTES[mode]
    assert palette["BG_MAIN"] != palette["BG_CARD"]
    assert palette["BG_CARD"] != palette["BG_INPUT"]
    # A border is what carries the edge when the fills are close, so it must clear the card.
    assert ratio(palette["BORDER_SUBTLE"], palette["BG_CARD"]) > 1.05


@pytest.mark.parametrize("mode", MODES)
def test_every_token_exists_in_both_palettes(mode):
    """A token missing from one palette only fails when that theme is selected at runtime."""
    other = LIGHT if mode == DARK else DARK
    assert set(_PALETTES[mode]) == set(_PALETTES[other])
