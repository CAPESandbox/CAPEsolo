"""
Centralized design tokens for CAPEsolo's wxPython UI, in a dark or light palette.

Usage:
    from .theme import apply_theme, BG_MAIN, BG_CARD, BG_INPUT
    from .theme import FG_PRIMARY, FG_SECONDARY
    from .theme import ACCENT_RED, ACCENT_GREEN, ACCENT_ORANGE, ACCENT_ERROR
    from .theme import FONT_UI, FONT_BOLD, FONT_CODE

    # In any panel/frame __init__, after building the widget tree:
    apply_theme(self)

Select the palette with a [gui] section in cfg.ini:

    [gui]
    theme = light        ; light | dark (default: dark)

The colour tokens are wx.Colour objects mutated in place by set_theme(), so modules
that did `from .theme import BG_INPUT` see the change without being reimported.
"""

import configparser
import logging
import os
import sys
from contextlib import suppress

import wx
import wx.grid as gridlib

from CAPEsolo.capelib.config_paths import config_paths, user_config_path

log = logging.getLogger(__name__)

DARK = "dark"
LIGHT = "light"
DEFAULT_THEME = DARK

# ---------------------------------------------------------------------------
# ThemeFont — A lazy wrapper around wx.Font to avoid PyNoAppError at import time.
# ---------------------------------------------------------------------------
class ThemeFont(wx.Font):
    def __init__(self, *args, **kwargs):
        self._args = args
        self._kwargs = kwargs
        self._initialized = False

    def _init_real(self):
        if not self._initialized:
            super().__init__(*self._args, **self._kwargs)
            self._initialized = True


# ---------------------------------------------------------------------------
# Color tokens — Safe at import time (wx.Colour does not require wx.App)
# Structured dark theme design system to make control boundaries highly clear.
# ---------------------------------------------------------------------------
BG_MAIN    = wx.Colour(24,  28,  36)   # #181c24 - soft dark slate base background
BG_CARD    = wx.Colour(33,  38,  49)   # #212631 - distinct lighter card background
BG_INPUT   = wx.Colour(15,  17,  21)   # #0f1115 - inset dark grey for inputs (creates a "wells" look)
BG_BUTTON  = wx.Colour(53,  60,  77)   # #353c4d - raised slate grey for clickable buttons
# Dropdowns are all CB_READONLY pickers, so they read as controls rather than text wells.
# Pitched away from BG_CARD far enough to give a visible edge without dulling the text.
BG_DROPDOWN = wx.Colour(66, 74,  94)   # #424a5e

FG_PRIMARY   = wx.Colour(201, 209, 217)  # #c9d1d9 - soft grey-white text (GitHub/VS Code standard)
FG_SECONDARY = wx.Colour(139, 148, 158)  # #8b949e - cool muted grey text

# Selection. The Windows system highlight is a saturated blue (0,120,215) that gives only
# ~3:1 against our body text and ~1.1:1 against the syntax colours, so grids override it.
BG_SELECT = wx.Colour(30,  64,  102)     # #1e4066 - selected row fill
FG_SELECT = wx.Colour(201, 209, 217)     # #c9d1d9 - selected row text

# Premium Red alert styling for warnings/emergency actions (high contrast, low fatigue)
BG_RED_ALERT = wx.Colour(92,  29,  29)   # #5c1d1d - deep crimson warning background
FG_RED_ALERT = wx.Colour(255, 180, 180)  # #ffb4b4 - soft light red text for legibility

ACCENT_CYAN   = wx.Colour(88,  166, 255)  # #58a6ff - premium cyan accent for headers/group boundaries
ACCENT_RED    = wx.Colour(255, 51,  51)   # #ff3333

# Row-highlight backgrounds for the debugger lists, drawn underneath FG_PRIMARY. On a dark
# palette these have to be deep tints: saturated fills leave the light text unreadable.
ACCENT_GREEN  = wx.Colour(22,  80,  52)   # #165034 - CIP row
ACCENT_ORANGE = wx.Colour(94,  63,  8)    # #5e3f08 - stack pointer row
ACCENT_ERROR  = wx.Colour(138, 34,  34)   # #8a2222 - breakpoint row

# Disassembly mnemonic colours. Tokens rather than wx.BLUE/wx.GREEN so they can be tuned
# per palette: pure blue is unreadable on a dark background and pure green on a light one.
ACCENT_CALL = wx.Colour(110, 178, 255)    # #6eb2ff - call instructions
ACCENT_JUMP = wx.Colour(0,   255, 0)      # #00ff00 - jmp / conditional jumps

# Countdown bar, "running low" state. ACCENT_ORANGE cannot be reused: it is a deep row-tint
# meant to sit underneath text, so as a solid fill it reads as almost nothing.
TIMER_WARN = wx.Colour(210, 153, 34)      # #d29922

# ---------------------------------------------------------------------------
# Surface, border, state and semantic-action tokens.
#
# These exist because the tokens above describe only resting fills: they can say what a
# button looks like, but not what it looks like under the pointer, held down, focused or
# disabled. Native MSW controls did not need them (the OS drew those states, ignoring our
# colours in the process); the owner-drawn controls in ui_kit.py have to draw every state
# themselves, so each one needs a name here rather than an ad-hoc tweak at the call site.
# ---------------------------------------------------------------------------

# Elevation. BG_MAIN is the window, BG_CARD a grouped section, BG_SURFACE something raised
# above a card (a popup, a header row, a hovered tab).
BG_SURFACE = wx.Colour(39,  45,  58)     # #272d3a

# Borders. SUBTLE separates regions that are already distinguished by fill; STRONG outlines
# a control that has to read as interactive against a similar background.
BORDER_SUBTLE = wx.Colour(44,  51,  64)  # #2c3340
BORDER_STRONG = wx.Colour(61,  70,  87)  # #3d4657

# Interaction states, applied to buttons, tabs, list rows and anything else clickable.
BG_HOVER   = wx.Colour(44,  52,  68)     # #2c3444
BG_PRESSED = wx.Colour(27,  32,  40)     # #1b2028

# Disabled. wxMSW draws native controls' disabled text in a system grey that ignores the
# palette, which is why disabled buttons are barely legible on the dark theme today; the
# owner-drawn controls use these instead. FG_DISABLED still clears 3:1 against BG_CARD, so
# a disabled label is dim but readable rather than invisible.
FG_DISABLED = wx.Colour(110, 118, 129)   # #6e7681
BG_DISABLED = wx.Colour(35,  40,  52)    # #232834

# Primary action. A single accent, shared by focus rings, the active tab indicator, links
# and primary buttons, so the eye has exactly one thing to follow per screen.
ACCENT          = wx.Colour(88,  166, 255)  # #58a6ff
ACCENT_HOVER    = wx.Colour(121, 192, 255)  # #79c0ff
ACCENT_PRESSED  = wx.Colour(56,  139, 253)  # #388bfd
FG_ON_ACCENT    = wx.Colour(13,  17,  23)   # #0d1117 - dark text on the light accent fill
FOCUS_RING      = wx.Colour(88,  166, 255)  # #58a6ff

# Destructive action (Kill, Delete). Distinct from ACCENT_RED, which is a text/plot colour.
DANGER        = wx.Colour(218, 54,  51)   # #da3633
DANGER_HOVER  = wx.Colour(248, 81,  73)   # #f85149
FG_ON_DANGER  = wx.Colour(255, 255, 255)  # #ffffff

# Confirmed / running (Launch). ACCENT_GREEN is a row tint and far too dark for a fill that
# has to carry a label, so the button green is its own token.
SUCCESS        = wx.Colour(35,  134, 54)   # #238636
SUCCESS_HOVER  = wx.Colour(46,  160, 67)   # #2ea043
FG_ON_SUCCESS  = wx.Colour(255, 255, 255)  # #ffffff

# ---------------------------------------------------------------------------
# Spacing and radius scale, in DIPs. Pass through dip() before use.
#
# Every border= and AddSpacer() in the UI was a bare literal (5, 8, 10, 12, 24 all appear
# within one panel), which is most of why the layout reads as arbitrary. These are the only
# gaps the UI is allowed to use.
# ---------------------------------------------------------------------------
SP_XS  = 4
SP_SM  = 8
SP_MD  = 12
SP_LG  = 16
SP_XL  = 24
SP_2XL = 32

RADIUS_SM = 4    # inputs, small buttons
RADIUS_MD = 6    # buttons, pickers
RADIUS_LG = 10   # cards, popups

# Stroke width for focus rings and control outlines, in DIPs.
BORDER_WIDTH = 1
FOCUS_WIDTH = 2


# ---------------------------------------------------------------------------
# Font tokens — Must be ThemeFont instances to delay C++ initialization
#
# A type scale, not a single size: with everything at FONT_UI the only way to signal "this
# is a section, that is a field" was to draw a box around it, which is what makes the
# current UI read as a wall of controls. Sizes are points, resolved against the display DPI
# by wx, so these do not need dip().
# ---------------------------------------------------------------------------
FONT_UI   = ThemeFont(10, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, faceName="Segoe UI")
FONT_BOLD = ThemeFont(10, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD,   faceName="Segoe UI")
FONT_CODE = ThemeFont(10, wx.FONTFAMILY_MODERN,  wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, faceName="Consolas")

# Card and dialog titles.
FONT_H1 = ThemeFont(13, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD, faceName="Segoe UI")
# Section headers inside a card, and tab labels.
FONT_H2 = ThemeFont(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD, faceName="Segoe UI")
# Hints, units, status text - anything secondary to the control it annotates.
FONT_SMALL = ThemeFont(9, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, faceName="Segoe UI")
# Dense monospace: hex views, address columns, log tails.
FONT_CODE_SMALL = ThemeFont(9, wx.FONTFAMILY_MODERN, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, faceName="Consolas")

_FONTS = (FONT_UI, FONT_BOLD, FONT_CODE, FONT_H1, FONT_H2, FONT_SMALL, FONT_CODE_SMALL)

# Face preferences, most wanted first. Segoe UI and Consolas do not exist off Windows, and
# wx's fallback there is a serif face that looks nothing like the target platform, so the
# harness screenshots would be misleading. Resolved once, in _init().
_UI_FACES = ("Segoe UI", "Inter", "Noto Sans", "DejaVu Sans", "Cantarell", "Arial")
_CODE_FACES = ("Consolas", "Cascadia Mono", "JetBrains Mono", "DejaVu Sans Mono", "Liberation Mono", "Monospace")

# ---------------------------------------------------------------------------
# Dark-mode alternating row color for grids
# ---------------------------------------------------------------------------
GRID_ROW_ALT = wx.Colour(25, 30, 40)      # #191e28 - alternating grid row

# ---------------------------------------------------------------------------
# Dark-mode category colors for behavior panel (replaces bright pastels).
# ---------------------------------------------------------------------------
BEHAVIOR_CATEGORY_COLORS = {
    "filesystem":    (80,  50,  20),
    "registry":      (80,  20,  20),
    "process":       (20,  40,  80),
    "threading":     (25,  40,  80),
    "services":      (40,  20,  80),
    "device":        (50,  30,  40),
    "network":       (20,  60,  20),
    "socket":        (20,  60,  20),
    "synchronization": (60, 20,  70),
    "browser":       (20,  55,  20),
    "crypto":        (55,  55,  20),
    "system":        (60,  55,  20),
    "hooking":       (50,  50,  50),
    "misc":          (40,  40,  40),
    "all":           (33,  38,  49),   # == BG_CARD
}

# ---------------------------------------------------------------------------
# Palettes. The dark entries must stay in sync with the literals declared above,
# which are only the pre-set_theme() defaults.
# ---------------------------------------------------------------------------
_PALETTES = {
    DARK: {
        "BG_MAIN":      (24,  28,  36),
        "BG_CARD":      (33,  38,  49),
        "BG_INPUT":     (15,  17,  21),
        "BG_BUTTON":    (53,  60,  77),
        "BG_DROPDOWN":  (66,  74,  94),
        "FG_PRIMARY":   (201, 209, 217),
        "FG_SECONDARY": (139, 148, 158),
        "BG_SELECT":    (30,  64,  102),
        "FG_SELECT":    (201, 209, 217),
        "BG_RED_ALERT": (92,  29,  29),
        "FG_RED_ALERT": (255, 180, 180),
        "ACCENT_CYAN":  (88,  166, 255),
        "ACCENT_RED":   (255, 51,  51),
        "ACCENT_GREEN": (22,  80,  52),
        "ACCENT_ORANGE": (94,  63,  8),
        "ACCENT_ERROR": (138, 34,  34),
        "ACCENT_CALL":  (110, 178, 255),
        "ACCENT_JUMP":  (0,   255, 0),
        "TIMER_WARN":   (210, 153, 34),
        "GRID_ROW_ALT": (25,  30,  40),
        # Surfaces, borders and interaction states (see the token block above).
        "BG_SURFACE":    (39,  45,  58),
        "BORDER_SUBTLE": (44,  51,  64),
        # BG_SURFACE sits ~1.1:1 from BG_CARD, so the border is what actually marks the
        # edge of an input or picker and has to clear 3:1 on its own. #677081 measures
        # 3.04:1; the old #3d4657 was 1.60:1 and the controls lost their outline.
        "BORDER_STRONG": (103, 112, 129),
        "BG_HOVER":      (44,  52,  68),
        "BG_PRESSED":    (27,  32,  40),
        "FG_DISABLED":   (110, 118, 129),
        "BG_DISABLED":   (35,  40,  52),
        "ACCENT":         (88,  166, 255),
        "ACCENT_HOVER":   (121, 192, 255),
        "ACCENT_PRESSED": (56,  139, 253),
        "FG_ON_ACCENT":   (13,  17,  23),
        "FOCUS_RING":     (88,  166, 255),
        "DANGER":         (218, 54,  51),
        "DANGER_HOVER":   (248, 81,  73),
        "FG_ON_DANGER":   (255, 255, 255),
        "SUCCESS":        (35,  134, 54),
        "SUCCESS_HOVER":  (46,  160, 67),
        "FG_ON_SUCCESS":  (255, 255, 255),
    },
    LIGHT: {
        "BG_MAIN":      (236, 239, 244),  # #eceff4 - light grey base
        "BG_CARD":      (246, 248, 250),  # #f6f8fa - card surface
        "BG_INPUT":     (255, 255, 255),  # #ffffff - inputs read as bright wells on light
        "BG_BUTTON":    (225, 228, 232),  # #e1e4e8 - raised grey
        "BG_DROPDOWN":  (191, 197, 207),  # #bfc5cf - dropdowns, distinct from the near-white card
        "FG_PRIMARY":   (36,  41,  47),   # #24292f - near-black body text
        "FG_SECONDARY": (87,  96,  106),  # #57606a - muted label text
        "BG_SELECT":    (204, 232, 255),  # #cce8ff - Explorer-style pale blue selection
        "FG_SELECT":    (36,  41,  47),   # #24292f
        "BG_RED_ALERT": (255, 235, 233),  # #ffebe9 - pale alert fill
        "FG_RED_ALERT": (130, 7,   30),   # #82071e - deep red alert text
        "ACCENT_CYAN":  (9,   105, 218),  # #0969da - group box labels
        "ACCENT_RED":   (207, 34,  46),   # #cf222e
        # Row-highlight backgrounds drawn under FG_PRIMARY. Pastels rather than saturated
        # fills so the near-black text stays readable, but deep enough to be distinguishable
        # from the white BG_INPUT they sit against - a near-white tint reads as no highlight.
        "ACCENT_GREEN": (110, 231, 183),  # #6ee7b7 - CIP row
        "ACCENT_ORANGE": (250, 204, 21),  # #facc15 - stack pointer row
        "ACCENT_ERROR": (252, 165, 165),  # #fca5a5 - breakpoint row
        "ACCENT_CALL":  (9,   105, 218),  # #0969da
        "ACCENT_JUMP":  (26,  127, 55),   # #1a7f37
        # Much darker than the dark-palette amber: measured against the near-white card,
        # #bf8700 gives only 2.95:1 (under the 3:1 needed for a non-text fill) and #d29922
        # is worse still. #8a6100 measures 5.20:1.
        "TIMER_WARN":   (138, 97,  0),    # #8a6100
        "GRID_ROW_ALT": (246, 248, 250),  # #f6f8fa - alternating row on white cells
        # Surfaces, borders and interaction states. Light needs the opposite relationship
        # to dark: a raised surface gets *lighter* than the card, and hover gets darker,
        # because there is no room to brighten past white.
        "BG_SURFACE":    (255, 255, 255),  # #ffffff
        "BORDER_SUBTLE": (216, 222, 228),  # #d8dee4
        # As on dark: BG_SURFACE is white against a near-white card, so the border carries
        # the edge by itself. #88919a measures 3.01:1; #afb8c1 was 1.89:1.
        "BORDER_STRONG": (136, 145, 154),  # #88919a
        "BG_HOVER":      (234, 238, 242),  # #eaeef2
        "BG_PRESSED":    (215, 222, 229),  # #d7dee5
        # #838c96 measures 3.01:1 against BG_DISABLED: dim, still legible. The previous
        # #8c959f cleared the card but only managed 2.68:1 against the disabled fill it is
        # actually drawn on.
        "FG_DISABLED":   (131, 140, 150),  # #838c96
        "BG_DISABLED":   (238, 241, 244),  # #eef1f4
        # The accent has to carry white text here, so it is the deeper blue rather than the
        # dark palette's bright one: #0969da measures 4.61:1 against white.
        "ACCENT":         (9,   105, 218),  # #0969da
        "ACCENT_HOVER":   (7,   87,  186),  # #0757ba
        "ACCENT_PRESSED": (5,   69,  148),  # #054594
        "FG_ON_ACCENT":   (255, 255, 255),  # #ffffff
        "FOCUS_RING":     (9,   105, 218),  # #0969da
        "DANGER":         (207, 34,  46),   # #cf222e - 4.83:1 against white
        "DANGER_HOVER":   (167, 26,  36),   # #a71a24
        "FG_ON_DANGER":   (255, 255, 255),  # #ffffff
        "SUCCESS":        (26,  127, 55),   # #1a7f37 - 4.54:1 against white
        "SUCCESS_HOVER":  (20,  103, 44),   # #14672c
        "FG_ON_SUCCESS":  (255, 255, 255),  # #ffffff
    },
}

_BEHAVIOR_PALETTES = {
    DARK: dict(BEHAVIOR_CATEGORY_COLORS),
    LIGHT: {
        "filesystem":    (255, 237, 213),
        "registry":      (254, 226, 226),
        "process":       (219, 234, 254),
        "threading":     (224, 231, 255),
        "services":      (237, 233, 254),
        "device":        (253, 232, 241),
        "network":       (220, 252, 231),
        "socket":        (220, 252, 231),
        "synchronization": (250, 232, 255),
        "browser":       (226, 252, 231),
        "crypto":        (254, 249, 195),
        "system":        (254, 243, 199),
        "hooking":       (243, 244, 246),
        "misc":          (249, 250, 251),
        "all":           (246, 248, 250),  # == light BG_CARD
    },
}

_mode = DEFAULT_THEME
_initialized = False


def is_dark() -> bool:
    """Whether the active palette is the dark one."""
    return _mode == DARK


def set_theme(mode: str) -> str:
    """Switch the active palette, mutating the colour tokens in place.

    In-place mutation is what lets modules that captured a token by value
    (``from .theme import BG_INPUT``) follow the change without being reimported.
    """
    global _mode
    if mode not in _PALETTES:
        log.warning("Unknown theme %r, falling back to %s", mode, DEFAULT_THEME)
        mode = DEFAULT_THEME

    for name, rgb in _PALETTES[mode].items():
        globals()[name].Set(*rgb)

    BEHAVIOR_CATEGORY_COLORS.clear()
    BEHAVIOR_CATEGORY_COLORS.update(_BEHAVIOR_PALETTES[mode])

    _mode = mode
    return mode


def _read_gui_setting(key: str, fallback: str) -> str:
    """Read one [gui] key from cfg.ini, preferring the user file over the packaged one."""
    config = configparser.ConfigParser()
    try:
        config.read(config_paths())
    except configparser.Error as e:
        log.warning("Could not parse cfg.ini for the [gui] %s setting: %s", key, e)
        return fallback

    return config.get("gui", key, fallback=fallback).strip().lower()


def _read_theme_name() -> str:
    """Read [gui] theme from cfg.ini, preferring the user file over the packaged one."""
    return _read_gui_setting("theme", DEFAULT_THEME)


# Windows 11 21H2. Used as the cut-off for wxMSW's dark mode opt-in, see below.
WINDOWS_11_BUILD = 22000


def native_dark_mode_allowed() -> tuple:
    """Whether to opt wxMSW into dark mode for the widgets we cannot draw, and why.

    The opt-in is all or nothing, and on Windows 10 one part of it is worse than not
    having it: popup menus. wxMSW draws menu items itself once dark mode is on, filling
    the item background from the `DarkMode::Menu` and `DarkMode_ImmersiveStart::Menu`
    visual-style classes. Those classes are a Windows 11 addition; on Windows 10 the
    lookup fails, the background is left to the system - which paints it light - and the
    text is drawn in the dark-mode colour, so the item reads white on white. A light menu
    beside a dark window looks worse than one that follows the theme, but it is legible,
    and legible wins. Reported from a Windows 10 guest VM.

    The rest of the opt-in (tooltips, the grid cell editor, common dialogs) goes with it,
    since wx offers no way to keep those and skip menus. Scrollbars and combo drop-downs
    are unaffected - apply_native_theme() sets `DarkMode_Explorer` on each widget directly,
    which Windows 10 1809+ does support.

    Override with cfg.ini when a build behaves differently to the rule:

        [gui]
        native_dark_mode = always   ; always | never | auto (default)

    Returns (allowed, reason); the reason is logged.
    """
    setting = _read_gui_setting("native_dark_mode", "auto")
    if setting in ("always", "on", "true", "yes", "1"):
        return True, "forced on by cfg.ini"
    if setting in ("never", "off", "false", "no", "0"):
        return False, "disabled in cfg.ini"

    if not sys.platform.startswith("win"):
        return False, "not Windows"

    try:
        build = sys.getwindowsversion().build
    except (AttributeError, OSError):
        # Nothing in the GUI may fail to start because a platform probe is unavailable.
        return False, "cannot read the Windows build"

    if build < WINDOWS_11_BUILD:
        return (
            False,
            f"Windows build {build} has no dark popup menu theme "
            f"(needs {WINDOWS_11_BUILD}+); menu text would be unreadable",
        )

    return True, f"Windows build {build}"


def _write_theme_name(mode: str) -> None:
    """Persist the palette to the user cfg.ini, the copy pip upgrades never overwrite.

    Read-modify-write so the rest of the user's settings survive, and best effort: a
    read-only config directory must not stop the toggle working for the current session.
    """
    path = user_config_path()
    config = configparser.ConfigParser()
    with suppress(configparser.Error, OSError):
        config.read(path)

    if not config.has_section("gui"):
        config.add_section("gui")
    config.set("gui", "theme", mode)

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as handle:
            config.write(handle)
    except OSError as e:
        log.warning("Could not save the theme setting to %s: %s", path, e)


def ToggleTheme() -> str:
    """Switch to the other palette and remember the choice. Returns the new mode.

    Only the tokens change here. set_theme mutates them in place so anything that captured
    one by value follows along, but widgets copied their colours when they were styled, so
    the caller still has to re-walk its tree with apply_theme.
    """
    mode = LIGHT if is_dark() else DARK
    set_theme(mode)
    _write_theme_name(mode)

    return mode


def _resolve_face(candidates, fallbackFamily):
    """First installed face from *candidates*, or the system default for the family.

    wx silently substitutes a missing face, and what it substitutes off Windows is a serif
    that misrepresents how the UI will actually look - which would make every screenshot
    taken on the dev box misleading.
    """
    try:
        installed = {name.lower() for name in wx.FontEnumerator.GetFacenames()}
    except Exception:
        return candidates[0]

    for face in candidates:
        if face.lower() in installed:
            return face

    return wx.SystemSettings.GetFont(wx.SYS_DEFAULT_GUI_FONT).GetFaceName()


def _init():
    """Select the palette and build all wx.Font objects. Called once after wx.App exists."""
    global _initialized
    if _initialized:
        return

    set_theme(_read_theme_name())

    uiFace = _resolve_face(_UI_FACES, wx.FONTFAMILY_DEFAULT)
    codeFace = _resolve_face(_CODE_FACES, wx.FONTFAMILY_MODERN)
    for font in _FONTS:
        # _args is (pointSize, family, style, weight); the face is a keyword.
        family = font._args[1]
        font._kwargs["faceName"] = codeFace if family == wx.FONTFAMILY_MODERN else uiFace
        font._init_real()

    _initialized = True


def dip(window, value):
    """Scale a DIP spacing/radius token to physical pixels for *window*'s display.

    The tokens are declared at 96 DPI. FromDIP is per-window because a multi-monitor setup
    can mix scale factors, and it needs a realised window, so this is called at layout time
    rather than at import time.
    """
    if window is None:
        return value
    try:
        return window.FromDIP(value)
    except Exception:
        # wx < 4.1 and some GTK builds; the unscaled value is the 96 DPI answer.
        return value


def dip_size(window, width, height):
    """wx.Size from DIP dimensions. -1 (meaning 'best size') is passed through unscaled."""
    return wx.Size(
        width if width < 0 else dip(window, width),
        height if height < 0 else dip(window, height),
    )


def band_rows(listCtrl):
    """Shade every other row of a report-mode ListCtrl, as the grids are shaded.

    wx can do this itself, but only for virtual controls: EnableAlternateRowColours asserts
    otherwise. Ours are ordinary controls, so the colour goes on per item, which means this
    has to be called after the items are inserted and again after they are replaced.
    """
    for row in range(listCtrl.GetItemCount()):
        listCtrl.SetItemBackgroundColour(
            row, GRID_ROW_ALT if row % 2 == 0 else BG_INPUT
        )


def lock_font(widget, font):
    """Set *font* on *widget* and stop apply_theme from overwriting it.

    The theme walker assigns FONT_UI to every StaticText, Button and CheckBox it sees,
    which is right for body text and wrong for anything deliberately set to another step of
    the type scale: a card title styled FONT_H2 at construction came back out of the walker
    as FONT_UI, so headings were indistinguishable from the rows beneath them.
    """
    widget.SetFont(font)
    widget._lockedFont = font
    return widget


def _set_font(widget, font):
    """Apply the theme's font unless the widget asked to keep its own."""
    locked = getattr(widget, "_lockedFont", None)
    widget.SetFont(locked if locked is not None else font)


# ---------------------------------------------------------------------------
# Immersive Dark Mode for Windows Frame Title Bars
# ---------------------------------------------------------------------------
def apply_window_theme(frame):
    """Set the title bar to match the active palette, for a top-level window (Frame or Dialog)
    on Windows."""
    if isinstance(frame, wx.TopLevelWindow):
        import ctypes
        hwnd = frame.GetHandle()
        try:
            dwmapi = ctypes.WinDLL("dwmapi")
            use_dark = ctypes.c_int(1 if is_dark() else 0)
            # Try attribute 20 (Windows 10 20H1+ and Windows 11)
            hr = dwmapi.DwmSetWindowAttribute(
                hwnd, 
                20, 
                ctypes.byref(use_dark), 
                ctypes.sizeof(use_dark)
            )
            if hr != 0:
                # Try attribute 19 (older Windows 10 versions)
                dwmapi.DwmSetWindowAttribute(
                    hwnd, 
                    19, 
                    ctypes.byref(use_dark), 
                    ctypes.sizeof(use_dark)
                )
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Immersive Dark Mode for Native Windows Controls (dropdowns, scrollbars, etc.)
# ---------------------------------------------------------------------------
def apply_native_theme(widget):
    """Apply the matching native Windows subtheme (scrollbars, arrows, borders).

    Without this following the palette, a light theme keeps dark scrollbars and
    dropdown arrows because these are drawn by the OS, not by wx.

    Applied uniformly. Do not special-case a control kind here without being able to see
    the result: SetWindowTheme returns S_OK for any string, including invalid ones, so a
    class the OS silently ignores looks identical to one it honours. Using "DarkMode_CFD"
    for combo boxes appeared reasonable and left their popup list unthemed, which put
    near-white item text on a white background.
    """
    try:
        hwnd = widget.GetHandle()
        if hwnd:
            import ctypes
            uxtheme = ctypes.WinDLL("uxtheme")
            uxtheme.SetWindowTheme(hwnd, "DarkMode_Explorer" if is_dark() else "Explorer", None)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Recursive theme applicator
# ---------------------------------------------------------------------------
def apply_theme(widget):
    """
    Recursively walk *widget* and all its children, applying the Dark Cyber
    Theme based on each widget's type.
    """
    _init()
    if isinstance(widget, wx.TopLevelWindow):
        apply_window_theme(widget)
    _style_widget(widget)
    # Recolouring a widget (SetBackgroundColour, etc.) does not by itself repaint it, and an
    # owner-drawn ui_kit control (Field, Button, Picker, TabBar, ...) reads the current
    # palette only from its own _OnPaint - it has no other code path that would pick up the
    # change. Invalidating the whole window from the top, as RefreshTheme() used to do
    # alone, does not reach separate native child windows on MSW (each is its own HWND, and
    # Refresh() there is a plain InvalidateRect on that one window). Explicitly refreshing
    # every widget on the way down is what actually gets them all repainted - e.g. without
    # this, a disabled ui.Field (the Start tab's download-path box) kept showing the
    # palette's old BG_DISABLED fill after a Dark <-> Light toggle.
    widget.Refresh()
    for child in widget.GetChildren():
        apply_theme(child)


def _log_style_change(w):
    """Trace the one call that can raise wxMSW's 'SetFocus failed with error 0x57'.

    SetWindowStyleFlag makes wxMSW recreate the native control and then restore focus,
    which fails for a control that is not currently on screen. This is the only call site
    in the codebase that does that, so if a 0x57 follows one of these lines, the widget
    named here is the one responsible - and if no line precedes it, the cause is elsewhere.

    Written to stderr so it interleaves with wx's own message, which does not go through
    the Python logging module or the active wx.Log target. Off unless CAPESOLO_THEME_DEBUG
    is set.
    """
    # The caller already wraps this in try/except, so no guard is needed here.
    if not os.environ.get("CAPESOLO_THEME_DEBUG"):
        return
    print(
        f"[theme] SetWindowStyleFlag {type(w).__name__} name={w.GetName()!r} "
        f"shown={w.IsShown()} onscreen={w.IsShownOnScreen()}",
        file=sys.stderr,
        flush=True,
    )


def _style_widget(w):
    """Apply colours / font to a single widget based on its runtime type."""
    # ui_kit.Field builds its wx.TextCtrl with BORDER_NONE on purpose and draws its own
    # rounded, focus-aware border around it (see Field's docstring) - forcing BORDER_SIMPLE
    # back on below would draw a second, square native border inside that one, showing up
    # as a hard grey box around the text on top of the intended rounded outline.
    from . import ui_kit

    isFieldCtrl = isinstance(w, wx.TextCtrl) and isinstance(w.GetParent(), ui_kit.Field)

    # Native Windows subtheme for scrollbars, borders, native arrows, etc. A disabled
    # Field's background used to stay the OS's pale disabled fill regardless of this -
    # that turned out to be Windows routing a WS_DISABLED Edit control's painting through
    # WM_CTLCOLORSTATIC (which ignores our colours) rather than anything UxTheme does, so
    # it is fixed at the source in ui_kit._FieldTextCtrl instead (Enable/Disable toggle
    # SetEditable() there, so the control never actually goes WS_DISABLED) and this can
    # stay unconditional.
    apply_native_theme(w)

    # Apply solid borders around interactive controls to ensure clear boundaries and relief
    if not isFieldCtrl and isinstance(w, (wx.TextCtrl, wx.ComboBox, wx.Choice, wx.ListBox, wx.ListCtrl, gridlib.Grid)):
        try:
            style = w.GetWindowStyleFlag()
            wanted = style & ~(
                wx.BORDER_NONE | wx.BORDER_STATIC | wx.BORDER_SIMPLE | wx.BORDER_RAISED | wx.BORDER_SUNKEN | wx.BORDER_THEME
            )
            wanted |= wx.BORDER_SIMPLE
            # Setting the flag makes wxMSW rebuild the native control, and the focus restore
            # that follows fails with 0x57 for anything not currently visible (inactive
            # notebook page, collapsed pane). apply_theme runs over the same widgets several
            # times - the frame walks everything and each panel walks itself - so only touch
            # the style when it actually changes.
            if wanted != style:
                _log_style_change(w)
                w.SetWindowStyleFlag(wanted)
        except Exception:
            pass

    # --- Panels & generic windows (background only) ---
    if isinstance(w, wx.Panel):
        w.SetBackgroundColour(BG_CARD)
        w.SetForegroundColour(FG_PRIMARY)
        _set_font(w, FONT_UI)
        return

    # wx.SplitterWindow is not a wx.Panel, so it fell through this walk untouched, staying
    # at the OS default background. That is the gutter/sash colour and also what a child
    # (e.g. ui.Notice) reads via GetBackgroundColour() if it is parented directly to the
    # splitter instead of a themed panel - so it must match BG_CARD too.
    if isinstance(w, wx.SplitterWindow):
        w.SetBackgroundColour(BG_CARD)
        return

    # --- Static text labels ---
    if isinstance(w, wx.StaticText):
        w.SetForegroundColour(FG_PRIMARY)
        _set_font(w, FONT_UI)
        return

    # --- Static lines (separators) ---
    if isinstance(w, wx.StaticLine):
        w.SetBackgroundColour(BG_INPUT)
        return

    # --- Text controls (single-line and multiline) ---
    if isinstance(w, wx.TextCtrl):
        if w.IsEnabled():
            w.SetBackgroundColour(BG_INPUT)
            w.SetForegroundColour(FG_PRIMARY)
        else:
            # Matches the BG_DISABLED/FG_DISABLED look ui_kit.Field's own owner-drawn
            # backdrop already uses for a disabled field - otherwise the native control
            # inside it kept the enabled BG_INPUT fill no matter its enabled state.
            w.SetBackgroundColour(BG_DISABLED)
            w.SetForegroundColour(FG_DISABLED)
        # Preserve font if caller already set a code font (Consolas)
        if w.GetFont().GetFaceName().lower() not in ("consolas",):
            _set_font(w, FONT_UI)
        return

    # --- ComboBox / Choice ---
    if isinstance(w, (wx.ComboBox, wx.Choice)):
        w.SetBackgroundColour(BG_DROPDOWN)
        w.SetForegroundColour(FG_PRIMARY)
        _set_font(w, FONT_UI)
        return

    # --- ListBox ---
    if isinstance(w, wx.ListBox):
        w.SetBackgroundColour(BG_INPUT)
        w.SetForegroundColour(FG_PRIMARY)
        _set_font(w, FONT_UI)
        return

    # --- ListCtrl (used in debugger panels) ---
    if isinstance(w, wx.ListCtrl):
        w.SetBackgroundColour(BG_INPUT)
        w.SetForegroundColour(FG_PRIMARY)
        _set_font(w, FONT_CODE)
        # Row banding is not done here: wx's EnableAlternateRowColours asserts unless the
        # control is virtual, and none of ours are. Callers run band_rows() once they have
        # inserted their items.
        return

    # --- TreeCtrl (process tree window) ---
    if isinstance(w, wx.TreeCtrl):
        w.SetBackgroundColour(BG_INPUT)
        w.SetForegroundColour(FG_PRIMARY)
        _set_font(w, FONT_UI)
        return

    # --- Buttons ---
    # Every button in the app is a ui_kit.Button, which draws itself and derives from
    # wx.Control rather than wx.Button, so it never lands here. This branch is the
    # fallback that keeps a stray native button legible instead of system-coloured;
    # semantic colouring lives in the ui_kit variants (PRIMARY / DANGEROUS / ...).
    if isinstance(w, wx.Button):
        w.SetBackgroundColour(BG_BUTTON)
        w.SetForegroundColour(FG_PRIMARY)
        _set_font(w, FONT_UI)
        return

    # --- CheckBoxes and RadioButtons ---
    # RadioButton is not a CheckBox subclass, so it needs naming explicitly or it falls
    # through this walk entirely and renders in system colours.
    if isinstance(w, (wx.CheckBox, wx.RadioButton)):
        w.SetForegroundColour(FG_PRIMARY)
        _set_font(w, FONT_UI)
        return

    # --- StaticBox (group box containers) ---
    if isinstance(w, wx.StaticBox):
        w.SetBackgroundColour(BG_CARD)
        w.SetForegroundColour(ACCENT_CYAN)    # Highlight group box borders/labels with Cyan
        _set_font(w, FONT_BOLD)
        return

    # --- Notebook tabs ---
    # wx.Notebook only: the main shell is a wx.Simplebook with a drawn ui.TabBar, and the
    # debug console's inner notebook is the last plain one left.
    if isinstance(w, wx.Notebook):
        w.SetBackgroundColour(BG_MAIN)
        w.SetForegroundColour(FG_PRIMARY)
        return

    # --- CollapsiblePane ---
    if isinstance(w, wx.CollapsiblePane):
        w.SetBackgroundColour(BG_CARD)
        w.SetForegroundColour(FG_PRIMARY)
        _set_font(w, FONT_UI)
        # The label ("Debugger options", "analysis.conf") is drawn by an internal wx.Control
        # that is neither a StaticText nor a Button, so it matches none of the branches above
        # and keeps the default black text. Style it directly; skip the inner pane, which is a
        # wx.Panel and gets handled when apply_theme recurses.
        for child in w.GetChildren():
            if not isinstance(child, wx.Panel):
                child.SetBackgroundColour(BG_CARD)
                child.SetForegroundColour(FG_PRIMARY)
                _set_font(child, FONT_UI)
                child.Refresh()
        return

    # --- wx.grid.Grid ---
    if isinstance(w, gridlib.Grid):
        w.SetDefaultCellBackgroundColour(BG_INPUT)
        w.SetDefaultCellTextColour(FG_PRIMARY)
        w.SetDefaultCellFont(FONT_UI)
        w.SetLabelBackgroundColour(BG_CARD)
        w.SetLabelTextColour(FG_SECONDARY)
        w.SetLabelFont(FONT_BOLD)
        w.SetGridLineColour(BG_MAIN)
        # The cursor cell is outlined in system black otherwise, which reads as a hole in
        # a dark grid.
        w.SetCellHighlightColour(ACCENT)
        # Override the system highlight, which is too saturated to read our text against.
        w.SetSelectionBackground(BG_SELECT)
        w.SetSelectionForeground(FG_SELECT)
        # Header height follows the font, but only where there is a header: several panels
        # hide theirs with SetColLabelSize(0) and must stay hidden.
        if w.GetColLabelSize() > 0:
            w.SetColLabelSize(dip(w, 26))
        return

    # --- Top-level windows (secondary frames and dialogs) ---
    if isinstance(w, wx.TopLevelWindow):
        w.SetBackgroundColour(BG_MAIN)
        w.SetForegroundColour(FG_PRIMARY)
        return
