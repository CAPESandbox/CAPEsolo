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
# Font tokens — Must be ThemeFont instances to delay C++ initialization
# ---------------------------------------------------------------------------
FONT_UI   = ThemeFont(10, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, faceName="Segoe UI")
FONT_BOLD = ThemeFont(10, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD,   faceName="Segoe UI")
FONT_CODE = ThemeFont(10, wx.FONTFAMILY_MODERN,  wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, faceName="Consolas")

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


def _read_theme_name() -> str:
    """Read [gui] theme from cfg.ini, preferring the user file over the packaged one."""
    config = configparser.ConfigParser()
    try:
        config.read(config_paths())
    except configparser.Error as e:
        log.warning("Could not parse cfg.ini for the theme setting: %s", e)
        return DEFAULT_THEME

    return config.get("gui", "theme", fallback=DEFAULT_THEME).strip().lower()


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


def _init():
    """Select the palette and build all wx.Font objects. Called once after wx.App exists."""
    global _initialized
    if _initialized:
        return

    set_theme(_read_theme_name())

    FONT_UI._init_real()
    FONT_BOLD._init_real()
    FONT_CODE._init_real()

    _initialized = True


# ---------------------------------------------------------------------------
# Immersive Dark Mode for Windows Frame Title Bars
# ---------------------------------------------------------------------------
def apply_window_theme(frame):
    """Set the title bar to match the active palette, for a wx.Frame on Windows."""
    if isinstance(frame, wx.Frame):
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
    if isinstance(widget, wx.Frame):
        apply_window_theme(widget)
    _style_widget(widget)
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
    # Native Windows subtheme for scrollbars, borders, native arrows, etc.
    apply_native_theme(w)

    # Apply solid borders around interactive controls to ensure clear boundaries and relief
    if isinstance(w, (wx.TextCtrl, wx.ComboBox, wx.Choice, wx.ListBox, wx.ListCtrl, gridlib.Grid)):
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
        w.SetFont(FONT_UI)
        return

    # --- Static text labels ---
    if isinstance(w, wx.StaticText):
        w.SetForegroundColour(FG_PRIMARY)
        w.SetFont(FONT_UI)
        return

    # --- Static lines (separators) ---
    if isinstance(w, wx.StaticLine):
        w.SetBackgroundColour(BG_INPUT)
        return

    # --- Text controls (single-line and multiline) ---
    if isinstance(w, wx.TextCtrl):
        w.SetBackgroundColour(BG_INPUT)
        w.SetForegroundColour(FG_PRIMARY)
        # Preserve font if caller already set a code font (Consolas)
        if w.GetFont().GetFaceName().lower() not in ("consolas",):
            w.SetFont(FONT_UI)
        return

    # --- ComboBox / Choice ---
    if isinstance(w, (wx.ComboBox, wx.Choice)):
        w.SetBackgroundColour(BG_DROPDOWN)
        w.SetForegroundColour(FG_PRIMARY)
        w.SetFont(FONT_UI)
        return

    # --- ListBox ---
    if isinstance(w, wx.ListBox):
        w.SetBackgroundColour(BG_INPUT)
        w.SetForegroundColour(FG_PRIMARY)
        w.SetFont(FONT_UI)
        return

    # --- ListCtrl (used in debugger panels) ---
    if isinstance(w, wx.ListCtrl):
        w.SetBackgroundColour(BG_INPUT)
        w.SetForegroundColour(FG_PRIMARY)
        w.SetFont(FONT_CODE)
        return

    # --- TreeCtrl (process tree window) ---
    if isinstance(w, wx.TreeCtrl):
        w.SetBackgroundColour(BG_INPUT)
        w.SetForegroundColour(FG_PRIMARY)
        w.SetFont(FONT_UI)
        return

    # --- Buttons (Support both wx.Button and generic GenButton) ---
    import wx.lib.buttons as buttons
    if isinstance(w, (wx.Button, buttons.GenButton)):
        label = w.GetLabel().lower()
        # Semantic color coding: Highlight destructive, emergency or cancel actions with alert red
        if any(x in label for x in ["kill", "terminate", "delete", "cancel", "stop"]):
            w.SetBackgroundColour(BG_RED_ALERT)
            w.SetForegroundColour(FG_RED_ALERT)
        elif "launch" in label:
            # The counterpart to Kill: the one control that starts a detonation. Shares
            # ACCENT_GREEN with the debugger's CIP row rather than adding a token, because
            # that colour is already defined as a fill sat underneath FG_PRIMARY and is
            # tuned for both palettes - retune it there and this follows.
            w.SetBackgroundColour(ACCENT_GREEN)
            w.SetForegroundColour(FG_PRIMARY)
        else:
            w.SetBackgroundColour(BG_BUTTON)
            w.SetForegroundColour(FG_PRIMARY)
        w.SetFont(FONT_UI)
        return

    # --- CheckBoxes and RadioButtons ---
    # RadioButton is not a CheckBox subclass, so it needs naming explicitly or it falls
    # through this walk entirely and renders in system colours.
    if isinstance(w, (wx.CheckBox, wx.RadioButton)):
        w.SetForegroundColour(FG_PRIMARY)
        w.SetFont(FONT_UI)
        return

    # --- StaticBox (group box containers) ---
    if isinstance(w, wx.StaticBox):
        w.SetBackgroundColour(BG_CARD)
        w.SetForegroundColour(ACCENT_CYAN)    # Highlight group box borders/labels with Cyan
        w.SetFont(FONT_BOLD)
        return

    # --- Notebook tabs ---
    import wx.lib.agw.flatnotebook as fnb
    if isinstance(w, (wx.Notebook, fnb.FlatNotebook)):
        w.SetBackgroundColour(BG_MAIN)
        w.SetForegroundColour(FG_PRIMARY)
        if isinstance(w, fnb.FlatNotebook):
            w.SetActiveTabColour(BG_CARD)
            w.SetActiveTabTextColour(FG_PRIMARY)
            w.SetNonActiveTabTextColour(FG_SECONDARY)
            w.SetTabAreaColour(BG_MAIN)
        return

    # --- CollapsiblePane ---
    if isinstance(w, wx.CollapsiblePane):
        w.SetBackgroundColour(BG_CARD)
        w.SetForegroundColour(FG_PRIMARY)
        w.SetFont(FONT_UI)
        # The label ("Debugger options", "analysis.conf") is drawn by an internal wx.Control
        # that is neither a StaticText nor a Button, so it matches none of the branches above
        # and keeps the default black text. Style it directly; skip the inner pane, which is a
        # wx.Panel and gets handled when apply_theme recurses.
        for child in w.GetChildren():
            if not isinstance(child, wx.Panel):
                child.SetBackgroundColour(BG_CARD)
                child.SetForegroundColour(FG_PRIMARY)
                child.SetFont(FONT_UI)
                child.Refresh()
        return

    # --- wx.grid.Grid ---
    if isinstance(w, gridlib.Grid):
        w.SetDefaultCellBackgroundColour(BG_INPUT)
        w.SetDefaultCellTextColour(FG_PRIMARY)
        w.SetDefaultCellFont(FONT_UI)
        w.SetLabelBackgroundColour(BG_CARD)
        w.SetLabelTextColour(FG_SECONDARY)
        w.SetGridLineColour(BG_MAIN)
        # Override the system highlight, which is too saturated to read our text against.
        w.SetSelectionBackground(BG_SELECT)
        w.SetSelectionForeground(FG_SELECT)
        return

    # --- Frames (secondary windows) ---
    if isinstance(w, wx.Frame):
        w.SetBackgroundColour(BG_MAIN)
        w.SetForegroundColour(FG_PRIMARY)
        return
