"""
Dark Cyber Theme — centralized design tokens for CAPEsolo's wxPython UI.

Usage:
    from .theme import apply_theme, BG_MAIN, BG_CARD, BG_INPUT
    from .theme import FG_PRIMARY, FG_SECONDARY
    from .theme import ACCENT_RED, ACCENT_GREEN, ACCENT_ORANGE, ACCENT_ERROR
    from .theme import FONT_UI, FONT_BOLD, FONT_CODE

    # In any panel/frame __init__, after building the widget tree:
    apply_theme(self)
"""

import wx
import wx.grid as gridlib

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

FG_PRIMARY   = wx.Colour(201, 209, 217)  # #c9d1d9 - soft grey-white text (GitHub/VS Code standard)
FG_SECONDARY = wx.Colour(139, 148, 158)  # #8b949e - cool muted grey text

# Premium Red alert styling for warnings/emergency actions (high contrast, low fatigue)
BG_RED_ALERT = wx.Colour(92,  29,  29)   # #5c1d1d - deep crimson warning background
FG_RED_ALERT = wx.Colour(255, 180, 180)  # #ffb4b4 - soft light red text for legibility

ACCENT_CYAN   = wx.Colour(88,  166, 255)  # #58a6ff - premium cyan accent for headers/group boundaries
ACCENT_RED    = wx.Colour(255, 51,  51)   # #ff3333
ACCENT_GREEN  = wx.Colour(244, 63,  94)   # #f43f5e
ACCENT_ORANGE = wx.Colour(255, 159, 10)   # #ff9f0a
ACCENT_ERROR  = wx.Colour(255, 59,  48)   # #ff3b30

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

_initialized = False


def _init():
    """Build all wx.Font objects. Called once after wx.App exists."""
    global _initialized
    if _initialized:
        return

    FONT_UI._init_real()
    FONT_BOLD._init_real()
    FONT_CODE._init_real()

    _initialized = True


# ---------------------------------------------------------------------------
# Immersive Dark Mode for Windows Frame Title Bars
# ---------------------------------------------------------------------------
def apply_window_theme(frame):
    """Set immersive dark mode title bar for a wx.Frame on Windows."""
    if isinstance(frame, wx.Frame):
        import ctypes
        hwnd = frame.GetHandle()
        try:
            dwmapi = ctypes.WinDLL("dwmapi")
            use_dark = ctypes.c_int(1)
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
def apply_uxtheme_dark(widget):
    """Apply native Windows DarkMode_Explorer theme to controls via ctypes."""
    try:
        hwnd = widget.GetHandle()
        if hwnd:
            import ctypes
            uxtheme = ctypes.WinDLL("uxtheme")
            uxtheme.SetWindowTheme(hwnd, "DarkMode_Explorer", None)
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


def _style_widget(w):
    """Apply colours / font to a single widget based on its runtime type."""
    # Apply native Windows dark theme for scrollbars, borders, native arrows, etc.
    apply_uxtheme_dark(w)

    # Apply solid borders around interactive controls to ensure clear boundaries and relief
    if isinstance(w, (wx.TextCtrl, wx.ComboBox, wx.Choice, wx.ListBox, wx.ListCtrl, gridlib.Grid)):
        try:
            style = w.GetWindowStyleFlag()
            style &= ~(wx.BORDER_NONE | wx.BORDER_STATIC | wx.BORDER_SIMPLE | wx.BORDER_RAISED | wx.BORDER_SUNKEN | wx.BORDER_THEME)
            w.SetWindowStyleFlag(style | wx.BORDER_SIMPLE)
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
        w.SetBackgroundColour(BG_INPUT)
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

    # --- Buttons (Support both wx.Button and generic GenButton) ---
    import wx.lib.buttons as buttons
    if isinstance(w, (wx.Button, buttons.GenButton)):
        label = w.GetLabel().lower()
        # Semantic color coding: Highlight destructive, emergency or cancel actions with alert red
        if any(x in label for x in ["kill", "terminate", "delete", "cancel", "stop"]):
            w.SetBackgroundColour(BG_RED_ALERT)
            w.SetForegroundColour(FG_RED_ALERT)
        else:
            w.SetBackgroundColour(BG_BUTTON)
            w.SetForegroundColour(FG_PRIMARY)
        w.SetFont(FONT_UI)
        return

    # --- CheckBoxes ---
    if isinstance(w, wx.CheckBox):
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
        return

    # --- wx.grid.Grid ---
    if isinstance(w, gridlib.Grid):
        w.SetDefaultCellBackgroundColour(BG_INPUT)
        w.SetDefaultCellTextColour(FG_PRIMARY)
        w.SetDefaultCellFont(FONT_UI)
        w.SetLabelBackgroundColour(BG_CARD)
        w.SetLabelTextColour(FG_SECONDARY)
        w.SetGridLineColour(BG_MAIN)
        return

    # --- Frames (secondary windows) ---
    if isinstance(w, wx.Frame):
        w.SetBackgroundColour(BG_MAIN)
        w.SetForegroundColour(FG_PRIMARY)
        return
