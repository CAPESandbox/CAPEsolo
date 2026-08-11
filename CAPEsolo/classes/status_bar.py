import wx

from .theme import (
    ACCENT_CYAN,
    ACCENT_RED,
    BG_CARD,
    BG_DROPDOWN,
    BG_INPUT,
    FG_PRIMARY,
    FG_RED_ALERT,
    FG_SECONDARY,
    FONT_CODE,
    FONT_UI,
    TIMER_WARN,
)

# Fractions of the analysis timeout at which the countdown changes colour.
WARN_FRACTION = 0.25
CRITICAL_FRACTION = 0.10

BAR_HEIGHT = 28
# Width reserved on the right for the countdown block (digits + depleting bar).
COUNTDOWN_WIDTH = 190
PADDING = 8


def format_clock(seconds):
    """Seconds as MM:SS, or H:MM:SS past an hour."""
    seconds = max(0, int(seconds))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


class AnalysisStatusBar(wx.Panel):
    """Persistent status line docked at the bottom of the main frame.

    Custom-painted rather than a wx.StatusBar because the native MSW status bar largely
    ignores SetBackgroundColour, so it would sit as a light grey strip along the bottom of
    the dark palette - the same problem apply_native_theme exists to work around.
    """

    def __init__(self, parent):
        super(AnalysisStatusBar, self).__init__(parent, size=(-1, BAR_HEIGHT))
        self.state = "Idle"
        self.total = 0
        self.remaining = 0
        self.running = False

        self.timer = wx.Timer(self)
        self.Bind(wx.EVT_TIMER, self.OnTick, self.timer)
        self.Bind(wx.EVT_PAINT, self.OnPaint)
        # The bar repaints every second; without these it flickers on each tick.
        self.Bind(wx.EVT_ERASE_BACKGROUND, lambda evt: None)
        self.SetDoubleBuffered(True)
        self.SetMinSize((-1, BAR_HEIGHT))

    # -- public API ---------------------------------------------------------
    def StartCountdown(self, seconds):
        """Begin counting down from *seconds*, the configured analysis timeout."""
        self.total = max(1, int(seconds))
        self.remaining = self.total
        self.state = "Analyzing"
        self.running = True
        self.timer.Start(1000)
        self.Refresh()

    def Finish(self, text="Analysis complete"):
        """Stop counting and hold a terminal state.

        Deliberately does not hide or reset the bar: the final state stays on screen for the
        rest of the session so there is still something to read after the run ends.
        """
        self.timer.Stop()
        self.running = False
        self.remaining = 0
        self.state = text
        self.Refresh()

    def SetMessage(self, text):
        """Show *text* on the status line immediately (used to report auto-processing progress)."""
        self.state = text
        self.Refresh()
        self.Update()

    def Reset(self):
        self.timer.Stop()
        self.running = False
        self.state = "Idle"
        self.total = 0
        self.remaining = 0
        self.Refresh()

    # -- internals ----------------------------------------------------------
    def OnTick(self, event):
        if self.remaining > 0:
            self.remaining -= 1
            self.Refresh()
        else:
            # The analyzer decides when the run is actually over; reaching zero only means
            # the configured timeout elapsed, so stop ticking but leave the state alone.
            self.timer.Stop()
            self.running = False
            self.Refresh()

    def _fraction(self):
        return (self.remaining / self.total) if self.total else 0

    def _accent(self):
        """Bar fill colour. Non-text, so 3:1 against BG_CARD is the bar to clear."""
        if not self.running:
            return FG_SECONDARY
        fraction = self._fraction()
        if fraction <= CRITICAL_FRACTION:
            return ACCENT_RED
        if fraction <= WARN_FRACTION:
            return TIMER_WARN
        return ACCENT_CYAN

    def _digit_colour(self):
        """Colour for the MM:SS digits, which need 4.5:1 as text.

        Deliberately not the bar accent: ACCENT_RED measures 4.16:1 against BG_CARD on the
        dark palette, so red digits would be legible-ish but under the text threshold.
        FG_RED_ALERT is the existing alert-text token and measures ~9:1 in both palettes.
        """
        if self.running and self._fraction() <= CRITICAL_FRACTION:
            return FG_RED_ALERT
        return FG_PRIMARY

    def OnPaint(self, event):
        dc = wx.BufferedPaintDC(self)
        width, height = self.GetClientSize()

        dc.SetBackground(wx.Brush(BG_CARD))
        dc.Clear()

        # Hairline along the top so the bar reads as a separate region from the notebook.
        dc.SetPen(wx.Pen(BG_INPUT))
        dc.DrawLine(0, 0, width, 0)

        dc.SetFont(FONT_UI)
        dc.SetTextForeground(FG_SECONDARY)
        _, textHeight = dc.GetTextExtent(self.state)
        dc.DrawText(self.state, PADDING, (height - textHeight) // 2)

        if self.total:
            self._DrawCountdown(dc, width, height)

    def _DrawCountdown(self, dc, width, height):
        accent = self._accent()
        left = width - COUNTDOWN_WIDTH
        label = format_clock(self.remaining)

        dc.SetFont(FONT_CODE)
        labelWidth, labelHeight = dc.GetTextExtent(label)
        dc.SetTextForeground(self._digit_colour())
        dc.DrawText(label, left, (height - labelHeight) // 2 - 2)

        # Depleting bar, filled proportionally to time left.
        barLeft = left + labelWidth + PADDING
        barWidth = width - barLeft - PADDING
        if barWidth <= 0:
            return

        barTop = height // 2 - 3
        dc.SetPen(wx.TRANSPARENT_PEN)
        # BG_DROPDOWN rather than BG_INPUT for the empty trough: on the light palette
        # BG_INPUT is pure white and measures 1.06:1 against the card, i.e. invisible.
        dc.SetBrush(wx.Brush(BG_DROPDOWN))
        dc.DrawRectangle(barLeft, barTop, barWidth, 6)

        filled = int(barWidth * max(0.0, min(1.0, self._fraction())))
        if filled:
            dc.SetBrush(wx.Brush(accent))
            dc.DrawRectangle(barLeft, barTop, filled, 6)
