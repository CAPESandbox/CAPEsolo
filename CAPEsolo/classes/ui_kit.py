"""Owner-drawn widget primitives for CAPEsolo's UI.

Why these exist
---------------
Everything on screen used to be a native Win32 control. wxMSW hands those to the OS to
draw, which means SetBackgroundColour is a suggestion at best: buttons render as flat grey
slabs with square 1px borders, disabled labels come out in a system grey that ignores the
palette entirely (unreadable on the dark theme), and there is no hover or focus feedback to
theme in the first place. Colour tokens cannot fix a control we do not draw.

So the interactive controls draw themselves, from the tokens in theme.py, through
wx.GraphicsContext (anti-aliased, so rounded corners are actually round). A side effect
worth having: the result is identical on wxMSW and wxGTK, so the Linux screenshot harness
shows what Windows will show.

What is *not* here
------------------
Text entry, grids, trees and list controls stay native. Their behaviour - IME, selection,
scrolling, accessibility, 200k-row virtual grids - is far more valuable than their chrome,
and their chrome is mostly themeable through SetWindowTheme anyway.

Conventions
-----------
- Every control reads its colours at paint time, never at construction, so the live theme
  toggle needs nothing more than a Refresh().
- Sizes are DIPs, scaled per-window through theme.dip().
- The buttons emit wx.EVT_BUTTON with their own id, so existing Bind() calls are unchanged.
"""

import wx

from .theme import (
    ACCENT,
    ACCENT_HOVER,
    ACCENT_PRESSED,
    BG_CARD,
    BG_DISABLED,
    BG_HOVER,
    BG_INPUT,
    BG_MAIN,
    BG_PRESSED,
    BG_SURFACE,
    BORDER_STRONG,
    BORDER_SUBTLE,
    DANGER,
    DANGER_HOVER,
    FG_DISABLED,
    FG_ON_ACCENT,
    FG_ON_DANGER,
    FG_ON_SUCCESS,
    FG_PRIMARY,
    FG_SECONDARY,
    FOCUS_RING,
    FONT_H2,
    FONT_SMALL,
    FONT_UI,
    RADIUS_MD,
    RADIUS_SM,
    SP_LG,
    SP_MD,
    SP_SM,
    SP_XS,
    SUCCESS,
    SUCCESS_HOVER,
    TIMER_WARN,
    dip,
    lock_font,
)

# Button variants. The old code picked a button's colour by substring-matching its label
# ("kill", "launch") inside the theme walker, which broke as soon as a label was reworded
# and could not express "this is the primary action of this screen" at all.
PRIMARY = "primary"      # the one action the screen exists for
SECONDARY = "secondary"  # everything else with a visible body
DANGEROUS = "danger"     # destructive: Kill, Delete, Terminate
GHOST = "ghost"          # no body until hovered: toolbars, icon buttons
SUCCESSFUL = "success"   # Launch


def _blend(first, second, ratio):
    """Mix two colours. ratio=0 gives *first*, ratio=1 gives *second*."""
    return wx.Colour(
        int(first.Red() + (second.Red() - first.Red()) * ratio),
        int(first.Green() + (second.Green() - first.Green()) * ratio),
        int(first.Blue() + (second.Blue() - first.Blue()) * ratio),
    )


def _contrasting(colour):
    """Black or white, whichever is readable on *colour*.

    Rec. 709 luma, which tracks perceived brightness closely enough to pick a text colour
    for an arbitrary fill. The 0.6 threshold errs towards white text.
    """
    luma = (0.2126 * colour.Red() + 0.7152 * colour.Green() + 0.0722 * colour.Blue()) / 255
    return wx.Colour(20, 22, 26) if luma > 0.6 else wx.Colour(255, 255, 255)


def _gc(dc):
    """A GraphicsContext with anti-aliasing on, or None if the platform has no renderer."""
    context = wx.GraphicsContext.Create(dc)
    if context:
        context.SetAntialiasMode(wx.ANTIALIAS_DEFAULT)
    return context


def _split_mnemonic(label):
    """Split wx's label markup into (visible text, mnemonic letter, index in that text).

    "&Save" -> ("Save", "s", 0), "Save &As" -> ("Save As", "a", 5), "R&&D" -> ("R&D", None,
    -1). The toolkit parses this for native controls; a drawn label has to do it here or
    the ampersand appears on screen. Only the first marker counts, as in wx.

    The letter is lowercased for comparison against a keycode.
    """
    text = []
    key = None
    at = -1
    index = 0
    while index < len(label):
        char = label[index]
        if char != "&":
            text.append(char)
            index += 1
            continue
        following = label[index + 1] if index + 1 < len(label) else ""
        if following == "&":
            text.append("&")
            index += 2
            continue
        if following and key is None:
            key = following.lower()
            at = len(text)
        # A trailing lone "&" is dropped, matching the toolkit.
        index += 1
    return "".join(text), key, at


class _Mnemonic:
    """Alt+letter activation for controls that draw their own label.

    The toolkit does this for a native button or checkbox; an owner-drawn one has to parse
    the marker, underline the letter and listen for the key itself. Mix in before the
    wx.Control base, call _ParseLabel() with the raw label and _HookMnemonic() once the
    control exists, and implement _ActivateFromMnemonic().
    """

    mnemonic = None

    def _ParseLabel(self, label):
        """Populate text / mnemonic / mnemonicAt from a label that may carry markup."""
        self.text, self.mnemonic, self.mnemonicAt = _split_mnemonic(label)

    def _HookMnemonic(self):
        """Listen for Alt+letter on the top-level window.

        A char hook only reaches the focused window and its parents, and a mnemonic has to
        fire while the caret is somewhere else entirely, so the hook goes on the frame or
        dialog. Controls with no marker install nothing, which is all of them today.
        """
        if self.mnemonic is None:
            return
        top = wx.GetTopLevelParent(self)
        if top is None:
            return
        top.Bind(wx.EVT_CHAR_HOOK, self._OnMnemonic)
        self.Bind(wx.EVT_WINDOW_DESTROY, self._OnMnemonicOwnerDestroyed)

    def _UnhookMnemonic(self):
        if self.mnemonic is None:
            return
        top = wx.GetTopLevelParent(self)
        if top is not None:
            top.Unbind(wx.EVT_CHAR_HOOK, handler=self._OnMnemonic)

    def _OnMnemonicOwnerDestroyed(self, event):
        # Fires for descendants too, and the hook outlives this window otherwise: the frame
        # would go on calling a handler bound to a deleted control.
        if event.GetEventObject() is self:
            self._UnhookMnemonic()
        event.Skip()

    def _OnMnemonic(self, event):
        key = event.GetKeyCode()
        if (
            event.AltDown()
            and 0 < key < 256
            and chr(key).lower() == self.mnemonic
            and self.IsEnabled()
            and self.IsShownOnScreen()
        ):
            self.SetFocus()
            self._ActivateFromMnemonic()
            return
        event.Skip()

    def _ActivateFromMnemonic(self):
        raise NotImplementedError

    def _DrawMnemonic(self, context, left, top, textHeight, colour):
        """Underline the mnemonic letter, as the native control does under Alt."""
        if self.mnemonicAt < 0:
            return
        before = context.GetTextExtent(self.text[: self.mnemonicAt])[0]
        letter = context.GetTextExtent(self.text[self.mnemonicAt])[0]
        baseline = top + textHeight - dip(self, 1)
        context.SetPen(_stroke(context, colour, dip(self, 1)))
        context.StrokeLine(left + before, baseline, left + before + letter, baseline)


def _stroke(context, colour, width):
    """A pen of fractional width.

    wx.Pen only takes an integer width, but these strokes are DIP values scaled by a
    fractional factor (a 1.6 DIP chevron at 125% is 2.0 physical pixels), and rounding them
    to an int before the GraphicsContext sees them throws away exactly the sub-pixel detail
    that keeps hairlines hairline. GraphicsPenInfo carries a float through.
    """
    return context.CreatePen(wx.GraphicsPenInfo(colour).Width(float(width)))


def _fill_round_rect(context, x, y, width, height, radius, fill, border=None, borderWidth=1):
    if fill is not None:
        context.SetBrush(wx.Brush(fill))
    else:
        context.SetBrush(wx.TRANSPARENT_BRUSH)

    if border is not None:
        # Inset by half the stroke so the outline lands inside the widget rather than being
        # clipped in half by its own edge.
        offset = borderWidth / 2.0
        context.SetPen(_stroke(context, border, borderWidth))
        context.DrawRoundedRectangle(
            x + offset, y + offset, width - borderWidth, height - borderWidth, radius
        )
        return

    context.SetPen(wx.TRANSPARENT_PEN)
    context.DrawRoundedRectangle(x, y, width, height, radius)


class _Themed(wx.Control):
    """Shared plumbing: borderless, double-buffered, transparent-background control.

    Subclasses implement Draw(context, width, height) and DoGetBestSize().
    """

    def __init__(self, parent, id=wx.ID_ANY, style=0, name="themed"):
        super().__init__(parent, id, style=style | wx.BORDER_NONE, name=name)
        self.hovered = False
        self.pressed = False
        self.SetDoubleBuffered(True)
        # AutoBufferedPaintDC asserts on this: the control paints every pixel itself, so
        # the toolkit must not erase the background first.
        self.SetBackgroundStyle(wx.BG_STYLE_PAINT)
        self.Bind(wx.EVT_PAINT, self._OnPaint)
        # The parent's background shows through the rounded corners, so the control must not
        # paint its own rectangle first - that would leave square dark corners on every card.
        self.Bind(wx.EVT_ERASE_BACKGROUND, lambda event: None)
        self.Bind(wx.EVT_ENTER_WINDOW, self._OnEnter)
        self.Bind(wx.EVT_LEAVE_WINDOW, self._OnLeave)

    # -- painting -----------------------------------------------------------
    def _OnPaint(self, event):
        dc = wx.AutoBufferedPaintDC(self)
        # Fill with the parent's colour, not ours: this is the backdrop the rounded corners
        # are cut out of, so it has to match whatever the control is sitting on.
        dc.SetBackground(wx.Brush(self.GetParent().GetBackgroundColour()))
        dc.Clear()
        context = _gc(dc)
        if context is None:
            return
        width, height = self.GetClientSize()
        self.Draw(context, width, height)

    def Draw(self, context, width, height):
        raise NotImplementedError

    # -- state --------------------------------------------------------------
    def _OnEnter(self, event):
        if self.IsEnabled():
            self.hovered = True
            self.Refresh()
        event.Skip()

    def _OnLeave(self, event):
        self.hovered = False
        self.pressed = False
        self.Refresh()
        event.Skip()

    def Enable(self, enable=True):
        changed = super().Enable(enable)
        if not enable:
            self.hovered = self.pressed = False
        self.Refresh()
        return changed

    def AcceptsFocusFromKeyboard(self):
        return self.IsEnabled()


# --- accessibility ---------------------------------------------------------------------
# Drawing a control ourselves also throws away everything the toolkit told the platform
# about it. To MSAA/UIA an owner-drawn wx.Control is an anonymous pane, so a screen reader
# announces "pane" where the native control announced "Launch, button, disabled". These
# objects hand the role, name and state back.
#
# MSAA-backed, so this is a Windows path: wxGTK builds with wxUSE_ACCESSIBILITY off and
# SetAccessible is a no-op there, which is why every hook below is written to be harmless
# when the platform ignores it.


class _Accessible(wx.Accessible):
    """Re-declares an owner-drawn control as the native control it replaces."""

    ROLE = wx.ROLE_SYSTEM_CLIENT
    FOCUSABLE = True

    def GetRole(self, childId):
        return (wx.ACC_OK, self.ROLE)

    def GetName(self, childId):
        window = self.GetWindow()
        if window is None:
            return (wx.ACC_NOT_IMPLEMENTED, "")
        # The drawn text is the accessible name, the same way a native control's label is.
        # Strip the mnemonic marker so it is not read out as an ampersand.
        label = window.GetLabel() or window.GetName()
        return (wx.ACC_OK, label.replace("&&", "\0").replace("&", "").replace("\0", "&"))

    def GetState(self, childId):
        window = self.GetWindow()
        if window is None:
            return (wx.ACC_NOT_IMPLEMENTED, 0)
        state = wx.ACC_STATE_SYSTEM_FOCUSABLE if self.FOCUSABLE else 0
        if not window.IsEnabled():
            state |= wx.ACC_STATE_SYSTEM_UNAVAILABLE
        elif window.HasFocus():
            state |= wx.ACC_STATE_SYSTEM_FOCUSED
        return (wx.ACC_OK, state | self.ExtraState(window))

    def ExtraState(self, window):
        """Role-specific state bits: checked, pressed, expanded."""
        return 0


class _ButtonAccessible(_Accessible):
    ROLE = wx.ROLE_SYSTEM_PUSHBUTTON

    def ExtraState(self, window):
        return wx.ACC_STATE_SYSTEM_PRESSED if window.pressed else 0


class _CheckAccessible(_Accessible):
    ROLE = wx.ROLE_SYSTEM_CHECKBUTTON

    def ExtraState(self, window):
        return wx.ACC_STATE_SYSTEM_CHECKED if window.GetValue() else 0


class _RadioAccessible(_CheckAccessible):
    ROLE = wx.ROLE_SYSTEM_RADIOBUTTON


class _PickerAccessible(_Accessible):
    ROLE = wx.ROLE_SYSTEM_COMBOBOX

    def GetName(self, childId):
        # A picker carries no label of its own. Declining the name lets the platform fall
        # back to the static text in front of it, which is how the native combo is named.
        return (wx.ACC_NOT_IMPLEMENTED, "")

    def GetValue(self, childId):
        window = self.GetWindow()
        if window is None:
            return (wx.ACC_NOT_IMPLEMENTED, "")
        return (wx.ACC_OK, window.GetValue())

    def ExtraState(self, window):
        expanded = window._popup is not None and window._popup.IsShown()
        return (
            wx.ACC_STATE_SYSTEM_EXPANDED if expanded else wx.ACC_STATE_SYSTEM_COLLAPSED
        )


class _TabsAccessible(_Accessible):
    """The tab strip as a whole.

    Announced as a tab list whose value is the open tab. The individual tabs are drawn, not
    windows, so exposing them one by one would mean implementing the child half of the
    wx.Accessible protocol (GetChildCount / GetChild / navigation) against a list of
    rectangles; the strip plus its current value is what a reader needs to follow along.
    """

    ROLE = wx.ROLE_SYSTEM_PAGETABLIST

    def GetValue(self, childId):
        window = self.GetWindow()
        if window is None:
            return (wx.ACC_NOT_IMPLEMENTED, "")
        book = window.book
        index = book.GetSelection()
        open_tab = book.GetPageText(index) if index >= 0 else ""
        return (wx.ACC_OK, open_tab)


class _SectionAccessible(_Accessible):
    """Static, unfocusable content: card titles and section headers."""

    ROLE = wx.ROLE_SYSTEM_STATICTEXT
    FOCUSABLE = False


class _GroupAccessible(_Accessible):
    """A card: a named grouping around its contents."""

    ROLE = wx.ROLE_SYSTEM_GROUPING
    FOCUSABLE = False


class _DisclosureAccessible(_Accessible):
    """A collapsible's header: a button that reports whether the pane is open.

    The header draws the owning Collapsible's label and holds none of the state itself.
    """

    ROLE = wx.ROLE_SYSTEM_PUSHBUTTON

    def GetName(self, childId):
        window = self.GetWindow()
        if window is None:
            return (wx.ACC_NOT_IMPLEMENTED, "")
        return (wx.ACC_OK, window.owner.label)

    def ExtraState(self, window):
        return (
            wx.ACC_STATE_SYSTEM_EXPANDED
            if window.owner.IsExpanded()
            else wx.ACC_STATE_SYSTEM_COLLAPSED
        )


def _announce(window, accessibleClass):
    """Attach an accessible object, where the platform supports it.

    Takes the class, not an instance: on a port built without wxUSE_ACCESSIBILITY - wxGTK,
    which is what this is developed on - wx.Accessible cannot even be constructed, so the
    object has to be built inside the guard. The first failure latches, so the rest of the
    window is not built one exception at a time.

    The reference is kept on the window: wxWidgets takes ownership of the C++ side, but
    nothing holds the Python object, and a collected proxy takes the callbacks with it.
    """
    global _ACCESSIBILITY
    if not _ACCESSIBILITY:
        return
    setter = getattr(window, "SetAccessible", None)
    if setter is None:
        _ACCESSIBILITY = False
        return
    try:
        accessible = accessibleClass()
        setter(accessible)
    except (NotImplementedError, TypeError, wx.wxAssertionError):
        _ACCESSIBILITY = False
        return
    window._accessible = accessible


# Latched off the first time the platform refuses an accessible object.
_ACCESSIBILITY = True


class Button(_Mnemonic, _Themed):
    """Flat, rounded, owner-drawn button. Drop-in for wx.Button.

    Emits wx.EVT_BUTTON exactly as the native control does, so call sites only change the
    class name: `wx.Button(self, label="Kill")` -> `ui.Button(self, label="Kill",
    variant=ui.DANGEROUS)`.
    """

    # Padding inside the body, in DIPs.
    PAD_X = SP_MD
    PAD_Y = SP_SM
    GLYPH = 14       # icon box, DIPs
    GLYPH_GAP = SP_SM

    def __init__(
        self,
        parent,
        id=wx.ID_ANY,
        label="",
        variant=SECONDARY,
        size=wx.DefaultSize,
        name="button",
        tooltip=None,
        colour=None,
        glyph=None,
    ):
        self.label = label
        # Sets text / mnemonic / mnemonicAt from the label's "&" markup.
        self._ParseLabel(label)
        self.variant = variant
        # One of the names in _GLYPHS, or None. Drawn in the label's colour, so it dims with
        # the button rather than needing a second disabled asset.
        self.glyph = glyph
        # Overrides the variant's fill. Only for buttons whose colour carries meaning of its
        # own - the API-category swatches in the behaviour panel, where the colour is the
        # legend for the matching grid rows.
        self.colour = colour
        super().__init__(parent, id, name=name)
        lock_font(self, FONT_UI)
        if tooltip:
            self.SetToolTip(tooltip)
        if size != wx.DefaultSize:
            self.SetInitialSize(size)
        else:
            self.InvalidateBestSize()

        self.Bind(wx.EVT_LEFT_DOWN, self._OnDown)
        self.Bind(wx.EVT_LEFT_UP, self._OnUp)
        self.Bind(wx.EVT_SET_FOCUS, self._OnFocus)
        self.Bind(wx.EVT_KILL_FOCUS, self._OnFocus)
        self.Bind(wx.EVT_KEY_DOWN, self._OnKey)
        _announce(self, _ButtonAccessible)
        self._HookMnemonic()

    # -- API parity with wx.Button -----------------------------------------
    def SetLabel(self, label):
        self._UnhookMnemonic()
        self.label = label
        self._ParseLabel(label)
        self._HookMnemonic()
        self.InvalidateBestSize()
        self.Refresh()

    def GetLabel(self):
        return self.label

    def GetLabelText(self):
        """The label without the mnemonic markers, matching wx.Control.GetLabelText."""
        return self.text

    def SetVariant(self, variant):
        self.variant = variant
        self.Refresh()

    def SetButtonColour(self, colour):
        self.colour = colour
        self.Refresh()

    # -- colours ------------------------------------------------------------
    def _colours(self):
        """(fill, text, border) for the current variant and state."""
        if not self.IsEnabled():
            # Ghost buttons have no body when idle and should not grow one when disabled.
            fill = None if self.variant == GHOST else BG_DISABLED
            return fill, FG_DISABLED, BORDER_SUBTLE

        if self.colour is not None:
            # Shade towards white on hover and black on press so the state is still visible
            # whatever the caller's colour is.
            fill = self.colour
            if self.pressed:
                fill = _blend(fill, wx.BLACK, 0.2)
            elif self.hovered:
                fill = _blend(fill, wx.WHITE, 0.15)
            return fill, _contrasting(self.colour), None

        if self.variant == PRIMARY:
            fill = ACCENT_PRESSED if self.pressed else (ACCENT_HOVER if self.hovered else ACCENT)
            return fill, FG_ON_ACCENT, None

        if self.variant == DANGEROUS:
            fill = DANGER_HOVER if (self.hovered and not self.pressed) else DANGER
            if self.pressed:
                fill = _blend(DANGER, wx.BLACK, 0.2)
            return fill, FG_ON_DANGER, None

        if self.variant == SUCCESSFUL:
            fill = SUCCESS_HOVER if (self.hovered and not self.pressed) else SUCCESS
            if self.pressed:
                fill = _blend(SUCCESS, wx.BLACK, 0.2)
            return fill, FG_ON_SUCCESS, None

        if self.variant == GHOST:
            if self.pressed:
                return BG_PRESSED, FG_PRIMARY, None
            if self.hovered:
                return BG_HOVER, FG_PRIMARY, None
            return None, FG_SECONDARY, None

        # SECONDARY: a bordered body, so it still reads as a control against a card.
        fill = BG_PRESSED if self.pressed else (BG_HOVER if self.hovered else BG_SURFACE)
        return fill, FG_PRIMARY, BORDER_STRONG

    # -- drawing ------------------------------------------------------------
    def Draw(self, context, width, height):
        fill, text, border = self._colours()
        radius = dip(self, RADIUS_MD)
        _fill_round_rect(
            context, 0, 0, width, height, radius, fill, border, dip(self, 1)
        )

        if self.HasFocus() and self.IsEnabled():
            # Drawn inside the body rather than around it: an outside ring would be clipped
            # by the sizer's border and only half of it would survive.
            inset = dip(self, 2)
            context.SetBrush(wx.TRANSPARENT_BRUSH)
            context.SetPen(_stroke(context, FOCUS_RING, dip(self, 1)))
            context.DrawRoundedRectangle(
                inset, inset, width - inset * 2, height - inset * 2, max(1, radius - inset)
            )

        context.SetFont(self.GetFont(), text)
        textWidth, textHeight = context.GetTextExtent(self.text)[:2]
        glyph = dip(self, self.GLYPH) if self.glyph else 0
        gap = dip(self, self.GLYPH_GAP) if (self.glyph and self.text) else 0
        # Centre the icon and the label as one group, so adding an icon does not shove the
        # text off centre.
        left = (width - (glyph + gap + textWidth)) / 2
        top = (height - textHeight) / 2
        if self.glyph:
            _draw_glyph(
                context,
                self.glyph,
                left,
                (height - glyph) / 2,
                glyph,
                text,
                dip(self, 1.3),
            )
        textLeft = left + glyph + gap
        context.DrawText(self.text, textLeft, top)
        self._DrawMnemonic(context, textLeft, top, textHeight, text)

    def DoGetBestSize(self):
        dc = wx.ClientDC(self)
        dc.SetFont(self.GetFont())
        textWidth, textHeight = dc.GetTextExtent(self.text)
        glyph = dip(self, self.GLYPH) if self.glyph else 0
        gap = dip(self, self.GLYPH_GAP) if (self.glyph and self.text) else 0
        return wx.Size(
            textWidth + glyph + gap + dip(self, self.PAD_X) * 2,
            max(textHeight, glyph) + dip(self, self.PAD_Y) * 2,
        )

    # -- input --------------------------------------------------------------
    def _OnDown(self, event):
        if not self.IsEnabled():
            return
        self.pressed = True
        self.SetFocus()
        self.CaptureMouse()
        self.Refresh()

    def _OnUp(self, event):
        if self.HasCapture():
            self.ReleaseMouse()
        if not self.pressed:
            return
        self.pressed = False
        self.Refresh()
        # Only fire if the pointer is still inside: dragging off a button is the standard
        # way to cancel a click, and Kill is one of these.
        if self.GetClientRect().Contains(event.GetPosition()):
            self._Fire()

    def _OnKey(self, event):
        if event.GetKeyCode() in (wx.WXK_SPACE, wx.WXK_RETURN, wx.WXK_NUMPAD_ENTER):
            self._Fire()
            return
        event.Skip()

    def _OnFocus(self, event):
        self.Refresh()
        event.Skip()

    def _ActivateFromMnemonic(self):
        self._Fire()

    def _Fire(self):
        clicked = wx.CommandEvent(wx.EVT_BUTTON.typeId, self.GetId())
        clicked.SetEventObject(self)
        self.GetEventHandler().ProcessEvent(clicked)


class _Toggle(_Mnemonic, _Themed):
    """Shared behaviour for Check and Radio: a drawn glyph plus a label."""

    GLYPH = 16   # glyph box, DIPs
    GAP = SP_SM  # glyph-to-label gap
    # Which role this toggle reports to the platform; the subclasses differ only in that
    # and in what _Activate does.
    ACCESSIBLE = _Accessible

    def __init__(self, parent, id=wx.ID_ANY, label="", style=0, name="toggle"):
        self.label = label
        self._ParseLabel(label)
        self._value = False
        super().__init__(parent, id, name=name)
        lock_font(self, FONT_UI)
        self.Bind(wx.EVT_LEFT_DOWN, self._OnDown)
        self.Bind(wx.EVT_SET_FOCUS, lambda event: (self.Refresh(), event.Skip()))
        self.Bind(wx.EVT_KILL_FOCUS, lambda event: (self.Refresh(), event.Skip()))
        self.Bind(wx.EVT_KEY_DOWN, self._OnKey)
        _announce(self, self.ACCESSIBLE)
        self._HookMnemonic()

    # -- API parity with wx.CheckBox / wx.RadioButton -----------------------
    def GetValue(self):
        return self._value

    def SetValue(self, value):
        self._value = bool(value)
        self.Refresh()

    def SetLabel(self, label):
        self._UnhookMnemonic()
        self.label = label
        self._ParseLabel(label)
        self._HookMnemonic()
        self.InvalidateBestSize()
        self.Refresh()

    def GetLabel(self):
        return self.label

    def GetLabelText(self):
        """The label without the mnemonic markers, matching wx.Control.GetLabelText."""
        return self.text

    def _ActivateFromMnemonic(self):
        self._Activate()

    def DoGetBestSize(self):
        dc = wx.ClientDC(self)
        dc.SetFont(self.GetFont())
        textWidth, textHeight = dc.GetTextExtent(self.text)
        glyph = dip(self, self.GLYPH)
        return wx.Size(
            glyph + dip(self, self.GAP) + textWidth,
            max(glyph, textHeight) + dip(self, SP_XS),
        )

    def _OnKey(self, event):
        if event.GetKeyCode() == wx.WXK_SPACE:
            self._Activate()
            return
        event.Skip()

    def _OnDown(self, event):
        if not self.IsEnabled():
            return
        self.SetFocus()
        self._Activate()

    def _Activate(self):
        raise NotImplementedError

    def _Fire(self, eventType):
        changed = wx.CommandEvent(eventType.typeId, self.GetId())
        changed.SetEventObject(self)
        changed.SetInt(int(self._value))
        self.GetEventHandler().ProcessEvent(changed)

    def _label_colour(self):
        return FG_PRIMARY if self.IsEnabled() else FG_DISABLED

    def _DrawLabel(self, context, width, height):
        colour = self._label_colour()
        context.SetFont(self.GetFont(), colour)
        textWidth, textHeight = context.GetTextExtent(self.text)[:2]
        left = dip(self, self.GLYPH) + dip(self, self.GAP)
        top = (height - textHeight) / 2
        context.DrawText(self.text, left, top)
        self._DrawMnemonic(context, left, top, textHeight, colour)

    def _DrawFocus(self, context, width, height):
        if not (self.HasFocus() and self.IsEnabled()):
            return
        context.SetBrush(wx.TRANSPARENT_BRUSH)
        context.SetPen(_stroke(context, FOCUS_RING, dip(self, 1)))
        context.DrawRoundedRectangle(0, 0, width - 1, height - 1, dip(self, RADIUS_SM))


class Check(_Toggle):
    """Owner-drawn checkbox. Emits wx.EVT_CHECKBOX."""

    ACCESSIBLE = _CheckAccessible

    def _Activate(self):
        self._value = not self._value
        self.Refresh()
        self._Fire(wx.EVT_CHECKBOX)

    def Draw(self, context, width, height):
        glyph = dip(self, self.GLYPH)
        top = (height - glyph) / 2
        radius = dip(self, RADIUS_SM)
        enabled = self.IsEnabled()

        if self._value:
            fill = ACCENT if enabled else BG_DISABLED
            _fill_round_rect(context, 0, top, glyph, glyph, radius, fill)
            tick = FG_ON_ACCENT if enabled else FG_DISABLED
            # Proportional to the box so it stays a tick at every scale factor.
            path = context.CreatePath()
            path.MoveToPoint(glyph * 0.24, top + glyph * 0.52)
            path.AddLineToPoint(glyph * 0.43, top + glyph * 0.71)
            path.AddLineToPoint(glyph * 0.77, top + glyph * 0.31)
            if not enabled:
                _fill_round_rect(
                    context, 0, top, glyph, glyph, radius, None, BORDER_SUBTLE, dip(self, 1)
                )
            context.SetPen(_stroke(context, tick, max(1, dip(self, 2))))
            context.SetBrush(wx.TRANSPARENT_BRUSH)
            context.StrokePath(path)
        else:
            fill = BG_INPUT if enabled else BG_DISABLED
            border = (BORDER_STRONG if not self.hovered else ACCENT) if enabled else BORDER_SUBTLE
            _fill_round_rect(context, 0, top, glyph, glyph, radius, fill)
            _fill_round_rect(
                context, 0, top, glyph, glyph, radius, None, border, dip(self, 1)
            )

        self._DrawLabel(context, width, height)
        self._DrawFocus(context, width, height)


class Radio(_Toggle):
    """Owner-drawn radio button. Emits wx.EVT_RADIOBUTTON.

    Grouping follows wx.RB_GROUP the same way the native control does: a button with the
    style starts a group, and the siblings after it join it. Done here rather than left to
    the OS because an owner-drawn control gets no help with mutual exclusion.
    """

    ACCESSIBLE = _RadioAccessible

    def __init__(self, parent, id=wx.ID_ANY, label="", style=0, name="radio"):
        self.startsGroup = bool(style & wx.RB_GROUP)
        super().__init__(parent, id, label=label, name=name)

    def _Group(self):
        """Siblings belonging to the same group, in creation order."""
        siblings = [
            child for child in self.GetParent().GetChildren() if isinstance(child, Radio)
        ]
        if self not in siblings:
            return [self]

        start = 0
        for index, sibling in enumerate(siblings):
            if sibling.startsGroup:
                start = index
            if sibling is self:
                break

        group = []
        for sibling in siblings[start:]:
            if sibling.startsGroup and group:
                break
            group.append(sibling)
        return group

    def SetValue(self, value):
        super().SetValue(value)
        if value:
            for sibling in self._Group():
                if sibling is not self and sibling._value:
                    sibling._value = False
                    sibling.Refresh()

    def _Activate(self):
        if self._value:
            return
        self.SetValue(True)
        self._Fire(wx.EVT_RADIOBUTTON)

    # -- keyboard -----------------------------------------------------------
    def AcceptsFocusFromKeyboard(self):
        """A radio group is one tab stop, as it is natively.

        Tab reaches the checked button and then leaves the group; the arrows move within
        it. Without this every button in the group is its own stop, so tabbing through a
        panel with six options takes six presses and lands the caret on options the user
        has not chosen.
        """
        if not self.IsEnabled():
            return False
        group = [sibling for sibling in self._Group() if sibling.IsEnabled()]
        checked = next((sibling for sibling in group if sibling._value), None)
        # Nothing checked yet: the first enabled button takes the stop, so the group is
        # still reachable.
        return self is (checked or (group[0] if group else self))

    def _OnKey(self, event):
        key = event.GetKeyCode()
        if key in (wx.WXK_UP, wx.WXK_LEFT):
            self._Step(-1)
            return
        if key in (wx.WXK_DOWN, wx.WXK_RIGHT):
            self._Step(1)
            return
        super()._OnKey(event)

    def _Step(self, step):
        """Move the selection to the next enabled button in the group, wrapping."""
        group = [sibling for sibling in self._Group() if sibling.IsEnabled()]
        if self not in group or len(group) < 2:
            return
        target = group[(group.index(self) + step) % len(group)]
        target.SetFocus()
        target._Activate()

    def Draw(self, context, width, height):
        glyph = dip(self, self.GLYPH)
        top = (height - glyph) / 2
        enabled = self.IsEnabled()

        fill = BG_INPUT if enabled else BG_DISABLED
        border = (BORDER_STRONG if not self.hovered else ACCENT) if enabled else BORDER_SUBTLE
        context.SetBrush(wx.Brush(fill))
        context.SetPen(_stroke(context, border, dip(self, 1)))
        context.DrawEllipse(0.5, top + 0.5, glyph - 1, glyph - 1)

        if self._value:
            dot = glyph * 0.44
            context.SetBrush(wx.Brush(ACCENT if enabled else FG_DISABLED))
            context.SetPen(wx.TRANSPARENT_PEN)
            context.DrawEllipse(
                (glyph - dot) / 2, top + (glyph - dot) / 2, dot, dot
            )

        self._DrawLabel(context, width, height)
        self._DrawFocus(context, width, height)


class Card(wx.Panel):
    """A rounded surface with an optional title, replacing wx.StaticBoxSizer.

    A StaticBox draws an etched rectangle with the title notched into it - the single most
    dated container in the Win32 vocabulary, and it nests badly: two boxes inside a third
    produce three competing outlines. A card separates by fill and a subtle border instead,
    so nesting stays readable.

    Add content to `card.body`, the sizer inside the padding.
    """

    def __init__(self, parent, title=None, subtitle=None, padding=SP_MD):
        super().__init__(parent, style=wx.BORDER_NONE)
        self.SetBackgroundColour(BG_CARD)
        self.SetDoubleBuffered(True)
        # AutoBufferedPaintDC asserts on this: the control paints every pixel itself, so
        # the toolkit must not erase the background first.
        self.SetBackgroundStyle(wx.BG_STYLE_PAINT)
        self.Bind(wx.EVT_PAINT, self._OnPaint)
        self.Bind(wx.EVT_ERASE_BACKGROUND, lambda event: None)

        pad = dip(self, padding)
        outer = wx.BoxSizer(wx.VERTICAL)
        self.body = wx.BoxSizer(wx.VERTICAL)

        if title:
            heading = lock_font(wx.StaticText(self, label=title), FONT_H2)
            heading.SetForegroundColour(FG_PRIMARY)
            self.body.Add(heading, 0, wx.BOTTOM, dip(self, SP_XS if subtitle else SP_SM))

        if subtitle:
            note = lock_font(wx.StaticText(self, label=subtitle), FONT_SMALL)
            note.SetForegroundColour(FG_SECONDARY)
            self.body.Add(note, 0, wx.BOTTOM, dip(self, SP_SM))

        outer.Add(self.body, 1, wx.EXPAND | wx.ALL, pad)
        self.SetSizer(outer)

        if title:
            # The title is drawn by a StaticText, so nothing else tells the platform what
            # this grouping is called. The window label has no visual effect on a panel.
            self.SetLabel(title)
        _announce(self, _GroupAccessible)

    def _OnPaint(self, event):
        dc = wx.AutoBufferedPaintDC(self)
        dc.SetBackground(wx.Brush(self.GetParent().GetBackgroundColour()))
        dc.Clear()
        context = _gc(dc)
        if context is None:
            return
        width, height = self.GetClientSize()
        _fill_round_rect(
            context, 0, 0, width, height, dip(self, RADIUS_MD), BG_CARD
        )
        _fill_round_rect(
            context,
            0,
            0,
            width,
            height,
            dip(self, RADIUS_MD),
            None,
            BORDER_SUBTLE,
            dip(self, 1),
        )


class SectionHeader(wx.Panel):
    """A label and a hairline: groups a few rows without the weight of a card."""

    def __init__(self, parent, text):
        super().__init__(parent, style=wx.BORDER_NONE)
        self.text = text
        self.SetBackgroundColour(parent.GetBackgroundColour())
        self.SetDoubleBuffered(True)
        # AutoBufferedPaintDC asserts on this: the control paints every pixel itself, so
        # the toolkit must not erase the background first.
        self.SetBackgroundStyle(wx.BG_STYLE_PAINT)
        self.Bind(wx.EVT_PAINT, self._OnPaint)
        self.Bind(wx.EVT_ERASE_BACKGROUND, lambda event: None)
        dc = wx.ClientDC(self)
        dc.SetFont(FONT_H2)
        self.SetMinSize(wx.Size(-1, dc.GetTextExtent(text)[1] + dip(self, SP_XS)))
        # The heading is drawn, not a StaticText, so it needs declaring.
        self.SetLabel(text)
        _announce(self, _SectionAccessible)

    def _OnPaint(self, event):
        dc = wx.AutoBufferedPaintDC(self)
        dc.SetBackground(wx.Brush(self.GetParent().GetBackgroundColour()))
        dc.Clear()
        context = _gc(dc)
        if context is None:
            return
        width, height = self.GetClientSize()
        context.SetFont(FONT_H2, FG_PRIMARY)
        textWidth, textHeight = context.GetTextExtent(self.text)[:2]
        context.DrawText(self.text, 0, (height - textHeight) / 2)

        left = textWidth + dip(self, SP_MD)
        if left < width:
            context.SetPen(_stroke(context, BORDER_SUBTLE, dip(self, 1)))
            context.StrokeLine(left, height / 2, width, height / 2)


class Picker(_Themed):
    """Owner-drawn read-only dropdown, replacing wx.ComboBox(style=CB_READONLY).

    The native combo is the worst offender in the dark palette: wxMSW paints the closed
    control in system colours no matter what we set, and its popup list is drawn by the OS
    with a white background, so light text lands on white. SetWindowTheme("DarkMode_CFD")
    fixes the closed state and leaves the popup broken, which is how the app ended up
    pitching BG_DROPDOWN light enough to survive both.

    So the popup is ours too: a transient window that draws its own rows. Emits
    wx.EVT_COMBOBOX on selection, and mirrors enough of wx.ComboBox's API that call sites
    only change the class name.
    """

    ARROW = 10       # chevron box, DIPs
    PAD_X = SP_SM
    PAD_Y = SP_SM
    MAX_VISIBLE = 12  # rows before the popup starts scrolling

    def __init__(self, parent, id=wx.ID_ANY, choices=None, value="", name="picker", tooltip=None):
        self.choices = list(choices or [])
        self.selection = self.choices.index(value) if value in self.choices else -1
        self._popup = None
        super().__init__(parent, id, name=name)
        lock_font(self, FONT_UI)
        if tooltip:
            self.SetToolTip(tooltip)

        self.Bind(wx.EVT_LEFT_DOWN, self._OnDown)
        self.Bind(wx.EVT_SET_FOCUS, lambda event: (self.Refresh(), event.Skip()))
        self.Bind(wx.EVT_KILL_FOCUS, lambda event: (self.Refresh(), event.Skip()))
        self.Bind(wx.EVT_KEY_DOWN, self._OnKey)
        self.Bind(wx.EVT_MOUSEWHEEL, self._OnWheel)
        _announce(self, _PickerAccessible)

    # -- API parity with wx.ComboBox ----------------------------------------
    def GetValue(self):
        return self.choices[self.selection] if self.selection >= 0 else ""

    def SetValue(self, value):
        self.SetStringSelection(value)

    GetStringSelection = GetValue

    def SetStringSelection(self, value):
        self.selection = self.choices.index(value) if value in self.choices else -1
        self.InvalidateBestSize()
        self.Refresh()

    def GetSelection(self):
        return self.selection

    def SetSelection(self, index):
        self.selection = index if 0 <= index < len(self.choices) else -1
        self.Refresh()

    def GetCount(self):
        return len(self.choices)

    def GetItems(self):
        return list(self.choices)

    def GetString(self, index):
        return self.choices[index]

    def Append(self, item):
        if isinstance(item, (list, tuple)):
            self.choices.extend(item)
        else:
            self.choices.append(item)
        self.InvalidateBestSize()

    def AppendItems(self, items):
        self.choices.extend(items)
        self.InvalidateBestSize()

    def Set(self, items):
        self.choices = list(items)
        self.selection = -1
        self.InvalidateBestSize()
        self.Refresh()

    SetItems = Set

    def Clear(self):
        self.choices = []
        self.selection = -1
        self.Refresh()

    # -- drawing ------------------------------------------------------------
    def Draw(self, context, width, height):
        enabled = self.IsEnabled()
        radius = dip(self, RADIUS_MD)
        fill = BG_SURFACE if enabled else BG_DISABLED
        if enabled and self.hovered:
            fill = BG_HOVER
        border = FOCUS_RING if (self.HasFocus() and enabled) else (
            BORDER_STRONG if enabled else BORDER_SUBTLE
        )
        _fill_round_rect(context, 0, 0, width, height, radius, fill)
        _fill_round_rect(context, 0, 0, width, height, radius, None, border, dip(self, 1))

        arrow = dip(self, self.ARROW)
        padX = dip(self, self.PAD_X)
        label = self.GetValue()
        colour = FG_PRIMARY if enabled else FG_DISABLED
        context.SetFont(self.GetFont(), colour)
        textWidth, textHeight = context.GetTextExtent(label)[:2]
        # Clip rather than overflow into the chevron when the value is too long for the box.
        context.Clip(padX, 0, max(0, width - padX * 2 - arrow), height)
        context.DrawText(label, padX, (height - textHeight) / 2)
        context.ResetClip()

        _draw_chevron(
            context,
            width - padX - arrow,
            (height - arrow / 2) / 2,
            arrow,
            colour,
            dip(self, 1.6),
            pointing="down",
        )

    def DoGetBestSize(self):
        dc = wx.ClientDC(self)
        dc.SetFont(self.GetFont())
        # Sized to the longest choice, not to the current value, so the control does not
        # resize (and reflow the row it sits in) every time the selection changes.
        widest = max(
            [dc.GetTextExtent(choice)[0] for choice in self.choices] or [0]
        )
        textHeight = dc.GetTextExtent("Xg")[1]
        return wx.Size(
            widest + dip(self, self.PAD_X) * 3 + dip(self, self.ARROW),
            textHeight + dip(self, self.PAD_Y) * 2,
        )

    # -- input --------------------------------------------------------------
    def _OnDown(self, event):
        if not self.IsEnabled():
            return
        self.SetFocus()
        self.ShowPopup()

    def _OnKey(self, event):
        code = event.GetKeyCode()
        if code in (wx.WXK_SPACE, wx.WXK_RETURN, wx.WXK_NUMPAD_ENTER, wx.WXK_DOWN):
            self.ShowPopup()
            return
        event.Skip()

    def _OnWheel(self, event):
        """Step through the choices, matching the native combo's wheel behaviour."""
        if not self.IsEnabled() or not self.choices:
            return
        step = -1 if event.GetWheelRotation() > 0 else 1
        index = min(max(self.selection + step, 0), len(self.choices) - 1)
        if index != self.selection:
            self._Choose(index)

    def ShowPopup(self):
        if self._popup:
            return
        self._popup = _PickerPopup(self)
        self._popup.Popup()

    def _Choose(self, index):
        if index == self.selection:
            return
        self.SetSelection(index)
        # Both event types: the Picker replaces wx.ComboBox and wx.Choice, and call sites
        # bind whichever one the control they had used to send.
        for eventType in (wx.EVT_COMBOBOX, wx.EVT_CHOICE):
            chosen = wx.CommandEvent(eventType.typeId, self.GetId())
            chosen.SetEventObject(self)
            chosen.SetInt(index)
            chosen.SetString(self.GetValue())
            self.GetEventHandler().ProcessEvent(chosen)


class _PickerPopup(wx.PopupTransientWindow):
    """The dropped-down list for a Picker, drawn rather than delegated to the OS."""

    def __init__(self, owner):
        super().__init__(owner.GetTopLevelParent(), wx.BORDER_NONE)
        self.owner = owner
        self.highlighted = owner.GetSelection()
        self.SetDoubleBuffered(True)
        self.SetBackgroundStyle(wx.BG_STYLE_PAINT)
        self.Bind(wx.EVT_PAINT, self._OnPaint)
        self.Bind(wx.EVT_ERASE_BACKGROUND, lambda event: None)
        self.Bind(wx.EVT_MOTION, self._OnMotion)
        self.Bind(wx.EVT_LEFT_UP, self._OnUp)

        dc = wx.ClientDC(self)
        dc.SetFont(FONT_UI)
        self.rowHeight = dc.GetTextExtent("Xg")[1] + dip(self, SP_SM)
        visible = min(len(owner.choices), owner.MAX_VISIBLE)
        self.SetSize(
            wx.Size(
                max(owner.GetSize().width, dip(self, 120)),
                visible * self.rowHeight + dip(self, SP_XS) * 2,
            )
        )

    def Popup(self, focus=None):
        # Below the control, or above it when there is no room underneath.
        origin = self.owner.ClientToScreen((0, self.owner.GetSize().height))
        height = self.GetSize().height
        display = wx.Display(max(0, wx.Display.GetFromWindow(self.owner))).GetClientArea()
        if origin.y + height > display.GetBottom():
            origin = self.owner.ClientToScreen((0, 0))
            origin.y -= height
        self.SetPosition(origin)
        super().Popup(focus)

    def _RowAt(self, y):
        index = (y - dip(self, SP_XS)) // self.rowHeight
        return int(index) if 0 <= index < len(self.owner.choices) else -1

    def _OnMotion(self, event):
        index = self._RowAt(event.GetY())
        if index != self.highlighted:
            self.highlighted = index
            self.Refresh()

    def _OnUp(self, event):
        index = self._RowAt(event.GetY())
        if index >= 0:
            self.owner._Choose(index)
        self.Dismiss()

    def Dismiss(self):
        # OnDismiss only fires for a dismissal the toolkit initiated (a click outside, a
        # focus loss); calling Dismiss() directly - which is what choosing a row does -
        # bypasses it, leaving the owner believing its popup is still open and refusing to
        # open another. Clearing here covers both paths.
        self._Release()
        super().Dismiss()

    def OnDismiss(self):
        self._Release()

    def _Release(self):
        if self.owner._popup is self:
            self.owner._popup = None
            self.owner.Refresh()

    def _OnPaint(self, event):
        dc = wx.AutoBufferedPaintDC(self)
        dc.SetBackground(wx.Brush(BG_SURFACE))
        dc.Clear()
        context = _gc(dc)
        if context is None:
            return

        width, height = self.GetClientSize()
        radius = dip(self, RADIUS_MD)
        _fill_round_rect(context, 0, 0, width, height, radius, BG_SURFACE)
        _fill_round_rect(context, 0, 0, width, height, radius, None, BORDER_STRONG, dip(self, 1))

        padX = dip(self, SP_SM)
        top = dip(self, SP_XS)
        for index, choice in enumerate(self.owner.choices[: self.owner.MAX_VISIBLE]):
            rowTop = top + index * self.rowHeight
            if index == self.highlighted:
                _fill_round_rect(
                    context, padX / 2, rowTop, width - padX, self.rowHeight,
                    dip(self, RADIUS_SM), ACCENT,
                )
                colour = FG_ON_ACCENT
            elif index == self.owner.GetSelection():
                colour = ACCENT
            else:
                colour = FG_PRIMARY

            context.SetFont(FONT_UI, colour)
            textHeight = context.GetTextExtent(choice)[1]
            context.DrawText(choice, padX, rowTop + (self.rowHeight - textHeight) / 2)


def _draw_chevron(context, x, y, size, colour, width, pointing="down"):
    """A chevron (the dropdown / disclosure arrow) as two strokes, not a glyph.

    Drawn rather than set in text because the character that looks right differs per font
    and platform, and a missing glyph renders as a tofu box.
    """
    path = context.CreatePath()
    if pointing == "down":
        path.MoveToPoint(x, y)
        path.AddLineToPoint(x + size / 2, y + size / 2)
        path.AddLineToPoint(x + size, y)
    elif pointing == "right":
        path.MoveToPoint(x + size / 4, y - size / 2)
        path.AddLineToPoint(x + size * 3 / 4, y)
        path.AddLineToPoint(x + size / 4, y + size / 2)
    context.SetPen(_stroke(context, colour, width))
    context.SetBrush(wx.TRANSPARENT_BRUSH)
    context.StrokePath(path)


# --- glyphs ------------------------------------------------------------------------------
# Stroked outlines on a unit square, scaled and coloured at draw time. Bitmaps would have to
# be produced at each DPI and recoloured for each palette; wx.ArtProvider's stock icons are
# fixed-palette light-theme artwork and read as foreign against BG_MAIN. These take the
# label's colour, so they follow the variant and the disabled state without any assets.
#
# Each entry is a list of paths; a path is (closed, [(x, y), ...]) in 0..1 coordinates.
FOLDER = "folder"
PLAY = "play"
STOP = "stop"
REFRESH = "refresh"
DOWNLOAD = "download"
SEARCH = "search"
SETTINGS = "settings"
ARCHIVE = "archive"
DOCUMENT = "document"

_GLYPHS = {
    FOLDER: [
        (True, [(0.05, 0.25), (0.42, 0.25), (0.5, 0.37), (0.95, 0.37), (0.95, 0.85),
                (0.05, 0.85)]),
    ],
    PLAY: [
        (True, [(0.22, 0.12), (0.88, 0.5), (0.22, 0.88)]),
    ],
    STOP: [
        (True, [(0.18, 0.18), (0.82, 0.18), (0.82, 0.82), (0.18, 0.82)]),
    ],
    REFRESH: [
        # Three quarters of a circle plus an arrowhead; a full circle reads as a spinner.
        (False, [(0.88, 0.5), (0.86, 0.68), (0.74, 0.83), (0.55, 0.9), (0.35, 0.86),
                 (0.2, 0.73), (0.13, 0.54), (0.18, 0.33), (0.33, 0.18), (0.53, 0.12),
                 (0.72, 0.18)]),
        (False, [(0.5, 0.06), (0.75, 0.19), (0.52, 0.34)]),
    ],
    DOWNLOAD: [
        (False, [(0.5, 0.1), (0.5, 0.66)]),
        (False, [(0.28, 0.46), (0.5, 0.68), (0.72, 0.46)]),
        (False, [(0.14, 0.88), (0.86, 0.88)]),
    ],
    SEARCH: [
        (True, [(0.62, 0.16), (0.78, 0.32), (0.78, 0.56), (0.62, 0.72), (0.38, 0.72),
                (0.22, 0.56), (0.22, 0.32), (0.38, 0.16)]),
        (False, [(0.68, 0.68), (0.9, 0.9)]),
    ],
    # Sliders rather than a gear: a gear's teeth close up into a blob at 14 DIPs, and the
    # outline version reads as a sparkle.
    SETTINGS: [
        (False, [(0.1, 0.26), (0.9, 0.26)]),
        (True, [(0.56, 0.18), (0.7, 0.18), (0.7, 0.34), (0.56, 0.34)]),
        (False, [(0.1, 0.5), (0.9, 0.5)]),
        (True, [(0.26, 0.42), (0.4, 0.42), (0.4, 0.58), (0.26, 0.58)]),
        (False, [(0.1, 0.74), (0.9, 0.74)]),
        (True, [(0.6, 0.66), (0.74, 0.66), (0.74, 0.82), (0.6, 0.82)]),
    ],
    ARCHIVE: [
        (True, [(0.08, 0.2), (0.92, 0.2), (0.92, 0.38), (0.08, 0.38)]),
        (True, [(0.16, 0.38), (0.84, 0.38), (0.84, 0.86), (0.16, 0.86)]),
        (False, [(0.42, 0.54), (0.58, 0.54)]),
    ],
    DOCUMENT: [
        (True, [(0.22, 0.08), (0.62, 0.08), (0.8, 0.3), (0.8, 0.92), (0.22, 0.92)]),
        (False, [(0.36, 0.5), (0.66, 0.5)]),
        (False, [(0.36, 0.68), (0.66, 0.68)]),
    ],
}


# Shapes small enough to read better solid than as an outline.
_FILLED = {PLAY, STOP, SETTINGS}


def _draw_glyph(context, name, x, y, size, colour, width):
    """Stroke the named glyph into a size x size box at (x, y)."""
    paths = _GLYPHS.get(name)
    if not paths:
        return
    context.SetPen(_stroke(context, colour, width))
    context.SetBrush(wx.Brush(colour))
    for closed, points in paths:
        path = context.CreatePath()
        first = True
        for px, py in points:
            point = (x + px * size, y + py * size)
            if first:
                path.MoveToPoint(*point)
                first = False
            else:
                path.AddLineToPoint(*point)
        if closed:
            path.CloseSubpath()
        # Outlines with a hole in them (folder, archive) would swallow their own detail if
        # filled, so only the small solid shapes are.
        if closed and name in _FILLED:
            context.FillPath(path)
        context.StrokePath(path)


class _FieldTextCtrl(wx.TextCtrl):
    """A wx.TextCtrl that never actually goes wx.WS_DISABLED.

    On MSW, a *disabled* Edit control is always painted by Windows itself (routed through
    WM_CTLCOLORSTATIC instead of WM_CTLCOLOREDIT), which ignores whatever
    SetBackgroundColour/SetForegroundColour the app has set - the system's pale disabled
    fill shows through no matter which of our palettes is active, and stripping the
    control's UxTheme subtheme (see theme.py's _style_widget) does not change that: it is
    which message Windows sends, not how the theme draws it, that is disabled-specific.
    A read-only-but-still-enabled control keeps routing through WM_CTLCOLOREDIT, which
    does honour custom colours, so Enable()/Disable() here toggle SetEditable() instead of
    the real wx enabled state. IsEnabled() is overridden to match, so callers asking "is
    this control enabled" (Field._OnPaint, theme.py's per-widget styling) see the same
    answer they would have from a genuinely disabled control, without the paint problem.
    """

    def Enable(self, enable=True):
        self.SetEditable(enable)
        return super().Enable(True)

    def Disable(self):
        return self.Enable(False)

    def IsEnabled(self):
        return self.IsEditable()


class Field(wx.Panel):
    """A native wx.TextCtrl inside a drawn, rounded, focus-aware border.

    The text control itself stays native - selection, IME, undo and clipboard behaviour are
    worth far more than its chrome - but its border is not themeable on MSW, which is why
    theme.py had to force BORDER_SIMPLE on every input and why every field on the Start tab
    is a hard grey rectangle. Here the control is borderless and the panel draws the box.

    The wx.TextCtrl is `field.ctrl`; call sites that held a TextCtrl keep holding one.
    """

    def __init__(
        self,
        parent,
        value="",
        hint=None,
        style=0,
        multiline=False,
        name="field",
        size=wx.DefaultSize,
    ):
        super().__init__(parent, style=wx.BORDER_NONE, name=name)
        self.SetDoubleBuffered(True)
        self.SetBackgroundStyle(wx.BG_STYLE_PAINT)
        self.Bind(wx.EVT_PAINT, self._OnPaint)
        self.Bind(wx.EVT_ERASE_BACKGROUND, lambda event: None)

        if multiline:
            style |= wx.TE_MULTILINE
        self.ctrl = _FieldTextCtrl(self, value=value, style=style | wx.BORDER_NONE)
        self.ctrl.SetBackgroundColour(BG_INPUT)
        self.ctrl.SetForegroundColour(FG_PRIMARY)
        lock_font(self.ctrl, FONT_UI)
        if hint:
            self.ctrl.SetHint(hint)

        # Repaint the frame when focus moves, so the ring follows the caret.
        self.ctrl.Bind(wx.EVT_SET_FOCUS, self._OnFocus)
        self.ctrl.Bind(wx.EVT_KILL_FOCUS, self._OnFocus)

        # Asymmetric padding: the horizontal gap keeps text off the rounded corners, the
        # vertical one only has to clear the caret. Equal padding made every field as tall
        # as a button and turned each row of the Start tab into its own band.
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(
            self.ctrl, 1, wx.EXPAND | wx.LEFT | wx.RIGHT, dip(self, SP_SM)
        )
        sizer.Insert(0, 0, dip(self, SP_XS))
        sizer.Add(0, dip(self, SP_XS))
        self.SetSizer(sizer)
        if size != wx.DefaultSize:
            # On the wrapper, not on the TextCtrl: the caller is sizing the visible box, and
            # the box is what this panel draws.
            self.SetInitialSize(size)

    def _OnFocus(self, event):
        self.Refresh()
        event.Skip()

    def _OnPaint(self, event):
        dc = wx.AutoBufferedPaintDC(self)
        dc.SetBackground(wx.Brush(self.GetParent().GetBackgroundColour()))
        dc.Clear()
        context = _gc(dc)
        if context is None:
            return

        width, height = self.GetClientSize()
        radius = dip(self, RADIUS_MD)
        enabled = self.ctrl.IsEnabled()
        _fill_round_rect(
            context, 0, 0, width, height, radius, BG_INPUT if enabled else BG_DISABLED
        )

        focused = self.ctrl.HasFocus()
        border = FOCUS_RING if focused else (BORDER_STRONG if enabled else BORDER_SUBTLE)
        _fill_round_rect(
            context, 0, 0, width, height, radius, None, border,
            dip(self, 2 if focused else 1),
        )


class Collapsible(wx.Panel):
    """A disclosure section: clickable header with a chevron, plus a content pane.

    Replaces wx.CollapsiblePane, whose header is an internal control that matches none of
    the branches in theme.py's walker - which is why that file has a special case poking at
    its children to stop the label rendering in black.

    Mirrors the parts of the wx API the panels use: GetPane(), Collapse(), Expand(),
    IsCollapsed(), and a wx.CollapsiblePaneEvent on toggle.
    """

    HEADER_PAD = SP_SM
    CHEVRON = 10

    def __init__(self, parent, label="", collapsed=True, name="collapsible"):
        super().__init__(parent, style=wx.BORDER_NONE, name=name)
        self.label = label
        self.collapsed = collapsed
        self.hovered = False
        self.SetBackgroundColour(parent.GetBackgroundColour())

        self.header = _CollapsibleHeader(self)
        self.pane = wx.Panel(self)
        self.pane.SetBackgroundColour(parent.GetBackgroundColour())
        self.pane.Show(not collapsed)

        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self.header, 0, wx.EXPAND)
        sizer.Add(self.pane, 1, wx.EXPAND | wx.LEFT | wx.TOP, dip(self, SP_SM))
        self.SetSizer(sizer)

    # -- API parity with wx.CollapsiblePane ---------------------------------
    def GetPane(self):
        return self.pane

    def IsCollapsed(self):
        return self.collapsed

    def IsExpanded(self):
        return not self.collapsed

    def Collapse(self, collapse=True):
        if collapse == self.collapsed:
            return
        self.collapsed = collapse
        self.pane.Show(not collapse)
        self.header.Refresh()
        self._Relayout()

    def Expand(self):
        self.Collapse(False)

    def SetLabel(self, label):
        self.label = label
        self.header.Refresh()

    def Toggle(self):
        self.Collapse(not self.collapsed)
        changed = wx.CollapsiblePaneEvent(self, self.GetId(), self.collapsed)
        changed.SetEventObject(self)
        self.GetEventHandler().ProcessEvent(changed)

    def _Relayout(self):
        """Re-run layout up the chain; a pane that grew has to push its container open."""
        window = self
        while window:
            window.Layout()
            if isinstance(window, wx.TopLevelWindow):
                break
            window = window.GetParent()


class _CollapsibleHeader(_Themed):
    """The clickable title row of a Collapsible."""

    def __init__(self, owner):
        self.owner = owner
        super().__init__(owner, name="collapsible-header")
        lock_font(self, FONT_H2)
        self.SetCursor(wx.Cursor(wx.CURSOR_HAND))
        self.Bind(wx.EVT_LEFT_UP, lambda event: self.owner.Toggle())
        self.Bind(wx.EVT_KEY_DOWN, self._OnKey)
        self.Bind(wx.EVT_SET_FOCUS, lambda event: (self.Refresh(), event.Skip()))
        self.Bind(wx.EVT_KILL_FOCUS, lambda event: (self.Refresh(), event.Skip()))
        _announce(self, _DisclosureAccessible)

    def _OnKey(self, event):
        if event.GetKeyCode() in (wx.WXK_SPACE, wx.WXK_RETURN, wx.WXK_NUMPAD_ENTER):
            self.owner.Toggle()
            return
        event.Skip()

    def DoGetBestSize(self):
        dc = wx.ClientDC(self)
        dc.SetFont(self.GetFont())
        return wx.Size(-1, dc.GetTextExtent("Xg")[1] + dip(self, self.owner.HEADER_PAD) * 2)

    def Draw(self, context, width, height):
        if self.hovered:
            _fill_round_rect(
                context, 0, 0, width, height, dip(self, RADIUS_SM), BG_HOVER
            )

        chevron = dip(self, self.owner.CHEVRON)
        colour = FG_PRIMARY if self.IsEnabled() else FG_DISABLED
        _draw_chevron(
            context,
            0,
            height / 2 - (chevron / 4 if self.owner.collapsed else 0),
            chevron,
            colour,
            dip(self, 1.6),
            pointing="right" if self.owner.collapsed else "down",
        )

        context.SetFont(self.GetFont(), colour)
        textHeight = context.GetTextExtent(self.owner.label)[1]
        context.DrawText(
            self.owner.label, chevron + dip(self, SP_SM), (height - textHeight) / 2
        )


class TabBar(_Themed):
    """Tab strip for a wx.Simplebook, drawn as labels with an underline indicator.

    FlatNotebook draws boxed tabs with a simple border, which is the most dated element on
    screen and cannot be restyled beyond the four colours it exposes. Pairing a drawn strip
    with a plain Simplebook also means the page widgets keep the book as their parent, so
    panels that read attributes off GetParent() are unaffected.

    The book owns the pages and the selection; this only draws and dispatches.
    """

    PAD_X = SP_MD
    PAD_Y = SP_SM
    INDICATOR = 2  # underline thickness, DIPs

    def __init__(self, parent, book, name="tabbar"):
        self.book = book
        self.tabs = []       # (label, x, width), rebuilt on every paint
        self.hoveredTab = -1
        super().__init__(parent, name=name)
        lock_font(self, FONT_UI)
        self.SetBackgroundColour(BG_MAIN)
        self.Bind(wx.EVT_LEFT_DOWN, self._OnDown)
        self.Bind(wx.EVT_MOTION, self._OnMotion)
        self.Bind(wx.EVT_SIZE, lambda event: self.Refresh())
        self.Bind(wx.EVT_KEY_DOWN, self._OnKey)
        self.Bind(wx.EVT_SET_FOCUS, lambda event: (self.Refresh(), event.Skip()))
        self.Bind(wx.EVT_KILL_FOCUS, lambda event: (self.Refresh(), event.Skip()))
        _announce(self, _TabsAccessible)

    def _Labels(self):
        return [self.book.GetPageText(index) for index in range(self.book.GetPageCount())]

    def DoGetBestSize(self):
        dc = wx.ClientDC(self)
        dc.SetFont(self.GetFont())
        return wx.Size(-1, dc.GetTextExtent("Xg")[1] + dip(self, self.PAD_Y) * 2 + dip(self, self.INDICATOR))

    def _Measure(self, context):
        padX = dip(self, self.PAD_X)
        positions = []
        x = 0
        for label in self._Labels():
            width = context.GetTextExtent(label)[0] + padX * 2
            positions.append((label, x, width))
            x += width
        return positions

    def _TabAt(self, x):
        for index, (_, left, width) in enumerate(self.tabs):
            if left <= x < left + width:
                return index
        return -1

    def _OnDown(self, event):
        self.SetFocus()
        index = self._TabAt(event.GetX())
        if index >= 0 and index != self.book.GetSelection():
            self.book.SetSelection(index)
            self.Refresh()

    def _OnKey(self, event):
        """Arrow through the tabs, as a native notebook does.

        The strip is one tab stop and the arrows move within it; without this the tabs are
        reachable by mouse only, since the pages are switched from here rather than by the
        Simplebook, which draws nothing and handles no keys.
        """
        count = self.book.GetPageCount()
        if count < 2:
            event.Skip()
            return

        key = event.GetKeyCode()
        current = self.book.GetSelection()
        if key in (wx.WXK_LEFT, wx.WXK_UP):
            target = (current - 1) % count
        elif key in (wx.WXK_RIGHT, wx.WXK_DOWN):
            target = (current + 1) % count
        elif key == wx.WXK_HOME:
            target = 0
        elif key == wx.WXK_END:
            target = count - 1
        else:
            event.Skip()
            return

        if target != current:
            self.book.SetSelection(target)
        self.Refresh()

    def _OnMotion(self, event):
        index = self._TabAt(event.GetX())
        if index != self.hoveredTab:
            self.hoveredTab = index
            self.SetCursor(wx.Cursor(wx.CURSOR_HAND if index >= 0 else wx.CURSOR_ARROW))
            self.Refresh()

    def _OnLeave(self, event):
        self.hoveredTab = -1
        self.SetCursor(wx.Cursor(wx.CURSOR_ARROW))
        super()._OnLeave(event)

    def Draw(self, context, width, height):
        context.SetBrush(wx.Brush(BG_MAIN))
        context.SetPen(wx.TRANSPARENT_PEN)
        context.DrawRectangle(0, 0, width, height)

        context.SetFont(self.GetFont(), FG_SECONDARY)
        self.tabs = self._Measure(context)
        selected = self.book.GetSelection()
        indicator = dip(self, self.INDICATOR)

        # Hairline under the whole strip, so the tabs read as sitting on the content.
        context.SetPen(_stroke(context, BORDER_SUBTLE, dip(self, 1)))
        context.StrokeLine(0, height - 1, width, height - 1)

        for index, (label, left, tabWidth) in enumerate(self.tabs):
            active = index == selected
            if index == self.hoveredTab and not active:
                _fill_round_rect(
                    context, left, dip(self, SP_XS) / 2, tabWidth,
                    height - dip(self, SP_XS), dip(self, RADIUS_SM), BG_HOVER,
                )

            colour = FG_PRIMARY if active else FG_SECONDARY
            context.SetFont(FONT_H2 if active else self.GetFont(), colour)
            textWidth, textHeight = context.GetTextExtent(label)[:2]
            context.DrawText(
                label, left + (tabWidth - textWidth) / 2, (height - indicator - textHeight) / 2
            )

            if active:
                context.SetBrush(wx.Brush(ACCENT))
                context.SetPen(wx.TRANSPARENT_PEN)
                context.DrawRectangle(left, height - indicator, tabWidth, indicator)

                if self.HasFocus():
                    # The strip is the focusable window, so the ring goes round the tab the
                    # arrows would move away from - otherwise keyboard users get no caret.
                    context.SetBrush(wx.TRANSPARENT_BRUSH)
                    context.SetPen(_stroke(context, FOCUS_RING, dip(self, 1)))
                    inset = dip(self, SP_XS) / 2
                    context.DrawRoundedRectangle(
                        left + inset,
                        inset,
                        tabWidth - inset * 2,
                        height - indicator - inset * 2,
                        dip(self, RADIUS_SM),
                    )


class Dialog(wx.Dialog):
    """wx.Dialog with the palette applied and Escape wired up.

    wx.Dialog itself is themeable - it is the *contents* that are not - so this only sets the
    background and gives subclasses a consistent way to close. Subclasses build their own
    content and call EndModal() with a wx.ID_* value.
    """

    def __init__(self, parent, title, style=wx.DEFAULT_DIALOG_STYLE, size=wx.DefaultSize):
        super().__init__(parent, title=title, style=style, size=size)
        self.escapeId = wx.ID_CANCEL
        self.SetBackgroundColour(BG_MAIN)
        self.SetForegroundColour(FG_PRIMARY)
        lock_font(self, FONT_UI)
        self.Bind(wx.EVT_CHAR_HOOK, self._OnCharHook)

    def SetEscapeId(self, id):
        self.escapeId = id

    def _OnCharHook(self, event):
        # The buttons are ui_kit controls, not wx.Button, so wxWidgets cannot find an
        # ID_CANCEL/ID_OK button to map Escape/Enter onto - there is no native "default
        # button" for it to click. Do both here.
        key = event.GetKeyCode()
        if key == wx.WXK_ESCAPE and self.IsModal():
            self.EndModal(self.escapeId)
            return

        if key in (wx.WXK_RETURN, wx.WXK_NUMPAD_ENTER) and self.IsModal():
            focus = self.FindFocus()
            # A focused Button handles its own Enter key (see Button._OnKey), and a
            # multiline text control wants Enter as a newline, not a submit.
            focusHandlesEnter = isinstance(focus, Button) or (
                isinstance(focus, wx.TextCtrl) and focus.HasFlag(wx.TE_MULTILINE)
            )
            okButton = self.FindWindow(wx.ID_OK)
            if not focusHandlesEnter and isinstance(okButton, Button) and okButton.IsEnabled():
                okButton._Fire()
                return

        event.Skip()


def dialog_buttons(parent, ok="OK", cancel="Cancel"):
    """Right-aligned OK/Cancel row, the themed CreateStdDialogButtonSizer.

    The buttons keep the standard ids, so wxDialog's own wxID_OK / wxID_CANCEL handling
    closes the dialog and any `Bind(wx.EVT_BUTTON, handler, id=wx.ID_OK)` the dialog
    installed still runs first and can refuse to close. Pass None for a label to leave
    that button out.
    """
    row = wx.BoxSizer(wx.HORIZONTAL)
    row.AddStretchSpacer()
    if cancel is not None:
        row.Add(Button(parent, wx.ID_CANCEL, cancel), 0, wx.LEFT, dip(parent, SP_SM))
    if ok is not None:
        row.Add(
            Button(parent, wx.ID_OK, ok, variant=PRIMARY), 0, wx.LEFT, dip(parent, SP_SM)
        )
    return row


# Severity badge glyphs, drawn rather than pulled from wx.ArtProvider: the system icons are
# fixed-palette and read as light-theme artwork against BG_MAIN.
_BADGE_ERROR = "error"
_BADGE_WARNING = "warning"
_BADGE_INFO = "info"
_BADGE_QUESTION = "question"


class _Badge(_Themed):
    """Filled circle with a glyph, sized to the heading step."""

    SIZE = 32

    def __init__(self, parent, kind):
        self.kind = kind
        super().__init__(parent, name="badge")

    def DoGetBestSize(self):
        size = dip(self, self.SIZE)
        return wx.Size(size, size)

    def _colour(self):
        if self.kind == _BADGE_ERROR:
            return DANGER
        if self.kind == _BADGE_WARNING:
            return TIMER_WARN
        return ACCENT

    def Draw(self, context, width, height):
        size = min(width, height)
        colour = self._colour()
        context.SetBrush(wx.Brush(colour))
        context.SetPen(wx.TRANSPARENT_PEN)
        context.DrawEllipse(0, 0, size, size)

        glyph = {
            _BADGE_ERROR: "!",
            _BADGE_WARNING: "!",
            _BADGE_QUESTION: "?",
        }.get(self.kind, "i")
        # The three badge colours span red to amber, so neither FG_ON_ACCENT nor FG_PRIMARY
        # works for all of them. Pick by luminance instead.
        context.SetFont(FONT_H2, _contrasting(colour))
        textWidth, textHeight = context.GetTextExtent(glyph)[:2]
        context.DrawText(glyph, (size - textWidth) / 2, (size - textHeight) / 2)


# Kinds accepted by Notice, and by the badge it draws.
INFO = _BADGE_INFO
WARNING = _BADGE_WARNING
ERROR = _BADGE_ERROR


class Notice(wx.Panel):
    """The empty, waiting or failed state of a results area.

    These states used to be a sentence typed into the read-only text box that normally
    holds output - "Extract after Yara Processing." - which reads as content rather than
    as an explanation of why there is none, and inherits the monospace body of whatever
    view it is standing in for.

    Present() swaps this in for the control it was installed over; Dismiss() puts that
    control back. Both re-lay out the parent, so a panel can flip between the two without
    knowing how it was laid out.
    """

    WRAP = 420

    def __init__(self, parent, replaces=None, kind=INFO, title="", detail=""):
        super().__init__(parent, style=wx.BORDER_NONE)
        self.replaces = replaces
        self.SetBackgroundColour(parent.GetBackgroundColour())

        self.badge = _Badge(self, kind)
        self.title = lock_font(wx.StaticText(self, label=title), FONT_H2)
        self.title.SetForegroundColour(FG_PRIMARY)
        self.detail = lock_font(wx.StaticText(self, label=detail), FONT_UI)
        self.detail.SetForegroundColour(FG_SECONDARY)

        column = wx.BoxSizer(wx.VERTICAL)
        column.Add(self.badge, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.BOTTOM, dip(self, SP_MD))
        column.Add(self.title, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.BOTTOM, dip(self, SP_XS))
        column.Add(self.detail, 0, wx.ALIGN_CENTER_HORIZONTAL)

        # Centred in both directions: the state belongs to the whole empty area, not to its
        # top-left corner.
        outer = wx.BoxSizer(wx.VERTICAL)
        outer.AddStretchSpacer()
        outer.Add(column, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, dip(self, SP_LG))
        outer.AddStretchSpacer()
        self.SetSizer(outer)
        self.Set(kind, title, detail)

    def Set(self, kind=None, title=None, detail=None):
        if kind is not None:
            self.badge.kind = kind
            self.badge.Refresh()
        if title is not None:
            self.title.SetLabel(title)
        if detail is not None:
            self.detail.SetLabel(detail)
            self.detail.Wrap(dip(self, self.WRAP))
        self.Layout()

    def Present(self, title=None, detail=None, kind=None):
        self.Set(kind, title, detail)
        if self.replaces is not None:
            self.replaces.Hide()
        self.Show()
        self.GetParent().Layout()

    def Dismiss(self):
        if not self.IsShown():
            return
        self.Hide()
        if self.replaces is not None:
            self.replaces.Show()
        self.GetParent().Layout()


def notice_for(control, kind=INFO, title="", detail=""):
    """Install a hidden Notice in *control*'s sizer slot, matching its layout flags.

    Reading the flags off the existing item rather than taking them as arguments keeps the
    state the same shape as the content it stands in for - a results box that expands has a
    state that expands with it.
    """
    sizer = control.GetContainingSizer()
    notice = Notice(control.GetParent(), control, kind, title, detail)
    if sizer is None:
        # Nothing to match against; the caller places it.
        notice.Hide()
        return notice

    item = sizer.GetItem(control)
    index = next(
        (
            position
            for position in range(len(sizer.GetChildren()))
            if sizer.GetItem(position).GetWindow() is control
        ),
        0,
    )
    sizer.Insert(index, notice, item.GetProportion(), item.GetFlag(), item.GetBorder())
    notice.Hide()
    return notice


class _MessageDialog(Dialog):
    """The themed wx.MessageBox. Built by message(); not meant to be used directly."""

    # Message text wraps at this width before the dialog is allowed to grow.
    WRAP = 420

    def __init__(self, parent, message, caption, style):
        super().__init__(parent, caption, style=wx.DEFAULT_DIALOG_STYLE & ~wx.RESIZE_BORDER)
        outer = wx.BoxSizer(wx.VERTICAL)

        body = wx.BoxSizer(wx.HORIZONTAL)
        kind = self._Kind(style)
        if kind is not None:
            body.Add(_Badge(self, kind), 0, wx.ALIGN_TOP | wx.RIGHT, dip(self, SP_MD))

        text = wx.StaticText(self, label=message)
        text.SetForegroundColour(FG_PRIMARY)
        lock_font(text, FONT_UI)
        text.Wrap(dip(self, self.WRAP))
        body.Add(text, 1, wx.ALIGN_TOP)
        outer.Add(body, 1, wx.EXPAND | wx.ALL, dip(self, SP_LG))

        actions = wx.BoxSizer(wx.HORIZONTAL)
        actions.AddStretchSpacer()
        for id, label, variant, isDefault in self._Actions(style):
            button = Button(self, id=id, label=label, variant=variant)
            button.Bind(wx.EVT_BUTTON, self._OnAction)
            actions.Add(button, 0, wx.LEFT, dip(self, SP_SM))
            if isDefault:
                button.SetFocus()
        outer.Add(
            actions, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, dip(self, SP_LG)
        )

        self.SetSizerAndFit(outer)
        if parent:
            self.CentreOnParent()
        else:
            self.CentreOnScreen()

    @staticmethod
    def _Kind(style):
        for flag, kind in (
            (wx.ICON_ERROR, _BADGE_ERROR),
            (wx.ICON_WARNING, _BADGE_WARNING),
            (wx.ICON_QUESTION, _BADGE_QUESTION),
            (wx.ICON_INFORMATION, _BADGE_INFO),
        ):
            if style & flag == flag:
                return kind
        return None

    @staticmethod
    def _Actions(style):
        """[(id, label, variant, isDefault)] in left-to-right order.

        Mirrors wx.MessageBox: YES_NO replaces the OK button, CANCEL is additive, and
        NO_DEFAULT / CANCEL_DEFAULT move the initial focus off the affirmative action.
        """
        actions = []
        if style & wx.YES_NO == wx.YES_NO:
            wantsNoDefault = bool(style & wx.NO_DEFAULT)
            actions.append((wx.ID_YES, "Yes", PRIMARY, not wantsNoDefault))
            actions.append((wx.ID_NO, "No", SECONDARY, wantsNoDefault))
        else:
            actions.append((wx.ID_OK, "OK", PRIMARY, True))
        if style & wx.CANCEL:
            wantsCancelDefault = bool(style & wx.CANCEL_DEFAULT)
            if wantsCancelDefault:
                actions = [(id, label, variant, False) for id, label, variant, _ in actions]
            actions.append((wx.ID_CANCEL, "Cancel", SECONDARY, wantsCancelDefault))
        return actions

    def _OnAction(self, event):
        self.EndModal(event.GetId())


# wx.MessageBox reports the button by flag, not by window id.
_MESSAGE_RESULTS = {
    wx.ID_OK: wx.OK,
    wx.ID_YES: wx.YES,
    wx.ID_NO: wx.NO,
    wx.ID_CANCEL: wx.CANCEL,
}


def message(message, caption="Message", style=wx.OK | wx.CENTRE, parent=None):
    """Themed stand-in for wx.MessageBox, with the same arguments and return values.

    wx.MessageBox is a native task dialog: it ignores the palette completely and shows up as a
    light popup over the dark UI. This renders the same thing from the theme.

    Returns wx.OK, wx.YES, wx.NO or wx.CANCEL. The x/y arguments of wx.MessageBox are not
    supported - nothing in the codebase passes them, and the dialog centres on its parent.
    """
    dialog = _MessageDialog(parent, message, caption, style)
    # Escape means "no" when there is one, "cancel" when there is one, and is the same as OK
    # for a single-button dialog - matching the native behaviour.
    if style & wx.CANCEL:
        dialog.SetEscapeId(wx.ID_CANCEL)
    elif style & wx.YES_NO == wx.YES_NO:
        dialog.SetEscapeId(wx.ID_NO)
    else:
        dialog.SetEscapeId(wx.ID_OK)
    try:
        return _MESSAGE_RESULTS.get(dialog.ShowModal(), wx.CANCEL)
    finally:
        dialog.Destroy()

