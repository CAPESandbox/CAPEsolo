"""Specimen sheet for CAPEsolo's ui_kit primitives, rendered by shoot.py.

Every control in every state on one screen, so a change to the drawing code can be checked
at a glance instead of by hunting for an instance of it somewhere in the app.
"""

import os

import wx

from CAPEsolo.classes import ui_kit as ui
from CAPEsolo.classes.theme import (
    BG_MAIN,
    FG_PRIMARY,
    FG_SECONDARY,
    FONT_H1,
    FONT_SMALL,
    SP_LG,
    SP_MD,
    SP_SM,
    apply_theme,
    dip,
)

VARIANTS = (
    ("primary", ui.PRIMARY),
    ("secondary", ui.SECONDARY),
    ("success", ui.SUCCESSFUL),
    ("danger", ui.DANGEROUS),
    ("ghost", ui.GHOST),
)


class GalleryFrame(wx.Frame):
    def __init__(self, size):
        super().__init__(None, title="ui_kit gallery", size=size)
        panel = wx.Panel(self)
        panel.SetBackgroundColour(BG_MAIN)
        outer = wx.BoxSizer(wx.VERTICAL)
        pad = dip(panel, SP_LG)

        # GTK will not give a window more height than the monitor work area, so the whole
        # sheet cannot be captured in one shot on a normal screen. UIDEV_SECTIONS picks a
        # subset ("glyphs,states"), which is how the README images are produced.
        wanted = os.environ.get("UIDEV_SECTIONS", "").strip()
        wanted = [name.strip() for name in wanted.split(",") if name.strip()]

        sections = (
            ("tabs", self._Tabs, 0),
            ("buttons", self._Buttons, 0),
            ("glyphs", self._Glyphs, 0),
            ("toggles", self._Toggles, 0),
            ("inputs", self._Inputs, 0),
            ("states", self._States, 0),
            ("surfaces", self._Surfaces, 1),
        )
        shown = [entry for entry in sections if not wanted or entry[0] in wanted]
        if not shown:
            raise SystemExit(
                f"UIDEV_SECTIONS matched nothing; known: {[s[0] for s in sections]}"
            )
        # Whatever ends up last gets the slack, so a one-section sheet is not letterboxed
        # by an empty strip at the bottom.
        shown[-1] = (shown[-1][0], shown[-1][1], 1)

        for index, (_, build, proportion) in enumerate(shown):
            flags = wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM
            if index == 0:
                flags |= wx.TOP
            outer.Add(build(panel), proportion, flags, pad)

        panel.SetSizer(outer)
        apply_theme(self)
        # apply_theme walks wx.Panel subclasses and repaints them in card colours, which
        # would hide the page background the cards are meant to sit on.
        panel.SetBackgroundColour(BG_MAIN)

    def _Heading(self, parent, text):
        label = wx.StaticText(parent, label=text)
        label.SetFont(FONT_H1)
        label.SetForegroundColour(FG_PRIMARY)
        return label

    def _Buttons(self, parent):
        card = ui.Card(parent, title="Buttons", subtitle="variant x state")
        grid = wx.FlexGridSizer(rows=len(VARIANTS) + 1, cols=4, hgap=dip(card, SP_MD), vgap=dip(card, SP_SM))

        for header in ("", "idle", "hover", "disabled"):
            label = wx.StaticText(card, label=header)
            label.SetFont(FONT_SMALL)
            label.SetForegroundColour(FG_SECONDARY)
            grid.Add(label, 0, wx.ALIGN_CENTER_VERTICAL)

        for name, variant in VARIANTS:
            label = wx.StaticText(card, label=name)
            label.SetForegroundColour(FG_SECONDARY)
            grid.Add(label, 0, wx.ALIGN_CENTER_VERTICAL)

            grid.Add(ui.Button(card, label="Launch", variant=variant), 0)

            # Hover cannot be produced without a pointer under Xvfb, so it is faked by
            # setting the flag the paint code reads.
            hovered = ui.Button(card, label="Launch", variant=variant)
            hovered.hovered = True
            grid.Add(hovered, 0)

            disabled = ui.Button(card, label="Launch", variant=variant)
            disabled.Enable(False)
            grid.Add(disabled, 0)

        card.body.Add(grid, 0)
        return card

    def _Glyphs(self, parent):
        """Every glyph on a button, plus one disabled, to check they dim with the label."""
        card = ui.Card(parent, title="Glyphs", subtitle="stroked at draw time, no assets")
        row = wx.WrapSizer(wx.HORIZONTAL)

        for name in (
            ui.FOLDER,
            ui.PLAY,
            ui.STOP,
            ui.REFRESH,
            ui.DOWNLOAD,
            ui.SEARCH,
            ui.SETTINGS,
            ui.ARCHIVE,
            ui.DOCUMENT,
        ):
            row.Add(
                ui.Button(card, label=name, glyph=name),
                0,
                wx.RIGHT | wx.BOTTOM,
                dip(card, SP_SM),
            )

        disabled = ui.Button(card, label="disabled", glyph=ui.PLAY)
        disabled.Enable(False)
        row.Add(disabled, 0, wx.RIGHT | wx.BOTTOM, dip(card, SP_SM))
        row.Add(
            ui.Button(card, label="Launch", variant=ui.SUCCESSFUL, glyph=ui.PLAY),
            0,
            wx.RIGHT | wx.BOTTOM,
            dip(card, SP_SM),
        )
        row.Add(ui.Button(card, label="Kill", variant=ui.DANGEROUS, glyph=ui.STOP), 0)

        card.body.Add(row, 0, wx.EXPAND)
        return card

    def _States(self, parent):
        """The three Notice kinds side by side, at the size a results area gives them."""
        sizer = wx.BoxSizer(wx.HORIZONTAL)

        for kind, title, detail in (
            (ui.INFO, "No yara results yet", "Process yara results to list rule hits."),
            (ui.WARNING, "Partial results", "Three files could not be read."),
            (ui.ERROR, "File not found", "sample.exe is listed but is not on disk."),
        ):
            card = ui.Card(parent)
            notice = ui.Notice(card, kind=kind, title=title, detail=detail)
            notice.SetMinSize(wx.Size(-1, dip(parent, 150)))
            card.body.Add(notice, 1, wx.EXPAND)
            sizer.Add(card, 1, wx.EXPAND | wx.RIGHT, dip(parent, SP_LG))

        return sizer

    def _Toggles(self, parent):
        card = ui.Card(parent, title="Toggles")
        row = wx.BoxSizer(wx.HORIZONTAL)

        for value, enabled, text in (
            (False, True, "unchecked"),
            (True, True, "checked"),
            (False, False, "disabled"),
            (True, False, "disabled checked"),
        ):
            check = ui.Check(card, label=text)
            check.SetValue(value)
            check.Enable(enabled)
            row.Add(check, 0, wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, dip(card, SP_LG))

        radioRow = wx.BoxSizer(wx.HORIZONTAL)
        for index, text in enumerate(("full", "minhook", "zerohook", "native")):
            radio = ui.Radio(card, label=text, style=wx.RB_GROUP if index == 0 else 0)
            if index == 0:
                radio.SetValue(True)
            radioRow.Add(radio, 0, wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, dip(card, SP_LG))

        disabledRadio = ui.Radio(card, label="disabled")
        disabledRadio.Enable(False)
        radioRow.Add(disabledRadio, 0, wx.ALIGN_CENTER_VERTICAL)

        card.body.Add(row, 0, wx.BOTTOM, dip(card, SP_MD))
        card.body.Add(radioRow, 0)
        return card

    def _Surfaces(self, parent):
        sizer = wx.BoxSizer(wx.HORIZONTAL)

        card = ui.Card(parent, title="Card with a title", subtitle="and a subtitle line")
        card.body.Add(ui.SectionHeader(card, "Section header"), 0, wx.EXPAND | wx.BOTTOM, dip(card, SP_SM))
        field = wx.TextCtrl(card, value="native text control, for contrast")
        card.body.Add(field, 0, wx.EXPAND | wx.BOTTOM, dip(card, SP_SM))
        buttons = wx.BoxSizer(wx.HORIZONTAL)
        buttons.Add(ui.Button(card, label="Primary", variant=ui.PRIMARY), 0, wx.RIGHT, dip(card, SP_SM))
        buttons.Add(ui.Button(card, label="Secondary"), 0, wx.RIGHT, dip(card, SP_SM))
        buttons.Add(ui.Button(card, label="Kill", variant=ui.DANGEROUS), 0)
        card.body.Add(buttons, 0)

        plain = ui.Card(parent, title="Untitled card")
        plain.body.Add(
            wx.StaticText(plain, label="Cards nest without stacking outlines."), 0
        )

        sizer.Add(card, 1, wx.EXPAND | wx.RIGHT, dip(parent, SP_LG))
        sizer.Add(plain, 1, wx.EXPAND)
        return sizer

    def _Tabs(self, parent):
        """A live TabBar over a Simplebook, the pairing that replaces FlatNotebook."""
        holder = wx.Panel(parent)
        holder.SetBackgroundColour(BG_MAIN)
        book = wx.Simplebook(holder)
        for label in ("Start", "Info", "Behavior", "Signatures", "Payloads", "Yara", "Configs"):
            page = wx.Panel(book)
            book.AddPage(page, label)
        book.SetSelection(0)
        book.Hide()  # only the strip is being shown here

        bar = ui.TabBar(holder, book)
        bar.hoveredTab = 2  # faked: Xvfb has no pointer to hover with

        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(bar, 0, wx.EXPAND)
        holder.SetSizer(sizer)
        return holder

    def _Inputs(self, parent):
        card = ui.Card(parent, title="Inputs")
        row = wx.BoxSizer(wx.HORIZONTAL)

        picker = ui.Picker(card, choices=["Auto-detect", "exe", "dll", "shellcode"], value="Auto-detect")
        row.Add(picker, 0, wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, dip(card, SP_MD))

        disabledPicker = ui.Picker(card, choices=["1 - error codes only", "2 - all exceptions"], value="1 - error codes only")
        disabledPicker.Enable(False)
        row.Add(disabledPicker, 0, wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, dip(card, SP_MD))

        field = ui.Field(card, value="C:\\Users\\analyst\\Desktop\\sample.exe")
        row.Add(field, 1, wx.ALIGN_CENTER_VERTICAL)

        hinted = ui.Field(card, hint="<md5, sha1, sha256>")
        row.Add(hinted, 1, wx.LEFT | wx.ALIGN_CENTER_VERTICAL, dip(card, SP_MD))

        collapsed = ui.Collapsible(card, label="Debugger options")
        expanded = ui.Collapsible(card, label="Monitor Yara", collapsed=False)
        inner = wx.StaticText(expanded.GetPane(), label="pane content lives here")
        paneSizer = wx.BoxSizer(wx.VERTICAL)
        paneSizer.Add(inner, 0)
        expanded.GetPane().SetSizer(paneSizer)

        card.body.Add(row, 0, wx.EXPAND | wx.BOTTOM, dip(card, SP_MD))
        card.body.Add(collapsed, 0, wx.EXPAND)
        card.body.Add(expanded, 0, wx.EXPAND)
        return card
