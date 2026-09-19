import wx
import wx.lib.scrolledpanel as scrolled

# MAX_INSTRUCTION_LEN is read past the end of a page so the last instruction decodes
# whole instead of being cut mid-encoding.
from CAPEsolo.capelib.debug_session import MAX_INSTRUCTION_LEN, Disassemble

from . import ui_kit as ui
from .key_event import KeyEventHandlerMixin
from .theme import FONT_CODE, SP_XS, apply_theme, dip

# Page sizes in KB. Disassembly text runs several times the size of the bytes it
# describes, so these are smaller than the hex view's.
PAGE_SIZE_CHOICES = [4, 16, 64, 256]
DEFAULT_PAGE_SIZE = 16
ARCH_CHOICES = ["x86", "x64"]
# 8 offset digits + 2 spaces + 24 byte columns + 2 spaces + mnemonic.
LINE_WIDTH = 80


class DisasmWindow(wx.Frame, KeyEventHandlerMixin):
    def __init__(
        self,
        parent,
        title,
        filepath,
        main_window_position,
        main_window_size,
        bits=32,
        startOffset=0,
        *args,
        **kwargs,
    ):
        super().__init__(parent, title=title, *args, **kwargs)
        self.panel = scrolled.ScrolledPanel(
            self, -1, style=wx.TAB_TRAVERSAL | wx.SUNKEN_BORDER
        )
        self.panel.SetAutoLayout(1)
        self.panel.SetupScrolling(scroll_x=True, scroll_y=True)
        self.vbox = wx.BoxSizer(wx.VERTICAL)
        self.filepath = filepath
        try:
            self.fileSize = filepath.stat().st_size
        except OSError:
            self.fileSize = 0
        self.bits = 64 if bits == 64 else 32
        self.bytesPerPage = DEFAULT_PAGE_SIZE * 1024
        self.currentPage = max(0, startOffset) // self.bytesPerPage + 1
        self.BindKeyEvents()
        self.mainWindowPosition = main_window_position
        self.mainWindowSize = main_window_size
        self.InitUI()

    def InitUI(self):
        self.vbox.AddSpacer(10)
        self.CreateTextCtrl()
        self.CreateControls()
        self.LoadPage()
        self.panel.SetSizer(self.vbox)
        # Offset a copy: the caller reuses the wx.Point it passed in, so mutating it here
        # would silently move whatever it positions next.
        position = wx.Point(self.mainWindowPosition)
        position.x += self.mainWindowSize.x
        self.SetPosition(position)
        self.panel.Layout()
        self.Layout()
        apply_theme(self)

    def TotalPages(self):
        if self.fileSize <= 0:
            return 1
        return max(1, -(-self.fileSize // self.bytesPerPage))

    def ReadPage(self, page):
        """Decode only the requested slice, so nothing scales with file size."""
        start = (page - 1) * self.bytesPerPage
        try:
            with open(self.filepath, "rb") as hfile:
                hfile.seek(start)
                data = hfile.read(self.bytesPerPage + MAX_INSTRUCTION_LEN)
        except OSError as e:
            wx.LogError(f"Cannot open file '{self.filepath}'. Error: {e}")
            return ""

        return self.FormatDisasm(data, start)

    def FormatDisasm(self, data, offset=0):
        """Format a linear sweep of *data* starting at file offset *offset*.

        Addresses are file offsets rather than a synthesised virtual address, so a line
        here refers to the same byte as the matching line in the hex view.

        A sweep that begins at an arbitrary offset can start part way through an
        instruction, so the first instruction or two of a page may be nonsense until the
        stream re-synchronises. That is inherent to disassembling from a fixed offset, not
        a decoding failure - the offset label above shows where the sweep began.
        """
        # No instruction is shorter than one byte, so this cannot truncate the page.
        instructions = Disassemble(offset, data, self.bits, len(data))
        pageEnd = offset + self.bytesPerPage
        lines = []
        for instruction in instructions:
            address = int(instruction["address"], 16)
            # The read ran past the page so the final instruction decodes whole; anything
            # actually starting beyond the page belongs to the next one.
            if address >= pageEnd:
                break
            lines.append(
                f'{address:08x}  {instruction["bytes"]:<24}  {instruction["text"]}'
            )

        return "\n".join(lines)

    def CreateTextCtrl(self):
        # FONT_CODE rather than a locally built teletype font: apply_theme only leaves a
        # TextCtrl's font alone when its face name is Consolas, so any other monospace font
        # would be replaced with the proportional UI font and the columns would misalign.
        font = FONT_CODE
        # Named resultsWindow because SearchDialog looks that attribute up on its parent.
        # Content goes in via ChangeValue, never the constructor: passing it as value= makes
        # wxMSW hand the whole string to CreateWindowEx as the window title, which fails on
        # a large payload.
        self.resultsWindow = wx.TextCtrl(
            self.panel,
            style=wx.TE_MULTILINE | wx.TE_READONLY | wx.HSCROLL,
        )
        self.resultsWindow.SetFont(font)

        dc = wx.ClientDC(self.resultsWindow)
        dc.SetFont(font)
        textWidth, _ = dc.GetTextExtent("0" * LINE_WIDTH)

        self.SetSize(textWidth + 80, self.mainWindowSize.y)
        self.vbox.Add(self.resultsWindow, 1, wx.EXPAND | wx.ALL, 10)

    def CreateControls(self):
        self.offsetLabel = wx.StaticText(self.panel, label="")
        self.vbox.Add(self.offsetLabel, 0, wx.LEFT | wx.RIGHT, 10)

        self.paginationSizer = wx.BoxSizer(wx.HORIZONTAL)

        self.firstPageButton = ui.Button(self.panel, label="<<")
        self.firstPageButton.Bind(wx.EVT_BUTTON, self.OnFirstPage)
        self.paginationSizer.Add(self.firstPageButton, 0, wx.ALL, dip(self, SP_XS))

        self.prevButton = ui.Button(self.panel, label="Previous")
        self.prevButton.Bind(wx.EVT_BUTTON, self.OnPrevPage)
        self.paginationSizer.Add(self.prevButton, 0, wx.ALL, dip(self, SP_XS))

        self.pageLabel = wx.StaticText(self.panel, label="Page 1 of 1")
        self.paginationSizer.Add(self.pageLabel, 0, wx.ALL | wx.CENTER, 5)

        self.pageField = ui.Field(
            self.panel, value="1", size=wx.Size(60, -1), style=wx.TE_PROCESS_ENTER
        )
        self.pageInput = self.pageField.ctrl
        self.pageInput.Bind(wx.EVT_TEXT_ENTER, self.OnGoToPage)
        self.paginationSizer.Add(self.pageField, 0, wx.ALL, dip(self, SP_XS))

        self.goButton = ui.Button(self.panel, label="Go")
        self.goButton.Bind(wx.EVT_BUTTON, self.OnGoToPage)
        self.paginationSizer.Add(self.goButton, 0, wx.ALL, dip(self, SP_XS))

        self.nextButton = ui.Button(self.panel, label="Next")
        self.nextButton.Bind(wx.EVT_BUTTON, self.OnNextPage)
        self.paginationSizer.Add(self.nextButton, 0, wx.ALL, dip(self, SP_XS))

        self.lastPageButton = ui.Button(self.panel, label=">>")
        self.lastPageButton.Bind(wx.EVT_BUTTON, self.OnLastPage)
        self.paginationSizer.Add(self.lastPageButton, 0, wx.ALL, dip(self, SP_XS))

        self.paginationSizer.Add(
            wx.StaticText(self.panel, label="KB per page:"), 0, wx.ALL | wx.CENTER, 5
        )
        self.pageSizeDropdown = ui.Picker(
            self.panel,
            value=str(DEFAULT_PAGE_SIZE),
            choices=[str(c) for c in PAGE_SIZE_CHOICES],
        )
        self.pageSizeDropdown.Bind(wx.EVT_COMBOBOX, self.OnPageSizeChange)
        self.paginationSizer.Add(self.pageSizeDropdown, 0, wx.ALL, dip(self, SP_XS))

        self.paginationSizer.Add(
            wx.StaticText(self.panel, label="Arch:"), 0, wx.ALL | wx.CENTER, 5
        )
        self.archDropdown = ui.Picker(
            self.panel,
            value="x64" if self.bits == 64 else "x86",
            choices=ARCH_CHOICES,
        )
        self.archDropdown.Bind(wx.EVT_COMBOBOX, self.OnArchChange)
        self.paginationSizer.Add(self.archDropdown, 0, wx.ALL, dip(self, SP_XS))

        self.vbox.Add(self.paginationSizer, 0, wx.CENTER | wx.BOTTOM, 5)

    def LoadPage(self):
        self.resultsWindow.ChangeValue(self.ReadPage(self.currentPage))
        self.resultsWindow.ShowPosition(0)
        self.UpdatePaginationControls()

    def UpdatePaginationControls(self):
        totalPages = self.TotalPages()
        self.pageLabel.SetLabel(f"Page {self.currentPage} of {totalPages}")
        self.firstPageButton.Enable(self.currentPage > 1)
        self.prevButton.Enable(self.currentPage > 1)
        self.nextButton.Enable(self.currentPage < totalPages)
        self.lastPageButton.Enable(self.currentPage < totalPages)
        self.pageInput.SetValue(str(self.currentPage))

        start = (self.currentPage - 1) * self.bytesPerPage
        end = min(start + self.bytesPerPage, self.fileSize)
        last = max(start, end - 1)
        self.offsetLabel.SetLabel(
            f"Sweep from offset 0x{start:08x} - 0x{last:08x} of "
            f"0x{max(0, self.fileSize - 1):08x}  ({self.fileSize:,} bytes)  "
            f"{'x64' if self.bits == 64 else 'x86'}"
        )
        self.panel.Layout()

    def OnFirstPage(self, event):
        self.currentPage = 1
        self.LoadPage()

    def OnPrevPage(self, event):
        if self.currentPage > 1:
            self.currentPage -= 1
            self.LoadPage()

    def OnNextPage(self, event):
        if self.currentPage < self.TotalPages():
            self.currentPage += 1
            self.LoadPage()

    def OnLastPage(self, event):
        self.currentPage = self.TotalPages()
        self.LoadPage()

    def OnGoToPage(self, event):
        totalPages = self.TotalPages()
        try:
            pageNum = int(self.pageInput.GetValue())
        except ValueError:
            ui.message(
                "Please enter a valid integer page number.",
                "Invalid Input",
                wx.OK | wx.ICON_ERROR,
            )
            self.pageInput.SetValue(str(self.currentPage))
            return

        if 1 <= pageNum <= totalPages:
            self.currentPage = pageNum
            self.LoadPage()
        else:
            ui.message(
                f"Page number must be between 1 and {totalPages}.",
                "Invalid Page Number",
                wx.OK | wx.ICON_ERROR,
            )
            self.pageInput.SetValue(str(self.currentPage))

    def OnPageSizeChange(self, event):
        newSize = int(self.pageSizeDropdown.GetValue()) * 1024
        if newSize == self.bytesPerPage:
            return

        # Keep the view near the same file offset rather than jumping back to the start.
        currentOffset = (self.currentPage - 1) * self.bytesPerPage
        self.bytesPerPage = newSize
        self.currentPage = min(currentOffset // newSize + 1, self.TotalPages())
        self.LoadPage()

    def OnArchChange(self, event):
        bits = 64 if self.archDropdown.GetValue() == "x64" else 32
        if bits == self.bits:
            return

        self.bits = bits
        self.LoadPage()
