import re

import wx
import wx.lib.scrolledpanel as scrolled

from .disasm_window import ARCH_CHOICES, DisasmWindow
from .key_event import KeyEventHandlerMixin
from .theme import FONT_CODE, apply_theme
from CAPEsolo.capelib.parse_pe import IsPEImage, PortableExecutable

# Read size for the file-wide search. Chunks overlap by the pattern length so a match
# straddling a boundary is still found.
SEARCH_CHUNK = 1024 * 1024

BYTES_PER_LINE = 16
# Page sizes in KB. 64 KB is 4096 lines / ~315 KB of text, which fills instantly; the whole
# file used to be formatted at once, which is ~5 bytes of text per file byte.
PAGE_SIZE_CHOICES = [16, 64, 256, 1024]
DEFAULT_PAGE_SIZE = 64
# 8 offset digits + 2 spaces + 48 hex columns + 2 spaces + 16 ascii characters.
LINE_WIDTH = 76


class HexViewWindow(wx.Frame, KeyEventHandlerMixin):
    def __init__(
        self,
        parent,
        title,
        filepath,
        main_window_position,
        main_window_size,
        *args,
        **kwargs,
    ):
        super(HexViewWindow, self).__init__(parent, title=title, *args, **kwargs)
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
        self.bytesPerPage = DEFAULT_PAGE_SIZE * 1024
        self.currentPage = 1
        self.disasmWindow = None
        self.defaultBits = self.DetectBits()
        self.BindKeyEvents()
        self.mainWindowPosition = main_window_position
        self.mainWindowSize = main_window_size
        self.InitUI()

    def InitUI(self):
        self.vbox.AddSpacer(10)
        self.CreateTextCtrl()
        self.CreatePaginationControls()
        self.LoadPage()
        self.panel.SetSizer(self.vbox)
        # Size to the wider of the hex dump and the bottom control row (7 buttons, a page
        # input, two dropdowns and Disassemble), so the pagination bar is never cut off. The
        # margin covers the frame border and the vertical scrollbar.
        width = max(self.hexWidth, self.paginationSizer.GetMinSize().width + 60)
        self.SetSize(width, self.mainWindowSize.y)
        # Offset a copy: the caller reuses the wx.Point it passed in, so mutating it here
        # would silently move whatever it positions next.
        position = wx.Point(self.mainWindowPosition)
        position.x += self.mainWindowSize.x
        self.SetPosition(position)
        self.panel.Layout()
        self.Layout()
        apply_theme(self)

    def DetectBits(self):
        """Pick the disassembly default from the payload's own PE header.

        Sniffs the first 1024 bytes first, the same cheap check PayloadsPanel uses to
        decide whether to offer its PE button, so a large payload is not fully parsed
        just to open the hex view. Anything that is not a PE - shellcode, a dropped
        document - falls back to x86, which the viewer's Arch dropdown can override.
        """
        try:
            with open(self.filepath, "rb") as hfile:
                head = hfile.read(1024)
        except OSError:
            return 32

        if not IsPEImage(head):
            return 32

        # is_64bit returns None when pefile could not parse the file at all.
        return 64 if PortableExecutable(str(self.filepath)).is_64bit() else 32

    def TotalPages(self):
        if self.fileSize <= 0:
            return 1
        return max(1, -(-self.fileSize // self.bytesPerPage))

    def ReadPage(self, page):
        """Read and format only the requested slice, so nothing scales with file size."""
        start = (page - 1) * self.bytesPerPage
        try:
            with open(self.filepath, "rb") as hfile:
                hfile.seek(start)
                data = hfile.read(self.bytesPerPage)
        except OSError as e:
            wx.LogError(f"Cannot open file '{self.filepath}'. Error: {e}")
            return ""

        return self.FormatHexData(data, start)

    def FormatHexData(self, data, offset=0):
        lines = []
        for i in range(0, len(data), BYTES_PER_LINE):
            chunk = data[i : i + BYTES_PER_LINE]
            hexChunk = " ".join(f"{byte:02x}" for byte in chunk)
            asciiChunk = "".join(
                chr(byte) if 32 <= byte <= 126 else "." for byte in chunk
            )
            # offset is the page's base, so the address column keeps showing the true file
            # offset instead of restarting at zero on every page.
            lines.append(f"{offset + i:08x}  {hexChunk:<48}  {asciiChunk}")
        return "\n".join(lines)

    def CreateTextCtrl(self):
        # FONT_CODE rather than a locally built teletype font: apply_theme only leaves a
        # TextCtrl's font alone when its face name is Consolas, so any other monospace font
        # would be replaced with the proportional UI font and the columns would misalign.
        font = FONT_CODE
        # Named resultsWindow because SearchDialog looks that attribute up on its parent;
        # while the control was a local, Ctrl+F in this window raised AttributeError.
        # Content goes in via ChangeValue, never the constructor: passing it as value= makes
        # wxMSW hand the whole string to CreateWindowEx as the window title, which fails on
        # a large payload ("CreateWindowEx("EDIT", ... title-len=10123774)").
        self.resultsWindow = wx.TextCtrl(
            self.panel,
            style=wx.TE_MULTILINE | wx.TE_READONLY | wx.HSCROLL,
        )
        self.resultsWindow.SetFont(font)

        # Measure a canonical full-width line rather than page content, so the window sizes
        # the same regardless of which page loads first and on an empty file.
        dc = wx.ClientDC(self.resultsWindow)
        dc.SetFont(font)
        textWidth, _ = dc.GetTextExtent("0" * LINE_WIDTH)

        # Width the hex dump wants; the final window width (set in InitUI) is the wider of
        # this and the bottom control row, so neither is cut off.
        self.hexWidth = textWidth + 80
        self.vbox.Add(self.resultsWindow, 1, wx.EXPAND | wx.ALL, 10)

    def CreatePaginationControls(self):
        self.offsetLabel = wx.StaticText(self.panel, label="")
        self.vbox.Add(self.offsetLabel, 0, wx.LEFT | wx.RIGHT, 10)

        self.paginationSizer = wx.BoxSizer(wx.HORIZONTAL)

        self.firstPageButton = wx.Button(self.panel, label="<<")
        self.firstPageButton.Bind(wx.EVT_BUTTON, self.OnFirstPage)
        self.paginationSizer.Add(self.firstPageButton, 0, wx.ALL, 5)

        self.prevButton = wx.Button(self.panel, label="Previous")
        self.prevButton.Bind(wx.EVT_BUTTON, self.OnPrevPage)
        self.paginationSizer.Add(self.prevButton, 0, wx.ALL, 5)

        self.pageLabel = wx.StaticText(self.panel, label="Page 1 of 1")
        self.paginationSizer.Add(self.pageLabel, 0, wx.ALL | wx.CENTER, 5)

        self.pageInput = wx.TextCtrl(
            self.panel, value="1", size=wx.Size(60, -1), style=wx.TE_PROCESS_ENTER
        )
        self.pageInput.Bind(wx.EVT_TEXT_ENTER, self.OnGoToPage)
        self.paginationSizer.Add(self.pageInput, 0, wx.ALL, 5)

        self.goButton = wx.Button(self.panel, label="Go")
        self.goButton.Bind(wx.EVT_BUTTON, self.OnGoToPage)
        self.paginationSizer.Add(self.goButton, 0, wx.ALL, 5)

        self.nextButton = wx.Button(self.panel, label="Next")
        self.nextButton.Bind(wx.EVT_BUTTON, self.OnNextPage)
        self.paginationSizer.Add(self.nextButton, 0, wx.ALL, 5)

        self.lastPageButton = wx.Button(self.panel, label=">>")
        self.lastPageButton.Bind(wx.EVT_BUTTON, self.OnLastPage)
        self.paginationSizer.Add(self.lastPageButton, 0, wx.ALL, 5)

        self.paginationSizer.Add(
            wx.StaticText(self.panel, label="KB per page:"), 0, wx.ALL | wx.CENTER, 5
        )
        self.pageSizeDropdown = wx.ComboBox(
            self.panel,
            value=str(DEFAULT_PAGE_SIZE),
            choices=[str(c) for c in PAGE_SIZE_CHOICES],
            style=wx.CB_READONLY,
        )
        self.pageSizeDropdown.Bind(wx.EVT_COMBOBOX, self.OnPageSizeChange)
        self.paginationSizer.Add(self.pageSizeDropdown, 0, wx.ALL, 5)

        self.archDropdown = wx.ComboBox(
            self.panel,
            value="x64" if self.defaultBits == 64 else "x86",
            choices=ARCH_CHOICES,
            style=wx.CB_READONLY,
        )
        self.paginationSizer.Add(self.archDropdown, 0, wx.ALL, 5)

        self.disasmButton = wx.Button(self.panel, label="Disassemble")
        self.disasmButton.Bind(wx.EVT_BUTTON, self.OnDisassemble)
        self.paginationSizer.Add(self.disasmButton, 0, wx.ALL, 5)

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
            f"Offset 0x{start:08x} - 0x{last:08x} of 0x{max(0, self.fileSize - 1):08x}"
            f"  ({self.fileSize:,} bytes)"
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
            wx.MessageBox(
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
            wx.MessageBox(
                f"Page number must be between 1 and {totalPages}.",
                "Invalid Page Number",
                wx.OK | wx.ICON_ERROR,
            )
            self.pageInput.SetValue(str(self.currentPage))

    def FindInFile(self, text, caseSensitive=False, fullWord=False, startOffset=0):
        """Search the whole file, not just the page on screen.

        Matches the file's bytes rather than the rendered dump, so the hex column's
        spacing never interferes. Returns the absolute file offset, or -1.
        """
        if not text:
            return -1

        try:
            needle = text.encode("latin-1")
        except UnicodeEncodeError:
            # Nothing outside latin-1 can appear in a byte-oriented search.
            return -1

        pattern = re.escape(needle)
        if fullWord:
            pattern = rb"\b" + pattern + rb"\b"
        regex = re.compile(pattern, 0 if caseSensitive else re.IGNORECASE)

        # Overlap so a match spanning two reads is not missed. \b needs one byte of
        # context on each side, hence the +1.
        overlap = len(needle) + 1
        start = max(0, startOffset)
        try:
            with open(self.filepath, "rb") as hfile:
                hfile.seek(start)
                base = start
                carry = b""
                while True:
                    chunk = hfile.read(SEARCH_CHUNK)
                    if not chunk:
                        return -1
                    window = carry + chunk
                    match = regex.search(window)
                    if match:
                        found = base - len(carry) + match.start()
                        if found >= startOffset:
                            return found
                    carry = window[-overlap:] if overlap else b""
                    base += len(chunk)
        except OSError as e:
            wx.LogError(f"Cannot search file '{self.filepath}'. Error: {e}")
            return -1

    def GoToOffset(self, offset):
        """Bring the page holding *offset* on screen and select that line."""
        if offset < 0 or offset >= max(1, self.fileSize):
            return

        page = offset // self.bytesPerPage + 1
        if page != self.currentPage:
            self.currentPage = page
            self.LoadPage()

        pageStart = (self.currentPage - 1) * self.bytesPerPage
        lineIndex = (offset - pageStart) // BYTES_PER_LINE
        lines = self.resultsWindow.GetValue().split("\n")
        if lineIndex >= len(lines):
            return

        # XYToPosition rather than summing Python string lengths: GetValue() hands back
        # "\n"-separated text while the native control counts "\r\n", so a manual sum
        # lands progressively further into the wrong line the further down the page it is.
        pos = self.resultsWindow.XYToPosition(0, lineIndex)
        if pos < 0:
            return

        self.resultsWindow.ShowPosition(pos)
        self.resultsWindow.SetSelection(pos, pos + len(lines[lineIndex]))
        self.resultsWindow.SetFocus()

    def OnDisassemble(self, event):
        """Open the disassembly viewer at the offset currently on screen."""
        # Raise the existing window rather than stacking a second one; OnDisasmClose
        # clears the reference when the user closes it.
        if self.disasmWindow:
            self.disasmWindow.Raise()
            return

        bits = 64 if self.archDropdown.GetValue() == "x64" else 32
        try:
            # Title differs from this window's so PayloadsPanel.IsWindowOpen, which
            # matches on title, cannot confuse the two.
            self.disasmWindow = DisasmWindow(
                self,
                f"{self.filepath} - Disassembly",
                self.filepath,
                self.GetPosition(),
                self.GetSize(),
                bits=bits,
                startOffset=(self.currentPage - 1) * self.bytesPerPage,
            )
            self.disasmWindow.Bind(wx.EVT_CLOSE, self.OnDisasmClose)
            self.disasmWindow.Show()
        except Exception as e:
            self.disasmWindow = None
            wx.MessageBox(
                f"Failed to disassemble: {e}", "Error", wx.OK | wx.ICON_ERROR
            )

    def OnDisasmClose(self, event):
        self.disasmWindow = None
        event.Skip()

    def OnPageSizeChange(self, event):
        newSize = int(self.pageSizeDropdown.GetValue()) * 1024
        if newSize == self.bytesPerPage:
            return

        # Keep the view near the same file offset rather than jumping back to the start.
        currentOffset = (self.currentPage - 1) * self.bytesPerPage
        self.bytesPerPage = newSize
        self.currentPage = min(currentOffset // newSize + 1, self.TotalPages())
        self.LoadPage()
