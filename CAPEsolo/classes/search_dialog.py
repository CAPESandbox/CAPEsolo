import re

import wx

from .theme import BG_INPUT, BG_SELECT, FG_PRIMARY, FG_RED_ALERT


class SearchDialog(wx.Dialog):
    def __init__(self, parent):
        super(SearchDialog, self).__init__(
            parent,
            title="Find",
            size=wx.Size(400, 100),
            style=wx.DEFAULT_DIALOG_STYLE | wx.STAY_ON_TOP,
        )
        self.caseSensitive = False
        self.fullWord = False
        grid = getattr(parent, "grid", None)
        # Checked before resultsWindow: the hex view has both, and searching the whole
        # file beats searching only the page that happens to be on screen.
        if hasattr(parent, "FindInFile"):
            self.hexView = parent
            self.Finder = self.FindFile
            self.FinderNext = self.FindFileNext
            self.lastFileOffset = -1
        # Only search the grid when it is the view actually on screen. BehaviorPanel owns
        # both a grid and a text control and hides the grid unless a process is being
        # shown, so preferring it unconditionally made Ctrl+F report "not found" for text
        # plainly visible in resultsWindow. Panels with only a grid are unaffected.
        elif grid is not None and (
            grid.IsShown() or not hasattr(parent, "resultsWindow")
        ):
            self.grid = grid
            self.Finder = self.FindCell
            self.FinderNext = self.FindNextCell
            self.currentSearchPos = (0, 0)
        elif hasattr(parent, "grids"):
            self.grids = parent.grids
            self.scrollHost = getattr(parent, "panel", None)
            self.Finder = self.FindInGrids
            self.FinderNext = self.FindInGridsNext
            self.currentGridPos = (0, 0, 0)
        elif hasattr(parent, "listCtrl"):
            self.listCtrl = parent.listCtrl
            self.Finder = self.FindInList
            self.FinderNext = self.FindInListNext
            self.currentSearchRow = 0
        else:
            self.resultsWindow = parent.resultsWindow
            self.lastFoundPos = -1
            self.Finder = self.OnFind
            self.FinderNext = self.OnFindNext

        self.InitUi()
        self.findWindow.Bind(wx.EVT_TEXT_ENTER, self.Finder)

    def InitUi(self):
        sizer = wx.BoxSizer(wx.VERTICAL)
        self.findWindow = wx.TextCtrl(self, style=wx.TE_PROCESS_ENTER)

        findButton = wx.Button(self, label="Find")
        findButton.Bind(wx.EVT_BUTTON, self.Finder)
        findNextButton = wx.Button(self, label="Find Next")
        findNextButton.Bind(wx.EVT_BUTTON, self.FinderNext)

        hbox1 = wx.BoxSizer(wx.HORIZONTAL)
        hbox1.Add(findButton, proportion=1, flag=wx.EXPAND | wx.RIGHT, border=5)
        hbox1.Add(findNextButton, proportion=1, flag=wx.EXPAND)


        self.chkCase = wx.CheckBox(self, label="Aa")
        self.chkCase.SetValue(False)
        self.chkCase.Bind(wx.EVT_CHECKBOX, self.OnCaseToggle)

        self.chkFull = wx.CheckBox(self, label="\u00A6ab\u00A6")
        self.chkFull.SetValue(False)
        self.chkFull.Bind(wx.EVT_CHECKBOX, self.OnFullWordToggle)

        hbox2 = wx.BoxSizer(wx.HORIZONTAL)
        hbox2.Add(self.chkCase, flag=wx.RIGHT, border=10)
        hbox2.Add(self.chkFull)

        sizer.Add(self.findWindow, proportion=0, flag=wx.EXPAND | wx.ALL, border=5)
        sizer.Add(hbox1, proportion=0, flag=wx.EXPAND | wx.ALL, border=5)
        sizer.Add(hbox2, proportion=0, flag=wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, border=5)

        self.SetSizer(sizer)
        self.Fit()

    def OnFind(self, event):
        self.FindText()

    def OnFindNext(self, event):
        self.FindText(startPos=self.lastFoundPos + 1)

    def FindText(self, startPos=0):
        searchText = self.findWindow.GetValue()
        content = self.resultsWindow.GetValue()
        if not self.caseSensitive:
            searchText = searchText.lower()
            content = content.lower()

        self.lastFoundPos = -1
        if self.fullWord:
            pattern = r'\b' + re.escape(searchText) + r'\b'
            match = re.search(pattern, content[startPos:])
            if match:
                self.lastFoundPos = startPos + match.start()
        else:
            self.lastFoundPos = content.find(searchText, startPos)

        self.HighlightText()

    def ControlPos(self, index):
        """Map an index into GetValue() to a position the control understands.

        GetValue() returns "\\n"-separated text; a plain TE_MULTILINE control stores "\\r\\n"
        (two chars per line break) while TE_RICH2 stores one, so a raw string index lands one
        character early per preceding line on the former and highlights the wrong text.

        Detect which by comparing the control's own length (GetLastPosition) with the "\\n"
        text length, then add one position per preceding line break for "\\r\\n" controls.
        This deliberately avoids XYToPosition: its line coordinates count word-wrapped display
        lines (EM_LINEINDEX), so once any line wraps the mapping drifts further the lower the
        match is - which broke Find Next in every wrapping panel.
        """
        content = self.resultsWindow.GetValue()
        if self.resultsWindow.GetLastPosition() <= len(content):
            return index  # one char per line break (TE_RICH2): indices already agree
        return index + content.count("\n", 0, index)

    def HighlightText(self):
        if self.lastFoundPos != -1:
            searchText = self.findWindow.GetValue()
            searchTextLength = len(searchText)
            textCtrl = self.resultsWindow
            start = self.ControlPos(self.lastFoundPos)
            # Theme tokens, not wx.SystemSettings: those return the OS colours (#FFFFFF /
            # #000000) whatever palette is active, so a match used to be painted as a white
            # block inside a dark control and the reset below left it black on white.
            textCtrl.SetStyle(
                start,
                start + searchTextLength,
                wx.TextAttr(FG_RED_ALERT, BG_SELECT),
            )
            textCtrl.ShowPosition(start)
            wx.CallLater(5000, self.ResetHighlight, textCtrl, start, searchTextLength)
            textCtrl.SetInsertionPoint(start)
            textCtrl.SetFocus()
        else:
            wx.MessageBox("Text not found.", "Search Result", wx.OK | wx.ICON_INFORMATION)

    def ResetHighlight(self, textCtrl, start, length):
        # start is already a control position, converted by HighlightText.
        textCtrl.SetStyle(
            start,
            start + length,
            wx.TextAttr(FG_PRIMARY, BG_INPUT),
        )
        textCtrl.Refresh()
        textCtrl.Update()

    def SetSelection(self, textCtrl, searchTextLength):
        start = self.ControlPos(self.lastFoundPos)
        textCtrl.SetSelection(start, start + searchTextLength)
        textCtrl.ShowPosition(start)
        textCtrl.Refresh()

    def FindFile(self, event):
        self.lastFileOffset = -1
        self.SearchFile(0)

    def FindFileNext(self, event):
        self.SearchFile(self.lastFileOffset + 1)

    def SearchFile(self, startOffset):
        searchText = self.findWindow.GetValue()
        offset = self.hexView.FindInFile(
            searchText, self.caseSensitive, self.fullWord, startOffset
        )
        if offset < 0:
            self.lastFileOffset = -1
            wx.MessageBox(
                "Text not found.", "Search Result", wx.OK | wx.ICON_INFORMATION
            )
            return

        self.lastFileOffset = offset
        self.hexView.GoToOffset(offset)

    def FindInGrids(self, event):
        self.currentGridPos = (0, 0, 0)
        self.SearchGrids()

    def FindInGridsNext(self, event):
        self.SearchGrids()

    def SearchGrids(self):
        """Walk several grids in display order, so Find Next crosses from one to the next."""
        searchText = self.findWindow.GetValue()
        if not self.caseSensitive:
            searchText = searchText.lower()

        startGrid, startRow, startCol = self.currentGridPos
        for gridIndex in range(startGrid, len(self.grids)):
            grid = self.grids[gridIndex]
            rows, cols = grid.GetNumberRows(), grid.GetNumberCols()
            firstRow = startRow if gridIndex == startGrid else 0
            for row in range(firstRow, rows):
                firstCol = startCol if (gridIndex == startGrid and row == firstRow) else 0
                for col in range(firstCol, cols):
                    cellText = grid.GetCellValue(row, col)
                    cmpText = cellText if self.caseSensitive else cellText.lower()
                    if self.fullWord:
                        match = searchText == cmpText
                    else:
                        match = searchText in cmpText

                    if match:
                        grid.SetGridCursor(row, col)
                        grid.MakeCellVisible(row, col)
                        grid.SelectBlock(row, col, row, col)
                        if hasattr(self.scrollHost, "ScrollChildIntoView"):
                            self.scrollHost.ScrollChildIntoView(grid)
                        nextCol = col + 1
                        if nextCol >= cols:
                            self.currentGridPos = (gridIndex, row + 1, 0)
                        else:
                            self.currentGridPos = (gridIndex, row, nextCol)
                        if self.currentGridPos[1] >= rows:
                            self.currentGridPos = (gridIndex + 1, 0, 0)
                        return

        wx.MessageBox(
            f"'{self.findWindow.GetValue()}' not found.",
            "Search Result",
            wx.OK | wx.ICON_INFORMATION,
        )
        self.currentGridPos = (0, 0, 0)

    def SearchCells(self):
        match = False
        searchText = self.findWindow.GetValue()
        if not self.caseSensitive:
            searchText = searchText.lower()

        rows = self.grid.GetNumberRows()
        cols = self.grid.GetNumberCols()
        startRow, startCol = self.currentSearchPos
        for row in range(startRow, rows):
            for col in range(startCol if row == startRow else 0, cols):
                cellText = self.grid.GetCellValue(row, col)
                cmpText = cellText if self.caseSensitive else cellText.lower()
                if self.fullWord:
                    match = searchText == cmpText
                else:
                    match = searchText in cmpText

                if match:
                    self.grid.SetGridCursor(row, col)
                    self.grid.MakeCellVisible(row, col)
                    self.grid.SelectBlock(row, col, row, col)
                    self.currentSearchPos = (row, col + 1)

                    if self.currentSearchPos[1] >= cols:
                        self.currentSearchPos = (self.currentSearchPos[0] + 1, 0)
                    return

        if not match:
            wx.MessageBox(f"'{searchText}' not found.", "Search Result", wx.OK | wx.ICON_INFORMATION)

        self.currentSearchPos = (0, 0)

    def FindCell(self, event):
        self.currentSearchPos = (0, 0)
        self.SearchCells()

    def FindNextCell(self, event):
        self.SearchCells()

    def SearchList(self):
        match = False
        searchText = self.findWindow.GetValue()
        if not self.caseSensitive:
            searchText = searchText.lower()

        rows = self.listCtrl.GetItemCount()
        cols = self.listCtrl.GetColumnCount()
        startRow = self.currentSearchRow

        for row in range(startRow, rows):
            for col in range(cols):
                cellText = self.listCtrl.GetItem(row, col).GetText()
                cmpText = cellText if self.caseSensitive else cellText.lower()
                if self.fullWord:
                    match = searchText == cmpText
                else:
                    match = searchText in cmpText

                if match:
                    self.listCtrl.Select(row)
                    self.listCtrl.Focus(row)
                    self.listCtrl.EnsureVisible(row)
                    self.currentSearchRow = row + 1

                    if self.currentSearchRow >= rows:
                        self.currentSearchRow = 0
                    return

        if not match:
            wx.MessageBox(f"'{searchText}' not found.", "Search Result", wx.OK | wx.ICON_INFORMATION)

        self.currentSearchRow = 0

    def FindInList(self, event):
        self.currentSearchRow = 0
        self.SearchList()

    def FindInListNext(self, event):
        self.SearchList()

    def OnCaseToggle(self, event):
        self.caseSensitive = self.chkCase.GetValue()

    def OnFullWordToggle(self, event):
        self.fullWord = self.chkFull.GetValue()
