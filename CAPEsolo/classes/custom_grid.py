import wx
import wx.grid as gridlib

from . import ui_kit as ui


def SortKey(value):
    """Numbers (decimal or 0x hex) sort by value and ahead of text; text sorts case-insensitively."""
    text = str(value).strip()
    try:
        return (0, int(text, 0), "")
    except ValueError:
        pass
    try:
        return (0, float(text), "")
    except ValueError:
        return (1, 0, text.lower())


class CopyableGrid(gridlib.Grid):
    def __init__(self, parent, rows, cols):
        super(CopyableGrid, self).__init__(parent)
        self.CreateGrid(rows, cols)
        self.sortCol = -1
        self.sortReverse = False
        self.sortLabel = ""

        self.Bind(gridlib.EVT_GRID_CELL_RIGHT_CLICK, self.onRightClick)
        self.Bind(gridlib.EVT_GRID_LABEL_LEFT_CLICK, self.onLabelClick)
        self.Bind(wx.EVT_KEY_DOWN, self.onKeyDown)

        self.popup_menu = wx.Menu()
        copy_item = self.popup_menu.Append(wx.ID_COPY, "Copy")
        self.Bind(wx.EVT_MENU, self.onCopy, copy_item)
        copy_row_item = self.popup_menu.Append(wx.ID_ANY, "Copy row")
        self.Bind(wx.EVT_MENU, self.onCopyRow, copy_row_item)

    def onRightClick(self, event):
        row, col = event.GetRow(), event.GetCol()
        if not self.IsInSelection(row, col):
            self.SetGridCursor(row, col)
            self.SelectBlock(row, col, row, col)
        self.PopupMenu(self.popup_menu, event.GetPosition())

    def onKeyDown(self, event):
        # EVT_KEY_DOWN reports the uppercase key code.
        if event.ControlDown() and event.GetKeyCode() == ord("C"):
            self.onCopy(None)
        else:
            event.Skip()

    def onCopy(self, event):
        lines = []
        for block in self.GetSelectedBlocks():
            for row in range(block.GetTopRow(), block.GetBottomRow() + 1):
                lines.append(
                    "\t".join(
                        self.GetCellValue(row, col)
                        for col in range(block.GetLeftCol(), block.GetRightCol() + 1)
                    )
                )
        if not lines:
            row, col = self.GetGridCursorRow(), self.GetGridCursorCol()
            if row < 0 or col < 0:
                return
            lines.append(self.GetCellValue(row, col))
        self.SetClipboard("\n".join(lines))

    def onCopyRow(self, event):
        row = self.GetGridCursorRow()
        if row < 0:
            return
        self.SetClipboard(
            "\t".join(self.GetCellValue(row, col) for col in range(self.GetNumberCols()))
        )

    def SetClipboard(self, text):
        if wx.TheClipboard.Open():
            wx.TheClipboard.SetData(wx.TextDataObject(text))
            wx.TheClipboard.Close()
        else:
            ui.message("Unable to open the clipboard", "Error")

    def NextSort(self, col):
        """Advance the sort state for a header click on col and mark its label. Returns reverse."""
        if col == self.sortCol:
            self.sortReverse = not self.sortReverse
        else:
            self.ResetSort()
            self.sortCol = col
            self.sortReverse = False
            self.sortLabel = self.GetColLabelValue(col)
        arrow = "▼" if self.sortReverse else "▲"
        self.SetColLabelValue(col, f"{self.sortLabel} {arrow}")
        return self.sortReverse

    def ResetSort(self):
        if self.sortCol >= 0:
            self.SetColLabelValue(self.sortCol, self.sortLabel)
        self.sortCol = -1
        self.sortReverse = False

    def onLabelClick(self, event):
        col = event.GetCol()
        if col < 0:
            event.Skip()
            return
        reverse = self.NextSort(col)
        numCols = self.GetNumberCols()
        rows = [
            [self.GetCellValue(row, c) for c in range(numCols)]
            for row in range(self.GetNumberRows())
        ]
        rows.sort(key=lambda values: SortKey(values[col]), reverse=reverse)
        for row, values in enumerate(rows):
            for c, value in enumerate(values):
                self.SetCellValue(row, c, value)
        self.AutoSizeRows()
