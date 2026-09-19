import wx
import wx.grid as gridlib

from . import ui_kit as ui


class CopyableGrid(gridlib.Grid):
    def __init__(self, parent, rows, cols):
        super(CopyableGrid, self).__init__(parent)
        self.CreateGrid(rows, cols)

        self.Bind(gridlib.EVT_GRID_CELL_RIGHT_CLICK, self.onRightClick)
        self.Bind(wx.EVT_KEY_DOWN, self.onKeyDown)

        self.popup_menu = wx.Menu()
        copy_item = self.popup_menu.Append(wx.ID_COPY, "Copy")
        self.Bind(wx.EVT_MENU, self.onCopy, copy_item)

    def onRightClick(self, event):
        self.row = event.GetRow()
        self.col = event.GetCol()
        self.PopupMenu(self.popup_menu, event.GetPosition())

    def onKeyDown(self, event):
        if event.ControlDown() and event.GetKeyCode() == ord("c"):
            self.onCopy(None)
        else:
            event.Skip()

    def onCopy(self, event):
        if hasattr(self, "row") and hasattr(self, "col"):
            cell_value = self.GetCellValue(self.row, self.col)
            if wx.TheClipboard.Open():
                wx.TheClipboard.SetData(wx.TextDataObject(cell_value))
                wx.TheClipboard.Close()
            else:
                ui.message("Unable to open the clipboard", "Error")
        else:
            selected_cells = self.GetSelectedCells()
            if selected_cells:
                cell_value = self.GetCellValue(
                    selected_cells[0].Row, selected_cells[0].Col
                )
                if wx.TheClipboard.Open():
                    wx.TheClipboard.SetData(wx.TextDataObject(cell_value))
                    wx.TheClipboard.Close()
                else:
                    ui.message("Unable to open the clipboard", "Error")
