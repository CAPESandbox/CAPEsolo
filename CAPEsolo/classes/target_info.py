import wx
import wx.grid as gridlib

from .custom_grid import CopyableGrid
from .pe_window import PeWindow
from .theme import GRID_ROW_ALT, apply_theme
from CAPEsolo.capelib.objects import File


class TargetInfoPanel(wx.Panel):
    def __init__(self, parent):
        super(TargetInfoPanel, self).__init__(parent)
        self.parent = parent
        self.infoLoaded = False
        self.peData = {}
        self.InitUI()

    def InitUI(self):
        vbox = wx.BoxSizer(wx.VERTICAL)
        vbox.AddSpacer(10)
        self.grid = CopyableGrid(self,0, 2)
        self.grid.SetColLabelSize(0)
        self.grid.SetRowLabelSize(0)

        for col in range(self.grid.GetNumberCols()):
            attr = gridlib.GridCellAttr()
            attr.SetAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)
            self.grid.SetColAttr(col, attr)

        self.grid.SetColAttr(0, attr.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE))
        self.grid.SetColAttr(1, attr.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE))
        self.grid.EnableEditing(False)
        vbox.Add(self.grid, proportion=1, flag=wx.EXPAND | wx.ALL, border=5)
        self.peButton = wx.Button(self, label="PE")
        self.peButton.Bind(wx.EVT_BUTTON, self.OnShowPe)
        self.peButton.Hide()
        vbox.Add(self.peButton, proportion=0, flag=wx.LEFT, border=5)

        self.SetSizer(vbox)
        apply_theme(self)

    def AddNewRow(self, value0, value1):
        current_row = self.grid.GetNumberRows()
        self.grid.AppendRows(1)
        self.grid.SetCellValue(current_row, 0, value0)
        self.grid.SetCellValue(current_row, 1, value1)

    def LoadAndDisplayContent(self):
        self.targetFile = self.parent.targetFile
        if self.infoLoaded or not self.targetFile:
            return
        fileObj = File(str(self.targetFile))
        fileinfo = fileObj.get_all()[0]
        self.AddNewRow("Path", str(self.targetFile))
        for key, value in fileinfo.items():
            if key not in "path" and value:
                if not isinstance(value, str):
                    value = str(value) + " bytes"
                if value.startswith("s_"):
                    value = value[2:]
                self.AddNewRow(key[0].upper() + key[1:], value)
        self.grid.AutoSizeColumns()
        self.grid.SetColSize(0, 120)
        self.grid.AutoSizeRows()
        self.ApplyAlternateRowShading()
        self.peButton.Show()
        self.Layout()
        self.infoLoaded = True

    def ApplyAlternateRowShading(self):
        numRows = self.grid.GetNumberRows()

        for row in range(numRows):
            if row % 2 == 0:
                attr = gridlib.GridCellAttr()
                attr.SetBackgroundColour(GRID_ROW_ALT)
                self.grid.SetRowAttr(row, attr)
        self.grid.ForceRefresh()

    def OnShowPe(self, event):
        try:
            main_frame = self.GetMainFrame()
            size = main_frame.GetSize()
            position = main_frame.GetPosition()
            viewer_window = PeWindow(
                self, f"{str(self.targetFile)}", self.targetFile, position, size
            )
            viewer_window.Show()
        except Exception as e:
            wx.MessageBox(
                f"Failed to execute the command: {e}", "Error", wx.OK | wx.ICON_ERROR
            )

    def GetMainFrame(self):
        parent = self.GetParent()
        while parent and not isinstance(parent, wx.Frame):
            parent = parent.GetParent()
        return parent
