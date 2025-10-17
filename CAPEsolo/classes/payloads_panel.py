from pathlib import Path

import wx
import wx.grid as gridlib
import wx.lib.scrolledpanel as scrolled

from .custom_grid import CopyableGrid
from .hexview_window import HexViewWindow
from .pe_window import PeWindow
from CAPEsolo.capelib.cape_utils import (
    get_cape_name_from_cape_type,
    metadata_processing,
)
from CAPEsolo.capelib.objects import File
from CAPEsolo.capelib.parse_pe import IsPEImage
from CAPEsolo.capelib.utils import JsonPathExists, LoadFilesJson


class PayloadsPanel(wx.Panel):
    def __init__(self, parent):
        super(PayloadsPanel, self).__init__(parent)
        self.parent = parent
        self.analysisDir = parent.analysisDir
        self.payloadsLoaded = False
        self.jsonFileExists = False
        self.button_to_path = {}
        self.panel = scrolled.ScrolledPanel(
            self, -1, style=wx.TAB_TRAVERSAL | wx.SUNKEN_BORDER
        )
        self.panel.SetupScrolling(scroll_x=True, scroll_y=True)
        self.panel.SetAutoLayout(1)
        self.panelsizer = wx.BoxSizer(wx.VERTICAL)
        self.panel.SetSizer(self.panelsizer)
        self.panel.Hide()
        self.vbox = wx.BoxSizer(wx.VERTICAL)
        self.vbox.AddSpacer(10)
        self.vbox.Add(self.panel, 1, wx.EXPAND | wx.ALL, 10)
        self.SetSizer(self.vbox)

    def GridConf(self, grid):
        for col in range(grid.GetNumberCols()):
            attr = gridlib.GridCellAttr()
            attr.SetAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)
            grid.SetColAttr(col, attr)

        grid.SetColAttr(0, attr.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE))
        grid.SetColAttr(1, attr.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE))
        grid.EnableEditing(False)

    def AddNewRow(self, grid, value0, value1):
        current_row = grid.GetNumberRows()
        grid.AppendRows(1)
        grid.SetCellValue(current_row, 0, value0)
        grid.SetCellValue(current_row, 1, value1)

    def PayloadsReady(self):
        if JsonPathExists(self.analysisDir):
            self.jsonFileExists = True
            self.LoadAndDisplayContent()

    def LoadAndDisplayContent(self):
        if self.payloadsLoaded or not self.jsonFileExists:
            return

        popup = wx.ProgressDialog(
            "Loading payloads",
            "Please wait...",
            maximum=100,
            parent=self,
            style=wx.PD_APP_MODAL | wx.PD_AUTO_HIDE,
        )
        popup.Update(0)
        data = LoadFilesJson(self.analysisDir)
        if "error" in data:
            return
        else:
            data = dict(sorted(data.items(), key=lambda x: x[1]["size"], reverse=True))

        for key, value in data.items():
            if not key.startswith("aux_"):
                cape_info = {}
                metadata = data[key].get("metadata", "")
                if metadata:
                    cape_info = metadata_processing(metadata)

                path = Path(self.analysisDir) / key
                fileinfo = File(str(path)).get_all()[0]
                filepath = key[0].upper() + key[1:]

                grid = CopyableGrid(self.panel, 0, 2)
                grid.SetColLabelSize(0)
                grid.SetRowLabelSize(0)
                self.AddNewRow(grid, "Payload Path", filepath)
                self.AddNewRow(grid, "Original Path", data.get(key, {}).get("filepath", ""))

                if "cape_type" in cape_info:
                    if cape_info.get("cape_type", ""):
                        self.AddNewRow(
                            grid, "CAPE Type", cape_info.get("cape_type", "N/A")
                        )

                if "cape_type_string" in cape_info:
                    cape_type = cape_info.get("cape_type_string", "N/A")
                    self.AddNewRow(grid, "CAPE Type", cape_type)
                    capename = get_cape_name_from_cape_type(cape_type).split(" ")[0]
                    self.parent.configHits.append({filepath: capename})

                if "target_path" in cape_info:
                    self.AddNewRow(
                        grid, "Target Path", cape_info.get("target_path", "N/A")
                    )

                if "target_process" in cape_info:
                    self.AddNewRow(
                        grid, "Target Process", cape_info.get("target_process", "N/A")
                    )

                if "target_pid" in cape_info:
                    self.AddNewRow(
                        grid, "Target Pid", cape_info.get("target_pid", "N/A")
                    )

                if "virtual_address" in cape_info:
                    self.AddNewRow(
                        grid, "Virtual Address", cape_info.get("virtual_address", "N/A")
                    )

                if "pid" in cape_info:
                    self.AddNewRow(grid, "Pid", cape_info.get("pid", "N/A"))

                for key, value in fileinfo.items():
                    if key not in "path" and value:
                        if key == "size":
                            value = str(value) + " bytes"
                        self.AddNewRow(grid, key[0].upper() + key[1:], value)

                grid.AutoSizeColumns()
                grid.SetColSize(0, 120)
                grid.AutoSizeRows()
                self.panelsizer.Add(
                    grid, proportion=0, flag=wx.EXPAND | wx.ALL, border=5
                )
                self.ApplyAlternateRowShading(grid)

                buttonBox = wx.BoxSizer(wx.HORIZONTAL)
                hexBtn = wx.Button(self.panel, label="Hex View")
                hexBtn.Bind(wx.EVT_BUTTON, self.OnShowHexview)
                self.button_to_path[hexBtn.GetId()] = path
                buttonBox.Add(hexBtn, 0, wx.ALIGN_LEFT | wx.ALL, 5)

                if IsPEImage(path.read_bytes()[:1024], 1024):
                    peBtn = wx.Button(self.panel, label="PE")
                    peBtn.Bind(wx.EVT_BUTTON, self.OnShowPe)
                    self.button_to_path[peBtn.GetId()] = path
                    buttonBox.Add(peBtn, 0, wx.ALIGN_LEFT | wx.ALL, 5)

                self.panelsizer.Add(buttonBox, proportion=1, flag=wx.EXPAND)

                self.panelsizer.AddSpacer(5)

        self.panel.Layout()
        popup.Update(100)
        popup.Destroy()
        self.panel.Show()
        self.Layout()
        self.payloadsLoaded = True

    def ApplyAlternateRowShading(self, grid):
        numRows = grid.GetNumberRows()
        lightGrey = wx.Colour(240, 240, 240)

        for row in range(numRows):
            if row % 2 == 0:
                attr = gridlib.GridCellAttr()
                attr.SetBackgroundColour(lightGrey)
                grid.SetRowAttr(row, attr)

        grid.ForceRefresh()

    def GetMainFrame(self):
        parent = self.GetParent()
        while parent and not isinstance(parent, wx.Frame):
            parent = parent.GetParent()

        return parent

    def IsWindowOpen(self, title):
        for child in self.GetChildren():
            if isinstance(child, wx.Frame) and child.GetTitle() == title:
                return True

        return False

    def OnShowPe(self, event):
        try:
            main_frame = self.GetMainFrame()
            size = main_frame.GetSize()
            position = main_frame.GetPosition()
            buttonId = event.GetId()
            path = self.button_to_path.get(buttonId, "")
            if path and not self.IsWindowOpen(str(path)):
                viewer_window = PeWindow(self, str(path), path, position, size)
                viewer_window.Show()

        except Exception as e:
            wx.MessageBox(
                f"Failed to execute the command: {e}", "Error", wx.OK | wx.ICON_ERROR
            )

    def OnShowHexview(self, event):
        try:
            main_frame = self.GetMainFrame()
            size = main_frame.GetSize()
            position = main_frame.GetPosition()
            buttonId = event.GetId()
            path = self.button_to_path.get(buttonId, "")
            if path and not self.IsWindowOpen(str(path)):
                viewer_window = HexViewWindow(self, str(path), path, position, size)
                viewer_window.Show()

        except Exception as e:
            wx.MessageBox(
                f"Failed to execute the command: {e}", "Error", wx.OK | wx.ICON_ERROR
            )
