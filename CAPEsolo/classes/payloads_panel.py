import subprocess
from pathlib import Path

import wx
import wx.grid as gridlib
import wx.lib.scrolledpanel as scrolled

from .custom_grid import CopyableGrid
from .hexview_window import HexViewWindow
from .pe_window import PeWindow
from .theme import GRID_ROW_ALT, apply_theme
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

        leftAttr0 = gridlib.GridCellAttr()
        leftAttr0.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE)
        grid.SetColAttr(0, leftAttr0)

        leftAttr1 = gridlib.GridCellAttr()
        leftAttr1.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE)
        grid.SetColAttr(1, leftAttr1)
        grid.EnableEditing(False)

    def AddNewRow(self, grid, value0, value1):
        # Values come straight from the analysis JSON, where pid, target_pid,
        # virtual_address and most fileinfo entries are numbers rather than strings.
        # SetCellValue only accepts strings and raises TypeError otherwise.
        current_row = grid.GetNumberRows()
        grid.AppendRows(1)
        grid.SetCellValue(current_row, 0, "" if value0 is None else str(value0))
        grid.SetCellValue(current_row, 1, "" if value1 is None else str(value1))

    def AddPayloadEntry(self, key, entry):
        cape_info = {}
        metadata = entry.get("metadata", "")
        if metadata:
            cape_info = metadata_processing(metadata, entry.get("pids"))

        path = Path(self.analysisDir) / key
        fileinfo = File(str(path)).get_all()[0]
        filepath = key[0].upper() + key[1:]

        grid = CopyableGrid(self.panel, 0, 2)
        grid.SetColLabelSize(0)
        grid.SetRowLabelSize(0)
        self.AddNewRow(grid, "Payload Path", filepath)
        self.AddNewRow(grid, "Original Path", entry.get("filepath", ""))

        if "cape_type" in cape_info:
            if cape_info.get("cape_type", ""):
                self.AddNewRow(grid, "CAPE Type", cape_info.get("cape_type", "N/A"))

        if "cape_type_string" in cape_info:
            cape_type = cape_info.get("cape_type_string", "N/A")
            self.AddNewRow(grid, "CAPE Type", cape_type)
            capename = get_cape_name_from_cape_type(cape_type).split(" ")[0]
            self.parent.configHits.append({filepath: capename})

        if "target_path" in cape_info:
            self.AddNewRow(grid, "Target Path", cape_info.get("target_path", "N/A"))

        if "target_process" in cape_info:
            self.AddNewRow(
                grid, "Target Process", cape_info.get("target_process", "N/A")
            )

        if "target_pid" in cape_info:
            self.AddNewRow(grid, "Target Pid", cape_info.get("target_pid", "N/A"))

        if "virtual_address" in cape_info:
            self.AddNewRow(
                grid, "Virtual Address", cape_info.get("virtual_address", "N/A")
            )

        if "pid" in cape_info:
            self.AddNewRow(grid, "Pid", cape_info.get("pid", "N/A"))

        for infoKey, infoValue in fileinfo.items():
            if infoKey not in "path" and infoValue:
                if infoKey == "size":
                    infoValue = str(infoValue) + " bytes"
                self.AddNewRow(grid, infoKey[0].upper() + infoKey[1:], infoValue)

        grid.AutoSizeColumns()
        grid.SetColSize(0, 120)
        grid.AutoSizeRows()
        self.panelsizer.Add(grid, proportion=0, flag=wx.EXPAND | wx.ALL, border=5)
        # These grids are built after the panel is constructed, so the usual
        # one-shot apply_theme never reached them: they kept black default text
        # while ApplyAlternateRowShading painted rows GRID_ROW_ALT, which is
        # near-black. Theme first, then shade - row attributes survive it.
        apply_theme(grid)
        self.ApplyAlternateRowShading(grid)

        buttonBox = wx.BoxSizer(wx.HORIZONTAL)
        hexBtn = wx.Button(self.panel, label="Hex View")
        hexBtn.Bind(wx.EVT_BUTTON, self.OnShowHexview)
        self.button_to_path[hexBtn.GetId()] = path
        buttonBox.Add(hexBtn, 0, wx.ALIGN_LEFT | wx.ALL, 5)

        # Read only the header. read_bytes()[:1024] loaded the entire payload
        # first, so opening this tab cost a full read per file; IsPEImage never
        # looks past PE_HEADER_LIMIT + 256 bytes. Size comes from the buffer so
        # its "too short to be a PE" guard still works on tiny files.
        with path.open("rb") as hfile:
            head = hfile.read(1024)
        if IsPEImage(head):
            peBtn = wx.Button(self.panel, label="PE")
            peBtn.Bind(wx.EVT_BUTTON, self.OnShowPe)
            self.button_to_path[peBtn.GetId()] = path
            buttonBox.Add(peBtn, 0, wx.ALIGN_LEFT | wx.ALL, 5)

        showBtn = wx.Button(self.panel, label="Show in Explorer")
        showBtn.Bind(wx.EVT_BUTTON, self.OnShowInExplorer)
        self.button_to_path[showBtn.GetId()] = path
        buttonBox.Add(showBtn, 0, wx.ALIGN_LEFT | wx.ALL, 5)

        self.panelsizer.Add(buttonBox, proportion=1, flag=wx.EXPAND)

        self.panelsizer.AddSpacer(5)

    def AddPayload(self, relPath):
        """Add a payload a config parser produced after this panel was built.

        LoadAndDisplayContent only ever runs once, so a file written during config
        extraction is appended on its own. If the tab was never opened there is nothing
        to append to: PayloadsReady will read it from files.json on first open.
        """
        if not self.payloadsLoaded:
            return

        data = LoadFilesJson(self.analysisDir)
        entry = data.get(relPath)
        if not entry:
            return

        self.AddPayloadEntry(relPath, entry)
        self.panel.Layout()
        self.Layout()
        # The scrolled panel caches its virtual size, so a grid added after the initial
        # load is unreachable until scrolling is recalculated.
        self.panel.SetupScrolling(scroll_x=True, scroll_y=True, scrollToTop=False)

    def PayloadsReady(self):
        if JsonPathExists(self.analysisDir):
            self.jsonFileExists = True
            # A busy cursor rather than the previous wx.ProgressDialog: that dialog was
            # PD_APP_MODAL, so it took focus and, being destroyed during the notebook page
            # change, left wx restoring focus to a window that was no longer valid - which
            # is where the 'SetFocus' failed with error 0x00000057 messages came from. It
            # also only ever reported 0% and 100%, so it showed no real progress, and the
            # "error" path below returned without ever destroying it.
            with wx.BusyCursor():
                self.LoadAndDisplayContent()

    def LoadAndDisplayContent(self):
        if self.payloadsLoaded or not self.jsonFileExists:
            return

        data = LoadFilesJson(self.analysisDir)
        if "error" in data:
            return
        else:
            data = dict(sorted(data.items(), key=lambda x: x[1]["size"], reverse=True))

        for key, value in data.items():
            if not key.startswith("aux_"):
                self.AddPayloadEntry(key, value)

        self.panel.Layout()
        self.panel.Show()
        self.Layout()
        # Covers the Hex View / PE buttons and the panel background, which were also
        # rendering in default system colours.
        apply_theme(self)
        self.payloadsLoaded = True

    def ApplyAlternateRowShading(self, grid):
        numRows = grid.GetNumberRows()

        for row in range(numRows):
            if row % 2 == 0:
                attr = gridlib.GridCellAttr()
                attr.SetBackgroundColour(GRID_ROW_ALT)
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

    def OnShowInExplorer(self, event):
        try:
            path = self.button_to_path.get(event.GetId(), "")
            if not path:
                return
            path = Path(path)
            if not path.exists():
                wx.MessageBox(
                    f"File not found:\n{path}", "Show in Explorer", wx.OK | wx.ICON_WARNING
                )
                return
            # explorer.exe returns exit code 1 even on success, so do not check the result;
            # /select, highlights the file in its folder. List form avoids shell quoting issues.
            subprocess.Popen(["explorer", "/select,", str(path)])
        except Exception as e:
            wx.MessageBox(
                f"Failed to open Explorer: {e}", "Error", wx.OK | wx.ICON_ERROR
            )
