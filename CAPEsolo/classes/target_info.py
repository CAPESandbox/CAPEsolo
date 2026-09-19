from pathlib import Path

import wx
import wx.grid as gridlib

from CAPEsolo.capelib.objects import File

from . import ui_kit as ui
from .custom_grid import CopyableGrid
from .pe_window import PeWindow
from .theme import GRID_ROW_ALT, SP_XS, apply_theme, dip
from .vt_helper import (
    confirm_vt_upload,
    format_vt_rows,
    peek_vt_cache,
    run_vt_lookup_async,
    run_vt_upload_async,
)


class TargetInfoPanel(wx.Panel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.infoLoaded = False
        self.peData = {}
        # Whatever the grid is currently describing, which the PE button acts on. Not
        # necessarily the analysis target: Get Info can show an arbitrary file.
        self.displayedFile = None
        self.displayedSha256 = None
        # Upload is only offered for the real analysis target, never an ad-hoc Get Info file (whose
        # contract is "display only - not copied, analysed or recorded").
        self.displayedIsTarget = False
        # sha256 a VT lookup has already been rendered for, so repeat clicks don't duplicate rows.
        self._vtDoneFor = None
        # A lookup is running: Get Info re-enables the button, so this stops a second thread starting.
        self._vtInFlight = False
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

        leftAttr0 = gridlib.GridCellAttr()
        leftAttr0.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE)
        self.grid.SetColAttr(0, leftAttr0)

        leftAttr1 = gridlib.GridCellAttr()
        leftAttr1.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE)
        self.grid.SetColAttr(1, leftAttr1)
        self.grid.EnableEditing(False)
        vbox.Add(self.grid, proportion=1, flag=wx.EXPAND | wx.ALL, border=dip(self, SP_XS))

        hboxButtons = wx.BoxSizer(wx.HORIZONTAL)
        self.getInfoButton = ui.Button(self, label="Get Info", variant=ui.PRIMARY)
        self.getInfoButton.SetToolTip(
            "Inspect the file currently selected on the Start tab. Display only - the "
            "file is not copied, analysed or recorded."
        )
        self.getInfoButton.Bind(wx.EVT_BUTTON, self.OnGetInfo)
        hboxButtons.Add(self.getInfoButton, proportion=0, flag=wx.RIGHT, border=dip(self, SP_XS))
        self.peButton = ui.Button(self, label="PE")
        self.peButton.Bind(wx.EVT_BUTTON, self.OnShowPe)
        self.peButton.Hide()
        hboxButtons.Add(self.peButton, proportion=0, flag=wx.RIGHT, border=dip(self, SP_XS))
        self.vtButton = ui.Button(self, label="VirusTotal")
        self.vtButton.Bind(wx.EVT_BUTTON, self.OnVirusTotalLookup)
        self.vtButton.Hide()
        hboxButtons.Add(self.vtButton, proportion=0, flag=wx.RIGHT, border=dip(self, SP_XS))
        self.uploadButton = ui.Button(self, label="Upload to VT")
        self.uploadButton.Bind(wx.EVT_BUTTON, self.OnVtUpload)
        self.uploadButton.Hide()
        hboxButtons.Add(self.uploadButton, proportion=0)
        vbox.Add(hboxButtons, proportion=0, flag=wx.LEFT | wx.BOTTOM, border=dip(self, SP_XS))

        self.SetSizer(vbox)
        apply_theme(self)

    def AddNewRow(self, value0, value1):
        current_row = self.grid.GetNumberRows()
        self.grid.AppendRows(1)
        self.grid.SetCellValue(current_row, 0, value0)
        self.grid.SetCellValue(current_row, 1, value1)

    def ClearGrid(self):
        rows = self.grid.GetNumberRows()
        if rows:
            self.grid.DeleteRows(0, rows)

    def PopulateGrid(self, path, is_target=False):
        """Render file info for *path*. Nothing is written anywhere."""
        self.ClearGrid()
        fileObj = File(str(path))
        fileinfo = fileObj.get_all()[0]
        self.AddNewRow("Path", str(path))
        for key, value in fileinfo.items():
            if key not in "path" and value:
                if not isinstance(value, str):
                    value = str(value) + " bytes"
                value = value.removeprefix("s_")
                self.AddNewRow(key[0].upper() + key[1:], value)
        self.grid.AutoSizeColumns()
        self.grid.SetColSize(0, 120)
        self.grid.AutoSizeRows()
        self.ApplyAlternateRowShading()
        self.displayedFile = Path(path)
        self.displayedSha256 = fileinfo.get("sha256")
        self.displayedIsTarget = is_target
        self._vtDoneFor = None
        self.peButton.Show()
        self.vtButton.Enable()
        self.vtButton.Show()
        # Hidden until a lookup confirms the target is not already on VT.
        self.uploadButton.Hide()
        # If VT info was already fetched for this file (e.g. at download time), show it now and
        # disable the lookup button rather than spending a request to re-fetch it.
        cached = peek_vt_cache(self.displayedSha256) if self.displayedSha256 else None
        if cached is not None:
            self._ShowVtResult(cached)
        self.Layout()

    def LoadAndDisplayContent(self):
        self.targetFile = self.parent.targetFile
        if self.infoLoaded or not self.targetFile:
            return
        self.PopulateGrid(self.targetFile, is_target=True)
        self.infoLoaded = True

    def OnGetInfo(self, event):
        """Show info for the file selected on the Start tab, without touching it.

        Deliberately does not set parent.targetFile, copy the file into the analysis
        directory or record anything: this is a look, not a submission. infoLoaded is
        left alone so a later analysis still replaces this with the real target's info.
        """
        startTab = getattr(self.GetMainFrame(), "startTab", None)
        selected = startTab.targetPath.GetValue().strip() if startTab else ""
        if not selected:
            ui.message(
                "No target file selected. Choose one on the Start tab first.",
                "No Target",
                wx.OK | wx.ICON_INFORMATION,
            )
            return

        path = Path(selected)
        if not path.is_file():
            ui.message(
                f"Not a readable file:\n{path}", "Error", wx.OK | wx.ICON_ERROR
            )
            return

        try:
            # get_all() hashes the whole file, so a large sample takes a moment.
            with wx.BusyCursor():
                self.PopulateGrid(path)
        except Exception as e:
            ui.message(
                f"Failed to read file info: {e}", "Error", wx.OK | wx.ICON_ERROR
            )

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
            # displayedFile, not targetFile: the grid may be showing an ad-hoc file.
            viewer_window = PeWindow(
                self, f"{self.displayedFile!s}", self.displayedFile, position, size
            )
            viewer_window.Show()
        except Exception as e:
            ui.message(
                f"Failed to execute the command: {e}", "Error", wx.OK | wx.ICON_ERROR
            )

    def OnVirusTotalLookup(self, event):
        sha256 = self.displayedSha256
        if not sha256 or self._vtDoneFor == sha256 or self._vtInFlight:
            return
        self._vtInFlight = True
        self.vtButton.Disable()
        run_vt_lookup_async(sha256, lambda result: self._OnVtDone(sha256, result))

    def _OnVtDone(self, sha256, result):
        self._vtInFlight = False
        # displayedSha256 may have changed if Get Info swapped the file mid-lookup: drop the result.
        if sha256 != self.displayedSha256:
            return
        if result.get("error"):
            self.vtButton.Enable()  # allow a retry
            ui.message(result.get("msg", "VirusTotal lookup failed"), "VirusTotal", wx.OK | wx.ICON_ERROR)
            return
        self._ShowVtResult(result)
        self.Layout()

    def _ShowVtResult(self, result):
        """Render a VT result into the grid and disable the lookup button (info is shown, no reason to
        look up again). For the target that is not on VT, reveal the upload button. Shared by a fresh
        lookup and a cached/download-time result."""
        for label, value in format_vt_rows(result):
            self.AddNewRow(label, value)
        self.grid.AutoSizeRows()
        self.ApplyAlternateRowShading()
        self._vtDoneFor = self.displayedSha256
        self.vtButton.Disable()
        if result.get("found") is False and self.displayedIsTarget:
            self.uploadButton.Show()

    def OnVtUpload(self, event):
        path, sha256 = self.displayedFile, self.displayedSha256
        if not path or not confirm_vt_upload(self, path):
            return
        self.uploadButton.Disable()
        self._SetStatus(f"Uploading {path.name} to VirusTotal...")
        run_vt_upload_async(path, sha256, lambda result: self._OnUploadDone(sha256, result))

    def _SetStatus(self, message):
        mainFrame = self.GetMainFrame()
        if mainFrame:
            mainFrame.statusBar.SetMessage(message)

    def _OnUploadDone(self, sha256, result):
        # Only touch the buttons/grid if the same file is still displayed - Get Info may have swapped
        # it during a slow upload, and its state must not be clobbered.
        current = sha256 == self.displayedSha256
        if result.get("error"):
            if current:
                self.uploadButton.Enable()
            self._SetStatus("VirusTotal upload failed")
            ui.message(result.get("msg", "Upload failed"), "VirusTotal", wx.OK | wx.ICON_ERROR)
            return
        self._SetStatus("Uploaded to VirusTotal - analysis queued")
        if current:
            # Submitted: the button has done its job, so retire it and note the pending analysis.
            self.uploadButton.Hide()
            self.AddNewRow("VT Upload", "Submitted - analysis pending")
            if result.get("permalink"):
                self.AddNewRow("VT Link", result["permalink"])
            self.grid.AutoSizeRows()
            self.ApplyAlternateRowShading()
            self.Layout()
        ui.message(
            "File submitted to VirusTotal. Analysis is queued.",
            "VirusTotal",
            wx.OK | wx.ICON_INFORMATION,
        )

    def GetMainFrame(self):
        parent = self.GetParent()
        while parent and not isinstance(parent, wx.Frame):
            parent = parent.GetParent()
        return parent
