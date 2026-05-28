import re
from pathlib import Path

import wx

from .key_event import KeyEventHandlerMixin
from .theme import FONT_CODE, apply_theme


class DebuggerPanel(wx.Panel, KeyEventHandlerMixin):
    def __init__(self, parent):
        super(DebuggerPanel, self).__init__(parent)
        self.analysisDir = parent.analysisDir
        self.coverageFilePath = None
        self.BindKeyEvents()
        self.InitUI()

    def InitUI(self):
        vbox = wx.BoxSizer(wx.VERTICAL)

        hbox = wx.BoxSizer(wx.HORIZONTAL)
        self.logFileDropdown = wx.ComboBox(self, style=wx.CB_READONLY)
        viewButton = wx.Button(self, label="View")
        viewButton.Bind(wx.EVT_BUTTON, self.OnViewButtonClick)

        hbox.Add(
            self.logFileDropdown, proportion=1, flag=wx.EXPAND | wx.RIGHT, border=10
        )
        hbox.Add(viewButton, flag=wx.EXPAND)
        vbox.Add(hbox, flag=wx.EXPAND | wx.ALL, border=10)

        self.resultsWindow = wx.TextCtrl(
            self, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_RICH2
        )
        self.resultsWindow.SetFont(FONT_CODE)
        vbox.Add(self.resultsWindow, proportion=1, flag=wx.EXPAND | wx.ALL, border=10)

        hboxCover = wx.BoxSizer(wx.HORIZONTAL)
        self.coverBtn = wx.Button(self, label="Create Coverage File")
        self.coverBtn.Bind(wx.EVT_BUTTON, self.OnCover)
        self.coverBtn.Disable()
        hboxCover.Add(self.coverBtn, proportion=0, flag=wx.ALL | wx.CENTER, border=5)
        self.coverageFileBtn = wx.Button(self, label="Copy Coverage File")
        self.coverageFileBtn.Bind(wx.EVT_BUTTON, self.OnCopyPath)
        self.coverageFileBtn.Disable()
        hboxCover.Add(self.coverageFileBtn, proportion=1, flag=wx.ALL | wx.CENTER, border=5)

        vbox.Add(hboxCover, proportion=0, flag=wx.ALL | wx.CENTER, border=5)

        self.SetSizer(vbox)
        apply_theme(self)

    def PopulateLogFileDropdown(self):
        path = Path(self.analysisDir, "debugger")
        try:
            logFiles = [file.name for file in path.iterdir() if file.is_file()]
            self.logFileDropdown.SetItems(logFiles)
            if logFiles:
                self.logFileDropdown.SetSelection(0)
        except FileNotFoundError:
            return

    def OnViewButtonClick(self, event):
        selectedFile = self.logFileDropdown.GetValue()
        self.LoadDebuggerResults(selectedFile)
        self.coverBtn.Enable()

    def LoadDebuggerResults(self, file_name):
        path = Path(self.analysisDir, "debugger") / file_name
        if not path.exists():
            self.resultsWindow.SetValue("Selected log file does not exist.")
            return
        self.resultsWindow.SetValue(path.read_text())

    def OnCover(self, event):
        pattern1 = r".*Target\s+DLL\s+loaded\s+at\s+(0x[A-F0-9]+):.*"
        pattern2 = r".*ImageBase\s*(0x[0-9A-F]+),.*"
        debugData = self.resultsWindow.GetValue()
        analysisLogPath = Path(self.analysisDir) / "analysis.log"
        analysisData = analysisLogPath.read_text()
        match = re.match(pattern1, analysisData, re.DOTALL)
        if not match:
            match = re.match(pattern2, debugData, re.DOTALL)
        if match:
            loaderBase = match.group(1)
        else:
            loaderBase = ""
        filteredLines = set()
        for line in debugData.splitlines():
            if line.strip().startswith("0x"):
                filteredLines.add(line.split()[0])

        dialog = wx.Dialog(self, title="Generate Coverage File", size=wx.Size(300, 150))
        panel = wx.Panel(dialog)
        vbox = wx.BoxSizer(wx.VERTICAL)

        hbox1 = wx.BoxSizer(wx.HORIZONTAL)
        currentLabel = wx.StaticText(panel, label="Current ImageBase   0x:")
        loaderBase = wx.TextCtrl(panel, value=f"{loaderBase}")
        hbox1.Add(currentLabel, flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, border=5)
        hbox1.Add(loaderBase, proportion=1)
        hbox2 = wx.BoxSizer(wx.HORIZONTAL)
        newLabel = wx.StaticText(panel, label="New ImageBase        0x:")
        imageBase = wx.TextCtrl(panel)
        hbox2.Add(newLabel, flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, border=5)
        hbox2.Add(imageBase, proportion=1)

        vbox.Add(hbox1, flag=wx.EXPAND | wx.ALL, border=5)
        vbox.Add(hbox2, flag=wx.EXPAND | wx.ALL, border=5)

        hbox3 = wx.BoxSizer(wx.HORIZONTAL)
        okButton = wx.Button(panel, wx.ID_OK, label="Ok")
        cancelButton = wx.Button(panel, wx.ID_CANCEL, label="Cancel")
        hbox3.Add(okButton, flag=wx.RIGHT, border=10)
        hbox3.Add(cancelButton, flag=wx.RIGHT, border=10)

        vbox.Add(hbox3, flag=wx.ALIGN_CENTER | wx.TOP | wx.BOTTOM, border=10)

        panel.SetSizer(vbox)

        if dialog.ShowModal() == wx.ID_OK:
            loaderBase = loaderBase.GetValue()
            if not "0x" in loaderBase:
                loaderBase = f"0x{loaderBase}"
            loaderBase = int(loaderBase, 16)
            imageBase = imageBase.GetValue()
            if imageBase:
                imageBase = int(imageBase, 16)
                filteredLines = [
                    self.rebase(line, imageBase, loaderBase) for line in filteredLines
                ]

        dialog.Destroy()

        coverData = "\n".join(filter(None, filteredLines))

        if coverData:
            coverageSaved = False
            logName = self.logFileDropdown.GetValue()
            filepath = (
                Path(self.analysisDir)
                / "debugger"
                / f"coverage_{logName.split('.')[0]}.txt"
            )

            filepath.write_text(coverData)
            self.coverageFilePath = str(filepath)

            if filepath.exists():
                coverageSaved = True
                self.coverageFileBtn.Enable()

            if coverageSaved:
                wx.MessageBox(
                    f"Coverage saved to {filepath}.",
                    "Success",
                    wx.OK | wx.ICON_INFORMATION,
                )
            else:
                wx.MessageBox(
                    "Coverage not saved.", "Failed", wx.OK | wx.ICON_INFORMATION
                )

    def rebase(self, offset, imageBase, loaderBase):
        offset = int(offset, 16)
        delta = offset - loaderBase
        rebased = imageBase + delta
        if rebased > 0:
            return hex(rebased)

    def OnCopyPath(self, event):
        if wx.TheClipboard.Open():
            file_data = wx.FileDataObject()
            file_data.AddFile(self.coverageFilePath)
            wx.TheClipboard.SetData(file_data)
            wx.TheClipboard.Close()
            wx.MessageBox(
                f"Analysis log copied: {self.coverageFilePath}",
                "Info",
                wx.OK | wx.ICON_INFORMATION,
            )
        else:
            wx.LogError("Unable to open the clipboard.")
