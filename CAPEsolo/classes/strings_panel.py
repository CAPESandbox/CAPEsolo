import os
from pathlib import Path

import wx

from CAPEsolo.capelib.utils import LoadFilesJson, extract_strings
from .key_event import KeyEventHandlerMixin
from .theme import FONT_CODE, apply_theme


class StringsPanel(wx.Panel, KeyEventHandlerMixin):
    def __init__(self, parent):
        super(StringsPanel, self).__init__(parent)
        self.parent = parent
        self.analysisDir = parent.analysisDir
        self.BindKeyEvents()
        self.InitUI()

    def InitUI(self):
        vbox = wx.BoxSizer(wx.VERTICAL)

        hbox = wx.BoxSizer(wx.HORIZONTAL)
        self.fileDropdown = wx.ComboBox(self, style=wx.CB_READONLY)
        viewButton = wx.Button(self, label="View")
        viewButton.Bind(wx.EVT_BUTTON, self.OnViewButtonClick)

        hbox.Add(self.fileDropdown, proportion=1, flag=wx.EXPAND | wx.RIGHT, border=10)
        hbox.Add(viewButton, flag=wx.EXPAND)
        vbox.Add(hbox, flag=wx.EXPAND | wx.ALL, border=10)

        self.resultsWindow = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_RICH2)
        self.resultsWindow.SetFont(FONT_CODE)
        vbox.Add(self.resultsWindow, proportion=1, flag=wx.EXPAND | wx.ALL, border=10)

        self.SetSizer(vbox)
        apply_theme(self)

    def PopulateFileDropdown(self):
        self.targetFile = self.parent.targetFile
        stringFiles = [str(self.targetFile)]
        data = LoadFilesJson(self.analysisDir)
        if "error" not in data:
            for file in data.keys():
                if data[file].get("category", "") in ("files", "CAPE", "procdump"):
                    path = os.path.join(file)
                    stringFiles.append(path)

        if stringFiles:
            self.fileDropdown.SetItems(stringFiles)
            self.fileDropdown.SetSelection(0)

        return stringFiles

    def OnViewButtonClick(self, event):
        selectedFile = self.fileDropdown.GetValue()
        self.LoadStringsResults(selectedFile)

    def LoadStringsResults(self, filename):
        path = Path(self.analysisDir, filename)
        if not path.exists():
            self.resultsWindow.SetValue("Selected file does not exist.")
            return

        stringsData = self.GetStrings(path)
        if not stringsData:
            stringsData = "No strings."

        self.resultsWindow.SetValue(stringsData)

    def GetStrings(self, filePath, minLength=4):
        extracted = extract_strings(filePath, dedup=True, minchars=minLength)
        stringList = sorted(list(set(extracted)), key=lambda x: (len(x), x))

        return "\n".join(stringList)
