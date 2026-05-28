from pathlib import Path

import wx

from CAPEsolo.capelib.cape_utils import get_cape_name_from_yara_hit
from .theme import FONT_CODE, apply_theme


class YaraPanel(wx.Panel):
    def __init__(self, parent):
        super(YaraPanel, self).__init__(parent)
        self.parent = parent
        self.yara = parent.yara
        self.analysisDir = parent.analysisDir
        self.yaraComplete = False
        self.filesjson = Path(self.analysisDir) / "files.json"
        self.InitUI()

    def InitUI(self):
        vbox = wx.BoxSizer(wx.VERTICAL)

        vbox.AddSpacer(10)
        self.yaraButton = wx.Button(self, label="Process Yara Results")
        self.yaraButton.Bind(wx.EVT_BUTTON, self.ProcessYara)
        self.yaraButton.Disable()
        vbox.Add(self.yaraButton, proportion=0, border=5)
        self.resultsWindow = wx.TextCtrl(
            self, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.EXPAND, size=wx.Size(-1, 100)
        )
        self.resultsWindow.SetFont(FONT_CODE)
        vbox.Add(self.resultsWindow, proportion=1, flag=wx.EXPAND | wx.ALL, border=10)

        self.SetSizer(vbox)
        apply_theme(self)

    def PrintResults(self):
        yaras = self.yara.yara_results
        content = ""
        for filehits in yaras:
            paths = filehits.keys()
            for file in paths:
                content += f"\u2022 {file}:\n"
                if len(filehits[file]) < 1:
                    content += "\tNo yara hits.\n"
                    continue
                for hit in filehits[file]:
                    capename = get_cape_name_from_yara_hit(hit)
                    if capename:
                        content += f"\tCAPE Name: {capename}\n"
                        self.parent.configHits.append({file: capename})
                    content += f'\tName: {hit.get("name")}\n'
                    content += "\tStrings:\n"
                    for strval in hit.get("strings", []):
                        content += f"\t\t{strval}\n"
                    content += "\tAddresses:\n"
                    addrs = hit.get("addresses", {})
                    for key in addrs.keys():
                        content += f"\t\t{key}: {addrs[key]}\n"
                content += "\n"
        if not content:
            content = "No yara hits."

        return content

    def ProcessYara(self, event):
        try:
            self.targetFile = self.parent.targetFile
            self.yara.Scan(str(self.targetFile))
        except FileNotFoundError:
            print("Target not found. This may be normal.")

        self.yara.ScanPayloads()
        content = self.PrintResults()
        self.resultsWindow.SetValue(content)
        self.yaraButton.Disable()
        self.yaraComplete = True

    def UpdateYaraButtonState(self):
        if not self.yaraComplete and self.parent.targetFile:
            self.yaraButton.Enable()
        else:
            self.yaraButton.Disable()
