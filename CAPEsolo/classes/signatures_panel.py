import wx
import wx.grid as gridlib
import wx.lib.scrolledpanel as scrolled

from .custom_grid import CopyableGrid
from .key_event import KeyEventHandlerMixin
from .theme import GRID_ROW_ALT, apply_theme
from CAPEsolo.capelib.signatures import RunSignatures


class SignaturesPanel(wx.Panel, KeyEventHandlerMixin):
    def __init__(self, parent):
        super(SignaturesPanel, self).__init__(parent)
        self.analysisDir = parent.analysisDir
        self.results = parent.results
        self.sigs = []
        self.BindKeyEvents()
        self.signaturesComplete = False
        self.InitUI()

    def InitUI(self):
        vbox = wx.BoxSizer(wx.VERTICAL)

        vbox.AddSpacer(10)
        self.signaturesButton = wx.Button(self, label="Generate Signatures Results")
        self.signaturesButton.Bind(wx.EVT_BUTTON, self.GenerateSignatures)
        self.signaturesButton.Disable()
        vbox.Add(self.signaturesButton, proportion=0, flag=wx.ALL, border=5)

        grid_panel = scrolled.ScrolledPanel(
            self, -1, style=wx.TAB_TRAVERSAL | wx.SUNKEN_BORDER
        )
        grid_panel.SetupScrolling(scroll_x=True, scroll_y=True)
        grid_panelsizer = wx.BoxSizer(wx.VERTICAL)
        grid_panel.SetSizer(grid_panelsizer)

        self.grid = CopyableGrid(grid_panel, 0, 1)
        self.grid.SetColLabelValue(0, "Signatures")
        self.grid.SetColLabelAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)
        attr = gridlib.GridCellAttr()
        attr.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE)
        self.grid.SetColAttr(0, attr)
        self.grid.SetRowLabelSize(0)
        self.grid.EnableEditing(False)
        grid_panelsizer.Add(self.grid, 1, wx.EXPAND)
        self.grid.Hide()
        vbox.Add(
            grid_panel,
            proportion=1,
            flag=wx.EXPAND | wx.ALL,
            border=5,
        )

        self.SetSizer(vbox)
        vbox.Fit(self)
        vbox.Layout()
        apply_theme(self)

    def onPaneChanged(self, event):
        self.Layout()

    def UpdateGenerateButtonState(self):
        if self.results and not self.signaturesComplete:
            self.signaturesButton.Enable()
        else:
            self.signaturesButton.Disable()

    def GenerateSignatures(self, event):
        RunSignatures(results=self.results, analysis_path=self.analysisDir).run()
        self.signaturesButton.Disable()
        self.AddTableData()
        self.signaturesComplete = True

    def AddTableData(self):
        try:
            for i, sig in enumerate(self.results.get("signatures")):
                if sig.get("description", ""):
                    sigData = sig.get("description")
                    if sig.get("data", []):
                        for item in sig.get("data", []):
                            if "type" not in item:
                                key = next(iter(item.keys()))
                                sigData += f"\n    \u2022 {key}: {item[key]}"
                    self.grid.AppendRows(1)
                    self.grid.SetCellValue(i, 0, sigData)
        except Exception as e:
            print(e)

        self.grid.AutoSizeColumns()
        self.grid.AutoSizeRows()
        self.ApplyAlternateRowShading()
        self.grid.Show()
        self.Layout()

    def ApplyAlternateRowShading(self):
        numRows = self.grid.GetNumberRows()

        for row in range(numRows):
            if row % 2 == 0:
                attr = gridlib.GridCellAttr()
                attr.SetBackgroundColour(GRID_ROW_ALT)
                self.grid.SetRowAttr(row, attr)
        self.grid.ForceRefresh()
