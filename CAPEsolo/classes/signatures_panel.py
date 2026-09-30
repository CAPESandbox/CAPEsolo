import wx
import wx.grid as gridlib
import wx.lib.scrolledpanel as scrolled

from CAPEsolo.capelib.network_summary import NetworkSummary
from CAPEsolo.capelib.signatures import RunSignatures
from CAPEsolo.capelib.utils import JsonPathExists

from . import ui_kit as ui
from .custom_grid import CopyableGrid
from .key_event import KeyEventHandlerMixin
from .theme import GRID_ROW_ALT, SP_XS, apply_theme, dip


class SignaturesPanel(wx.Panel, KeyEventHandlerMixin):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.analysisDir = parent.analysisDir
        self.results = parent.results
        self.sigs = []
        self.BindKeyEvents()
        self.signaturesComplete = False
        self.InitUI()

    def InitUI(self):
        vbox = wx.BoxSizer(wx.VERTICAL)

        vbox.AddSpacer(10)
        self.signaturesButton = ui.Button(
            self, label="Generate Signatures Results", variant=ui.PRIMARY
        )
        self.signaturesButton.Bind(wx.EVT_BUTTON, self.GenerateSignatures)
        self.signaturesButton.Disable()
        vbox.Add(self.signaturesButton, proportion=0, flag=wx.ALL, border=dip(self, SP_XS))

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
            border=dip(self, SP_XS),
        )

        self.SetSizer(vbox)
        vbox.Fit(self)
        vbox.Layout()
        apply_theme(self)

    def onPaneChanged(self, event):
        self.Layout()

    # A signature reads whatever is in results at the moment it runs; anything added later
    # simply does not exist for it, and it reports no error. Two shipped signatures read the
    # payload and config data, and 12 read the network summary, so running this pass before
    # those tabs have produced anything quietly under-reports. A tab with nothing to process
    # never publishes its key, so it only counts as missing when it has work to do.
    def MissingPrereqs(self):
        missing = []
        if "payloads" not in self.results and JsonPathExists(self.analysisDir):
            missing.append("Payloads")
        if "configs" not in self.results:
            yaraTab = getattr(self.GetMainFrame(), "yaraTab", None)
            if yaraTab and not yaraTab.yaraComplete:
                # The config hits come from the yara pass; before it runs "no hits" means nothing.
                missing.append("Yara")
            elif self.parent.configHits:
                missing.append("Configs")
        return missing

    def GetMainFrame(self):
        parent = self.GetParent()
        while parent and not isinstance(parent, wx.Frame):
            parent = parent.GetParent()

        return parent

    def UpdateGenerateButtonState(self):
        missing = self.MissingPrereqs()
        if self.results and not self.signaturesComplete and not missing:
            self.signaturesButton.Enable()
            self.signaturesButton.SetToolTip("Run the signature set over this analysis.")
        else:
            self.signaturesButton.Disable()
            if missing and not self.signaturesComplete:
                self.signaturesButton.SetToolTip(
                    "Process these tabs first, or the signatures that read them match "
                    f"nothing: {', '.join(missing)}."
                )

    def BuildSignatureInputs(self):
        """Fill in what the signature set reads and no tab owns.

        The Payloads, Configs and Yara tabs publish their own results; target info and the
        network summary have no tab that does, and the summary is cheap to derive from the
        behaviour and JS logs already present (no capture needed).
        """
        from .json_report import CapeView, TargetInfo

        if "target" not in self.results:
            targetFile = getattr(self.parent, "targetFile", None)
            if targetFile:
                self.results["target"] = TargetInfo(targetFile)
        if "network" not in self.results:
            self.results["network"] = NetworkSummary(
                behavior=self.results.get("behavior"), jsLog=self.results.get("js_log")
            )
        self.results["CAPE"] = CapeView(self.results)

    def GenerateSignatures(self, event):
        missing = self.MissingPrereqs()
        if missing:
            ui.message(
                "Process these tabs first, then run the signatures:\n\n  "
                + "\n  ".join(missing)
                + "\n\nA signature that reads data added after it ran matches nothing and "
                "reports no error, so the results would be quietly incomplete.",
                "Signatures",
                wx.OK | wx.ICON_INFORMATION,
            )
            return

        self.GetMainFrame().RunSteps([self.SignaturesStep()])

    def SignaturesStep(self):
        """The signature pass as a (label, compute, render) step: the pass runs on the
        processing worker, the grid is filled on the GUI thread. The prerequisites are checked
        again when it runs, since in the auto-process chain it is planned before the tabs it
        depends on have finished."""

        def compute():
            missing = ui.on_gui(self.MissingPrereqs)
            if missing:
                # Auto-process: lands in its failure summary instead of a modal mid-run.
                raise RuntimeError(f"Process these tabs first: {', '.join(missing)}")
            self.BuildSignatureInputs()
            try:
                RunSignatures(results=self.results, analysis_path=self.analysisDir).run()
            finally:
                # The view exists for the signature pass only; the tabs own the real keys.
                self.results.pop("CAPE", None)

        def render(_):
            self.signaturesButton.Disable()
            self.AddTableData()
            self.signaturesComplete = True

        return ("signatures", compute, render)

    def AddTableData(self):
        try:
            for sig in self.results.get("signatures"):
                if sig.get("description", ""):
                    sigData = sig.get("description")
                    if sig.get("data", []):
                        for item in sig.get("data", []):
                            if "type" not in item:
                                key = next(iter(item.keys()))
                                sigData += f"\n    \u2022 {key}: {item[key]}"
                    self.grid.AppendRows(1)
                    self.grid.SetCellValue(self.grid.GetNumberRows() - 1, 0, sigData)
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
