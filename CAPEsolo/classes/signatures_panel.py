import logging

import wx
import wx.grid as gridlib
import wx.lib.scrolledpanel as scrolled

from CAPEsolo.capelib.network_summary import NetworkSummary
from CAPEsolo.capelib.signatures import RunSignatures
from CAPEsolo.capelib.utils import JsonPathExists

from . import ui_kit as ui
from .custom_grid import CopyableGrid, SortKey
from .key_event import KeyEventHandlerMixin
from .theme import (
    ACCENT_ORANGE,
    DANGER,
    FG_ON_DANGER,
    FG_PRIMARY,
    GRID_ROW_ALT,
    SP_XS,
    apply_theme,
    dip,
)

log = logging.getLogger(__name__)


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

        columnLabels = ["Severity", "Name", "Description", "Confidence", "Families"]
        self.grid = CopyableGrid(grid_panel, 0, len(columnLabels))
        for i, label in enumerate(columnLabels):
            self.grid.SetColLabelValue(i, label)
        self.grid.SetColLabelAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)
        for col in range(len(columnLabels)):
            attr = gridlib.GridCellAttr()
            attr.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE)
            self.grid.SetColAttr(col, attr)
        self.grid.SetRowLabelSize(0)
        self.grid.EnableEditing(False)
        # Bound after CopyableGrid's own handler, so this runs first; rebuilding from
        # self.sigs keeps the severity colour on the right rows.
        self.grid.Bind(gridlib.EVT_GRID_LABEL_LEFT_CLICK, self.OnSortColumn)
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
        # self.sigs holds one (severity, cells) per row, in grid order, so a header sort can
        # rebuild the rows and the severity colour follows them (see ApplyAlternateRowShading).
        self.sigs = []
        try:
            sigs = sorted(
                self.results.get("signatures") or [],
                key=lambda s: (-(s.get("severity") or 0), s.get("name") or ""),
            )
            for sig in sigs:
                if sig.get("description", ""):
                    sigData = sig.get("description")
                    if sig.get("data", []):
                        for item in sig.get("data", []):
                            if "type" not in item:
                                key = next(iter(item.keys()))
                                sigData += f"\n    \u2022 {key}: {item[key]}"
                    cells = (
                        str(sig.get("severity", "")),
                        sig.get("name") or "",
                        sigData,
                        str(sig.get("confidence", "")),
                        ", ".join(sig.get("families") or []),
                    )
                    self.sigs.append((sig.get("severity") or 0, cells))
        except Exception:
            log.exception("Failed to show the signature results")

        self.FillGrid()
        self.grid.AutoSizeColumns()
        self.grid.Show()
        self.Layout()

    def FillGrid(self):
        rows = self.grid.GetNumberRows()
        if rows > 0:
            self.grid.DeleteRows(0, rows)
        self.grid.AppendRows(len(self.sigs))
        for row, (_, cells) in enumerate(self.sigs):
            for col, value in enumerate(cells):
                self.grid.SetCellValue(row, col, value)
        self.grid.AutoSizeRows()
        self.ApplyAlternateRowShading()

    def OnSortColumn(self, event):
        col = event.GetCol()
        if col < 0 or not self.sigs:
            return
        reverse = self.grid.NextSort(col)
        self.sigs.sort(key=lambda sig: SortKey(sig[1][col]), reverse=reverse)
        self.FillGrid()

    def ApplyAlternateRowShading(self):
        numRows = self.grid.GetNumberRows()

        for row in range(numRows):
            if row % 2 == 0:
                attr = gridlib.GridCellAttr()
                attr.SetBackgroundColour(GRID_ROW_ALT)
                self.grid.SetRowAttr(row, attr)
            # Severity cell: red fill for 3 and up, the orange row tint for 2. Re-applied here
            # because a theme switch calls this, and a cell keeps the colour it was given.
            severity = self.sigs[row][0] if row < len(self.sigs) else 0
            if severity >= 3:
                self.grid.SetCellBackgroundColour(row, 0, DANGER)
                self.grid.SetCellTextColour(row, 0, FG_ON_DANGER)
            elif severity == 2:
                self.grid.SetCellBackgroundColour(row, 0, ACCENT_ORANGE)
                self.grid.SetCellTextColour(row, 0, FG_PRIMARY)
        self.grid.ForceRefresh()
