from pathlib import Path

import wx
import wx.grid as gridlib

from CAPEsolo.capelib.cape_utils import get_cape_name_from_yara_hit

from . import ui_kit as ui
from .custom_grid import CopyableGrid
from .key_event import KeyEventHandlerMixin
from .theme import FONT_CODE, GRID_ROW_ALT, SP_XS, apply_theme, dip

ALL_FILES = "<All files>"

# A payload is named by its sha256 and a rule description is a sentence, so autosizing
# either column alone can take the whole width and push the rest of the row off screen.
FILE_COL_MAX = 320
DESC_COL_MAX = 400


def FormatOffset(offset):
    """Yara reports match offsets as ints; hex is what cross-references to a disassembly."""
    if isinstance(offset, int):
        return f"0x{offset:x}"

    return str(offset)


class YaraPanel(wx.Panel, KeyEventHandlerMixin):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.yara = parent.yara
        self.analysisDir = parent.analysisDir
        self.yaraComplete = False
        self.filesjson = Path(self.analysisDir) / "files.json"
        # One entry per rule match, flattened out of the per-file yara results so that a
        # grid row is a single hit. viewHits is the subset the grid currently shows, and is
        # what row indices map back through.
        self.hits = []
        self.viewHits = []
        # Every file scanned, including those that matched nothing: the grid holds hits
        # alone, so the filter dropdown is the only place a clean file is still visible.
        self.scanned = {}
        self.filterFiles = [ALL_FILES]
        self.BindKeyEvents()
        self.InitUI()

    def InitUI(self):
        vbox = wx.BoxSizer(wx.VERTICAL)

        vbox.AddSpacer(10)
        self.yaraButton = ui.Button(
            self, label="Process Yara Results", variant=ui.PRIMARY, glyph=ui.REFRESH
        )
        self.yaraButton.Bind(wx.EVT_BUTTON, self.ProcessYara)
        self.yaraButton.Disable()
        vbox.Add(self.yaraButton, proportion=0, flag=wx.ALL, border=dip(self, SP_XS))

        self.fileDropdown = ui.Picker(self)
        self.fileDropdown.Bind(wx.EVT_COMBOBOX, self.OnFileView)
        vbox.Add(
            wx.StaticText(self, label="Scanned files:"), flag=wx.LEFT | wx.TOP, border=dip(self, SP_XS)
        )
        vbox.Add(
            self.fileDropdown,
            proportion=0,
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=dip(self, SP_XS),
        )

        self.grid = CopyableGrid(self, 0, 5)
        for col, label in enumerate(
            ("File", "Rule", "CAPE Name", "Strings", "Description")
        ):
            self.grid.SetColLabelValue(col, label)
        self.grid.SetColLabelAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)
        # Only the string count reads as a number; left-align the rest so paths and rule
        # names line up down the column.
        for col in (0, 1, 2, 4):
            attr = gridlib.GridCellAttr()
            attr.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE)
            self.grid.SetColAttr(col, attr)
        self.grid.SetRowLabelSize(0)
        self.grid.EnableEditing(False)
        self.grid.Bind(gridlib.EVT_GRID_SELECT_CELL, self.OnSelectCell)
        self.grid.Hide()
        vbox.Add(
            self.grid,
            proportion=2,
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=dip(self, SP_XS),
        )

        self.resultsWindow = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.resultsWindow.SetFont(FONT_CODE)
        vbox.Add(
            self.resultsWindow,
            proportion=1,
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=dip(self, SP_XS),
        )
        # Until a scan has run there is no output, so the area explains itself instead of
        # holding a sentence in the results box's monospace.
        self.notice = ui.notice_for(
            self.resultsWindow,
            title="No yara results yet",
            detail="Process yara results to list rule hits.",
        )

        self.SetSizer(vbox)
        apply_theme(self)
        self.notice.Present()

    def AddHits(self, file, hits):
        """Flatten one file's yara results into hit records.

        The configHits side effect belongs here rather than in the rendering path: the grid
        is rebuilt every time the file filter changes, and appending a CAPE name again on
        each rebuild would make the Configs tab run every parser once per redraw.
        """
        self.scanned[file] = self.scanned.get(file, 0) + len(hits)
        for hit in hits:
            capename = get_cape_name_from_yara_hit(hit)
            if capename:
                self.parent.configHits.append({file: capename})

            meta = hit.get("meta") or {}
            # Folded onto one line for its grid cell: a rule description may contain
            # newlines, which would grow the row to the height of the whole description
            # once rows are autosized. Meta keeps its original form in the detail pane.
            description = " ".join(str(meta.get("description", "")).split())
            self.hits.append(
                {
                    "file": file,
                    "rule": hit.get("name", ""),
                    "capename": capename or "",
                    "meta": meta,
                    "description": description,
                    "strings": hit.get("strings") or [],
                    "addresses": hit.get("addresses") or {},
                }
            )

    def LoadFileFilter(self, selected=ALL_FILES):
        """Rebuild the file filter, keeping *selected* current if it still exists.

        The file names are held in a parallel list rather than parsed back out of the
        labels, which carry a trailing hit count that a path could otherwise contain.
        """
        self.filterFiles = [ALL_FILES] + list(self.scanned)
        self.fileDropdown.Clear()
        self.fileDropdown.Append(f"{ALL_FILES} ({len(self.hits)})")
        for file, count in self.scanned.items():
            self.fileDropdown.Append(f"{file} ({count})")

        index = self.filterFiles.index(selected) if selected in self.filterFiles else 0
        self.fileDropdown.SetSelection(index)

    def GetFilterFile(self):
        index = self.fileDropdown.GetSelection()
        if 0 <= index < len(self.filterFiles):
            return self.filterFiles[index]

        return ALL_FILES

    def OnFileView(self, event):
        self.AddTableData()

    def ClearGrid(self):
        self.grid.ClearGrid()
        rows = self.grid.GetNumberRows()
        if rows > 0:
            self.grid.DeleteRows(0, rows)

    def AddTableData(self):
        selected = self.GetFilterFile()
        if selected == ALL_FILES:
            # A copy, so a hit added later by AddPayload cannot leave viewHits longer than
            # the rows actually in the grid.
            self.viewHits = list(self.hits)
        else:
            self.viewHits = [hit for hit in self.hits if hit["file"] == selected]

        self.ClearGrid()
        for row, hit in enumerate(self.viewHits):
            self.grid.AppendRows(1)
            self.grid.SetCellValue(row, 0, hit["file"])
            self.grid.SetCellValue(row, 1, hit["rule"])
            self.grid.SetCellValue(row, 2, hit["capename"])
            self.grid.SetCellValue(row, 3, str(len(hit["strings"])))
            self.grid.SetCellValue(row, 4, hit["description"])

        self.grid.AutoSizeColumns()
        for col, limit in ((0, FILE_COL_MAX), (4, DESC_COL_MAX)):
            if self.grid.GetColSize(col) > limit:
                self.grid.SetColSize(col, limit)
        self.grid.AutoSizeRows()
        self.ApplyAlternateRowShading()
        if self.viewHits:
            self.notice.Dismiss()
            self.resultsWindow.SetValue(self.Summarize())
        else:
            # A scan that matched nothing is still a result, so it says which filter it
            # applies to rather than reading as "not run yet".
            self.notice.Present(
                title="No yara hits",
                detail=self.Summarize(),
            )
        self.Layout()

    def ApplyAlternateRowShading(self):
        numRows = self.grid.GetNumberRows()

        for row in range(numRows):
            if row % 2 == 0:
                attr = gridlib.GridCellAttr()
                attr.SetBackgroundColour(GRID_ROW_ALT)
                self.grid.SetRowAttr(row, attr)
        self.grid.ForceRefresh()

    def Summarize(self):
        if not self.hits:
            return "No yara hits."

        if not self.viewHits:
            return f"No yara hits for {self.GetFilterFile()}."

        files = len({hit["file"] for hit in self.viewHits})
        return (
            f"{len(self.viewHits)} hit(s) over {files} file(s), "
            f"{len(self.scanned)} file(s) scanned.\n"
            "Select a row to view that rule's meta, matched strings and offsets."
        )

    def FormatHit(self, hit):
        """The full detail for one hit, for the pane below the grid."""
        lines = [f'File:      {hit["file"]}', f'Rule:      {hit["rule"]}']
        if hit["capename"]:
            lines.append(f'CAPE Name: {hit["capename"]}')

        if hit["meta"]:
            lines.append("")
            lines.append("Meta:")
            lines.extend(f"    {key}: {value}" for key, value in hit["meta"].items())

        strings = hit["strings"]
        lines.append("")
        lines.append(f"Strings ({len(strings)}):")
        if strings:
            lines.extend(f"    {value}" for value in strings)
        else:
            lines.append("    None")

        addresses = hit["addresses"]
        lines.append("")
        lines.append(f"Offsets ({len(addresses)}):")
        if addresses:
            lines.extend(
                f"    ${key}: {FormatOffset(offset)}"
                for key, offset in addresses.items()
            )
        else:
            lines.append("    None")

        return "\n".join(lines)

    def OnSelectCell(self, event):
        row = event.GetRow()
        if 0 <= row < len(self.viewHits):
            # A NUL terminates the native text control, dropping everything after it with
            # no error anywhere. _yara_encode_string should already prevent this; the guard
            # stays because losing the rest of the detail is silent when it does happen.
            detail = self.FormatHit(self.viewHits[row])
            self.notice.Dismiss()
            self.resultsWindow.SetValue(detail.replace("\x00", ""))
        event.Skip()

    def ProcessYara(self, event):
        try:
            self.targetFile = self.parent.targetFile
            self.yara.Scan(str(self.targetFile))
        except FileNotFoundError:
            print("Target not found. This may be normal.")

        self.yara.ScanPayloads()
        for filehits in self.yara.yara_results:
            for file, hits in filehits.items():
                self.AddHits(file, hits)

        self.LoadFileFilter()
        # Shown before the rows go in, so the Layout that AddTableData ends with is the one
        # that sizes it, matching SignaturesPanel.
        self.grid.Show()
        self.AddTableData()
        self.UpdatePayloadCapeTypes()
        self.yaraButton.Disable()
        self.yaraComplete = True

    def AddPayload(self, relPath):
        """Scan a payload a config parser produced and append its hits to the report.

        Yara is a one-shot run, so a payload that only exists once configs have been
        extracted is scanned on its own rather than by re-running ScanPayloads. If yara
        has not run yet, ScanPayloads will pick the file up from files.json.
        """
        if not self.yaraComplete:
            return

        hits = self.yara.ScanPayload(relPath)
        self.AddHits(relPath, hits)
        # Read the filter before rebuilding it, so the view stays where the user left it.
        selected = self.GetFilterFile()
        self.LoadFileFilter(selected)
        self.AddTableData()
        self.UpdatePayloadCapeTypes()

    def GetMainFrame(self):
        parent = self.GetParent()
        while parent and not isinstance(parent, wx.Frame):
            parent = parent.GetParent()

        return parent

    def CapeTypesByFile(self):
        """Map each scanned file to a CAPE-type label built from its Yara hits.

        Prefer the cape_type meta of CAPE-family rules; for a file that is yara-positive only
        against rules with no cape_type, fall back to the matched rule name(s) so a positive
        file still shows what hit it.
        """
        capeTypes, ruleNames = {}, {}
        for hit in self.hits:
            file = hit["file"]
            capeType = (hit.get("meta") or {}).get("cape_type", "")
            if capeType:
                names = capeTypes.setdefault(file, [])
                if capeType not in names:
                    names.append(capeType)

            rule = hit.get("rule", "")
            if rule:
                rules = ruleNames.setdefault(file, [])
                if rule not in rules:
                    rules.append(rule)

        labels = {}
        for file in set(capeTypes) | set(ruleNames):
            if capeTypes.get(file):
                labels[file] = ", ".join(capeTypes[file])
            elif ruleNames.get(file):
                labels[file] = "Yara: " + ", ".join(ruleNames[file])

        return labels

    def UpdatePayloadCapeTypes(self):
        """Hand the Payloads tab the CAPE type per file so it can update its Type rows."""
        payloadsTab = getattr(self.GetMainFrame(), "payloadsTab", None)
        if payloadsTab:
            payloadsTab.ApplyYaraCapeTypes(self.CapeTypesByFile())

    def UpdateYaraButtonState(self):
        if not self.yaraComplete and self.parent.targetFile:
            self.yaraButton.Enable()
        else:
            self.yaraButton.Disable()
