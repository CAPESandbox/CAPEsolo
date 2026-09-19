import re
from pathlib import Path

import pefile
import wx

from . import ui_kit as ui
from .key_event import KeyEventHandlerMixin
from .theme import FONT_CODE, SP_SM, SP_XS, apply_theme, dip

# "0x0042EEE3  55                       PUSH      EBP"
# Two spaces then the instruction bytes: this excludes the stack-dump lines
# ("0x0012ff00 ([esp+0x0]): 0x00401000"), which are data, not code addresses.
TRACE_RE = re.compile(r"^(0x[0-9A-Fa-f]+)\s\s+[0-9A-F]{2,}\s")
# "Break at 0x0042EEE3 in svchost.exe (RVA 0x2eee3, thread 2816, Stack 0x00E71000-0x00E80000, ImageBase 0x00400000)"
BREAK_RE = re.compile(
    r"Break at (0x[0-9A-Fa-f]+)(?: in (\S+))? \(RVA (0x[0-9A-Fa-f]+),"
    r".*ImageBase (0x[0-9A-Fa-f]+)\)"
)
# "ActionDispatcher: Scanning region at 0x000001BF16390000."
SCAN_RE = re.compile(r"Scanning region at (0x[0-9A-Fa-f]+)")
# "DEBUG: 2688: The module loaded at 0x... has been selected for coverage: <path> (0x1e000 bytes)."
# "DEBUG: 2688: Target DLL loaded at 0x...: <path> (0x1e000 bytes)."
# "DEBUG: 2688: DLL loaded at 0x...: <path> (0x2c000 bytes)."
MODULE_RE = re.compile(
    r"DEBUG: (\d+): (The module|Target DLL|DLL) loaded at (0x[0-9A-Fa-f]+)"
    r"[^:]*: (.*?) \((0x[0-9A-Fa-f]+) bytes\)"
)
# "DEBUG: 2688: Monitor initialised: 64-bit capemon loaded in process 2688 at 0x..., thread 4, image base 0x00400000, stack from 0x...-0x..."
MONITOR_RE = re.compile(
    r"DEBUG: (\d+): Monitor initialised:.* image base (0x[0-9A-Fa-f]+),"
)
# The three module-load lines, most specific first.
MODULE_RANK = {"The module": 0, "Target DLL": 1, "DLL": 2}


class DebuggerPanel(wx.Panel, KeyEventHandlerMixin):
    def __init__(self, parent):
        super(DebuggerPanel, self).__init__(parent)
        self.parent = parent
        self.analysisDir = parent.analysisDir
        self.coverageFilePath = None
        self.loadedLog = ""
        self.BindKeyEvents()
        self.InitUI()

    def InitUI(self):
        vbox = wx.BoxSizer(wx.VERTICAL)

        hbox = wx.BoxSizer(wx.HORIZONTAL)
        self.logFileDropdown = ui.Picker(self)
        viewButton = ui.Button(self, label="View", variant=ui.PRIMARY)
        viewButton.Bind(wx.EVT_BUTTON, self.OnViewButtonClick)

        hbox.Add(
            self.logFileDropdown, proportion=1, flag=wx.EXPAND | wx.RIGHT, border=dip(self, SP_SM)
        )
        hbox.Add(viewButton, flag=wx.EXPAND)
        vbox.Add(hbox, flag=wx.EXPAND | wx.ALL, border=dip(self, SP_SM))

        self.resultsWindow = wx.TextCtrl(
            self, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_RICH2
        )
        self.resultsWindow.SetFont(FONT_CODE)
        vbox.Add(self.resultsWindow, proportion=1, flag=wx.EXPAND | wx.ALL, border=dip(self, SP_SM))
        self.notice = ui.notice_for(
            self.resultsWindow,
            title="No log opened",
            detail="Pick a debugger log and select View.",
        )

        hboxCover = wx.BoxSizer(wx.HORIZONTAL)
        self.coverBtn = ui.Button(self, label="Create Coverage File")
        self.coverBtn.Bind(wx.EVT_BUTTON, self.OnCover)
        self.coverBtn.Disable()
        hboxCover.Add(self.coverBtn, proportion=0, flag=wx.ALL | wx.CENTER, border=dip(self, SP_XS))
        self.coverageFileBtn = ui.Button(self, label="Copy Coverage File")
        self.coverageFileBtn.Bind(wx.EVT_BUTTON, self.OnCopyPath)
        self.coverageFileBtn.Disable()
        hboxCover.Add(self.coverageFileBtn, proportion=1, flag=wx.ALL | wx.CENTER, border=dip(self, SP_XS))

        vbox.Add(hboxCover, proportion=0, flag=wx.ALL | wx.CENTER, border=dip(self, SP_XS))

        self.SetSizer(vbox)
        apply_theme(self)
        self.notice.Present()

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
        self.loadedLog = selectedFile
        self.coverBtn.Enable()

    def LoadDebuggerResults(self, file_name):
        path = Path(self.analysisDir, "debugger") / file_name
        if not path.exists():
            self.notice.Present(
                title="Log not found",
                detail=f"{file_name} is no longer in the analysis debugger directory.",
                kind=ui.ERROR,
            )
            return
        self.notice.Dismiss()
        self.resultsWindow.SetValue(path.read_text())

    def ParseModules(self, analysisData, pid):
        """(rank, base, size, name) per capemon load line in analysis.log, best first."""
        modules = []
        for line in analysisData.splitlines():
            match = MODULE_RE.search(line)
            if not match or (pid and match.group(1) != pid):
                continue
            modules.append(
                (
                    MODULE_RANK[match.group(2)],
                    int(match.group(3), 16),
                    int(match.group(5), 16),
                    match.group(4),
                )
            )
        modules.sort(key=lambda entry: entry[0])
        return modules

    def DetectBases(self, debugData, analysisData, pid):
        """Candidate image bases for the trace, best guess first, plus the module map."""
        candidates = []
        for line in debugData.splitlines():
            match = BREAK_RE.search(line)
            if match:
                addr, base = int(match.group(1), 16), int(match.group(4), 16)
                # addr - ImageBase == RVA, so a bad match rejects itself.
                if addr - base == int(match.group(3), 16):
                    candidates.append((base, None, match.group(2)))
                continue
            # Weak: capemon logs the Scan operand's region when one is given, which
            # may be a data buffer rather than the traced module. Scoring decides.
            match = SCAN_RE.search(line)
            if match:
                candidates.append((int(match.group(1), 16), None, None))

        modules = self.ParseModules(analysisData, pid)
        # A plain "DLL loaded at" is a library (ntdll, kernel32): it maps the address
        # space but is never the module under analysis, so it is a range, not a
        # candidate. Otherwise a trace that idles in a library would win on hit count.
        candidates.extend(
            (base, size, name)
            for rank, base, size, name in modules
            if rank < MODULE_RANK["DLL"]
        )

        for line in analysisData.splitlines():
            match = MONITOR_RE.search(line)
            if match and (not pid or match.group(1) == pid):
                candidates.append((int(match.group(2), 16), None, None))

        sizes = {base: size for _, base, size, _ in modules}
        unique, seen = [], set()
        for base, size, name in candidates:
            if base in seen:
                continue
            seen.add(base)
            unique.append((base, size or sizes.get(base), name))
        return unique, [(base, size) for _, base, size, _ in modules]

    def PickBase(self, candidates, knownRanges, addrs):
        """The candidate accounting for the most trace addresses, ties going to rank."""
        bounds = sorted(
            {base for base, _ in knownRanges} | {base for base, _, _ in candidates}
        )
        best, bestScore = candidates[0], -1
        for base, size, name in candidates:
            end = base + size if size else next((b for b in bounds if b > base), None)
            # Score on the same predicate the rebase filter uses, so a base cannot
            # win on addresses that would then be discarded.
            score = sum(
                1
                for addr in addrs
                if (end is None or addr < end)
                and self.InTargetModule(addr, base, size, knownRanges)
            )
            if score > bestScore:
                best, bestScore = (base, size, name), score
        return best

    def InTargetModule(self, addr, base, size, knownRanges):
        """True unless the address belongs below, beyond, or to another known module."""
        if addr < base or (size and addr >= base + size):
            return False
        return not any(
            other != base and other <= addr < other + otherSize
            for other, otherSize in knownRanges
        )

    def TargetImageBase(self):
        """Preferred image base from the analysis target's PE header."""
        targetFile = getattr(self.parent, "targetFile", None)
        if not targetFile:
            return ""
        try:
            pe = pefile.PE(str(targetFile), fast_load=True)
            return f"0x{pe.OPTIONAL_HEADER.ImageBase:08X}"
        except Exception:
            return ""

    def OnCover(self, event):
        debugData = self.resultsWindow.GetValue()
        analysisLogPath = Path(self.analysisDir) / "analysis.log"
        analysisData = analysisLogPath.read_text() if analysisLogPath.exists() else ""
        # Debugger logs are named "<pid>.log", but the dropdown also lists the
        # coverage files this panel writes back into the same folder.
        stem = self.loadedLog.split(".")[0]
        pid = stem if stem.isdigit() else ""

        filteredLines = set()
        for line in debugData.splitlines():
            match = TRACE_RE.match(line)
            if match:
                filteredLines.add(match.group(1))

        candidates, knownRanges = self.DetectBases(debugData, analysisData, pid)
        addrs = [int(addr, 16) for addr in filteredLines]
        picked = self.PickBase(candidates, knownRanges, addrs) if candidates else None
        loaderBase = f"0x{picked[0]:08X}" if picked else ""

        dialog = ui.Dialog(self, title="Generate Coverage File", size=wx.Size(340, 170))
        panel = wx.Panel(dialog)
        vbox = wx.BoxSizer(wx.VERTICAL)

        hbox1 = wx.BoxSizer(wx.HORIZONTAL)
        currentLabel = wx.StaticText(panel, label="Current ImageBase   0x:")
        loaderField = ui.Field(panel, value=f"{loaderBase}")
        loaderCtrl = loaderField.ctrl
        hbox1.Add(currentLabel, flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, border=dip(self, SP_XS))
        hbox1.Add(loaderField, proportion=1)
        hbox2 = wx.BoxSizer(wx.HORIZONTAL)
        newLabel = wx.StaticText(panel, label="New ImageBase        0x:")
        imageField = ui.Field(panel, value=self.TargetImageBase())
        imageCtrl = imageField.ctrl
        hbox2.Add(newLabel, flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, border=dip(self, SP_XS))
        hbox2.Add(imageField, proportion=1)

        vbox.Add(hbox1, flag=wx.EXPAND | wx.ALL, border=dip(self, SP_XS))
        vbox.Add(hbox2, flag=wx.EXPAND | wx.ALL, border=dip(self, SP_XS))

        vbox.Add(
            ui.dialog_buttons(panel, ok="Ok"),
            flag=wx.EXPAND | wx.TOP | wx.BOTTOM | wx.RIGHT,
            border=dip(self, SP_SM),
        )

        panel.SetSizer(vbox)
        apply_theme(dialog)

        if dialog.ShowModal() == wx.ID_OK:
            current = loaderCtrl.GetValue().strip()
            new = imageCtrl.GetValue().strip()
            if current and new:
                loaderBase = int(current, 16)
                imageBase = int(new, 16)
                size = picked[1] if picked and picked[0] == loaderBase else None
                filteredLines = [
                    self.rebase(line, imageBase, loaderBase)
                    for line in filteredLines
                    if self.InTargetModule(
                        int(line, 16), loaderBase, size, knownRanges
                    )
                ]

        dialog.Destroy()

        coverData = "\n".join(filter(None, filteredLines))

        if coverData:
            coverageSaved = False
            filepath = Path(self.analysisDir) / "debugger" / f"coverage_{stem}.txt"

            filepath.write_text(coverData)
            self.coverageFilePath = str(filepath)

            if filepath.exists():
                coverageSaved = True
                self.coverageFileBtn.Enable()

            if coverageSaved:
                ui.message(
                    f"Coverage saved to {filepath}.",
                    "Success",
                    wx.OK | wx.ICON_INFORMATION,
                )
            else:
                ui.message(
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
            ui.message(
                f"Analysis log copied: {self.coverageFilePath}",
                "Info",
                wx.OK | wx.ICON_INFORMATION,
            )
        else:
            wx.LogError("Unable to open the clipboard.")
