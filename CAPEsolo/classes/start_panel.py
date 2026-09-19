import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from threading import Thread

import wx
import wx.lib.scrolledpanel as scrolled
from sflock.abstracts import File as SflockFile
from sflock.ident import identify as sflock_identify

from CAPEsolo.capelib.js_log import GetJsLogPath
from CAPEsolo.capelib.path_utils import path_exists
from CAPEsolo.capelib.resultserver import ResultServer
from CAPEsolo.capelib.utils import sanitize_filename
from CAPEsolo.lib.common.hashing import hash_file
from CAPEsolo.lib.common.zip_utils import (
    get_file_names,
    get_interesting_files,
    get_zip_file_names,
)
from CAPEsolo.utils.download_sample import (
    configured_sources,
    desktop_dir,
    download_dir,
    download_enabled,
)
from CAPEsolo.utils.update_yara import UpdateYara

from . import ui_kit as ui
from .analysis_conf import AnalysisConfPanel
from .debug_console import DebugConsole
from .html_report import ReportHTML
from .json_report import GetResults
from .key_event import EVT_ANALYZER_COMPLETE, EVT_ANALYZER_COMPLETE_ID
from .logger_window import LoggerWindow
from .process_tree_window import ProcessTreeWindow
from .theme import (
    BG_MAIN,
    FONT_CODE,
    SP_LG,
    SP_MD,
    SP_SM,
    SP_XL,
    SP_XS,
    apply_theme,
    dip,
    dip_size,
)
from .vt_helper import seed_vt_cache

log = logging.getLogger(__name__)

# How long to wait for the end-of-run uploads to appear in the analysis folder before the
# result server is stopped. Generous because it only elapses in full when something is
# genuinely wrong; the normal case returns within a couple of polls.
UPLOAD_WAIT_SECONDS = 15.0

SANDBOXPACKAGES = (
    "Shellcode",
    "Shellcode_trace",
    "Shellcode_x64",
    "Shellcode_x64_trace",
    "archive",
    "chm",
    "dll",
    "doc",
    "exe",
    "hta",
    "iso",
    "jar",
    "js",
    "lnk",
    "mht",
    "msi",
    "msix",
    "nsis",
    "ps1",
    "pub",
    "python",
    "rar",
    "regsvr",
    "sct",
    "service",
    "service_dll",
    "udf",
    "vbs",
    "vhd",
    "xls",
    "xps",
    "xslt",
    "zip",
)

# Every action accepted by capemon's ActionDispatcher (CAPE/Trace.c). Names are bare:
# GetDebuggerOptions appends ":<value>" from the value field for those taking an
# argument (If, hooks, Jmp, Count, SetDump, DumpSize, SetEax, ...). capemon compares
# with stricmp/strnicmp, so the casing here is for legibility only.
DEBUGACTIONS = [
    "Call",
    "ClearCarryFlag",
    "ClearSignFlag",
    "ClearZeroFlag",
    "Count",
    "Dump",
    "DumpImage",
    "DumpSize",
    "DumpStack",
    "DumpStrings",
    "Exit",
    "FlipCarryFlag",
    "FlipSignFlag",
    "FlipZeroFlag",
    "GoTo",
    "Guard",
    "hook-watch",
    "hooks",
    "If",
    "Jmp",
    "Nop",
    "Pop",
    "Print",
    "Push",
    "Ret",
    "Scan",
    "SetBp0",
    "SetBp1",
    "SetBp2",
    "SetBp3",
    "SetCarryFlag",
    "SetDst",
    "SetDump",
    "SetEax",
    "SetEbx",
    "SetEcx",
    "SetEdi",
    "SetEdx",
    "SetEsi",
    "SetPtr",
    "SetSignFlag",
    "SetSrc",
    "SetZeroFlag",
    "Skip",
    "Sleep",
    "Step2OEP",
    "Stop",
    "String",
    "Unwind",
    "Wret",
]

YARARULE = """
rule DebuggerRule
{
    meta:
        cape_options = ""
    strings:
        $string = ""
    condition:
        all of them
}
"""


def GetPreviousTarget(analysisDir):
    for path in Path(analysisDir).glob("s_*"):
        if path.is_file():
            return path
    return None


class AnalyzerCompleteEvent(wx.PyCommandEvent):
    def __init__(self, etype, eid, message=None):
        super().__init__(etype, eid)
        self.message = message


class _DownloadCredentialsDialog(ui.Dialog):
    """Startup prompt for sample downloads. A password decrypts stored encrypted keys; an API
    key can also be entered directly (used as-is, no decryption). All fields are masked."""

    def __init__(self, parent, hasStored):
        super().__init__(parent, title="Sample Download Credentials")
        outer = wx.BoxSizer(wx.VERTICAL)
        outer.Add(
            wx.StaticText(
                self,
                label=(
                    "Enter a password to unlock stored encrypted keys, and/or enter an\n"
                    "API key directly. Cancel to disable downloads."
                ),
            ),
            flag=wx.ALL,
            border=dip(self, SP_MD),
        )

        # Password (for stored encrypted keys) and directly-entered keys sit in separate
        # cards for clarity.
        self.pwdCtrl = None
        if hasStored:
            pwdCard = ui.Card(self, title="Password (unlock stored keys)")
            pwdField = ui.Field(pwdCard, style=wx.TE_PASSWORD)
            self.pwdCtrl = pwdField.ctrl
            pwdCard.body.Add(pwdField, flag=wx.EXPAND)
            outer.Add(pwdCard, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=dip(self, SP_MD))

        keyCard = ui.Card(self, title="Enter API key(s) directly")
        keyParent = keyCard
        grid = wx.FlexGridSizer(rows=2, cols=2, hgap=8, vgap=8)
        grid.AddGrowableCol(1, 1)
        grid.Add(wx.StaticText(keyParent, label="VirusTotal:"), flag=wx.ALIGN_CENTER_VERTICAL)
        vtField = ui.Field(keyParent, style=wx.TE_PASSWORD)
        self.vtCtrl = vtField.ctrl
        grid.Add(vtField, flag=wx.EXPAND)
        grid.Add(wx.StaticText(keyParent, label="MalwareBazaar:"), flag=wx.ALIGN_CENTER_VERTICAL)
        mbField = ui.Field(keyParent, style=wx.TE_PASSWORD)
        self.mbCtrl = mbField.ctrl
        grid.Add(mbField, flag=wx.EXPAND)
        keyCard.body.Add(grid, flag=wx.EXPAND)
        outer.Add(keyCard, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=dip(self, SP_MD))

        # Drawn buttons rather than CreateButtonSizer: the stock MSW dialog buttons render
        # natively and ignore SetBackgroundColour, so the theme could not darken them. wx.Dialog
        # still auto-handles the ID_OK / ID_CANCEL ids to end the modal with the right result.
        outer.Add(
            ui.dialog_buttons(self),
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=dip(self, SP_MD),
        )

        # Theme first, then fit: apply_theme swaps in FONT_UI, so fitting beforehand would size
        # the dialog to the smaller default font and squish the controls and the button row.
        self.SetSizer(outer)
        apply_theme(self)
        # apply_theme paints every wx.Panel BG_CARD, including this dialog's own background,
        # which would flatten the cards into it.
        self.SetBackgroundColour(BG_MAIN)
        self.Fit()
        if self.GetSize().width < 440:
            self.SetSize(wx.Size(440, self.GetSize().height))
        self.SetMinSize(self.GetSize())

        # Focus the first field once the dialog is actually shown - CallAfter runs inside
        # ShowModal's event loop - so the analyst can type straight away.
        firstField = self.pwdCtrl or self.vtCtrl
        wx.CallAfter(firstField.SetFocus)

    def GetCredentials(self):
        password = self.pwdCtrl.GetValue() if self.pwdCtrl else ""
        keys = {
            "VirusTotal": self.vtCtrl.GetValue().strip(),
            "MalwareBazaar": self.mbCtrl.GetValue().strip(),
        }
        return password, keys


class StartPanel(wx.Panel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.curDir = True
        self.manualExecution = False
        self.enforceTimeout = False
        self.debuggerControls = {}
        self.analysisDir = parent.analysisDir
        self.analysisLogPath = os.path.join(parent.analysisDir, "analysis.log")
        self.package = ""
        self.capesoloRoot = parent.capesoloRoot
        self.targetFile = GetPreviousTarget(self.analysisDir)
        self.parent.targetFile = self.targetFile
        self.idbg = False
        self.dbgConsole = None
        self.processTreeWindow = None
        self.downloadBroker = None
        self._downloading = False
        self.InitUi()
        # A prior/restored analysis (s_* found by GetPreviousTarget) is reportable without a run,
        # so enable the report buttons; the per-tab process buttons enable from their artifacts.
        if self.targetFile:
            self.jsonReportBtn.Enable()
            self.htmlReportBtn.Enable()
        self.LoadAnalysisConfFile()
        self.Bind(EVT_ANALYZER_COMPLETE, self.OnAnalyzerComplete)
        # Deferred so the frame is realized before the modal password dialog.
        wx.CallAfter(self._InitDownloadBroker)

        """ for debugging the panel layout
        mainFrame = self.GetMainFrame()
        width, height = mainFrame.GetSize()
        size = wx.Size(int(width * 2), height)
        position = mainFrame.GetPosition()
        dbgConsole = DebugConsole(self, "Debug Console", position, size)
        dbgConsole.OpenConsole()
        dbgConsole.frame.Show()
        """

    def InitUi(self):
        """Build the Start tab: scrolling cards, with the action bar pinned beneath them.

        The panel is a plain wx.Panel holding a ScrolledPanel rather than being one itself,
        so Launch and Kill stay on screen no matter how far the configuration above has been
        scrolled. Content is grouped into cards - Target, Package & options, Monitor, and
        the two collapsible editors - instead of eleven sibling rows separated only by a
        uniform 10px border, which gave a target picker, a credentials box and sixteen
        monitor switches exactly the same visual weight.
        """
        outer = wx.BoxSizer(wx.VERTICAL)
        self.scroll = scrolled.ScrolledPanel(self)
        self.scroll.SetBackgroundColour(BG_MAIN)
        body = self.scroll
        vbox = wx.BoxSizer(wx.VERTICAL)

        gapS = dip(self, SP_SM)
        gapM = dip(self, SP_MD)
        gapL = dip(self, SP_LG)

        # -- Target ---------------------------------------------------------
        targetCard = ui.Card(body, title="Target")

        pathRow = wx.BoxSizer(wx.HORIZONTAL)
        self.targetPathField = ui.Field(targetCard, value="<Target file>")
        self.targetPath = self.targetPathField.ctrl
        browseBtn = ui.Button(targetCard, label="Browse...", glyph=ui.FOLDER)
        browseBtn.Bind(wx.EVT_BUTTON, self.OnBrowse)
        pathRow.Add(self.targetPathField, 1, wx.EXPAND | wx.RIGHT, gapS)
        pathRow.Add(browseBtn, 0, wx.ALIGN_CENTER_VERTICAL)
        targetCard.body.Add(pathRow, 0, wx.EXPAND | wx.BOTTOM, gapM)

        # Download a sample by hash and feed it into the same target flow as Browse. The
        # source is auto-selected (VirusTotal first, then MalwareBazaar) from the hash and
        # which keys are configured; the controls are enabled once the download broker
        # starts (see _InitDownloadBroker). A section header rather than a nested group box:
        # a second etched rectangle inside the first is what made this read as a dialog.
        targetCard.body.Add(
            ui.SectionHeader(targetCard, "Download by hash"), 0, wx.EXPAND | wx.BOTTOM, gapS
        )

        hashRow = wx.BoxSizer(wx.HORIZONTAL)
        self.hashInputField = ui.Field(targetCard, hint="<md5, sha1, sha256>")
        self.hashInput = self.hashInputField.ctrl
        self.hashInput.SetToolTip("MD5/SHA1/SHA256 hex hash. MalwareBazaar requires SHA256.")
        self.downloadBtn = ui.Button(targetCard, label="Download", glyph=ui.DOWNLOAD)
        self.downloadBtn.Disable()
        self.downloadBtn.Bind(wx.EVT_BUTTON, self.OnDownloadSample)
        hashRow.Add(self.hashInputField, 1, wx.EXPAND | wx.RIGHT, gapS)
        hashRow.Add(self.downloadBtn, 0, wx.ALIGN_CENTER_VERTICAL)
        targetCard.body.Add(hashRow, 0, wx.EXPAND | wx.BOTTOM, gapS)

        # Where downloaded samples are saved; prefilled with the effective default
        # ([download] directory, else the user's Desktop) and editable per download.
        downloadPathRow = wx.BoxSizer(wx.HORIZONTAL)
        downloadPathRow.Add(
            wx.StaticText(targetCard, label="Path:"),
            0,
            wx.ALIGN_CENTER_VERTICAL | wx.RIGHT,
            gapS,
        )
        self.downloadPathField = ui.Field(targetCard, value=download_dir())
        self.downloadPathInput = self.downloadPathField.ctrl
        self.downloadPathInput.SetToolTip("Directory where downloaded samples are saved.")
        self.downloadPathInput.Disable()
        self.downloadDirBtn = ui.Button(targetCard, label="Browse...", glyph=ui.FOLDER)
        self.downloadDirBtn.Disable()
        self.downloadDirBtn.Bind(wx.EVT_BUTTON, self.OnBrowseDownloadDir)
        downloadPathRow.Add(self.downloadPathField, 1, wx.EXPAND | wx.RIGHT, gapS)
        downloadPathRow.Add(self.downloadDirBtn, 0, wx.ALIGN_CENTER_VERTICAL)
        targetCard.body.Add(downloadPathRow, 0, wx.EXPAND)

        # -- Package & options ----------------------------------------------
        packageCard = ui.Card(body, title="Package and options")

        packageRow = wx.BoxSizer(wx.HORIZONTAL)
        packageRow.Add(
            wx.StaticText(packageCard, label="Package"),
            0,
            wx.ALIGN_CENTER_VERTICAL | wx.RIGHT,
            gapS,
        )
        self.packageDropdown = ui.Picker(packageCard)
        self.packageDropdown.Bind(wx.EVT_COMBOBOX, self.OnPackageSelected)
        self.PackageDropdown()
        self.packageDropdown.SetValue("Auto-detect")
        self.runFromCurrentDirCheckbox = ui.Check(
            packageCard, label="Run sample from current directory"
        )
        self.runFromCurrentDirCheckbox.Bind(wx.EVT_CHECKBOX, self.OnCurrentDirCheckboxClick)
        self.runFromCurrentDirCheckbox.SetValue(True)
        self.manualExecutionCheckbox = ui.Check(packageCard, label="Manual Execution")
        self.manualExecutionCheckbox.Bind(wx.EVT_CHECKBOX, self.OnManualExecCheckboxClick)
        self.manualExecutionCheckbox.SetValue(False)
        packageRow.Add(self.packageDropdown, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, gapL)
        packageRow.Add(
            self.runFromCurrentDirCheckbox, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, gapL
        )
        packageRow.Add(self.manualExecutionCheckbox, 0, wx.ALIGN_CENTER_VERTICAL)
        packageCard.body.Add(packageRow, 0, wx.EXPAND | wx.BOTTOM, gapM)

        # Archive member selector: shown only for the archive/zip packages, lets the analyst
        # pick which file inside the archive to run (writes file=<name> into the Options box).
        # Hidden until RefreshArchiveFiles reveals it.
        self.hboxArchive = wx.BoxSizer(wx.HORIZONTAL)
        self.archiveFilesLabel = wx.StaticText(packageCard, label="Archive file:")
        self.archiveFilesDropdown = ui.Picker(packageCard)
        self.archiveFilesDropdown.Bind(wx.EVT_COMBOBOX, self.OnArchiveFileSelected)
        self.archiveFilesLabel.Hide()
        self.archiveFilesDropdown.Hide()
        self.hboxArchive.Add(
            self.archiveFilesLabel, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, gapS
        )
        self.hboxArchive.Add(self.archiveFilesDropdown, 1, wx.EXPAND)
        packageCard.body.Add(self.hboxArchive, 0, wx.EXPAND | wx.BOTTOM, gapM)

        optionsRow = wx.BoxSizer(wx.HORIZONTAL)
        optionsRow.Add(
            wx.StaticText(packageCard, label="Options"),
            0,
            wx.ALIGN_CENTER_VERTICAL | wx.RIGHT,
            gapS,
        )
        self.optionsField = ui.Field(
            packageCard,
            value="option1=value, option2=value, etc...",
            style=wx.TE_PROCESS_ENTER,
        )
        self.optionsCtrl = self.optionsField.ctrl
        self.optionsCtrl.Bind(wx.EVT_LEFT_DOWN, self.OnOptionInputClick)
        self.optionsCtrl.Bind(wx.EVT_KILL_FOCUS, self.OnOptionInputFocus)
        optionsRow.Add(self.optionsField, 1, wx.EXPAND)
        packageCard.body.Add(optionsRow, 0, wx.EXPAND | wx.BOTTOM, gapS)

        packageCard.body.Add(self.AddOptionsHelp(packageCard), 0, wx.EXPAND)

        # -- Monitor ---------------------------------------------------------
        monitorCard = ui.Card(body, title="Monitor")

        timeoutRow = wx.BoxSizer(wx.HORIZONTAL)
        self.enforceTimeoutCheckbox = ui.Check(monitorCard, label="Enforce timeout")
        self.enforceTimeoutCheckbox.Bind(wx.EVT_CHECKBOX, self.OnEnforceTimeoutCheckboxClick)
        self.enforceTimeoutCheckbox.SetValue(False)
        self.timeoutField = ui.Field(monitorCard, value="200")
        self.timeoutField.SetMinSize(dip_size(self, 80, -1))
        self.timeoutInput = self.timeoutField.ctrl
        timeoutRow.Add(
            self.enforceTimeoutCheckbox, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, gapM
        )
        timeoutRow.Add(self.timeoutField, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, gapS)
        timeoutRow.Add(
            wx.StaticText(monitorCard, label="seconds"), 0, wx.ALIGN_CENTER_VERTICAL
        )
        monitorCard.body.Add(timeoutRow, 0, wx.EXPAND | wx.BOTTOM, gapM)

        # Hooking mode. Note that minhook is a capemon option while free is handled
        # analyzer-side (lib/common/abstracts.py), despite sitting together here.
        hookingRow = wx.BoxSizer(wx.HORIZONTAL)
        hookingRow.Add(
            wx.StaticText(monitorCard, label="Hooking:"),
            0,
            wx.ALIGN_CENTER_VERTICAL | wx.RIGHT,
            gapS,
        )
        # capemon picks the hook set with a single else-if chain (hooks.c), so these are
        # mutually exclusive: minhook wins over zerohook, which wins over native, and
        # ticking two would silently ignore one. Radio buttons rather than checkboxes so
        # the UI cannot express a combination the monitor will not honour. "full" is
        # capemon's default and emits no option at all.
        self.hookSets = []
        for index, (label, option, tip) in enumerate(
            (
                ("full", "", "Full hook set (capemon default)"),
                ("minhook", "minhook", "Minimal hook set"),
                ("zerohook", "zerohook", "All hooks disabled except the essential ones"),
                ("native", "native", "Native hooks only (ntdll)"),
            )
        ):
            style = wx.RB_GROUP if index == 0 else 0
            radio = ui.Radio(monitorCard, label=label, style=style)
            radio.SetToolTip(tip)
            if index == 0:
                radio.SetValue(True)
            self.hookSets.append((radio, option))
            hookingRow.Add(radio, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, gapM)

        hookingRow.AddSpacer(gapL)
        self.free = ui.Check(monitorCard, label="free")
        self.free.SetToolTip(
            "Run without the monitor at all (handled by the analyzer, not capemon)"
        )
        self.free.Bind(wx.EVT_CHECKBOX, self.OnFreeChecked)
        hookingRow.Add(self.free, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, gapM)

        self.unhookOnExit = ui.Check(monitorCard, label="Unhook on exit")
        self.unhookOnExit.SetToolTip(
            "Restore hooked APIs (uninject the monitor) in surviving processes when the "
            "analysis ends, so the machine stays responsive."
        )
        self.unhookOnExit.SetValue(True)
        hookingRow.Add(self.unhookOnExit, 0, wx.ALIGN_CENTER_VERTICAL)
        monitorCard.body.Add(hookingRow, 0, wx.EXPAND | wx.BOTTOM, gapM)

        monitorCard.body.Add(
            ui.SectionHeader(monitorCard, "Logging"), 0, wx.EXPAND | wx.BOTTOM, gapS
        )

        # capemon reads log-exceptions and force-flush with atoi() and tests them against
        # more than one threshold, so both take a level rather than just on/off. The rest
        # are read as value[0] == '1' and are strictly boolean. See capemon config.c.
        # log-bps is an alias of log-breakpoints, so only one of the pair is offered.
        self.logExceptions = ui.Check(monitorCard, label="log-exceptions")
        self.logExceptions.SetToolTip("Exception logging")
        self.logExceptionsLevel = self._LevelChoice(
            monitorCard,
            ["1 - error codes only", "2 - all exceptions"],
            "1: only codes >= 0x80000000\n"
            "2: every exception, plus extra detail on access violations",
        )
        self.logVexcept = ui.Check(monitorCard, label="log-vexcept")
        self.logVexcept.SetToolTip("Vectored Exception logging")
        self.logBreakpoints = ui.Check(monitorCard, label="log-breakpoints")
        self.logBreakpoints.SetToolTip("Breakpoint logging to behavior log")
        self.fullLogs = ui.Check(monitorCard, label="full-logs")
        self.fullLogs.SetToolTip("Disable log suppression before network/file access")
        self.forceFlush = ui.Check(monitorCard, label="force-flush")
        self.forceFlush.SetToolTip("Flush buffered logs instead of relying on batching")
        self.forceFlushLevel = self._LevelChoice(
            monitorCard,
            ["1 - after each new API", "2 - after every log"],
            "1: flush after any non-duplicate API call\n2: flush after every log entry",
        )
        self.traceTimes = ui.Check(monitorCard, label="trace-times")
        self.traceTimes.SetToolTip("Trace timing")

        # (checkbox, option name, level selector or None) drives emission.
        self.loggingOptions = (
            (self.logExceptions, "log-exceptions", self.logExceptionsLevel),
            (self.logVexcept, "log-vexcept", None),
            (self.logBreakpoints, "log-breakpoints", None),
            (self.fullLogs, "full-logs", None),
            (self.forceFlush, "force-flush", self.forceFlushLevel),
            (self.traceTimes, "trace-times", None),
        )

        toggleRow = wx.BoxSizer(wx.HORIZONTAL)
        for box in (self.logVexcept, self.logBreakpoints, self.fullLogs, self.traceTimes):
            toggleRow.Add(box, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, gapL)
        monitorCard.body.Add(toggleRow, 0, wx.EXPAND | wx.BOTTOM, gapS)

        # The two that carry a level, each kept next to its dropdown in a pair sizer so the
        # two can never be separated.
        levelRow = wx.BoxSizer(wx.HORIZONTAL)
        for box, level in (
            (self.logExceptions, self.logExceptionsLevel),
            (self.forceFlush, self.forceFlushLevel),
        ):
            box.Bind(wx.EVT_CHECKBOX, self.OnLoggingLevelToggle)
            pair = wx.BoxSizer(wx.HORIZONTAL)
            pair.Add(box, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, gapS)
            pair.Add(level, 0, wx.ALIGN_CENTER_VERTICAL)
            levelRow.Add(pair, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, dip(self, SP_XL))
        monitorCard.body.Add(levelRow, 0, wx.EXPAND)

        # -- Debugger and analysis.conf ---------------------------------------
        # Both live in one card: they are the same kind of thing (an expandable editor), and
        # a card each spent a card's worth of padding on a single header row.
        advancedCard = ui.Card(body)
        self.debuggerCollapsePane = ui.Collapsible(advancedCard, label="Debugger options")
        self.debuggerCollapsePane.Bind(
            wx.EVT_COLLAPSIBLEPANE_CHANGED, self.OnCollapsiblePaneChanged
        )
        self.debuggerPane = self.debuggerCollapsePane.GetPane()

        self.flexDebuggerSizer = wx.FlexGridSizer(rows=8, cols=3, hgap=gapM, vgap=gapS)
        self.flexDebuggerSizer.AddGrowableCol(1, 1)

        for i in range(4):
            self.debuggerControls[i] = self.AddDebuggerControls(i)

        hboxBaseApi = wx.BoxSizer(wx.HORIZONTAL)
        hboxBaseApi.Add(
            wx.StaticText(self.debuggerPane, label="base-on-api:"),
            0,
            wx.ALIGN_CENTER_VERTICAL | wx.RIGHT,
            gapS,
        )
        self.baseApiField = ui.Field(self.debuggerPane)
        self.baseApiField.SetMinSize(dip_size(self, 120, -1))
        self.baseApi = self.baseApiField.ctrl
        hboxBaseApi.Add(self.baseApiField, 0, wx.ALIGN_CENTER_VERTICAL)

        hboxBreakRet = wx.BoxSizer(wx.HORIZONTAL)
        hboxBreakRet.Add(
            wx.StaticText(self.debuggerPane, label="break-on-return:"),
            0,
            wx.ALIGN_CENTER_VERTICAL | wx.RIGHT,
            gapS,
        )
        self.apiListField = ui.Field(self.debuggerPane)
        self.apiListField.SetMinSize(dip_size(self, 180, -1))
        self.apiList = self.apiListField.ctrl
        hboxBreakRet.Add(self.apiListField, 0, wx.ALIGN_CENTER_VERTICAL)

        self.baseAllocCheckbox = ui.Check(self.debuggerPane, label="base-on-alloc")

        hboxCount = wx.BoxSizer(wx.HORIZONTAL)
        hboxCount.Add(
            wx.StaticText(self.debuggerPane, label="count:"),
            0,
            wx.ALIGN_CENTER_VERTICAL | wx.RIGHT,
            gapS,
        )
        self.debugCountField = ui.Field(self.debuggerPane)
        self.debugCountField.SetMinSize(dip_size(self, 90, -1))
        self.debugCount = self.debugCountField.ctrl
        hboxCount.Add(self.debugCountField, 0, wx.ALIGN_CENTER_VERTICAL)

        hboxDepth = wx.BoxSizer(wx.HORIZONTAL)
        hboxDepth.Add(
            wx.StaticText(self.debuggerPane, label="depth:"),
            0,
            wx.ALIGN_CENTER_VERTICAL | wx.RIGHT,
            gapS,
        )
        self.debugDepthField = ui.Field(self.debuggerPane)
        self.debugDepthField.SetMinSize(dip_size(self, 60, -1))
        self.debugDepth = self.debugDepthField.ctrl
        hboxDepth.Add(self.debugDepthField, 0, wx.ALIGN_CENTER_VERTICAL)

        hCountDepth = wx.BoxSizer(wx.HORIZONTAL)
        hCountDepth.Add(hboxCount, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, gapM)
        hCountDepth.Add(hboxDepth, 0, wx.ALIGN_CENTER_VERTICAL)

        self.idbgCheckbox = ui.Check(self.debuggerPane, label="Interactive Debugger")
        self.idbgCheckbox.Bind(wx.EVT_CHECKBOX, self.OnIdbgChecked)

        self.yarascanDisable = ui.Check(self.debuggerPane, label="Disable Monitor Yarascan")

        self.flexDebuggerSizer.AddSpacer(1)
        self.flexDebuggerSizer.AddSpacer(1)
        self.flexDebuggerSizer.AddSpacer(1)
        self.flexDebuggerSizer.Add(hboxBaseApi, 0, wx.ALIGN_CENTER_VERTICAL)
        self.flexDebuggerSizer.Add(hboxBreakRet, 0, wx.ALIGN_CENTER_VERTICAL)
        self.flexDebuggerSizer.Add(hCountDepth, 0, wx.ALIGN_CENTER_VERTICAL)
        self.flexDebuggerSizer.Add(self.baseAllocCheckbox, 0, wx.ALIGN_CENTER_VERTICAL)
        self.flexDebuggerSizer.Add(self.yarascanDisable, 0, wx.ALIGN_CENTER_VERTICAL)
        self.flexDebuggerSizer.Add(self.idbgCheckbox, 0, wx.ALIGN_CENTER_VERTICAL)

        debuggerVert = wx.BoxSizer(wx.VERTICAL)
        debuggerVert.Add(self.flexDebuggerSizer, 0, wx.BOTTOM, gapM)

        yaraCollapsiblePane = ui.Collapsible(self.debuggerPane, label="Monitor Yara")
        yaraCollapsiblePane.Bind(
            wx.EVT_COLLAPSIBLEPANE_CHANGED, self.OnCollapsiblePaneChanged
        )
        yaraPane = yaraCollapsiblePane.GetPane()

        self.yaraRuleField = ui.Field(
            yaraPane, multiline=True, style=wx.HSCROLL | wx.VSCROLL
        )
        self.yaraRuleField.SetMinSize(dip_size(self, -1, 200))
        self.yaraRule = self.yaraRuleField.ctrl
        self.yaraRule.SetFont(FONT_CODE)
        self.YaraLoad()
        yaraSaveBtn = ui.Button(yaraPane, label="Save Rule")
        yaraSaveBtn.Bind(wx.EVT_BUTTON, self.OnYaraSave)
        yaraDeleteBtn = ui.Button(yaraPane, label="Delete Rule", variant=ui.DANGEROUS)
        yaraDeleteBtn.Bind(wx.EVT_BUTTON, self.OnYaraDelete)

        hboxYara = wx.BoxSizer(wx.HORIZONTAL)
        hboxYara.Add(yaraSaveBtn, 0, wx.RIGHT, gapS)
        hboxYara.Add(yaraDeleteBtn, 0)

        vboxYara = wx.BoxSizer(wx.VERTICAL)
        vboxYara.Add(self.yaraRuleField, 1, wx.EXPAND | wx.BOTTOM, gapS)
        vboxYara.Add(hboxYara, 0, wx.ALIGN_RIGHT)
        yaraPane.SetSizer(vboxYara)

        debuggerVert.Add(yaraCollapsiblePane, 0, wx.EXPAND)
        self.debuggerPane.SetSizer(debuggerVert)
        advancedCard.body.Add(self.debuggerCollapsePane, 0, wx.EXPAND | wx.BOTTOM, gapS)

        self.analysisConfExpander = ui.Collapsible(advancedCard, label="analysis.conf")
        self.analysisConfExpander.Bind(
            wx.EVT_COLLAPSIBLEPANE_CHANGED, self.OnCollapsiblePaneChanged
        )
        analysisConfPane = self.analysisConfExpander.GetPane()
        self.analysisEditor = AnalysisConfPanel(analysisConfPane)
        analysisConfPaneSizer = wx.BoxSizer(wx.VERTICAL)
        analysisConfPaneSizer.Add(self.analysisEditor, 1, wx.EXPAND)
        analysisConfPane.SetSizer(analysisConfPaneSizer)
        advancedCard.body.Add(self.analysisConfExpander, 1, wx.EXPAND)

        # -- scrolling content -----------------------------------------------
        for card in (targetCard, packageCard, monitorCard):
            vbox.Add(card, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP, gapS)
        vbox.Add(advancedCard, 1, wx.EXPAND | wx.ALL, gapS)

        self.scroll.SetSizer(vbox)
        # Vertical-only scrolling so the config sections stay reachable when the panel is
        # shorter than its content. SetupScrolling initialises the ScrolledPanel (scroll rate,
        # child-focus scroll), but its FitInside() sets the virtual size from the sizer's min
        # in BOTH axes - that pinned the virtual width to an oversized min (breaking the
        # horizontal fit GrowFrameToFitContent relies on) and left the virtual height below the
        # client height (an unpainted band that ghosted the bottom-row checkboxes). OnPanelSize
        # corrects the virtual size on every resize.
        self.scroll.SetupScrolling(scroll_x=False, scroll_y=True)
        self.scroll.Bind(wx.EVT_SIZE, self.OnPanelSize)

        # -- action bar, pinned outside the scroll area -----------------------
        self.launchAnalyzerBtn = ui.Button(
            self, label="Launch", variant=ui.SUCCESSFUL, glyph=ui.PLAY
        )
        self.launchAnalyzerBtn.Disable()
        self.launchAnalyzerBtn.Bind(wx.EVT_BUTTON, self.OnLaunchAnalyzer)

        self.staticAnalysis = ui.Check(self, label="Static analysis")
        self.staticAnalysis.SetToolTip("Check this box to enable static code analysis.")

        self.autoProcess = ui.Check(self, label="Auto-process")
        self.autoProcess.SetToolTip(
            "Automatically process and populate the result tabs when a run completes."
        )
        self.autoProcess.SetValue(True)

        self.jsonReportBtn = ui.Button(self, label="JSON Report", glyph=ui.DOCUMENT)
        self.jsonReportBtn.Disable()
        self.jsonReportBtn.Bind(wx.EVT_BUTTON, self.JsonReport)

        self.htmlReportBtn = ui.Button(self, label="HTML Report", glyph=ui.DOCUMENT)
        self.htmlReportBtn.Disable()
        self.htmlReportBtn.Bind(wx.EVT_BUTTON, self.HtmlReport)

        updateYaraBtn = ui.Button(self, label="Update Yara", glyph=ui.REFRESH)
        updateYaraBtn.Bind(wx.EVT_BUTTON, self.OnUpdateYara)

        self.zipResultsBtn = ui.Button(self, label="Zip Results", glyph=ui.ARCHIVE)
        self.zipResultsBtn.SetToolTip(
            "Zip the analysis directory to the Desktop, to restore in a clean VM."
        )
        self.zipResultsBtn.Bind(wx.EVT_BUTTON, self.OnZipResults)

        openDirBtn = ui.Button(self, label="View Analysis Directory", glyph=ui.FOLDER)
        openDirBtn.Bind(wx.EVT_BUTTON, self.OnOpenDirectory)

        self.terminateAnalyzerBtn = ui.Button(
            self, label="Kill", variant=ui.DANGEROUS, glyph=ui.STOP
        )
        self.terminateAnalyzerBtn.Disable()
        self.terminateAnalyzerBtn.Bind(wx.EVT_BUTTON, self.OnTerminateAnalyzer)

        actions = wx.BoxSizer(wx.HORIZONTAL)
        actions.Add(self.launchAnalyzerBtn, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, gapL)
        actions.Add(self.staticAnalysis, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, gapM)
        actions.Add(self.autoProcess, 0, wx.ALIGN_CENTER_VERTICAL)
        actions.AddStretchSpacer(1)
        for button in (
            self.jsonReportBtn,
            self.htmlReportBtn,
            updateYaraBtn,
            self.zipResultsBtn,
            openDirBtn,
        ):
            actions.Add(button, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, gapS)
        actions.Add(self.terminateAnalyzerBtn, 0, wx.ALIGN_CENTER_VERTICAL)

        outer.Add(self.scroll, 1, wx.EXPAND)
        outer.Add(
            wx.StaticLine(self, style=wx.LI_HORIZONTAL), 0, wx.EXPAND | wx.TOP, gapS
        )
        outer.Add(actions, 0, wx.EXPAND | wx.ALL, gapM)
        self.SetSizer(outer)
        self.SetBackgroundColour(BG_MAIN)

        apply_theme(self)
        # apply_theme treats every wx.Panel as a card surface; these two are page background.
        self.SetBackgroundColour(BG_MAIN)
        self.scroll.SetBackgroundColour(BG_MAIN)

    def AddOptionsHelp(self, parent):
        help = [
            ("serial", "system volume serial number"),
            ("force-sleepskip", "do we force sleep-skipping despite threads?"),
            ("api-rate-cap", "Disable api hooks based on excessive rate"),
            ("api-cap", "Disable api hooks based on excessive count"),
            ("lang", "Language override"),
            ("ntdll-protect", "ntdll write protection"),
            ("ntdll-remap", "ntdll remap protection"),
            ("log-vexcept", "vectored exception handler hook"),
            ("unpacker", "behavioural payload extraction options"),
            ("single-process", "prevent monitoring child processes"),
            ("log-breakpoints", "breakpoint logging to behavior log"),
            ("branch-trace", "branch tracing"),
            ("plugx", "for PlugX config & payload extraction"),
            ("fake-rdtsc", "Fake RDTSC"),
            ("nop-rdtscp", "NOP RDTSCP"),
            ("msi", "MSI hook set"),
            ("loaderlock-scans", "Allow scans/dumps with loader lock held"),
            (
                "exclude-apis",
                "Colon separated list of API functions to exclude from hooking",
            ),
            (
                "exclude-dlls",
                "Colon separated list of DLL names to exclude from hooking",
            ),
            ("dump-on-api", ""),
            ("coverage-modules", ""),
            ("dump-on-api-type", ""),
            ("break-on-apiname", ""),
            ("break-on-mod", ""),
            (
                "typestring, typestring0, typestring1, typestring2, typestring3",
                "Type strings",
            ),
            ("str", "search string"),
            ("loopskip", ""),
            ("trace-all", ""),
            ("step-out", ""),
            ("file-offsets", ""),
            ("no-logs", ""),
            ("disable-logging", ""),
            ("base-on-alloc", ""),
            ("base-on-caller", ""),
            ("trace-times", ""),
            ("trace-into-api", ""),
        ]

        hbox = wx.BoxSizer(wx.HORIZONTAL)
        self.helpList = ui.Picker(parent)
        self.helpList.SetToolTip("Select an option, then right-click to add it to the Options field.")
        self.helpList.Bind(wx.EVT_CONTEXT_MENU, self.OnOptionsHelpContext)
        helpOptions = sorted(help, key=lambda x: x[0])
        formattedHelp = [f"{name} - {comment}" if comment else name for name, comment in helpOptions]
        self.helpList.Append("Options Help")
        self.helpList.AppendItems(formattedHelp)
        self.helpList.SetSelection(0)
        hbox.Add(self.helpList, proportion=1, flag=wx.EXPAND)

        return hbox

    def OnOptionsHelpContext(self, event):
        # Index 0 is the "Options Help" placeholder, not a real option.
        if self.helpList.GetSelection() <= 0:
            return
        menu = wx.Menu()
        item = menu.Append(wx.ID_ANY, "Add to options")
        self.Bind(wx.EVT_MENU, self.OnAddHelpOption, item)
        self.PopupMenu(menu)
        menu.Destroy()

    def OnAddHelpOption(self, event):
        # Entries are "name - comment" or just "name"; some list several names comma-separated
        # (e.g. "typestring, typestring0, ...") - take the first. SetOption writes "name=" ready
        # for the analyst to type a value; a bare key with no "=" is dropped by get_options.
        selection = self.helpList.GetStringSelection()
        name = selection.split(" - ", 1)[0].split(",", 1)[0].strip()
        if name:
            self.SetOption(name, "")

    def AddDebuggerControls(self, index):
        hboxBp = wx.BoxSizer(wx.HORIZONTAL)
        bpTypes = [f"bp{index}", f"br{index}"]
        bpType = ui.Picker(self.debuggerPane, choices=bpTypes, value=bpTypes[0])
        addrTypeDropdown = ui.Picker(self.debuggerPane, choices=["RVA", "VA", "ep"], value="RVA")
        hexLabel = wx.StaticText(self.debuggerPane, label=": 0x")
        addrField = ui.Field(self.debuggerPane)
        addrField.SetMinSize(dip_size(self, 90, -1))
        addrTextCtrl = addrField.ctrl
        hboxBp.Add(bpType, proportion=0, flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, border=dip(self, SP_XS))
        hboxBp.Add(
            addrTypeDropdown,
            proportion=0,
            flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT,
            border=0,
        )
        hboxBp.Add(hexLabel, proportion=0, flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, border=0)
        hboxBp.Add(addrField, proportion=0, flag=wx.ALIGN_CENTER_VERTICAL)

        hboxAction = wx.BoxSizer(wx.HORIZONTAL)
        actionLabel = wx.StaticText(self.debuggerPane, label=f"action{index}:")
        actionDropdown = ui.Picker(self.debuggerPane, choices=[""])
        actionDropdown.AppendItems(DEBUGACTIONS)
        colon = wx.StaticText(self.debuggerPane, label=":")
        valueField = ui.Field(self.debuggerPane)
        valueField.SetMinSize(dip_size(self, 120, -1))
        valueTextCtrl = valueField.ctrl
        hboxAction.Add(
            actionLabel,
            proportion=0,
            flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT,
            border=dip(self, SP_XS),
        )
        hboxAction.Add(actionDropdown, proportion=0, flag=wx.RIGHT, border=dip(self, SP_XS))
        hboxAction.Add(colon, proportion=0, flag=wx.RIGHT, border=dip(self, 2))
        hboxAction.Add(valueField, proportion=0, flag=wx.ALIGN_CENTER_VERTICAL)

        hboxCount = wx.BoxSizer(wx.HORIZONTAL)
        countLabel = wx.StaticText(self.debuggerPane, label=f"count{index}: ")
        countField = ui.Field(self.debuggerPane)
        countField.SetMinSize(dip_size(self, 90, -1))
        countTextCtrl = countField.ctrl
        hboxCount.Add(countLabel, proportion=0, flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, border=0)
        hboxCount.Add(countField, proportion=0, flag=wx.ALIGN_CENTER_VERTICAL)
        hboxCount.AddSpacer(20)
        hcLabel = wx.StaticText(self.debuggerPane, label=f"hc{index}: ")
        hcField = ui.Field(self.debuggerPane)
        hcField.SetMinSize(dip_size(self, 60, -1))
        hcTextCtrl = hcField.ctrl
        hboxCount.Add(hcLabel, proportion=0, flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, border=0)
        hboxCount.Add(hcField, proportion=0, flag=wx.ALIGN_CENTER_VERTICAL)

        self.flexDebuggerSizer.Add(hboxBp, 0, wx.EXPAND)
        self.flexDebuggerSizer.Add(hboxAction, 0, wx.EXPAND)
        self.flexDebuggerSizer.Add(hboxCount, 0, wx.EXPAND)

        return (
            bpType,
            addrTypeDropdown,
            addrTextCtrl,
            actionDropdown,
            valueTextCtrl,
            countTextCtrl,
            hcTextCtrl,
        )

    def OnCollapsiblePaneChanged(self, event):
        scroll = getattr(self, "scroll", None)
        if scroll:
            scroll.Layout()
        self.Layout()
        self.GrowFrameToFitContent()
        # Content height changed, so recompute the scroll range. Guarded because this handler
        # can fire before the scroll area has its sizer.
        if scroll is not None and scroll.GetSizer() is not None:
            self._UpdateVirtualSize()
            scroll.Layout()
            self.Layout()
            self.Refresh()
        if event:
            event.Skip()

    def OnPanelSize(self, event):
        self._UpdateVirtualSize()
        event.Skip()

    def _UpdateVirtualSize(self):
        # Vertical-only scroll: pin the virtual width to the client width so children fill the
        # visible width (EXPAND) and horizontal growth stays with the frame (no horizontal
        # scrollbar). Keep the virtual height at least the client height so there is never an
        # unpainted band below the content - that band ghosted the bottom-row checkboxes.
        scroll = getattr(self, "scroll", None)
        sizer = scroll.GetSizer() if scroll else None
        if sizer is None:
            return
        client = scroll.GetClientSize()
        minHeight = sizer.GetMinSize().height
        target = wx.Size(client.width, max(minHeight, client.height))
        # Only set when it actually changes: toggling a vertical scrollbar changes the client
        # width and re-fires EVT_SIZE, so an unconditional set could churn.
        if scroll.GetVirtualSize() != target:
            scroll.SetVirtualSize(target)

    def GrowFrameToFitContent(self):
        """Widen the frame when an expanded pane needs more room than the window has.

        A wx.CollapsiblePane clips rather than pushing its frame wider, so expanding
        "Debugger options" left the rightmost controls cut off at the default width: the
        debugger grid needs the panel's full client width, but the pane sits inside a
        10px left/right border and so gets 20px less.

        Only ever grows, and never past the display, so it cannot fight a user who has
        deliberately sized or maximised the window.
        """
        # InitUi calls the handler for the analysis.conf pane before the debugger pane is
        # built, so this can run before the attribute exists.
        pane = getattr(self, "debuggerCollapsePane", None)
        if pane is None or not pane.IsExpanded():
            return

        frame = self.GetMainFrame()
        if not frame or frame.IsMaximized():
            return

        # Measure the debugger grid against the pane that holds it. The panel's own
        # GetBestSize is no use here: the analysis.conf editor is built with
        # size=self.GetSize(), so the panel always reports a best width far larger than
        # anything is actually asking for.
        deficit = self.flexDebuggerSizer.CalcMin().x - self.debuggerPane.GetClientSize().x
        if deficit <= 0:
            return

        screenWidth, _ = wx.DisplaySize()
        width = min(frame.GetSize().x + deficit, screenWidth)
        if width > frame.GetSize().x:
            frame.SetSize(wx.Size(width, frame.GetSize().y))
            frame.Layout()

    def OnCurrentDirCheckboxClick(self, event):
        self.curDir = self.runFromCurrentDirCheckbox.GetValue()

    def OnManualExecCheckboxClick(self, event):
        self.manualExecution = self.manualExecutionCheckbox.GetValue()
        self.curDir = True

    def OnEnforceTimeoutCheckboxClick(self, event):
        self.enforceTimeout = self.enforceTimeoutCheckbox.GetValue()

    def OnAnalyzerComplete(self, event):
        from CAPEsolo.analyzer import (
            INJECT_LIST,
            Files,
            disconnect_logger,
            disconnect_pipes,
            traceback,
            upload_files,
        )

        if self.dbgConsole:
            self.log("Shutting down debug console.")
            self.dbgConsole.shutdown()

        files = Files()
        files.dump_files()

        # Independently guarded, and logged where the analyst will see it. These two calls sat
        # outside the try below, and upload_files only catches IOError and socket.error - so
        # anything else raised while uploading the debugger logs skipped the tlsdump upload
        # entirely. Being a wx event handler, the traceback went to stderr rather than the
        # analysis log, so an artifact could go missing with nothing recorded anywhere.
        folders = ("debugger", "tlsdump")
        pending = self.PendingUploads(folders)
        for folder in folders:
            try:
                upload_files(folder)
            except Exception:
                self.log(f"Failed to upload {folder} files:\n{traceback.format_exc()}")

        self.WaitForUploads(pending)
        self.GetMainFrame().statusBar.Finish("Analysis complete")
        self.GetMainFrame().extendTimeoutBtn.Disable()
        self.log("Shutting down")
        try:
            if hasattr(self.analyzer, "command_pipe"):
                self.analyzer.command_pipe.stop()
            else:
                self.log("Analyzer object has no attribute 'command_pipe'")

            self.analyzer.log_pipe_server.stop()
            disconnect_pipes()
            disconnect_logger()
            for pid in INJECT_LIST:
                self.log(f"Monitor injection attempted but failed for process {pid}")

            self.log("Run completed")
            self.resultserver.shutdown_server()
            self.jsonReportBtn.Enable()
            self.htmlReportBtn.Enable()
        except Exception:
            self.log(traceback.format_exc())

        if self.autoProcess.GetValue():
            self.AutoProcessTabs()
        return True

    def AutoProcessTabs(self):
        """Populate the result tabs in dependency order after a run so the user need not
        open each tab and click its process button. Only called when Auto-process is
        checked; the handlers it calls each disable their own button and set a completion
        flag, so those buttons stay disabled once processed. When Auto-process is unchecked
        this is skipped and the buttons enable as before for manual processing.
        """
        mainFrame = self.GetMainFrame()
        statusBar = mainFrame.statusBar
        with wx.BusyCursor():
            self._AutoStep(statusBar, "info", mainFrame.infoTab.LoadAndDisplayContent)

            logsDir = Path(self.analysisDir) / "logs"
            if logsDir.exists() and any(logsDir.iterdir()) and not mainFrame.behaviorTab.behaviorComplete:
                self._AutoStep(statusBar, "behavior", lambda: mainFrame.behaviorTab.GenerateBehavior(None))

            # Before payloads so reconstructed files dropped from the JS network log are picked up by
            # PayloadsReady and the yara scan below in the same run.
            if not mainFrame.jsConsoleTab.jsLogComplete and path_exists(str(GetJsLogPath(self.analysisDir))):
                self._AutoStep(statusBar, "js log", mainFrame.jsConsoleTab.ProcessJsLog)

            self._AutoStep(statusBar, "payloads", mainFrame.payloadsTab.PayloadsReady)

            if self.targetFile and not mainFrame.yaraTab.yaraComplete:
                self._AutoStep(statusBar, "yara", lambda: mainFrame.yaraTab.ProcessYara(None))

            if self.parent.configHits:
                self._AutoStep(statusBar, "configs", lambda: mainFrame.configsTab.ExtractConfigs(None))

            if self.parent.results and not mainFrame.signaturesTab.signaturesComplete:
                self._AutoStep(statusBar, "signatures", lambda: mainFrame.signaturesTab.GenerateSignatures(None))
        statusBar.SetMessage("Analysis complete - tabs processed")

    def _AutoStep(self, statusBar, label, fn):
        statusBar.SetMessage(f"Processing {label}...")
        try:
            fn()
        except Exception:
            log.exception("Auto-process: failed to process %s", label)

    def PendingUploads(self, folders):
        """Destination paths the end-of-run uploads are expected to produce."""
        from CAPEsolo.analyzer import PATHS

        pending = []
        for folder in folders:
            source = Path(PATHS["root"], folder)
            if not source.is_dir():
                continue

            for path in sorted(source.iterdir()):
                if path.is_file():
                    pending.append(Path(self.analysisDir, folder, path.name))

        return pending

    def WaitForUploads(self, pending, timeout=UPLOAD_WAIT_SECONDS):
        """Wait for the end-of-run uploads to land before the result server is stopped.

        upload_to_host returns once the bytes are in the socket buffer, not when the result
        server has written them to disk. Shutting the server down straight afterwards closed
        the listener while an upload was still waiting to be accepted, and anything not yet
        accepted is dropped - the analysis log showed tlsdump.log handed over, then a
        connection closed "unnegotiated" and the file never written.

        Both ends are the same machine here, so the files themselves are the acknowledgement
        the protocol does not provide. Sleeping also hands the CPU to the server's thread,
        which is what lets it accept the connection at all: this handler otherwise runs from
        upload straight into shutdown without ever yielding.
        """
        if not pending:
            return

        deadline = time.monotonic() + timeout
        missing = [path for path in pending if not path.is_file()]
        while missing and time.monotonic() < deadline:
            time.sleep(0.1)
            missing = [path for path in missing if not path.is_file()]

        if missing:
            self.log(
                f"Uploads did not arrive within {timeout}s: "
                + ", ".join(str(path) for path in missing)
            )
        else:
            self.log(f"All {len(pending)} end-of-run upload(s) arrived")

    def MoveFiles(self, folder):
        logFolder = f"{self.analyzer.PATHS['root']}\\{folder}"
        try:
            if os.path.exists(logFolder):
                self.log(f"Uploading files at path {logFolder}")
            else:
                self.log(f"Folder at path {logFolder} does not exist, skipping")
                return
        except OSError as e:
            self.log(f"Unable to access folder at path {logFolder}: {e}")
            return

        for root, dirs, files in os.walk(logFolder):
            for file in files:
                filePath = os.path.join(root, file)
                analysisPath = os.path.join(folder, file)
                try:
                    # move files to analysis_path
                    shutil.move(filePath, analysisPath)
                except Exception as e:
                    self.log(f"Unable to copy file at path {filePath}: {e}")
        return

    def LoadAnalysisConfFile(self):
        # The default file is the schema: its keys become the controls and its ";" comments
        # become their tooltips, so it stays the one place a key is described.
        self.analysisEditor.Load(os.path.join(self.capesoloRoot, "analysis_conf.default"))

    def OnOptionInputClick(self, event):
        if self.optionsCtrl.GetValue() == "option1=value, option2=value, etc...":
            self.optionsCtrl.SetValue("")
        event.Skip()

    def OnOptionInputFocus(self, event):
        if self.optionsCtrl.GetValue() == "":
            self.optionsCtrl.SetValue("option1=value, option2=value, etc...")
        event.Skip()

    def IdentifyPackage(self):
        package = ""
        f = SflockFile.from_path(str(self.target).encode("utf-8"))
        try:
            tmpPackage = sflock_identify(f, check_shellcode=True)
        except Exception as e:
            log.error(f"Failed to sflock_ident due to {e}")
            tmpPackage = ""

        if tmpPackage and tmpPackage in SANDBOXPACKAGES:
            if tmpPackage in ("iso", "udf", "vhd"):
                package = "archive"
            else:
                package = tmpPackage

        return package

    def PackageDropdown(self):
        directory = "modules\\packages"
        try:
            self.packageDropdown.Append("Auto-detect")
            for name in os.listdir(directory):
                if "init" not in name:
                    self.packageDropdown.Append(name.split(".")[0])
        except OSError as e:
            wx.LogError(f"Error accessing directory '{directory}': {e}")

    def OnTargetSelection(self):
        selection = self.targetPath.GetValue()
        self.target = Path(selection)

        if self.target.exists() and self.target.is_file():
            self.launchAnalyzerBtn.Enable()
        else:
            self.launchAnalyzerBtn.Disable()
            ui.message(
                f"The file {self.target} does not exist.",
                "Error",
                wx.OK | wx.ICON_ERROR,
            )
        # A new target may need a fresh member list when archive/zip is already selected.
        self.RefreshArchiveFiles()

    def OnPackageSelected(self, event):
        self.RefreshArchiveFiles()
        event.Skip()

    def FindSevenZip(self):
        """Locate 7z.exe for listing non-zip archive types, matching where the
        archive/zip packages expect it (ProgramFiles\\7-Zip). None if unavailable."""
        candidates = []
        for env in ("ProgramFiles", "ProgramFiles(x86)"):
            base = os.environ.get(env)
            if base:
                candidates.append(os.path.join(base, "7-Zip", "7z.exe"))
        candidates.append(shutil.which("7z"))
        candidates.append(shutil.which("7z.exe"))
        for path in candidates:
            if path and os.path.isfile(path):
                return path
        return None

    def ListArchiveMembers(self, path):
        """Return the member paths of the archive at *path*, or [] if it cannot be read.

        Pure-Python zipfile first (zip/msix/jar/apk); falls back to 7z.exe for the broader
        archive types (7z/iso/vhd/rar/...) the archive package supports.
        """
        with wx.BusyCursor():
            try:
                return get_zip_file_names(path)
            except Exception:
                pass
            seven = self.FindSevenZip()
            if seven:
                try:
                    return get_file_names(seven, path)
                except Exception:
                    log.exception("Failed to list archive members with 7-Zip: %s", path)
        return []

    def RefreshArchiveFiles(self):
        """Show and populate the archive member selector for archive/zip packages only."""
        package = self.packageDropdown.GetValue()
        target = self.targetPath.GetValue()
        show = package in ("archive", "zip") and os.path.isfile(target)
        if show:
            self.PopulateArchiveFiles(target)
        else:
            self.archiveFilesDropdown.Clear()
            self.archiveFilesLabel.Hide()
            self.archiveFilesDropdown.Hide()
        self.Layout()
        self._UpdateVirtualSize()

    def PopulateArchiveFiles(self, path):
        members = [
            name
            for name in self.ListArchiveMembers(path)
            if name and not name.endswith("/")
        ]
        # Executables first so the likely target is easy to spot; keep the rest after.
        interesting = get_interesting_files(members)
        ordered = interesting + [name for name in members if name not in interesting]

        self.archiveFilesDropdown.Clear()
        if ordered:
            self.archiveFilesDropdown.Append("<Select file to run>")
            self.archiveFilesDropdown.AppendItems(ordered)
        else:
            self.archiveFilesDropdown.Append("<no files found / 7-Zip not available>")
            self.GetMainFrame().statusBar.SetMessage(
                "Could not list archive contents (unsupported type or 7-Zip not installed)."
            )
        self.archiveFilesDropdown.SetSelection(0)
        self.archiveFilesLabel.Show()
        self.archiveFilesDropdown.Show()

    def OnArchiveFileSelected(self, event):
        if self.archiveFilesDropdown.GetSelection() <= 0:
            event.Skip()
            return
        member = self.archiveFilesDropdown.GetStringSelection()
        # The options string is comma-delimited (split by Config.get_options), so a comma in
        # the member name would corrupt parsing - refuse it rather than write a broken option.
        if "," in member:
            self.GetMainFrame().statusBar.SetMessage(
                "Cannot set file option: archive member name contains a comma."
            )
            event.Skip()
            return
        self.SetOption("file", member)
        event.Skip()

    def SetOption(self, key, value):
        """Upsert key=value into the free-text Options box, preserving any other options."""
        text = self.optionsCtrl.GetValue().strip()
        if text == "option1=value, option2=value, etc...":
            text = ""
        pairs = []
        replaced = False
        for field in (f.strip() for f in text.split(",")):
            if not field:
                continue
            if "=" in field and field.split("=", 1)[0].strip() == key:
                pairs.append(f"{key}={value}")
                replaced = True
            else:
                pairs.append(field)
        if not replaced:
            pairs.append(f"{key}={value}")
        self.optionsCtrl.SetValue(", ".join(pairs))

    def OnBrowseDownloadDir(self, event):
        current = self.downloadPathInput.GetValue().strip()
        defaultPath = current if os.path.isdir(current) else ""
        with wx.DirDialog(
            self, "Choose download directory", defaultPath=defaultPath, style=wx.DD_DEFAULT_STYLE
        ) as dlg:
            if dlg.ShowModal() == wx.ID_OK:
                self.downloadPathInput.SetValue(dlg.GetPath())

    def OnBrowse(self, event):
        # Must be absolute and exist: wxFileDialog hands defaultDir to
        # SHCreateItemFromParsingName, which rejects a relative path outright with
        # 0x80070057. Path("sample.exe").parent is ".", so a bare filename hits this too.
        value = self.targetPath.GetValue()
        initialDir = Path(value).parent if value else Path(self.analysisDir)
        initialDir = initialDir.absolute()
        if not initialDir.is_dir():
            initialDir = Path.cwd()
        with wx.FileDialog(
            self,
            "Choose a file",
            wildcard="*.*",
            style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST | wx.FD_NO_FOLLOW,
            defaultDir=str(initialDir),
        ) as fileDialog:
            if fileDialog.ShowModal() == wx.ID_CANCEL:
                return

            pathname = fileDialog.GetPath()
            try:
                self.targetPath.SetValue(pathname)
                self.OnTargetSelection()
            except OSError:
                wx.LogError(f"Cannot open file '{pathname}'.")

    def _InitDownloadBroker(self):
        """When downloads are enabled, prompt once for a password and/or API keys and start the
        broker subprocess that holds them, so the GUI never retains the plaintext key. Left
        disabled with a hint when the feature is off or no credentials are supplied."""
        if not download_enabled():
            self.downloadBtn.SetToolTip(
                "Downloads disabled. Set [download] enabled = true in cfg.ini to use them."
            )
            return
        try:
            stored = configured_sources()
        except Exception:
            stored = []
        dlg = _DownloadCredentialsDialog(self, bool(stored))
        if dlg.ShowModal() != wx.ID_OK:
            dlg.Destroy()
            self.downloadBtn.SetToolTip("Restart CAPEsolo and enter credentials to enable downloads.")
            return
        password, keys = dlg.GetCredentials()
        dlg.Destroy()
        # A provider is usable with a directly-entered key, or a stored blob plus the password.
        if not (keys.get("VirusTotal") or keys.get("MalwareBazaar") or (password and stored)):
            self.downloadBtn.SetToolTip(
                "No key or password entered. Paste an API key at startup, or configure one with tools/encrypt_api_key.py."
            )
            return
        try:
            self.downloadBroker = subprocess.Popen(
                [sys.executable, "-m", "CAPEsolo.utils.download_sample", "--serve"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            self.downloadBroker.stdin.write(json.dumps({"password": password, "keys": keys}) + "\n")
            self.downloadBroker.stdin.flush()
        except Exception as e:
            self.downloadBroker = None
            ui.message(f"Could not start the download helper:\n{e}", "Error", wx.OK | wx.ICON_ERROR)
            return
        finally:
            password = None
            keys = None
        self.downloadBtn.Enable()
        self.downloadBtn.SetToolTip("Download by hash (auto: VirusTotal, then MalwareBazaar).")
        self.downloadPathInput.Enable()
        self.downloadDirBtn.Enable()

    def _StopDownloadBroker(self):
        """Kill the broker and wait for it to exit, so the password/key are gone from memory
        before detonation (its pages are reclaimed and zero-filled by the OS)."""
        broker = self.downloadBroker
        if not broker:
            return
        self.downloadBroker = None
        with suppress(Exception):
            broker.stdin.close()
        with suppress(Exception):
            broker.terminate()
        with suppress(Exception):
            broker.wait(timeout=5)

    def OnDownloadSample(self, event):
        # The button doubles as Cancel while a download is running.
        if self._downloading:
            self._CancelDownload()
            return
        if not self.downloadBroker or self.downloadBroker.poll() is not None:
            ui.message(
                "Downloads are not available. Restart CAPEsolo and enter the password.",
                "Error",
                wx.OK | wx.ICON_ERROR,
            )
            return
        sampleHash = self.hashInput.GetValue().strip()
        if not sampleHash:
            ui.message("Enter a sample hash to download.", "Error", wx.OK | wx.ICON_ERROR)
            return
        # Read the destination on the GUI thread; fall back to the configured/default dir.
        dest = self.downloadPathInput.GetValue().strip() or download_dir()
        self._downloading = True
        self.downloadBtn.SetLabel("Cancel")
        self.downloadBtn.SetToolTip("Cancel the download in progress.")
        self.hashInput.Disable()
        self.downloadPathInput.Disable()
        self.downloadDirBtn.Disable()
        self.GetMainFrame().statusBar.SetMessage(f"Downloading {sampleHash}...")
        Thread(target=self._DownloadSampleThread, args=(sampleHash, dest), daemon=True).start()

    def _CancelDownload(self):
        broker = self.downloadBroker
        if not broker:
            return
        # Tell the broker to abandon the in-flight download; it replies "cancelled" and stays
        # alive (keeps the held password), so downloads remain available afterwards.
        with suppress(Exception):
            broker.stdin.write(json.dumps({"action": "cancel"}) + "\n")
            broker.stdin.flush()
        self.downloadBtn.Disable()  # avoid double-cancel; _OnDownloadDone restores the button
        self.GetMainFrame().statusBar.SetMessage("Cancelling download...")

    def _DownloadSampleThread(self, sampleHash, dest):
        try:
            broker = self.downloadBroker
            if not broker or broker.poll() is not None:
                raise RuntimeError("download helper is not running")
            broker.stdin.write(json.dumps({"hash": sampleHash, "dest": dest}) + "\n")
            broker.stdin.flush()
            line = broker.stdout.readline()
            if not line:
                raise RuntimeError("no response from download helper")
            reply = json.loads(line)
            if reply.get("ok"):
                # The broker fetched VT info with the analyst's key at download time; cache it so the
                # Info tab shows it without a public-key request (which VT throttles).
                vtinfo = reply.get("vtinfo")
                if vtinfo and vtinfo.get("sha256"):
                    seed_vt_cache(vtinfo["sha256"], vtinfo)
                wx.CallAfter(self._OnDownloadDone, Path(reply["path"]), None)
            else:
                wx.CallAfter(self._OnDownloadDone, None, reply.get("error", "unknown error"))
        except Exception as e:
            wx.CallAfter(self._OnDownloadDone, None, str(e))

    def _OnDownloadDone(self, path, error):
        statusBar = self.GetMainFrame().statusBar
        self._downloading = False
        self.downloadBtn.SetLabel("Download")
        self.hashInput.Enable()
        if self.downloadBroker:  # only re-enable if downloads are still available
            self.downloadBtn.Enable()
            self.downloadBtn.SetToolTip("Download by hash (auto: VirusTotal, then MalwareBazaar).")
            self.downloadPathInput.Enable()
            self.downloadDirBtn.Enable()
        if error is not None:
            if str(error) == "cancelled":
                statusBar.SetMessage("Download cancelled")
            else:
                statusBar.SetMessage("Download failed")
                ui.message(f"Sample download failed:\n{error}", "Error", wx.OK | wx.ICON_ERROR)
            return
        statusBar.SetMessage(f"Downloaded {path.name}")
        # Reuse the Browse flow: set the target path and run the same validation.
        self.targetPath.SetValue(str(path))
        self.OnTargetSelection()

    def CopyTarget(self):
        self.targetFile = Path(self.analysisDir) / f"s_{hash_file(hashlib.sha256, self.target)}"
        shutil.copy(self.target, self.targetFile)

    def StartAnalysis(self):
        from CAPEsolo.analyzer import (
            Analyzer,
            CuckooError,
            traceback,
        )

        self.analyzer = None

        try:
            self.resultserver = ResultServer("localhost", 9999, self.analysisDir)
            self.analyzer = Analyzer()
            self.analyzer.prepare()
            mainFrame = self.GetMainFrame()
            width, height = mainFrame.GetSize()
            size = wx.Size(int(width * 2), height)
            position = mainFrame.GetPosition()
            if self.idbg:
                self.dbgConsole = DebugConsole(self, "Debug Console", position, size)
                self.dbgConsole.launch()
            mainFrame.statusBar.StartCountdown(self.countdown)
            self.StartAnalyzerThread(self.analyzer)
            self.terminateAnalyzerBtn.Enable()
            self.GetMainFrame().extendTimeoutBtn.Enable()
            # os.unlink(ANALYSIS_CONF)

        except CuckooError:
            self.log("You probably submitted the job with wrong package")

        except Exception as e:
            error_exc = traceback.format_exc()
            error = str(e)
            self.log(f"{error} - {error_exc}\n")

    def AddTargetOptions(self, event):
        currentDatetime = datetime.now()
        formattedDatetime = currentDatetime.strftime("%Y%m%dT%H:%M:%S")
        filename = str(self.target)
        userOptions = self.optionsCtrl.GetValue()
        timeout = int(self.timeoutInput.GetValue())
        sep = ","
        if userOptions == "option1=value, option2=value, etc...":
            userOptions = ""
            sep = ""
        if self.manualExecution:
            userOptions += f"{sep}manual=True, interactive=True"
            sep = ","
        # Exactly one hook set is selected; "full" is capemon's default and needs no option.
        for radio, option in self.hookSets:
            if option and radio.GetValue():
                userOptions += f"{sep}{option}=1"
                sep = ","
        if self.free.GetValue():
            userOptions += f"{sep}free=1"
            sep = ","
        userOptions += f"{sep}unhook-on-terminate={1 if self.unhookOnExit.GetValue() else 0}"
        sep = ","
        for box, name, level in self.loggingOptions:
            if box.GetValue():
                # Levelled options take the number leading their selected label; the
                # rest are booleans capemon tests with value[0] == '1'.
                value = level.GetStringSelection().split(" ", 1)[0] if level else "1"
                userOptions += f"{sep}{name}={value}"
                sep = ","
        if self.curDir:
            curdir = Path(filename).parent
            userOptions += f"{sep}curdir={curdir}"
            sep = ","
        if self.idbg:
            userOptions += f"{sep}idbg=1"
            timeout = 60 * 60 * 4  # 4 hours
            sep = ","

        self.countdown = timeout
        debuggerOptions = self.GetDebuggerOptions()
        # Returned rather than written back into the editor. Appending these to the editor's
        # own text meant a second launch in the same session appended them a second time, and
        # configparser rejects the duplicate keys outright - so the run failed before it began.
        return {
            "enforce_timeout": self.enforceTimeout,
            "timeout": timeout,
            "file_name": filename,
            "clock": formattedDatetime,
            "package": self.package,
            "options": f"{userOptions},{debuggerOptions}",
        }

    def GetDebuggerOptions(self):
        opts = []
        for i in range(4):
            bpType, addrType, addr, action, value, count, hc = self.debuggerControls[i]
            optstring = ""
            bpType = bpType.GetValue()
            addrType = addrType.GetValue()
            addr = addr.GetValue()
            action = action.GetValue()
            value = value.GetValue()
            count = count.GetValue()
            hc = hc.GetValue()
            if addrType == "ep":
                addr = None
                optstring = f"{bpType}=ep"
            if addr:
                optstring = f"{bpType}=0x{addr}"
                if addrType == "VA":
                    optstring += f",bpva{i}=1"
            if action:
                optstring += f",action{i}={action}"
                if value:
                    optstring += f":{value}"
            if count:
                optstring += f",count{i}={count}"
            if hc:
                optstring += f",hc{i}={hc}"
            if optstring:
                opts.append(optstring)
        if self.debugCount.GetValue():
            opts.append(f"count={self.debugCount.GetValue()}")
        if self.debugDepth.GetValue():
            opts.append(f"depth={self.debugDepth.GetValue()}")
        if self.yarascanDisable.GetValue():
            opts.append("yarascan=0")
        if self.baseApi.GetValue():
            opts.append(f"base-on-api={self.baseApi.GetValue()}")
        if self.apiList.GetValue():
            opts.append(f"break-on-return={self.apiList.GetValue()}")
        if self.baseAllocCheckbox.GetValue():
            opts.append("base-on-alloc=1")

        return ",".join(opts)

    def OnTerminateAnalyzer(self, event):
        try:
            idHash = "2b42b81577ab55cd2bcf2ac87b889bbb"
            completeFolder = os.path.join(os.environ["TMP"], idHash)
            Path(completeFolder).mkdir(exist_ok=True)
            self.terminateAnalyzerBtn.Disable()
            self.GetMainFrame().extendTimeoutBtn.Disable()
        except Exception as e:
            ui.message(f"Could not terminate analyzer: {e}", "Error", wx.OK | wx.ICON_ERROR)

    def OnExtendTimeout(self, event):
        analyzer = getattr(self, "analyzer", None)
        if not analyzer or not getattr(analyzer, "config", None):
            return
        extra = wx.GetNumberFromUser(
            "Extend the running analysis by:", "Seconds", "Extend timeout", 60, 1, 24 * 60 * 60, self
        )
        if extra <= 0:  # -1 on cancel
            return
        try:
            analyzer.config.timeout = int(analyzer.config.timeout) + extra
        except (TypeError, ValueError):
            analyzer.config.timeout = extra
        self.GetMainFrame().statusBar.AddTime(extra)
        self.GetMainFrame().statusBar.SetMessage(f"Timeout extended by {extra}s")

    def OnLaunchAnalyzer(self, event):
        originalPath = Path(self.targetPath.GetValue())
        newFilename = sanitize_filename(originalPath.name)
        if newFilename != originalPath.name:
            # Rename a hash-named file (e.g. a downloaded sample) to a shorter name so malware can't
            # detect it by its own hash. Guard the re-launch case: a prior launch already renamed it,
            # so the original no longer exists - reuse the renamed file instead of failing. Update the
            # field to the new name so this is idempotent, and replace() tolerates an existing target.
            self.target = Path(originalPath.parent, newFilename)
            if originalPath.exists():
                try:
                    originalPath.replace(self.target)
                except OSError as e:
                    ui.message(
                        f"Could not prepare the target file:\n{e}", "Error", wx.OK | wx.ICON_ERROR
                    )
                    return
                self.targetPath.SetValue(str(self.target))
        else:
            self.target = originalPath

        if not self.target.exists():
            ui.message(
                f"Target file not found:\n{self.target}", "Error", wx.OK | wx.ICON_ERROR
            )
            return

        self.CopyTarget()
        self.parent.targetFile = self.targetFile

        if self.staticAnalysis.GetValue():
            ui.message("Static analysis: Check info, yara, and config tabs.", "Status", wx.OK | wx.ICON_INFORMATION)
            return

        try:
            self.package = self.packageDropdown.GetValue()
            if self.package == "Auto-detect":
                package = self.IdentifyPackage()
                if package:
                    self.package = package
                else:
                    ui.message(
                        "Package identification error, select package manually.",
                        "Error",
                        wx.OK | wx.ICON_ERROR,
                    )
                    return

            self.SaveAnalysisFile(event, False, self.AddTargetOptions(event))
            mainFrame = self.GetMainFrame()
            size = mainFrame.GetSize()
            position = mainFrame.GetPosition()
            loggerWindow = LoggerWindow(
                self, "Analysis Log", position, size, maximized=mainFrame.IsMaximized()
            )
            loggerWindow.Show()
            if self.processTreeWindow:
                self.processTreeWindow.Close()
            self.processTreeWindow = ProcessTreeWindow(self, "Process Tree", position)
            self.processTreeWindow.Show()
            # Kill the download broker (holding the key password) before the sample runs.
            self._StopDownloadBroker()
            self.StartAnalysis()

        except Exception as e:
            ui.message(f"Failed to execute the command: {e}", "Error", wx.OK | wx.ICON_ERROR)

    def SaveAnalysisFile(self, event, ack=True, runtime=None):
        # Generated from the form every time, so the file never accumulates keys across runs.
        content = self.analysisEditor.GetText(runtime)
        path = os.path.join("analysis.conf")
        try:
            with open(path, "w") as hfile:
                hfile.write(content)

            # A second copy in the analysis folder. The analyzer reads the working-directory
            # one, but everything that examines a finished analysis expects to find the
            # config beside the results - RunSignatures builds conf_path that way
            # (capelib/signatures.py), matching CAPEv2, and it resolved to a file that was
            # never written. It also makes the folder self-describing: which options and
            # which auxiliary modules produced these results.
            with suppress(OSError):
                Path(self.analysisDir, "analysis.conf").write_text(content)

            if ack:
                ui.message(
                    "analysis.conf saved successfully.",
                    "Success",
                    wx.OK | wx.ICON_INFORMATION,
                )
        except OSError as e:
            ui.message(
                f"Failed to save analysis.conf: {e!s}",
                "Error",
                wx.OK | wx.ICON_ERROR,
            )

    def GetMainFrame(self):
        parent = self.GetParent()
        while parent and not isinstance(parent, wx.Frame):
            parent = parent.GetParent()
        return parent

    def GetCapturePath(self):
        """The capture chosen on the Network tab, so a report can include the wire view.

        Optional by design: the network summary is built from the behaviour and JS logs
        either way, and only the pcap-derived parts and the decrypted streams need this.
        """
        networkTab = getattr(self.GetMainFrame(), "networkTab", None)
        if networkTab is None:
            return ""

        return networkTab.GetPcapPath()

    def log(self, message):
        log.info(message)

    def RunAnalyzer(self, analyzer, callback=None):
        result = analyzer.run()
        if callback:
            wx.CallAfter(callback, result)

    def StartAnalyzerThread(self, analyzer):
        def OnComplete(result):
            if result:
                evt = AnalyzerCompleteEvent(EVT_ANALYZER_COMPLETE_ID, -1, "Analyzer completed")
                wx.PostEvent(self, evt)

        Thread(target=self.RunAnalyzer, args=(analyzer, OnComplete)).start()

    def OnOpenDirectory(self, event):
        os.startfile(self.analysisDir)

    def OnZipResults(self, event):
        """Zip the analysis directory to the Desktop so it can be restored in a clean VM."""
        dest = Path(desktop_dir()) / f"capesolo_analysis_{datetime.now():%Y%m%d_%H%M%S}"
        self.zipResultsBtn.Disable()
        self.GetMainFrame().statusBar.SetMessage("Zipping analysis results...")
        # Background thread: the analysis dir (logs/, files/, memory/, CAPE/, ...) can be large.
        Thread(target=self._ZipResultsThread, args=(dest,), daemon=True).start()

    def _ZipResultsThread(self, dest):
        try:
            # dest has no extension; make_archive appends .zip. The Desktop target is outside
            # analysisDir, so the growing archive is not swept into itself.
            shutil.make_archive(str(dest), "zip", root_dir=self.analysisDir)
            wx.CallAfter(self._OnZipResultsDone, dest.with_suffix(".zip"), None)
        except Exception as e:
            wx.CallAfter(self._OnZipResultsDone, None, str(e))

    def _OnZipResultsDone(self, path, error):
        statusBar = self.GetMainFrame().statusBar
        self.zipResultsBtn.Enable()
        if error is not None:
            statusBar.SetMessage("Zip failed")
            ui.message(f"Failed to zip results:\n{error}", "Error", wx.OK | wx.ICON_ERROR)
            return
        statusBar.SetMessage(f"Zipped results to {path.name}")
        ui.message(
            f"Analysis results zipped to:\n{path}\n\nTo restore in a clean VM, copy this file to "
            "C:\\Users\\Public\\CAPEsolo\\restore.zip and start CAPEsolo.",
            "Zip Results",
            wx.OK | wx.ICON_INFORMATION,
        )

    def _LevelChoice(self, parent, labels, tooltip):
        """Read-only selector for an option whose value is a level, not a flag.

        Labels start with the numeric value capemon expects, which is what gets emitted.
        Disabled until its checkbox is ticked, so it cannot show a level that is not
        being sent.
        """
        choice = ui.Picker(parent, choices=labels, value=labels[0])
        choice.SetToolTip(tooltip)
        choice.Enable(False)
        return choice

    def OnLoggingLevelToggle(self, event):
        for box, _name, level in self.loggingOptions:
            if level is not None:
                level.Enable(box.GetValue())
        event.Skip()

    def OnFreeChecked(self, event):
        """free runs without the monitor, so no hook set applies.

        Replaces the old minhook/free interlock: the choice is now a radio group, and
        disabling it as a whole says "no hooks are installed at all" more clearly than
        greying out a single checkbox.
        """
        enabled = not self.free.GetValue()
        for radio, _option in self.hookSets:
            radio.Enable(enabled)

    def OnIdbgChecked(self, event):
        self.idbg = self.idbgCheckbox.GetValue()

    def OnUpdateYara(self, event):
        confirm = ui.message(
            "Download and overwrite any existing YARA rules. "
            "This could take a few minutes.\n\n"
            "Do you want to continue?",
            "Confirm YARA Update",
            wx.YES_NO | wx.ICON_QUESTION | wx.CENTER,
        )

        if confirm != wx.YES:
            return

        try:
            busy = wx.BusyInfo("Please wait... Updating YARA rules.", parent=self)
            wx.Yield()
            updated = UpdateYara(Path(self.capesoloRoot))
            del busy
            if updated:
                details = "\n".join(f"{path}: {count} rules updated" for path, count in updated.items())
                ui.message(f"YARA rules updated successfully:\n\n{details}", "Update Complete", wx.OK | wx.ICON_INFORMATION)
            else:
                ui.message("No YARA rules were updated.", "Update Complete", wx.OK | wx.ICON_INFORMATION)

        except Exception as e:
            del busy  # noqa: F821
            ui.message(f"Failed to update YARA rules:\n{e!s}", "Error", wx.OK | wx.ICON_ERROR)

    def OnYaraSave(self, event):
        yaraText = self.yaraRule.GetValue()
        savePath = Path(self.capesoloRoot) / "data" / "yara" / "DebuggerRule.yar"

        try:
            savePath.write_text(yaraText)
        except OSError as e:
            ui.message(
                f"Failed to save Yara rule:\n{e}",
                "Save Failed",
                wx.OK | wx.ICON_ERROR,
            )
            return

        ui.message(
            f"Yara rule saved to: {savePath!s}",
            "Save Successful",
            wx.OK | wx.ICON_INFORMATION,
        )

    def OnYaraDelete(self, event):
        yaraPath = Path(self.capesoloRoot) / "data" / "yara" / "DebuggerRule.yar"

        try:
            yaraPath.unlink()
        except FileNotFoundError:
            ui.message(
                f"Yara rule file not found: {yaraPath!s}",
                "Delete Failed",
                wx.OK | wx.ICON_ERROR,
            )
            return
        except OSError as e:
            ui.message(
                f"Failed to delete Yara rule:\n{e}",
                "Delete Failed",
                wx.OK | wx.ICON_ERROR,
            )
            return

        ui.message(
            f"Yara rule deleted: {yaraPath!s}",
            "Delete Successful",
            wx.OK | wx.ICON_INFORMATION,
        )

    def YaraLoad(self):
        loadPath = Path(self.capesoloRoot) / "data" / "yara" / "DebuggerRule.yar"
        yaraText = YARARULE
        if loadPath.exists():
            with suppress(OSError, IOError):
                yaraText = loadPath.read_text()

        self.yaraRule.SetValue(yaraText)

    def JsonReport(self, event):
        confirm = ui.message(
            "Generate JSON report.\n\nDo you want to continue?",
            "Confirm",
            wx.YES_NO | wx.ICON_QUESTION | wx.CENTER,
        )

        if confirm != wx.YES:
            return

        try:
            busy = wx.BusyInfo("Please wait... Creating JSON report.", parent=self)
            wx.Yield()
            self.jsonReportBtn.Disable()
            completed, msg = GetResults(
                self.targetFile, self.analysisDir, pcapPath=self.GetCapturePath()
            )
            del busy
            if completed:
                ui.message("JSON report completed successfully.", "JSON Report", wx.OK | wx.ICON_INFORMATION)
            else:
                ui.message(f"JSON report was unsuccessful: {msg}", "JSON Report", wx.OK | wx.ICON_INFORMATION)

        except Exception as e:
            del busy  # noqa: F821
            ui.message(f"Failed to create JSON report:\n{e!s}", "Error", wx.OK | wx.ICON_ERROR)

    def HtmlReport(self, event):
        confirm = ui.message(
            "Generate HTML report.\n\nDo you want to continue?",
            "Confirm",
            wx.YES_NO | wx.ICON_QUESTION | wx.CENTER,
        )

        if confirm != wx.YES:
            return

        try:
            busy = wx.BusyInfo("Please wait... Creating HTML report.", parent=self)
            wx.Yield()
            self.htmlReportBtn.Disable()
            results = GetResults(
                self.targetFile, self.analysisDir, False, pcapPath=self.GetCapturePath()
            )
            report = ReportHTML()
            completed, msg = report.run(self.analysisDir, self.capesoloRoot, results)
            del busy
            if completed:
                ui.message("HTML report completed successfully.", "HTML Report", wx.OK | wx.ICON_INFORMATION)
            else:
                ui.message(f"HTML report was unsuccessful: {msg}", "HTML Report", wx.OK | wx.ICON_INFORMATION)

        except Exception as e:
            del busy  # noqa: F821
            ui.message(f"Failed to create HTML report:\n{e!s}", "Error", wx.OK | wx.ICON_ERROR)