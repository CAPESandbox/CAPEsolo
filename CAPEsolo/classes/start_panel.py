import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import time
import zipfile
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from threading import Thread

import wx
import wx.lib.scrolledpanel as scrolled
from sflock.abstracts import File as SflockFile
from sflock.ident import identify as sflock_identify

from CAPEsolo.capelib.capture_report import (
    CAPTURE_FILE,
    BuildCaptureReport,
    WriteCaptureReport,
)
from CAPEsolo.capelib.config_paths import user_config_path
from CAPEsolo.capelib.js_log import GetJsLogPath
from CAPEsolo.capelib.path_utils import path_exists
from CAPEsolo.capelib.resultserver import STATS, ResultServer
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
from CAPEsolo.utils.update_yara import Update

from . import ui_kit as ui
from .analysis_conf import AnalysisConfPanel
from .debug_console import DebugConsole
from .html_report import ReportHTML
from .json_report import GetResults, WriteJsonFile
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


class _ChoiceDialog(ui.Dialog):
    """A few groups of checkboxes and OK/Cancel: the Update and Reports prompts."""

    def __init__(self, parent, title, intro, groups, ok="OK"):
        """*groups* is [(card title, [(key, label, ticked), ...]), ...]."""
        super().__init__(parent, title=title)
        outer = wx.BoxSizer(wx.VERTICAL)
        outer.Add(wx.StaticText(self, label=intro), flag=wx.ALL, border=dip(self, SP_MD))

        self.checks = {}
        for cardTitle, options in groups:
            card = ui.Card(self, title=cardTitle)
            for key, label, ticked in options:
                check = ui.Check(card, label=label)
                check.SetValue(ticked)
                card.body.Add(check, flag=wx.BOTTOM, border=dip(self, SP_SM))
                self.checks[key] = check
            outer.Add(card, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=dip(self, SP_MD))

        outer.Add(
            ui.dialog_buttons(self, ok=ok),
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=dip(self, SP_MD),
        )

        # Theme first, then fit, as in _DownloadCredentialsDialog.
        self.SetSizer(outer)
        apply_theme(self)
        self.SetBackgroundColour(BG_MAIN)
        self.Fit()
        self.SetMinSize(self.GetSize())

    def GetChoices(self):
        return {key for key, check in self.checks.items() if check.GetValue()}


def AskChoices(parent, *args, **kwargs):
    """Show a _ChoiceDialog; the ticked keys, or None if it was cancelled."""
    dialog = _ChoiceDialog(parent, *args, **kwargs)
    try:
        return dialog.GetChoices() if dialog.ShowModal() == wx.ID_OK else None
    finally:
        dialog.Destroy()


class StartPanel(wx.Panel):
    def __init__(self, parent):
        # FULL_REPAINT_ON_RESIZE, as a constructor style (wxMSW picks the registered window
        # class at creation, so SetWindowStyleFlag afterwards is silently ignored).
        # Candidate fix, cause not established: several action-bar buttons come out doubled a
        # few pixels apart after a drag-resize and stay that way until a tab switch repaints
        # the page. Putting it on the container rather than the controls was tried because the
        # same flag on the drawn controls themselves (ui_kit._Themed, Card, SectionHeader,
        # Field) made the artifacting worse, not better.
        super().__init__(parent, style=wx.FULL_REPAINT_ON_RESIZE)
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
            self.reportsBtn.Enable()
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
        targetCard.body.Add(downloadPathRow, 0, wx.EXPAND | wx.BOTTOM, gapM)

        # Re-read an analysis without running one: the one already in the analysis directory
        # (e.g. restored from restore.zip at startup, which was never processed), or a full
        # results bundle from Zip Results.
        targetCard.body.Add(
            ui.SectionHeader(targetCard, "Previous analysis"), 0, wx.EXPAND | wx.BOTTOM, gapS
        )
        previousRow = wx.BoxSizer(wx.HORIZONTAL)
        self.reprocessBtn = ui.Button(
            targetCard,
            label="Reprocess",
            glyph=ui.REFRESH,
            tooltip="Clear the result tabs and process the analysis in the analysis directory again.",
        )
        self.reprocessBtn.Bind(wx.EVT_BUTTON, self.OnReprocess)
        self.openBundleBtn = ui.Button(
            targetCard,
            label="Open Bundle...",
            glyph=ui.ARCHIVE,
            tooltip="Extract a full results bundle (Zip Results) into the analysis directory and process it.",
        )
        self.openBundleBtn.Bind(wx.EVT_BUTTON, self.OnOpenBundle)
        previousRow.Add(self.reprocessBtn, 0, wx.RIGHT, gapS)
        previousRow.Add(self.openBundleBtn, 0)
        targetCard.body.Add(previousRow, 0, wx.EXPAND)

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

        self.reportsBtn = ui.Button(
            self, label="Reports", glyph=ui.DOCUMENT, tooltip="Build the JSON and/or HTML report."
        )
        self.reportsBtn.Disable()
        self.reportsBtn.Bind(wx.EVT_BUTTON, self.OnReports)

        updateBtn = ui.Button(
            self, label="Update", glyph=ui.REFRESH, tooltip="Download YARA rules and community signatures."
        )
        updateBtn.Bind(wx.EVT_BUTTON, self.OnUpdate)

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
            self.reportsBtn,
            updateBtn,
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
            self.reportsBtn.Enable()
        except Exception:
            self.log(traceback.format_exc())

        # Written after the server has drained, so the transfer counters cover late uploads
        # (STATS is only reset when the next ResultServer starts). This is the one place the
        # analyst is told the run lost something - until now it was a single line in the log.
        capture = WriteCaptureReport(self.analysisDir, stats=STATS.snapshot())
        warnings = capture.get("warnings") or []
        for warning in warnings:
            self.log(f"Capture: {warning}")
        if warnings:
            self.GetMainFrame().statusBar.SetMessage(
                f"Analysis complete - {len(warnings)} capture warning(s), see {CAPTURE_FILE}"
            )

        self.SetAnalysisControls(running=False)
        if self.autoProcess.GetValue():
            self.AutoProcessTabs()
        return True

    def AutoProcessTabs(self):
        """Populate the result tabs in dependency order after a run so the user need not
        open each tab and click its process button. Only called when Auto-process is
        checked; the steps each disable their tab's button and set its completion flag, so
        those buttons stay disabled once processed. When Auto-process is unchecked this is
        skipped and the buttons enable as before for manual processing.

        Runs on the processing worker (MainFrame.RunSteps), so the window stays usable. The
        steps come from a generator, so each condition below is checked only once the steps
        before it have finished - configHits, for one, is filled by the yara step.
        """
        mainFrame = self.GetMainFrame()
        if mainFrame.processing:
            # A tab the user started by hand is still running; RunSteps would refuse this,
            # and the run's processing would silently never happen.
            wx.CallLater(500, self.AutoProcessTabs)
            return

        def steps():
            step = mainFrame.infoTab.InfoStep()
            if step:
                yield step

            logsDir = Path(self.analysisDir) / "logs"
            if logsDir.exists() and any(logsDir.iterdir()) and not mainFrame.behaviorTab.behaviorComplete:
                yield mainFrame.behaviorTab.BehaviorStep()

            # Before payloads so reconstructed files dropped from the JS network log are picked up by
            # the payload list and the yara scan below in the same run.
            if not mainFrame.jsConsoleTab.jsLogComplete and path_exists(str(GetJsLogPath(self.analysisDir))):
                yield mainFrame.jsConsoleTab.JsLogStep()

            step = mainFrame.payloadsTab.PayloadsStep()
            if step:
                yield step

            if self.targetFile and not mainFrame.yaraTab.yaraComplete:
                yield mainFrame.yaraTab.YaraStep()

            if self.parent.configHits:
                yield mainFrame.configsTab.ConfigsStep()

            if self.parent.results and not mainFrame.signaturesTab.signaturesComplete:
                yield mainFrame.signaturesTab.SignaturesStep()

        def done(failed):
            if failed:
                mainFrame.statusBar.SetMessage(
                    f"Analysis complete - {len(failed)} tab(s) failed: {', '.join(failed)} (see log)"
                )
            else:
                mainFrame.statusBar.SetMessage("Analysis complete - tabs processed")

        mainFrame.RunSteps(steps(), onDone=done)

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

    def CopyTarget(self, targetFile):
        self.targetFile = targetFile
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
            position = mainFrame.GetPosition()
            # The console wants extra horizontal room for its side-by-side disassembly,
            # registers, memory and stack panes, but doubling the main frame's width
            # unconditionally could - and did - exceed the screen (e.g. a 1117px-wide main
            # frame doubles to 2234px, wider than a 1920px display), positioned starting at
            # the main frame's own on-screen origin. Clamp to what is actually left of the
            # screen from that origin.
            screenWidth, screenHeight = wx.DisplaySize()
            size = wx.Size(
                min(int(width * 2), screenWidth - position.x),
                min(height, screenHeight - position.y),
            )
            if self.idbg:
                self.dbgConsole = DebugConsole(self, "Debug Console", position, size)
                self.dbgConsole.launch()
            mainFrame.statusBar.StartCountdown(self.countdown)
            self.StartAnalyzerThread(self.analyzer)
            # One analyzer at a time: a second Launch would start another on the same result
            # server port and analysis directory. Re-enabled when the run ends.
            self.SetAnalysisControls(running=True)
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
            # The analyzer watches for md5("cape-<id>") of the id it was started with.
            config = getattr(getattr(self, "analyzer", None), "config", None)
            idHash = hashlib.md5(f"cape-{getattr(config, 'id', 2)}".encode()).hexdigest()
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
        # These rebuild the result pages, which a running processing job is still filling.
        if self.GetMainFrame().processing:
            return
        self._reportCache = None
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

        # One target per analysis directory (the VM is reverted between samples). A different
        # sample would land beside the previous one and mix into its logs and payloads;
        # relaunching the same sample, e.g. static then dynamic, is fine.
        targetFile = Path(self.analysisDir) / f"s_{hash_file(hashlib.sha256, self.target)}"
        previous = GetPreviousTarget(self.analysisDir)
        if previous and previous.name != targetFile.name:
            ui.message(
                f"{self.analysisDir} already holds the analysis of another sample "
                f"({previous.name}).\n\nRevert the VM before analysing a new sample, or use "
                "Zip Results first to keep this one.",
                "Launch",
                wx.OK | wx.ICON_WARNING,
            )
            return

        self.GetMainFrame().ResetResults()
        self.CopyTarget(targetFile)
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
        try:
            result = analyzer.run()
        except Exception:
            # Previously this killed the thread silently: the completion event never came and
            # the UI stayed in "Analyzing" with Launch locked out.
            log.exception("Analyzer run failed")
            wx.CallAfter(self.OnAnalyzerFailed)
            return
        if callback:
            wx.CallAfter(callback, result)

    def OnAnalyzerFailed(self):
        from CAPEsolo.analyzer import disconnect_logger, disconnect_pipes

        mainFrame = self.GetMainFrame()
        mainFrame.statusBar.Finish("Analysis failed - see the analysis log")
        mainFrame.extendTimeoutBtn.Disable()
        self.terminateAnalyzerBtn.Disable()
        # The same teardown OnAnalyzerComplete does, each step on its own so one failing does
        # not leave the rest (the pipe names are fixed for the session) for the next Launch.
        if self.dbgConsole:
            with suppress(Exception):
                self.dbgConsole.shutdown()
        with suppress(Exception):
            self.analyzer.command_pipe.stop()
        with suppress(Exception):
            self.analyzer.log_pipe_server.stop()
        with suppress(Exception):
            disconnect_pipes()
        with suppress(Exception):
            disconnect_logger()
        with suppress(Exception):
            self.resultserver.shutdown_server()
        self.SetAnalysisControls(running=False)

    def SetAnalysisControls(self, running):
        self._analyzing = running
        self.UpdateAnalysisControls()

    def UpdateAnalysisControls(self):
        """Launch, the previous-analysis actions and the reports are unavailable while a run is
        active or a processing job is: the first two rebuild the result pages the job is
        filling, and a report would parse the same directory at the same time."""
        busy = getattr(self, "_analyzing", False) or self.GetMainFrame().processing
        for button in (self.launchAnalyzerBtn, self.reprocessBtn, self.openBundleBtn):
            button.Enable(not busy)
        if self.targetFile:
            self.reportsBtn.Enable(not busy)

    def OnReprocess(self, event):
        # These rebuild the result pages, which a running processing job is still filling.
        if self.GetMainFrame().processing:
            return
        targetFile = GetPreviousTarget(self.analysisDir)
        if not targetFile:
            ui.message(
                f"There is no analysis in {self.analysisDir} to process.",
                "Reprocess",
                wx.OK | wx.ICON_INFORMATION,
            )
            return
        self.ProcessPrevious(targetFile)

    def ProcessPrevious(self, targetFile):
        self.GetMainFrame().ResetResults()
        self.targetFile = targetFile
        self.parent.targetFile = targetFile
        self.reportsBtn.Enable()
        self.AutoProcessTabs()

    def OnOpenBundle(self, event):
        from CAPEsolo.cli import _is_report_bundle

        # These rebuild the result pages, which a running processing job is still filling.
        if self.GetMainFrame().processing:
            return

        with wx.FileDialog(
            self,
            "Open a results bundle",
            wildcard="Zip files (*.zip)|*.zip",
            style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST,
        ) as dialog:
            if dialog.ShowModal() != wx.ID_OK:
                return
            bundlePath = dialog.GetPath()

        try:
            with zipfile.ZipFile(bundlePath) as archive:
                # Same check as the startup restore: a report bundle has no payloads, so the
                # tabs would read an analysis that is not on disk.
                if _is_report_bundle(archive):
                    ui.message(
                        "This is a report bundle (no payloads). Open it with "
                        "tools/report_viewer.py instead.",
                        "Open Bundle",
                        wx.OK | wx.ICON_INFORMATION,
                    )
                    return

                analysisDir = Path(self.analysisDir)
                if GetPreviousTarget(analysisDir):
                    if ui.message(
                        f"{analysisDir} already holds an analysis. It will be deleted and "
                        "replaced by the bundle.\n\nUse Zip Results first to keep it.\n\n"
                        "Replace it?",
                        "Open Bundle",
                        wx.YES_NO | wx.NO_DEFAULT | wx.ICON_WARNING,
                    ) != wx.YES:
                        return
                    # The Analysis Log window's handler keeps analysis.log open, and Windows
                    # refuses to delete an open file - half way through the directory.
                    root = logging.getLogger()
                    for handler in list(root.handlers):
                        if isinstance(handler, logging.FileHandler) and Path(handler.baseFilename).parent == analysisDir:
                            root.removeHandler(handler)
                            handler.close()
                    # Only reached for a directory holding an s_* target, i.e. one that really
                    # is an analysis directory, never an arbitrary configured path.
                    for child in sorted(analysisDir.iterdir(), key=lambda c: c.name.startswith("s_")):
                        if child.is_dir():
                            shutil.rmtree(child)
                        else:
                            child.unlink()
                archive.extractall(str(analysisDir))
        except (OSError, zipfile.BadZipFile) as e:
            ui.message(
                f"Could not open the bundle:\n{e}\n\nThe analysis directory may be partly cleared.",
                "Open Bundle",
                wx.OK | wx.ICON_ERROR,
            )
            return

        targetFile = GetPreviousTarget(self.analysisDir)
        if not targetFile:
            ui.message(
                "The bundle holds no analysed target (s_* file).", "Open Bundle", wx.OK | wx.ICON_ERROR
            )
            return
        self.ProcessPrevious(targetFile)

    def StartAnalyzerThread(self, analyzer):
        def OnComplete(result):
            if result:
                evt = AnalyzerCompleteEvent(EVT_ANALYZER_COMPLETE_ID, -1, "Analyzer completed")
                wx.PostEvent(self, evt)

        Thread(target=self.RunAnalyzer, args=(analyzer, OnComplete)).start()

    def OnOpenDirectory(self, event):
        os.startfile(self.analysisDir)

    # Members of a report bundle: everything needed to read the analysis on another machine,
    # and nothing executable. Payload bytes stay in the VM, so the archive can be copied to a
    # workstation without its antivirus quarantining the results.
    REPORT_BUNDLE_MEMBERS = ("report.json", CAPTURE_FILE, "analysis.log", "files.json")

    def OnZipResults(self, event):
        """Archive the analysis for another machine, or for restoring into a clean VM."""
        # A running job may still be writing into the directory (config dumps, JS drops).
        if self.GetMainFrame().processing:
            ui.message(
                "Processing is still running. Zip the results once it has finished.",
                "Zip Results",
                wx.OK | wx.ICON_INFORMATION,
            )
            return
        answer = ui.message(
            "Include the sample and dumped payloads?\n\n"
            "Yes - full bundle: the whole analysis directory, for restoring into a clean VM. "
            "It contains live malware.\n\n"
            "No - report bundle: report.json, the capture manifest, analysis.log and the file "
            "manifest. Safe to copy to a workstation and open in tools/report_viewer.py.",
            "Zip Results",
            wx.YES_NO | wx.CANCEL | wx.ICON_QUESTION,
        )
        if answer == wx.CANCEL:
            return

        full = answer == wx.YES
        if not (Path(self.analysisDir) / "report.json").is_file():
            prompt = (
                "There is no report.json in the analysis directory yet. Generate one now?\n\n"
                "This runs the same processing as the JSON Report button and can take a while."
            )
            if not full:
                prompt = (
                    "There is no report.json in the analysis directory yet, and a report bundle "
                    "is built around it. Generate one now?\n\n"
                    "This runs the same processing as the JSON Report button and can take a while."
                )
            if ui.message(prompt, "Zip Results", wx.YES_NO | wx.ICON_QUESTION) == wx.YES:
                # The report is built on the processing worker; zip once it is written.
                self.GenerateReports({"json"}, onDone=lambda ok: self._StartZip(full))
                return
            elif not full:
                return

        self._StartZip(full)

    def _StartZip(self, full):
        prefix = "capesolo_analysis" if full else "capesolo_report"
        dest = Path(desktop_dir()) / f"{prefix}_{datetime.now():%Y%m%d_%H%M%S}"
        self.zipResultsBtn.Disable()
        self.GetMainFrame().statusBar.SetMessage("Zipping analysis results...")
        # Background thread: the analysis dir (logs/, files/, memory/, CAPE/, ...) can be large.
        Thread(target=self._ZipResultsThread, args=(dest, full), daemon=True).start()

    def _ZipResultsThread(self, dest, full):
        try:
            # Refreshed here so the archive describes what is on disk right now, not what was
            # true when the analysis ended.
            WriteCaptureReport(self.analysisDir)
            if full:
                # dest has no extension; make_archive appends .zip. The Desktop target is outside
                # analysisDir, so the growing archive is not swept into itself.
                shutil.make_archive(str(dest), "zip", root_dir=self.analysisDir)
            else:
                self._WriteReportBundle(dest.with_suffix(".zip"))
            wx.CallAfter(self._OnZipResultsDone, dest.with_suffix(".zip"), None, full)
        except Exception as e:
            wx.CallAfter(self._OnZipResultsDone, None, str(e), full)

    def _WriteReportBundle(self, path):
        """Write the payload-free bundle: the four members, nothing else."""
        import zipfile

        analysisDir = Path(self.analysisDir)
        with zipfile.ZipFile(str(path), "w", zipfile.ZIP_DEFLATED) as archive:
            for name in self.REPORT_BUNDLE_MEMBERS:
                source = analysisDir / name
                if not source.is_file():
                    continue
                if name == CAPTURE_FILE:
                    # Stamped as a report bundle so the viewer can say payload bytes were left
                    # behind deliberately, and so _restore_results refuses to unpack it into an
                    # analysis directory it would only half fill.
                    archive.writestr(
                        name,
                        json.dumps(
                            BuildCaptureReport(self.analysisDir, bundle="report"), indent=4
                        ),
                    )
                else:
                    archive.write(str(source), name)

    def _OnZipResultsDone(self, path, error, full=True):
        statusBar = self.GetMainFrame().statusBar
        self.zipResultsBtn.Enable()
        if error is not None:
            statusBar.SetMessage("Zip failed")
            ui.message(f"Failed to zip results:\n{error}", "Error", wx.OK | wx.ICON_ERROR)
            return
        statusBar.SetMessage(f"Zipped results to {path.name}")
        if full:
            detail = (
                "To restore in a clean VM, copy this file to "
                "C:\\Users\\Public\\CAPEsolo\\restore.zip and start CAPEsolo.\n\n"
                "It contains the sample and the dumped payloads - treat it as live malware."
            )
        else:
            detail = (
                "Copy it to your workstation and open it with tools/report_viewer.py - the "
                "viewer reads the report straight out of the zip.\n\n"
                "No sample or payload bytes are included."
            )
        ui.message(
            f"Analysis results zipped to:\n{path}\n\n{detail}",
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

    def OnUpdate(self, event):
        userRoot = user_config_path().parent
        choices = AskChoices(
            self,
            "Update",
            "CAPEsolo and CAPEv2 replace the packaged YARA rules (the CAPE rules and the monitor\n"
            "rules capemon uses) with those of the repositories ticked; where both have a file,\n"
            f"CAPEsolo's is used. Community rules go to {userRoot / 'yara' / 'community'},\n"
            f"community signatures to {userRoot / 'signatures' / 'community'}.\n"
            "Your own rules and signatures are never touched. This could take a few minutes.",
            [
                ("YARA rules", [
                    ("capesolo", "CAPEsolo (CAPESandbox/CAPEsolo)", True),
                    ("capev2", "CAPEv2 (kevoreilly/CAPEv2)", False),
                    ("community", "Community (CAPESandbox/community)", False),
                ]),
                ("Signatures", [
                    ("signatures", "Community (CAPESandbox/community)", False),
                ]),
            ],
            ok="Update",
        )
        if not choices:
            return
        yaraSources = tuple(source for source in ("capesolo", "capev2", "community") if source in choices)
        signatures = "signatures" in choices

        outcome = {}

        def compute():
            outcome["updated"] = Update(Path(self.capesoloRoot), yaraSources, signatures)

        def done(failed):
            updated = outcome.get("updated")
            if failed:
                ui.message(
                    "Update failed - see the analysis log. The existing rules and signatures were kept.",
                    "Error",
                    wx.OK | wx.ICON_ERROR,
                )
            elif updated:
                details = "\n".join(f"{what}: {count} files" for what, count in updated.items())
                ui.message(f"Update complete:\n\n{details}", "Update Complete", wx.OK | wx.ICON_INFORMATION)
            else:
                ui.message("Nothing was updated.", "Update Complete", wx.OK | wx.ICON_INFORMATION)

        # Downloads a few hundred files: on the processing worker, not the GUI thread.
        self.GetMainFrame().RunSteps([("update", compute, None)], onDone=done)

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

    def _ReportResults(self, pcapPath):
        """The GetResults dict the JSON and HTML reports share. Each GetResults repeats behaviour,
        yara, strings, configs and signatures from scratch, so it runs once for both. Rebuilt
        when the capture or files.json changes (artifacts can still arrive after the run), and
        dropped on the next Launch. *pcapPath* is GetCapturePath(), read by the caller on the
        GUI thread: this runs on the processing worker."""
        filesJson = Path(self.analysisDir) / "files.json"
        key = (str(self.targetFile), pcapPath, filesJson.stat().st_mtime if filesJson.exists() else None)
        cached = getattr(self, "_reportCache", None)
        if not cached or cached[0] != key:
            cached = (key, GetResults(self.targetFile, self.analysisDir, False, pcapPath=pcapPath))
            self._reportCache = cached
        return cached[1]

    def OnReports(self, event):
        choices = AskChoices(
            self,
            "Reports",
            "Build the reports ticked from this analysis. Each is written to the Desktop and into\n"
            "the analysis directory.",
            [("Reports", [("json", "JSON (report.json)", True), ("html", "HTML (report.html)", True)])],
            ok="Generate",
        )
        if choices:
            self.GenerateReports(choices)

    def GenerateReports(self, kinds, onDone=None):
        """Build the *kinds* ("json", "html") of report on the processing worker, from one
        GetResults. onDone(ok) runs once they are written or have failed - Zip Results waits on
        it, since the caller cannot simply carry on after this returns."""
        outcome = {}
        pcapPath = self.GetCapturePath()

        def compute():
            results = self._ReportResults(pcapPath)
            if "json" in kinds:
                outcome["json"] = WriteJsonFile(results, self.analysisDir)
            if "html" in kinds:
                outcome["html"] = ReportHTML().run(self.analysisDir, self.capesoloRoot, results)

        def done(failed):
            if failed:
                ok = False
                ui.message("Failed to create the reports - see the analysis log.", "Error", wx.OK | wx.ICON_ERROR)
            else:
                ok, lines = True, []
                for kind, label in (("json", "JSON report"), ("html", "HTML report")):
                    if kind in outcome:
                        completed, msg = outcome[kind]
                        ok = ok and bool(completed)
                        lines.append(f"{label}: {'done' if completed else f'failed - {msg}'}")
                ui.message("\n".join(lines), "Reports", wx.OK | (wx.ICON_INFORMATION if ok else wx.ICON_WARNING))
            if onDone:
                onDone(ok)

        if not self.GetMainFrame().RunSteps([("reports", compute, None)], onDone=done):
            ui.message(
                "Processing is still running. Generate the reports once it has finished.",
                "Reports",
                wx.OK | wx.ICON_INFORMATION,
            )
