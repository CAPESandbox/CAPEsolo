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

from CAPEsolo.capelib.resultserver import ResultServer
from CAPEsolo.capelib.utils import sanitize_filename
from CAPEsolo.lib.common.hashing import hash_file
from CAPEsolo.utils.update_yara import UpdateYara
from CAPEsolo.utils.download_sample import configured_sources, download_dir, download_enabled
from .analysis_conf import AnalysisConfPanel
from .debug_console import DebugConsole
from .json_report import GetResults
from .html_report import ReportHTML
from .key_event import EVT_ANALYZER_COMPLETE, EVT_ANALYZER_COMPLETE_ID
from .logger_window import LoggerWindow
from .process_tree_window import ProcessTreeWindow
from .theme import apply_theme

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

DEBUGACTIONS = [
    "dump",
    "dumpimage",
    "jmp",
    "scan",
    "skip",
    "sleep",
    "setbp0",
    "setbp1",
    "setbp2",
    "setbp3",
    "setdump",
    "setdst",
    "setsrc",
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
        super(AnalyzerCompleteEvent, self).__init__(etype, eid)
        self.message = message


class _DownloadCredentialsDialog(wx.Dialog):
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
            border=12,
        )

        # Password (for stored encrypted keys) and directly-entered keys sit in separate
        # titled boxes for clarity.
        self.pwdCtrl = None
        if hasStored:
            pwdBox = wx.StaticBoxSizer(wx.VERTICAL, self, "Password (unlock stored keys)")
            self.pwdCtrl = wx.TextCtrl(pwdBox.GetStaticBox(), style=wx.TE_PASSWORD)
            pwdBox.Add(self.pwdCtrl, flag=wx.EXPAND | wx.ALL, border=8)
            outer.Add(pwdBox, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=12)

        keyBox = wx.StaticBoxSizer(wx.VERTICAL, self, "Enter API key(s) directly")
        keyParent = keyBox.GetStaticBox()
        grid = wx.FlexGridSizer(rows=2, cols=2, hgap=8, vgap=8)
        grid.AddGrowableCol(1, 1)
        grid.Add(wx.StaticText(keyParent, label="VirusTotal:"), flag=wx.ALIGN_CENTER_VERTICAL)
        self.vtCtrl = wx.TextCtrl(keyParent, style=wx.TE_PASSWORD)
        grid.Add(self.vtCtrl, flag=wx.EXPAND)
        grid.Add(wx.StaticText(keyParent, label="MalwareBazaar:"), flag=wx.ALIGN_CENTER_VERTICAL)
        self.mbCtrl = wx.TextCtrl(keyParent, style=wx.TE_PASSWORD)
        grid.Add(self.mbCtrl, flag=wx.EXPAND)
        keyBox.Add(grid, flag=wx.EXPAND | wx.ALL, border=8)
        outer.Add(keyBox, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=12)

        # Explicit wx.Buttons rather than CreateButtonSizer: the stock MSW dialog buttons render
        # natively and ignore SetBackgroundColour, so the theme could not darken them. wx.Dialog
        # still auto-handles the ID_OK / ID_CANCEL ids to end the modal with the right result.
        btnRow = wx.BoxSizer(wx.HORIZONTAL)
        okBtn = wx.Button(self, wx.ID_OK, "OK")
        okBtn.SetDefault()
        btnRow.AddStretchSpacer(1)
        btnRow.Add(okBtn, flag=wx.RIGHT, border=8)
        btnRow.Add(wx.Button(self, wx.ID_CANCEL, "Cancel"))
        outer.Add(btnRow, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=12)

        # Enter confirms OK from any field (SetDefault alone is unreliable while a text field
        # has focus); Escape still cancels via the dialog's built-in ID_CANCEL handling.
        self.Bind(wx.EVT_CHAR_HOOK, self._OnCharHook)

        # Theme first, then fit: apply_theme swaps in FONT_UI, so fitting beforehand would size
        # the dialog to the smaller default font and squish the controls and the button row.
        self.SetSizer(outer)
        apply_theme(self)
        self.Fit()
        if self.GetSize().width < 440:
            self.SetSize(wx.Size(440, self.GetSize().height))
        self.SetMinSize(self.GetSize())

    def _OnCharHook(self, event):
        if event.GetKeyCode() in (wx.WXK_RETURN, wx.WXK_NUMPAD_ENTER):
            self.EndModal(wx.ID_OK)
            return
        event.Skip()

    def GetCredentials(self):
        password = self.pwdCtrl.GetValue() if self.pwdCtrl else ""
        keys = {
            "VirusTotal": self.vtCtrl.GetValue().strip(),
            "MalwareBazaar": self.mbCtrl.GetValue().strip(),
        }
        return password, keys


class StartPanel(scrolled.ScrolledPanel):
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
        self.InitUi()
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
        vbox = wx.BoxSizer(wx.VERTICAL)

        # File Dropdown and Browse Button
        hbox1 = wx.BoxSizer(wx.HORIZONTAL)
        self.targetPath = wx.TextCtrl(self)
        self.targetPath.SetValue("<Target file>")
        browseBtn = wx.Button(self, label="Browse...")
        browseBtn.Bind(wx.EVT_BUTTON, self.OnBrowse)
        hbox1.Add(self.targetPath, proportion=1, flag=wx.EXPAND | wx.RIGHT, border=5)
        hbox1.Add(browseBtn, proportion=0)

        # Download a sample by hash and feed it into the same target flow as Browse. Grouped in
        # a titled box so it's clearly the download feature. The source is auto-selected
        # (VirusTotal first, then MalwareBazaar) from the hash and which keys are configured; the
        # controls are enabled once the download broker starts (see _InitDownloadBroker).
        dlBox = wx.StaticBoxSizer(wx.VERTICAL, self, "Download by hash")
        dlParent = dlBox.GetStaticBox()

        hboxDownload = wx.BoxSizer(wx.HORIZONTAL)
        self.hashInput = wx.TextCtrl(dlParent)
        self.hashInput.SetHint("<md5, sha1, sha256>")
        self.hashInput.SetToolTip("MD5/SHA1/SHA256 hex hash. MalwareBazaar requires SHA256.")
        self.downloadBtn = wx.Button(dlParent, label="Download")
        self.downloadBtn.Disable()
        self.downloadBtn.Bind(wx.EVT_BUTTON, self.OnDownloadSample)
        hboxDownload.Add(self.hashInput, proportion=1, flag=wx.EXPAND | wx.RIGHT, border=5)
        hboxDownload.Add(self.downloadBtn, proportion=0)
        dlBox.Add(hboxDownload, flag=wx.EXPAND | wx.ALL, border=5)

        # Where downloaded samples are saved; prefilled with the effective default
        # ([download] directory, else the user's Desktop) and editable per download.
        hboxDownloadPath = wx.BoxSizer(wx.HORIZONTAL)
        hboxDownloadPath.Add(
            wx.StaticText(dlParent, label="Path:"),
            flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT,
            border=5,
        )
        self.downloadPathInput = wx.TextCtrl(dlParent)
        self.downloadPathInput.SetValue(download_dir())
        self.downloadPathInput.SetToolTip("Directory where downloaded samples are saved.")
        self.downloadPathInput.Disable()
        self.downloadDirBtn = wx.Button(dlParent, label="Browse...")
        self.downloadDirBtn.Disable()
        self.downloadDirBtn.Bind(wx.EVT_BUTTON, self.OnBrowseDownloadDir)
        hboxDownloadPath.Add(self.downloadPathInput, proportion=1, flag=wx.EXPAND | wx.RIGHT, border=5)
        hboxDownloadPath.Add(self.downloadDirBtn, proportion=0)
        dlBox.Add(hboxDownloadPath, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=5)

        hbox2 = wx.BoxSizer(wx.HORIZONTAL)
        packageLabel = wx.StaticText(self, label="Packages")
        self.packageDropdown = wx.ComboBox(self, style=wx.CB_READONLY)
        self.PackageDropdown()
        self.packageDropdown.SetValue("Auto-detect")
        self.runFromCurrentDirCheckbox = wx.CheckBox(self, label="Run sample from current directory")
        self.runFromCurrentDirCheckbox.Bind(wx.EVT_CHECKBOX, self.OnCurrentDirCheckboxClick)
        self.runFromCurrentDirCheckbox.SetValue(True)
        self.manualExecutionCheckbox = wx.CheckBox(self, label="Manual Execution")
        self.manualExecutionCheckbox.Bind(wx.EVT_CHECKBOX, self.OnManualExecCheckboxClick)
        self.manualExecutionCheckbox.SetValue(False)
        hbox2.Add(packageLabel, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=10)
        hbox2.Add(self.packageDropdown, proportion=0, flag=wx.EXPAND | wx.RIGHT, border=10)
        hbox2.Add(self.runFromCurrentDirCheckbox, flag=wx.ALIGN_CENTER_VERTICAL)
        hbox2.Add(self.manualExecutionCheckbox, flag=wx.ALIGN_CENTER_VERTICAL)

        # Optional Arguments Input
        hbox3 = wx.BoxSizer(wx.HORIZONTAL)
        argsLabel = wx.StaticText(self, label="Options")
        self.optionsCtrl = wx.TextCtrl(
            self,
            value="option1=value, option2=value, etc...",
            style=wx.TE_PROCESS_ENTER,
        )
        self.optionsCtrl.Bind(wx.EVT_LEFT_DOWN, self.OnOptionInputClick)
        self.optionsCtrl.Bind(wx.EVT_KILL_FOCUS, self.OnOptionInputFocus)
        hbox3.Add(argsLabel, flag=wx.RIGHT, border=5)
        hbox3.Add(self.optionsCtrl, proportion=1, flag=wx.EXPAND)

        hboxHelp = self.AddOptionsHelp()

        # Enforce Timeout heckbox, Timeout, and Minimum and No Hook checkboxes
        hboxTimeout = wx.BoxSizer(wx.HORIZONTAL)
        self.enforceTimeoutCheckbox = wx.CheckBox(self, label="Enforce timeout")
        self.enforceTimeoutCheckbox.Bind(wx.EVT_CHECKBOX, self.OnEnforceTimeoutCheckboxClick)
        self.enforceTimeoutCheckbox.SetValue(False)
        msLabel = wx.StaticText(self, label=" seconds")
        self.timeoutInput = wx.TextCtrl(self, size=wx.Size(50, -1), value="200")
        hboxTimeout.Add(
            self.enforceTimeoutCheckbox,
            flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL,
            border=5,
        )
        hboxTimeout.Add(self.timeoutInput, flag=wx.ALIGN_CENTER_VERTICAL)
        hboxTimeout.Add(msLabel, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=5)
        # Hooking mode. Grouped under a label rather than trailing the timeout controls,
        # so it is clear these two select how much of the monitor is installed. Note that
        # minhook is a capemon option while free is handled analyzer-side
        # (lib/common/abstracts.py), despite sitting together here.
        hboxHooking = wx.BoxSizer(wx.HORIZONTAL)
        hboxHooking.Add(
            wx.StaticText(self, label="Hooking:"),
            flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL,
            border=5,
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
            radio = wx.RadioButton(self, label=label, style=style)
            radio.SetToolTip(tip)
            self.hookSets.append((radio, option))
            hboxHooking.Add(radio, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=10)

        hboxHooking.AddSpacer(10)
        self.free = wx.CheckBox(self, label="free")
        self.free.SetToolTip(
            "Run without the monitor at all (handled by the analyzer, not capemon)"
        )
        self.free.Bind(wx.EVT_CHECKBOX, self.OnFreeChecked)
        hboxHooking.Add(self.free, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=5)

        self.unhookOnExit = wx.CheckBox(self, label="Unhook on exit")
        self.unhookOnExit.SetToolTip(
            "Restore hooked APIs (uninject the monitor) in surviving processes when the "
            "analysis ends, so the machine stays responsive."
        )
        self.unhookOnExit.SetValue(True)
        hboxHooking.Add(self.unhookOnExit, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=5)

        # Monitor logging switches. Laid out as a fixed two-row grid rather than a
        # WrapSizer: wrapping gave no vertical gap between the lines it created (so they
        # collided), stretched whichever control landed last on a line, and left the level
        # dropdowns vertically offset from their checkboxes. The label sits in its own
        # grid column so the second row aligns under the first without measuring fonts.
        # log-bps is an alias of log-breakpoints, so only one of the pair is offered.
        gridLogging = wx.FlexGridSizer(rows=2, cols=2, hgap=12, vgap=6)
        # capemon reads log-exceptions and force-flush with atoi() and tests them against
        # more than one threshold, so both take a level rather than just on/off. The rest
        # are read as value[0] == '1' and are strictly boolean. See capemon config.c.
        self.logExceptions = wx.CheckBox(self, label="log-exceptions")
        self.logExceptions.SetToolTip("Exception logging")
        self.logExceptionsLevel = self._LevelChoice(
            ["1 - error codes only", "2 - all exceptions"],
            "1: only codes >= 0x80000000\n"
            "2: every exception, plus extra detail on access violations",
        )
        self.logVexcept = wx.CheckBox(self, label="log-vexcept")
        self.logVexcept.SetToolTip("Vectored Exception logging")
        self.logBreakpoints = wx.CheckBox(self, label="log-breakpoints")
        self.logBreakpoints.SetToolTip("Breakpoint logging to behavior log")
        self.fullLogs = wx.CheckBox(self, label="full-logs")
        self.fullLogs.SetToolTip("Disable log suppression before network/file access")
        self.forceFlush = wx.CheckBox(self, label="force-flush")
        self.forceFlush.SetToolTip("Flush buffered logs instead of relying on batching")
        self.forceFlushLevel = self._LevelChoice(
            ["1 - after each new API", "2 - after every log"],
            "1: flush after any non-duplicate API call\n2: flush after every log entry",
        )
        self.traceTimes = wx.CheckBox(self, label="trace-times")
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

        # Row one: the plain toggles. Row two: the two that carry a level, each kept next
        # to its dropdown in a pair sizer so the two can never be separated.
        toggleRow = wx.BoxSizer(wx.HORIZONTAL)
        for box in (self.logVexcept, self.logBreakpoints, self.fullLogs, self.traceTimes):
            toggleRow.Add(box, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=12)

        levelRow = wx.BoxSizer(wx.HORIZONTAL)
        for box, level in (
            (self.logExceptions, self.logExceptionsLevel),
            (self.forceFlush, self.forceFlushLevel),
        ):
            box.Bind(wx.EVT_CHECKBOX, self.OnLoggingLevelToggle)
            pair = wx.BoxSizer(wx.HORIZONTAL)
            pair.Add(box, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=6)
            pair.Add(level, flag=wx.ALIGN_CENTER_VERTICAL)
            levelRow.Add(pair, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=24)

        gridLogging.Add(
            wx.StaticText(self, label="Monitor logging:"), flag=wx.ALIGN_CENTER_VERTICAL
        )
        gridLogging.Add(toggleRow, flag=wx.ALIGN_CENTER_VERTICAL)
        gridLogging.AddSpacer(1)
        gridLogging.Add(levelRow, flag=wx.ALIGN_CENTER_VERTICAL)

        # analysis.conf editor
        analysisConfSizer = wx.BoxSizer(wx.VERTICAL)
        self.analysisConfExpander = wx.CollapsiblePane(self, label="analysis.conf")
        self.analysisConfExpander.Bind(wx.EVT_COLLAPSIBLEPANE_CHANGED, self.OnCollapsiblePaneChanged)
        self.analysisConfExpander.GetPane().SetMinSize(self.GetSize())
        analysisConfPane = self.analysisConfExpander.GetPane()
        self.analysisEditor = AnalysisConfPanel(analysisConfPane)
        analysisConfSizer.Add(self.analysisConfExpander, proportion=1, flag=wx.EXPAND | wx.ALL, border=0)
        analysisConfPaneSizer = wx.BoxSizer(wx.VERTICAL)
        analysisConfPaneSizer.Add(self.analysisEditor, proportion=1, flag=wx.EXPAND | wx.ALL, border=0)
        analysisConfPane.SetSizer(analysisConfPaneSizer)
        self.analysisConfExpander.Collapse(True)
        self.OnCollapsiblePaneChanged(None)

        # Debugger Collapsible Pane
        self.debuggerCollapsePane = wx.CollapsiblePane(self, label="Debugger options")
        self.debuggerCollapsePane.Bind(wx.EVT_COLLAPSIBLEPANE_CHANGED, self.OnCollapsiblePaneChanged)
        self.debuggerPane = self.debuggerCollapsePane.GetPane()

        self.flexDebuggerSizer = wx.FlexGridSizer(rows=8, cols=3, hgap=10, vgap=10)
        self.flexDebuggerSizer.AddGrowableCol(1, 1)

        for i in range(4):
            self.debuggerControls[i] = self.AddDebuggerControls(i)

        hboxBaseApi = wx.BoxSizer(wx.HORIZONTAL)
        baseApiLabel = wx.StaticText(self.debuggerPane, label="base-on-api:")
        self.baseApi = wx.TextCtrl(self.debuggerPane, size=wx.Size(98, -1))
        hboxBaseApi.Add(baseApiLabel, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=5)
        hboxBaseApi.Add(self.baseApi, flag=wx.ALIGN_CENTER_VERTICAL)

        hboxBreakRet = wx.BoxSizer(wx.HORIZONTAL)
        breakRetLabel = wx.StaticText(self.debuggerPane, label="break-on-return:")
        self.apiList = wx.TextCtrl(self.debuggerPane, size=wx.Size(158, -1))
        hboxBreakRet.Add(breakRetLabel, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=5)
        hboxBreakRet.Add(self.apiList, flag=wx.ALIGN_CENTER_VERTICAL)

        self.baseAllocCheckbox = wx.CheckBox(self.debuggerPane, label="base-on-alloc")

        hboxCount = wx.BoxSizer(wx.HORIZONTAL)
        countLabel = wx.StaticText(self.debuggerPane, label="count:")
        self.debugCount = wx.TextCtrl(self.debuggerPane, size=wx.Size(75, -1))
        hboxCount.Add(countLabel, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=8)
        hboxCount.Add(self.debugCount, proportion=0, flag=wx.EXPAND)

        hboxDepth = wx.BoxSizer(wx.HORIZONTAL)
        depthLabel = wx.StaticText(self.debuggerPane, label="depth:")
        self.debugDepth = wx.TextCtrl(self.debuggerPane, size=wx.Size(26, -1))
        hboxDepth.Add(depthLabel, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=2)
        hboxDepth.Add(self.debugDepth, proportion=0, flag=wx.EXPAND)

        hCountDepth = wx.BoxSizer(wx.HORIZONTAL)
        hCountDepth.Add(hboxCount, proportion=0, flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT)
        hCountDepth.AddSpacer(10)
        hCountDepth.Add(hboxDepth, proportion=0, flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT)

        self.idbgCheckbox = wx.CheckBox(self.debuggerPane, label="Interactive Debugger")
        self.idbgCheckbox.Bind(wx.EVT_CHECKBOX, self.OnIdbgChecked)

        self.yarascanDisable = wx.CheckBox(self.debuggerPane, label="Disable Monitor Yarascan")

        self.flexDebuggerSizer.AddSpacer(1)
        self.flexDebuggerSizer.AddSpacer(1)
        self.flexDebuggerSizer.AddSpacer(1)
        self.flexDebuggerSizer.Add(hboxBaseApi, proportion=0, flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, border=5)
        self.flexDebuggerSizer.Add(hboxBreakRet, proportion=0, flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, border=5)
        self.flexDebuggerSizer.Add(hCountDepth, proportion=0, flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, border=5)
        self.flexDebuggerSizer.Add(self.baseAllocCheckbox, proportion=0, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=5)
        self.flexDebuggerSizer.Add(self.yarascanDisable, proportion=0, flag=wx.EXPAND)
        self.flexDebuggerSizer.Add(self.idbgCheckbox, proportion=0, flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, border=5)

        debuggerVert = wx.BoxSizer(wx.VERTICAL)
        debuggerVert.Add(self.flexDebuggerSizer, proportion=0, border=1)

        yaraCollapsiblePane = wx.CollapsiblePane(self.debuggerPane, label="Monitor Yara", style=wx.CP_DEFAULT_STYLE)
        yaraCollapsiblePane.Bind(wx.EVT_COLLAPSIBLEPANE_CHANGED, self.OnCollapsiblePaneChanged)
        yaraPane = yaraCollapsiblePane.GetPane()

        self.yaraRule = wx.TextCtrl(yaraPane, style=wx.TE_MULTILINE | wx.HSCROLL | wx.VSCROLL, size=wx.Size(-1, 200))
        self.YaraLoad()
        yaraSaveBtn = wx.Button(yaraPane, label="Save Rule")
        yaraSaveBtn.Bind(wx.EVT_BUTTON, self.OnYaraSave)
        yaraDeleteBtn = wx.Button(yaraPane, label="Delete Rule")
        yaraDeleteBtn.Bind(wx.EVT_BUTTON, self.OnYaraDelete)

        hboxYara = wx.BoxSizer(wx.HORIZONTAL)
        hboxYara.Add(yaraSaveBtn, flag=wx.EXPAND | wx.ALL, border=5)
        hboxYara.Add(yaraDeleteBtn, flag=wx.EXPAND | wx.ALL, border=5)

        vboxYara = wx.BoxSizer(wx.VERTICAL)
        vboxYara.Add(self.yaraRule, proportion=1, flag=wx.EXPAND | wx.ALL, border=5)
        vboxYara.Add(hboxYara, flag=wx.ALIGN_RIGHT | wx.ALL, border=5)

        yaraPane.SetSizer(vboxYara)
        debuggerVert.Add(yaraCollapsiblePane, flag=wx.EXPAND | wx.ALL, border=10)
        self.debuggerPane.SetSizer(debuggerVert)

        # Bottom section
        hbox5 = wx.BoxSizer(wx.HORIZONTAL)
        self.launchAnalyzerBtn = wx.Button(self, label="Launch")
        self.launchAnalyzerBtn.Disable()
        self.launchAnalyzerBtn.Bind(wx.EVT_BUTTON, self.OnLaunchAnalyzer)

        self.staticAnalysis = wx.CheckBox(self, label="Static analysis")
        self.staticAnalysis.SetToolTip("Check this box to enable static code analysis.")

        self.autoProcess = wx.CheckBox(self, label="Auto-process")
        self.autoProcess.SetToolTip("Automatically process and populate the result tabs when a run completes.")
        self.autoProcess.SetValue(True)

        self.jsonReportBtn = wx.Button(self, label="JSON Report")
        self.jsonReportBtn.Disable()
        self.jsonReportBtn.Bind(wx.EVT_BUTTON, self.JsonReport)

        self.htmlReportBtn = wx.Button(self, label="HTML Report")
        self.htmlReportBtn.Disable()
        self.htmlReportBtn.Bind(wx.EVT_BUTTON, self.HtmlReport)

        updateYaraBtn = wx.Button(self, label="Update Yara")
        updateYaraBtn.Bind(wx.EVT_BUTTON, self.OnUpdateYara)

        openDirBtn = wx.Button(self, label="View Analysis Directory")
        openDirBtn.Bind(wx.EVT_BUTTON, self.OnOpenDirectory)
        self.terminateAnalyzerBtn = wx.Button(self, label="Kill")
        self.terminateAnalyzerBtn.Disable()
        self.terminateAnalyzerBtn.Bind(wx.EVT_BUTTON, self.OnTerminateAnalyzer)
        hbox5.Add(self.launchAnalyzerBtn, proportion=0, flag=wx.EXPAND | wx.RIGHT, border=5)
        hbox5.AddSpacer(10)
        hbox5.Add(self.staticAnalysis, proportion=0, flag=wx.EXPAND | wx.RIGHT, border=5)
        hbox5.Add(self.autoProcess, proportion=0, flag=wx.EXPAND | wx.RIGHT, border=5)

        hbox5.AddStretchSpacer(1)
        hbox5.Add(self.jsonReportBtn, proportion=0, flag=wx.EXPAND | wx.RIGHT, border=5)
        hbox5.Add(self.htmlReportBtn, proportion=0, flag=wx.EXPAND | wx.RIGHT, border=5)
        hbox5.Add(updateYaraBtn, proportion=0, flag=wx.EXPAND | wx.RIGHT, border=5)
        hbox5.Add(openDirBtn, proportion=0, flag=wx.EXPAND | wx.RIGHT, border=5)
        hbox5.Add(self.terminateAnalyzerBtn, proportion=0, flag=wx.EXPAND)
        self.terminateAnalyzerBtn.Disable()

        # Layout
        vbox.Add(hbox1, flag=wx.EXPAND | wx.ALL, border=10)
        vbox.Add(dlBox, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=10)
        vbox.Add(hbox2, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=10)
        vbox.Add(hbox3, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=10)
        vbox.Add(hboxHelp, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=10)
        vbox.Add(hboxTimeout, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=10)
        vbox.Add(hboxHooking, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=10)
        vbox.Add(gridLogging, flag=wx.LEFT | wx.RIGHT | wx.BOTTOM, border=10)
        vbox.Add(
            self.debuggerCollapsePane,
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=10,
        )
        vbox.Add(analysisConfSizer, proportion=1, flag=wx.EXPAND | wx.ALL, border=10)
        vbox.Add(
            wx.StaticLine(self, style=wx.LI_HORIZONTAL),
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=10,
        )
        vbox.Add(hbox5, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=10)

        self.SetSizer(vbox)
        # Vertical-only scrolling so the config sections stay reachable when the panel is
        # shorter than its content. SetupScrolling initialises the ScrolledPanel (scroll rate,
        # child-focus scroll), but its FitInside() sets the virtual size from the sizer's min
        # in BOTH axes - that pinned the virtual width to an oversized min (breaking the
        # horizontal fit GrowFrameToFitContent relies on) and left the virtual height below the
        # client height (an unpainted band that ghosted the bottom-row checkboxes). OnPanelSize
        # corrects the virtual size on every resize.
        self.SetupScrolling(scroll_x=False, scroll_y=True)
        self.Bind(wx.EVT_SIZE, self.OnPanelSize)
        apply_theme(self)

    def AddOptionsHelp(self):
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
        helpList = wx.ComboBox(self, style=wx.CB_READONLY)
        helpOptions = sorted(help, key=lambda x: x[0])
        formattedHelp = [f"{name} - {comment}" if comment else name for name, comment in helpOptions]
        helpList.Append("Options Help")
        helpList.AppendItems(formattedHelp)
        helpList.SetSelection(0)
        hbox.Add(helpList, proportion=1, flag=wx.LEFT | wx.ALIGN_CENTER_VERTICAL, border=5)

        return hbox

    def AddDebuggerControls(self, index):
        hboxBp = wx.BoxSizer(wx.HORIZONTAL)
        bpTypes = [f"bp{index}", f"br{index}"]
        bpType = wx.ComboBox(self.debuggerPane, style=wx.CB_READONLY, choices=bpTypes, value=bpTypes[0])
        addrTypeDropdown = wx.ComboBox(self.debuggerPane, style=wx.CB_READONLY, choices=["RVA", "VA", "ep"], value="RVA")
        hexLabel = wx.StaticText(self.debuggerPane, label=": 0x")
        addrTextCtrl = wx.TextCtrl(self.debuggerPane, size=wx.Size(75, -1))
        hboxBp.Add(bpType, proportion=0, flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, border=5)
        hboxBp.Add(
            addrTypeDropdown,
            proportion=0,
            flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT,
            border=0,
        )
        hboxBp.Add(hexLabel, proportion=0, flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, border=0)
        hboxBp.Add(addrTextCtrl, proportion=0, flag=wx.EXPAND)

        hboxAction = wx.BoxSizer(wx.HORIZONTAL)
        actionLabel = wx.StaticText(self.debuggerPane, label=f"action{index}:")
        actionDropdown = wx.ComboBox(self.debuggerPane, style=wx.CB_READONLY, choices=[""])
        actionDropdown.AppendItems(DEBUGACTIONS)
        colon = wx.StaticText(self.debuggerPane, label=":")
        valueTextCtrl = wx.TextCtrl(self.debuggerPane, size=wx.Size(100, -1))
        hboxAction.Add(
            actionLabel,
            proportion=0,
            flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT,
            border=5,
        )
        hboxAction.Add(actionDropdown, proportion=0, flag=wx.RIGHT, border=5)
        hboxAction.Add(colon, proportion=0, flag=wx.RIGHT, border=2)
        hboxAction.Add(valueTextCtrl, proportion=0, flag=wx.EXPAND)

        hboxCount = wx.BoxSizer(wx.HORIZONTAL)
        countLabel = wx.StaticText(self.debuggerPane, label=f"count{index}: ")
        countTextCtrl = wx.TextCtrl(self.debuggerPane, size=wx.Size(75, -1))
        hboxCount.Add(countLabel, proportion=0, flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, border=0)
        hboxCount.Add(countTextCtrl, proportion=0, flag=wx.EXPAND)
        hboxCount.AddSpacer(20)
        hcLabel = wx.StaticText(self.debuggerPane, label=f"hc{index}: ")
        hcTextCtrl = wx.TextCtrl(self.debuggerPane, size=wx.Size(35, -1))
        hboxCount.Add(hcLabel, proportion=0, flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, border=0)
        hboxCount.Add(hcTextCtrl, proportion=0, flag=wx.EXPAND)

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
        self.Layout()
        self.GrowFrameToFitContent()
        # Content height changed, so recompute the scroll range. Guarded because this handler
        # is also fired from InitUi (line ~315) before SetSizer, where there is no sizer yet.
        if self.GetSizer() is not None:
            self._UpdateVirtualSize()
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
        sizer = self.GetSizer()
        if sizer is None:
            return
        client = self.GetClientSize()
        minHeight = sizer.GetMinSize().height
        target = wx.Size(client.width, max(minHeight, client.height))
        # Only set when it actually changes: toggling a vertical scrollbar changes the client
        # width and re-fires EVT_SIZE, so an unconditional set could churn.
        if self.GetVirtualSize() != target:
            self.SetVirtualSize(target)

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
            Files,
            INJECT_LIST,
            disconnect_pipes,
            disconnect_logger,
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
        except IOError as e:
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
            wx.MessageBox(
                f"The file {self.target} does not exist.",
                "Error",
                wx.OK | wx.ICON_ERROR,
            )

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
            except IOError:
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
            wx.MessageBox(f"Could not start the download helper:\n{e}", "Error", wx.OK | wx.ICON_ERROR)
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
        if not self.downloadBroker or self.downloadBroker.poll() is not None:
            wx.MessageBox(
                "Downloads are not available. Restart CAPEsolo and enter the password.",
                "Error",
                wx.OK | wx.ICON_ERROR,
            )
            return
        sampleHash = self.hashInput.GetValue().strip()
        if not sampleHash:
            wx.MessageBox("Enter a sample hash to download.", "Error", wx.OK | wx.ICON_ERROR)
            return
        # Read the destination on the GUI thread; fall back to the configured/default dir.
        dest = self.downloadPathInput.GetValue().strip() or download_dir()
        self.downloadBtn.Disable()  # one download at a time over the single broker pipe
        self.GetMainFrame().statusBar.SetMessage(f"Downloading {sampleHash}...")
        Thread(target=self._DownloadSampleThread, args=(sampleHash, dest), daemon=True).start()

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
                wx.CallAfter(self._OnDownloadDone, Path(reply["path"]), None)
            else:
                wx.CallAfter(self._OnDownloadDone, None, reply.get("error", "unknown error"))
        except Exception as e:
            wx.CallAfter(self._OnDownloadDone, None, str(e))

    def _OnDownloadDone(self, path, error):
        statusBar = self.GetMainFrame().statusBar
        if self.downloadBroker:  # only re-enable if downloads are still available
            self.downloadBtn.Enable()
        if error is not None:
            statusBar.SetMessage("Download failed")
            wx.MessageBox(f"Sample download failed:\n{error}", "Error", wx.OK | wx.ICON_ERROR)
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
        except Exception as e:
            wx.MessageBox(f"Could not terminate analyzer: {e}", "Error", wx.OK | wx.ICON_ERROR)

    def OnLaunchAnalyzer(self, event):
        originalPath = Path(self.targetPath.GetValue())
        newFilename = sanitize_filename(originalPath.name)
        if newFilename != originalPath.name:
            self.target = Path(originalPath.parent, newFilename)
            originalPath.rename(self.target)

        self.CopyTarget()
        self.parent.targetFile = self.targetFile

        if self.staticAnalysis.GetValue():
            wx.MessageBox("Static analysis: Check info, yara, and config tabs.", "Status", wx.OK | wx.ICON_INFORMATION)
            return

        try:
            self.package = self.packageDropdown.GetValue()
            if self.package == "Auto-detect":
                package = self.IdentifyPackage()
                if package:
                    self.package = package
                else:
                    wx.MessageBox(
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
            wx.MessageBox(f"Failed to execute the command: {e}", "Error", wx.OK | wx.ICON_ERROR)

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
                wx.MessageBox(
                    "analysis.conf saved successfully.",
                    "Success",
                    wx.OK | wx.ICON_INFORMATION,
                )
        except IOError as e:
            wx.MessageBox(
                f"Failed to save analysis.conf: {str(e)}",
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

    def _LevelChoice(self, labels, tooltip):
        """Read-only selector for an option whose value is a level, not a flag.

        Labels start with the numeric value capemon expects, which is what gets emitted.
        Disabled until its checkbox is ticked, so it cannot show a level that is not
        being sent.
        """
        choice = wx.Choice(self, choices=labels)
        choice.SetSelection(0)
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
        confirm = wx.MessageBox(
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
                wx.MessageBox(f"YARA rules updated successfully:\n\n{details}", "Update Complete", wx.OK | wx.ICON_INFORMATION)
            else:
                wx.MessageBox("No YARA rules were updated.", "Update Complete", wx.OK | wx.ICON_INFORMATION)

        except Exception as e:
            del busy  # noqa: F821
            wx.MessageBox(f"Failed to update YARA rules:\n{str(e)}", "Error", wx.OK | wx.ICON_ERROR)

    def OnYaraSave(self, event):
        yaraText = self.yaraRule.GetValue()
        savePath = Path(self.capesoloRoot) / "data" / "yara" / "DebuggerRule.yar"

        try:
            savePath.write_text(yaraText)
        except (OSError, IOError) as e:
            wx.MessageBox(
                f"Failed to save Yara rule:\n{e}",
                "Save Failed",
                wx.OK | wx.ICON_ERROR,
            )
            return

        wx.MessageBox(
            f"Yara rule saved to: {str(savePath)}",
            "Save Successful",
            wx.OK | wx.ICON_INFORMATION,
        )

    def OnYaraDelete(self, event):
        yaraPath = Path(self.capesoloRoot) / "data" / "yara" / "DebuggerRule.yar"

        try:
            yaraPath.unlink()
        except FileNotFoundError:
            wx.MessageBox(
                f"Yara rule file not found: {str(yaraPath)}",
                "Delete Failed",
                wx.OK | wx.ICON_ERROR,
            )
            return
        except (OSError, IOError) as e:
            wx.MessageBox(
                f"Failed to delete Yara rule:\n{e}",
                "Delete Failed",
                wx.OK | wx.ICON_ERROR,
            )
            return

        wx.MessageBox(
            f"Yara rule deleted: {str(yaraPath)}",
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
        confirm = wx.MessageBox(
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
                wx.MessageBox(f"JSON report completed successfully.", "JSON Report", wx.OK | wx.ICON_INFORMATION)
            else:
                wx.MessageBox(f"JSON report was unsuccessful: {msg}", "JSON Report", wx.OK | wx.ICON_INFORMATION)

        except Exception as e:
            del busy  # noqa: F821
            wx.MessageBox(f"Failed to create JSON report:\n{str(e)}", "Error", wx.OK | wx.ICON_ERROR)

    def HtmlReport(self, event):
        confirm = wx.MessageBox(
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
                wx.MessageBox(f"HTML report completed successfully.", "HTML Report", wx.OK | wx.ICON_INFORMATION)
            else:
                wx.MessageBox(f"HTML report was unsuccessful: {msg}", "HTML Report", wx.OK | wx.ICON_INFORMATION)

        except Exception as e:
            del busy  # noqa: F821
            wx.MessageBox(f"Failed to create HTML report:\n{str(e)}", "Error", wx.OK | wx.ICON_ERROR)