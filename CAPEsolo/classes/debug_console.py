import bisect
import logging
import re
import struct
from collections import defaultdict
from contextlib import suppress
from queue import Queue
from threading import Condition, Lock, Thread

import pywintypes
import win32event
import win32file
import wx
from distorm3 import Decode, Decode32Bits, Decode64Bits

from CAPEsolo.capelib.api_protos import AppendUserPrototype, LoadPrototypes, ParsePrototypes
from CAPEsolo.capelib.call_args import PROTECT_VALUES, CallArguments, ParseRegisters
from CAPEsolo.capelib.cmdconsts import *
from CAPEsolo.capelib.console_commands import HelpText, ParseCommand
from CAPEsolo.capelib.page_cache import (
    BoundInstructions,
    ContiguousSpan,
    CoversAddress,
    DiffRegions,
    DistantPages,
    FindRegion,
    HotPages,
    PageBase,
    PageChanged,
    PageHash,
    PagesOfSpan,
    SelectWindowPages,
    StalePages,
)
from CAPEsolo.lib.core.pipe import PipeDispatcher, PipeServer, disconnect_pipes

from . import ui_kit as ui
from .debug_controls import (
    BreakpointDialog,
    BreakpointsListCtrl,
    CallStackListCtrl,
    DecodedInstruction,
    DisassemblyListCtrl,
    IsValidHexAddress,
    COMMENT_COL,
    MemDumpListCtrl,
    MemoryListCtrl,
    ModulesListCtrl,
    PrototypeDialog,
    RegsTextCtrl,
    StackListCtrl,
    ProtectText,
    StaticSlotAddress,
    ThreadListCtrl,
)
from .debug_pipe import CommandPipeHandler
from .patch_assembler import Assembler
from .patch_models import PatchEntry
from .theme import ACCENT_ORANGE, BG_CARD, FG_PRIMARY, FG_SECONDARY, FONT_CODE, apply_theme

log = logging.getLogger(__name__)

MAX_LEN = 256
PAGE_SIZE = 4 * 1024
BUFFER_SIZE = 65 * 1024
CHUNK_SIZE = BUFFER_SIZE // 2
# Buffered pages kept either side of CIP before eviction, so the retained cache is bounded
# at (2 * KEEP_PAGES + 1) * PAGE_SIZE regardless of how long the session runs.
KEEP_PAGES = 16
# Smallest a splitter pane may be dragged to, so no view can be collapsed out of reach.
MIN_PANE = 80
# Share of the window the Console/Modules/Threads/Breakpoints row opens at. A fraction rather
# than a row count so a tall window gives it more than the ~7 text rows it used to be fixed
# at; the sash is the user's from then on.
MISC_ROW_FRACTION = 0.28
# Command box history kept per session.
MAX_HISTORY = 100
# Placeholder shown in the empty command box.
COMMAND_HINT = "command, or 'help' for the list"
# Share of the width the left pane of each row opens at, shared by both rows so Disassembly
# and Memory Dump are one column and Registers and Stack are the other. This is the
# Disassembly/Registers split as it already was; the sashes are the user's after that.
LEFT_PANE_FRACTION = 0.6
DBGCMD = "DBGCMD"
# Request tags, sent as a leading "<id>:<purpose>|" field and echoed by capemon in the
# response. Replaces guessing a response's purpose from its length, which could not tell a
# 4-byte pointer read from a 4-byte panel dump, and lets a page load be matched to the
# request that caused it rather than merely counted.
TAG_DUMP = "DUMP"
TAG_FILE = "FILE"
TAG_DEREF = "DEREF"
TAG_STR = "STR"
TAG_STRW = "STRW"
TAG_PAGE = "PAGE"
TAG_PTRS = "PTRS"
# Slot addresses per RD request. capemon caps a reply at MAX_READ_ENTRIES (512) entries, so
# this stays under that and the rest of a larger set goes in further requests.
MAX_READ_BATCH = 256
STALE_MONITOR_MSG = (
    "Untagged debugger response: the monitor is older than this build of CAPEsolo. "
    "Update the monitor dlls."
)
DEBUG_PIPE = r"\\.\pipe\debugger_pipe"
REGISTERS = {
    "RAX",
    "RBX",
    "RCX",
    "RDX",
    "RSI",
    "RDI",
    "RSP",
    "RBP",
    "EAX",
    "EBX",
    "ECX",
    "EDX",
    "ESI",
    "EDI",
    "ESP",
    "EBP",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15",
}
wx.Bell = lambda: None
JMP_CALL_ADDR_RX = re.compile(
    r"\b(?P<mnemonic>jmp|call)\b\s+(?:[A-Za-z_]+\s+)*?(?P<operand>\[[^\]]+\]|0x[0-9A-Fa-f]+)$", re.IGNORECASE
)
# `call mod!Name` once export resolution has rewritten the operand, which is where the
# prototype lookup gets the API name from.
CALL_SYMBOL_RX = re.compile(r"^call\s+(?:[\w.\-]+!)?(?P<symbol>[A-Za-z_][\w@]*)\s*$", re.IGNORECASE)
LEA_MOV_ADDR_RX = re.compile(r"\b(?P<mnemonic>lea|mov)\b\s+(?P<dest>[A-Za-z0-9]+)\s*,\s*(?P<source>\[[^\]]+\])$", re.IGNORECASE)


class DebugConsole:
    """Manages launching the debug console window and communication with the debug server via a named pipe."""

    def __init__(self, parent, title, windowPosition, windowSize):
        self.parent = parent
        self.title = title
        self.windowPosition = windowPosition
        self.windowSize = windowSize
        self.pipe = DEBUG_PIPE
        self.frame = None

        # These shared condition variables and buffers are used by the pipe handler.
        self.breakCondition = Condition()
        self.pendingCommand = None
        self.lastCommand = None
        self.debuggerResponse = None
        self.commandPipe = None

    def OpenConsole(self):
        """Creates (but does not show) the console window."""
        self.frame = ConsoleFrame(self, self.title, self.windowPosition, self.windowSize)
        self.frame.Hide()

    def launch(self):
        """Starts the pipe server and waits for a connection from the debug server."""
        # noinspection PyTypeChecker
        self.commandPipe = PipeServer(
            PipeDispatcher,
            self.pipe,
            message=True,
            dispatcher=CommandPipeHandler(self),
        )
        self.commandPipe.daemon = True
        self.commandPipe.start()
        log.info("[DEBUG CONSOLE] Console pipe server started.")
        self.OpenConsole()
        wx.CallAfter(self.frame.consolePanel.InitPipe)
        log.info("[DEBUG CONSOLE] Console launched.")

    def shutdown(self):
        """Gracefully shuts down the debug console and disconnects any open pipes."""
        if self.frame:
            wx.CallAfter(self.frame.Close)
        disconnect_pipes()


class ConsoleFrame(wx.Frame):
    def __init__(self, parent, title, window_position, window_size):
        super().__init__(None, title=title, pos=window_position, size=window_size)
        self.parent = parent
        self.pipe = parent.pipe
        self.consolePanel = ConsolePanel(self)
        self.Bind(wx.EVT_CLOSE, self.OnClose)

        self.ID_STOP = wx.NewIdRef()
        self.ID_STEP_INTO = wx.NewIdRef()
        self.ID_STEP_OVER = wx.NewIdRef()
        self.ID_STEP_OUT = wx.NewIdRef()
        self.ID_RUN_UNTIL = wx.NewIdRef()
        self.ID_CONTINUE = wx.NewIdRef()
        self.ID_BACK = wx.NewIdRef()
        self.ID_SEARCH = wx.NewIdRef()

        # Space is handled by DisassemblyListCtrl.OnKeyDown, not here: as an accelerator it
        # fired frame-wide and stole activation from whichever button had focus.
        accels = wx.AcceleratorTable(
            [
                (wx.ACCEL_NORMAL, wx.WXK_F4, self.ID_RUN_UNTIL),
                (wx.ACCEL_NORMAL, wx.WXK_F7, self.ID_STEP_INTO),
                (wx.ACCEL_NORMAL, wx.WXK_F8, self.ID_STEP_OVER),
                (wx.ACCEL_NORMAL, wx.WXK_F9, self.ID_STEP_OUT),
                (wx.ACCEL_NORMAL, wx.WXK_F10, self.ID_CONTINUE),
                (wx.ACCEL_NORMAL, wx.WXK_ESCAPE, self.ID_BACK),
                (wx.ACCEL_CTRL, ord("Q"), self.ID_STOP),
                (wx.ACCEL_CMD, ord("F"), self.ID_SEARCH),
            ]
        )
        self.SetAcceleratorTable(accels)
        self.Bind(wx.EVT_MENU, self.consolePanel.OnRunUntilAccel, id=self.ID_RUN_UNTIL)
        self.Bind(wx.EVT_MENU, lambda evt: self.consolePanel.SendCommand(CMD_STEP_INTO), id=self.ID_STEP_INTO)
        self.Bind(wx.EVT_MENU, lambda evt: self.consolePanel.SendCommand(CMD_STEP_OVER), id=self.ID_STEP_OVER)
        self.Bind(wx.EVT_MENU, lambda evt: self.consolePanel.SendCommand(CMD_STEP_OUT), id=self.ID_STEP_OUT)
        self.Bind(wx.EVT_MENU, lambda evt: self.consolePanel.SendCommand(CMD_CONTINUE), id=self.ID_CONTINUE)
        self.Bind(wx.EVT_MENU, lambda evt: self.consolePanel.ShutdownConsole(), id=self.ID_STOP)
        self.Bind(wx.EVT_MENU, self.OnBack, id=self.ID_BACK)
        self.Bind(wx.EVT_MENU, lambda evt: self.consolePanel.OnDialogSearch(), id=self.ID_SEARCH)

    def OnClose(self, event):
        """Handles window close event gracefully."""
        self.consolePanel.ShutdownConsole()
        self.Destroy()

    def OnBack(self, event):
        focused = wx.Window.FindFocus()
        if not focused:
            return

        ctrl = focused
        while ctrl and not isinstance(ctrl, (DisassemblyListCtrl, MemDumpListCtrl, StackListCtrl)):
            ctrl = ctrl.GetParent()

        if hasattr(ctrl, "OnBack"):
            ctrl.OnBack(event)


class ConsolePanel(wx.Panel):
    """A wxPython panel that supports multi-threaded debugging with labeled sections, hotkeys, and logging.

    Threading: the page cache (pageBuffers, pendingPages, pageHashes) and the resolution
    maps are touched only from the wx main thread. PipeLoop is the sole reader thread and it
    marshals every message through wx.CallAfter, and CommandPipeHandler talks to DebugConsole
    via breakCondition rather than to this panel. There is deliberately no lock: the previous
    pageLock was taken by the writers but not by DoHotDecode, so it advertised a guarantee it
    did not provide. Anything moved off the main thread has to reintroduce locking at every
    reader as well.
    """

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.pipe = parent.pipe
        self.pipeHandle = None
        self.connected = False
        self.readLock = Lock()
        self.writeQueue = Queue()
        self.slotCount = 512
        self.initMemDump = True
        self.sashesPlaced = False
        self.inspectedTid = None
        self.cip = None
        self.bits = None
        self.pageBuffers: dict[int, bytes] = {}
        # request tag -> page base, for the page loads still outstanding. Correlating by tag
        # means a late response from an earlier break cannot satisfy this break's request.
        self.pendingPages: dict[str, int] = {}
        # Pages the target reported unreadable. Lets DoHotDecode tell "the bytes have not
        # arrived yet", which a page map refresh can fix, from "the target cannot read them",
        # which it cannot - refreshing on the latter never terminates.
        self.unreadablePages: set[int] = set()
        self.requestId = 0
        # Command box history, oldest first, and where Up/Down currently is in it.
        self.commandHistory: list[str] = []
        self.historyPos = None
        # Whether the command box currently holds the placeholder rather than input.
        self.hintShown = False
        # The page map arrives in pages; these hold the walk in progress. See CollectPageMap.
        self.pageMapPage = 0
        self.pageMapPages: list[str] = []
        self.pageHashes = {}
        # API prototypes, packaged plus whatever has been added, for naming call arguments.
        self.prototypes = LoadPrototypes()
        self.exports: dict[int, str] = {}
        # Sorted export addresses for nearest-symbol lookup, rebuilt when exports grow.
        self.exportAddrs: list[int] = []
        self.exportModules = []
        # Module names already read, so a module list refresh re-queues only what is new.
        self.exportsLoaded: set[str] = set()
        self.export = None
        self.resolvedExports: dict[int, dict[int, str]] = {}
        self.resolvedStrings: dict[int, str] = {}
        self.currentExportsModule = None
        self.exportsPage = 0
        self.moduleRanges = []
        self.patchHistory: list[PatchEntry] = []
        self.patchHistoryByAddr: dict[int, list[PatchEntry]] = defaultdict(list)
        self.dumpFilePath = None
        self.assembler = None
        self.firstBreak = True
        self.CMD_PAGE_MAP = None
        self.CMD_PAGE_LOAD = None
        self.CMD_REG_UPDATE = None
        self.CMD_MEM_DUMP = None
        self.CMD_STACK_UPDATE = None
        self.CMD_CONTINUE = None
        self.CMD_SET_BREAKPOINT = None
        self.CMD_DELETE_BREAKPOINT = None
        self.CMD_BREAKPOINT_LIST = None
        self.CMD_THREADS = None
        self.CMD_MODULE_LIST = None
        self.CMD_EXPORTS = None
        self.CMD_MOD_FLAG = None
        self.CMD_SET_CIP = None
        self.CMD_NOP_INSTRUCTION = None
        self.CMD_PATCH_BYTES = None
        self.InitGUI()

    def InitGUI(self):
        # Main Layout
        MAX_BTN_W = 120
        mainSizer = wx.BoxSizer(wx.VERTICAL)
        fontCourier = FONT_CODE

        # The four main views live in splitter panes so their boundaries can be dragged; the
        # panes were fixed sizer proportions before. Controls that call back into this panel
        # are given console=self, because their wx parent is now a pane rather than the panel.
        # The Console/Modules/Threads/Breakpoints row is a pane of its own rather than a
        # proportion-0 sizer entry, which pinned it to exactly its minimum height with no way
        # to drag it taller.
        self.outerSplitter = wx.SplitterWindow(self, style=wx.SP_LIVE_UPDATE | wx.SP_3DSASH)
        self.paneSplitter = wx.SplitterWindow(self.outerSplitter, style=wx.SP_LIVE_UPDATE | wx.SP_3DSASH)
        self.topSplitter = wx.SplitterWindow(self.paneSplitter, style=wx.SP_LIVE_UPDATE | wx.SP_3DSASH)
        self.bottomSplitter = wx.SplitterWindow(self.paneSplitter, style=wx.SP_LIVE_UPDATE | wx.SP_3DSASH)
        for splitter in (self.outerSplitter, self.paneSplitter, self.topSplitter, self.bottomSplitter):
            splitter.SetMinimumPaneSize(MIN_PANE)

        # Disassembly
        disasmPane = wx.Panel(self.topSplitter)
        consoleSizer = wx.BoxSizer(wx.VERTICAL)
        consoleSizer.Add(wx.StaticText(disasmPane, label="Disassembly Console"), 0, wx.ALL, 5)
        self.disassemblyConsole = DisassemblyListCtrl(disasmPane, console=self)
        self.disassemblyConsole.SetFont(fontCourier)
        consoleSizer.Add(self.disassemblyConsole, 1, wx.EXPAND | wx.ALL, 5)
        disasmPane.SetSizer(consoleSizer)

        # Registers
        regsPane = wx.Panel(self.topSplitter)
        regsSizer = wx.BoxSizer(wx.VERTICAL)
        regsSizer.Add(wx.StaticText(regsPane, label="Registers"), 0, wx.ALL, 5)
        self.threadBanner = wx.StaticText(regsPane, label="")
        self.threadBanner.Hide()
        regsSizer.Add(self.threadBanner, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM, 5)
        self.regsDisplay = RegsTextCtrl(regsPane, style=wx.TE_MULTILINE | wx.TE_READONLY, console=self)
        self.regsDisplay.SetFont(fontCourier)
        regsSizer.Add(self.regsDisplay, 1, wx.EXPAND | wx.ALL, 5)
        regsPane.SetSizer(regsSizer)

        # Memory Dump
        memPane = wx.Panel(self.bottomSplitter)
        memSizer = wx.BoxSizer(wx.VERTICAL)
        memSizer.Add(wx.StaticText(memPane, label="Memory Dump"), 0, wx.ALL, 5)
        self.memDumpDisplay = MemDumpListCtrl(memPane, console=self)
        self.memDumpDisplay.SetFont(fontCourier)
        memSizer.Add(self.memDumpDisplay, 1, wx.EXPAND | wx.ALL, 5)

        # Address input field
        memInput = wx.BoxSizer(wx.HORIZONTAL)
        memInput.Add(wx.StaticText(memPane, label="Memory Dump Address:"), 0, wx.LEFT | wx.ALIGN_CENTER_VERTICAL, 5)
        memAddressField = ui.Field(memPane, style=wx.TE_PROCESS_ENTER)
        # The console reads and writes the TextCtrl directly, so keep memAddressInput
        # pointing at it and lay out the drawn wrapper.
        self.memAddressInput = memAddressField.ctrl
        self.memAddressInput.SetFont(fontCourier)
        memInput.Add(memAddressField, 1, wx.EXPAND | wx.ALL, 5)
        self.memAddressInput.Bind(wx.EVT_TEXT_ENTER, self.OnAddressEnter)

        # Dump to File button
        btnDumpToFile = ui.Button(memPane, label="Dump Memory to File")
        btnDumpToFile.Bind(wx.EVT_BUTTON, self.OnDumpToFile)
        memInput.Add(btnDumpToFile, 0, wx.LEFT | wx.ALIGN_CENTER_VERTICAL, 5)
        memSizer.Add(memInput, 0, wx.EXPAND | wx.ALL, 5)
        memPane.SetSizer(memSizer)

        # Stack and Call Stack share the pane: raw stack words answer "what is on the
        # stack", walked frames answer "how did execution get here".
        stackPane = wx.Panel(self.bottomSplitter)
        stackSizer = wx.BoxSizer(wx.VERTICAL)
        self.stackNotebook = wx.Notebook(stackPane)

        rawPage = wx.Panel(self.stackNotebook)
        rawSizer = wx.BoxSizer(wx.VERTICAL)
        self.stackDisplay = StackListCtrl(rawPage, console=self)
        self.stackDisplay.SetFont(fontCourier)
        rawSizer.Add(self.stackDisplay, 1, wx.EXPAND | wx.ALL, 3)
        rawPage.SetSizer(rawSizer)
        self.stackNotebook.AddPage(rawPage, "Stack")

        framePage = wx.Panel(self.stackNotebook)
        frameSizer = wx.BoxSizer(wx.VERTICAL)
        self.callStackDisplay = CallStackListCtrl(framePage, console=self)
        self.callStackDisplay.SetFont(fontCourier)
        frameSizer.Add(self.callStackDisplay, 1, wx.EXPAND | wx.ALL, 3)
        framePage.SetSizer(frameSizer)
        self.stackNotebook.AddPage(framePage, "Call Stack")

        stackSizer.Add(self.stackNotebook, 1, wx.EXPAND | wx.ALL, 5)
        stackPane.SetSizer(stackSizer)

        # Gravity keeps the old proportions when the window itself is resized; the sash
        # positions are set once the panel has a real size, in _InitSashes. Both vertical
        # sashes take the same gravity as well as the same start, or a window resize would
        # pull the two columns back out of line.
        self.topSplitter.SplitVertically(disasmPane, regsPane)
        self.topSplitter.SetSashGravity(LEFT_PANE_FRACTION)
        self.bottomSplitter.SplitVertically(memPane, stackPane)
        self.bottomSplitter.SetSashGravity(LEFT_PANE_FRACTION)
        self.paneSplitter.SplitHorizontally(self.topSplitter, self.bottomSplitter)
        self.paneSplitter.SetSashGravity(0.5)

        # Console box
        miscPane = wx.Panel(self.outerSplitter)
        consoleSizer = wx.BoxSizer(wx.VERTICAL)
        self.outputConsole = wx.TextCtrl(miscPane, style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.outputConsole.SetFont(fontCourier)
        charH = self.outputConsole.GetCharHeight()
        # A floor now, not the height: the row's height is the sash position. These were
        # charH * 7, which was the only thing giving the row any height at all and therefore
        # also the smallest it could ever be.
        minRow = wx.Size(-1, charH * 3)
        self.outputConsole.SetMinSize(minRow)
        consoleSizer.Add(wx.StaticText(miscPane, label="Console Output"), 0, wx.ALL, 5)
        consoleSizer.Add(self.outputConsole, 1, wx.EXPAND | wx.ALL, 5)

        # Modules and Memory share the pane the way Stack and Call Stack do: what is loaded
        # and what has just been allocated are both "where did this code come from" questions.
        modulesSizer = wx.BoxSizer(wx.VERTICAL)
        self.modulesNotebook = wx.Notebook(miscPane)

        modulesPage = wx.Panel(self.modulesNotebook)
        modulesPageSizer = wx.BoxSizer(wx.VERTICAL)
        self.modulesDisplay = ModulesListCtrl(modulesPage, console=self)
        self.modulesDisplay.SetFont(fontCourier)
        modulesPageSizer.Add(self.modulesDisplay, 1, wx.EXPAND | wx.ALL, 3)
        modulesPage.SetSizer(modulesPageSizer)
        self.modulesNotebook.AddPage(modulesPage, "Modules")

        memoryPage = wx.Panel(self.modulesNotebook)
        memoryPageSizer = wx.BoxSizer(wx.VERTICAL)
        self.memoryDisplay = MemoryListCtrl(memoryPage, console=self)
        self.memoryDisplay.SetFont(fontCourier)
        memoryPageSizer.Add(self.memoryDisplay, 1, wx.EXPAND | wx.ALL, 3)
        memoryPage.SetSizer(memoryPageSizer)
        self.modulesNotebook.AddPage(memoryPage, "Memory")

        self.modulesNotebook.SetMinSize(minRow)
        modulesSizer.Add(self.modulesNotebook, 1, wx.EXPAND | wx.ALL, 5)

        # Threads List View
        threadsSizer = wx.BoxSizer(wx.VERTICAL)
        threadsSizer.Add(wx.StaticText(miscPane, label="Threads"), 0, wx.ALL, 5)
        self.threadsDisplay = ThreadListCtrl(miscPane, console=self)
        self.threadsDisplay.SetFont(fontCourier)
        self.threadsDisplay.SetMinSize(minRow)
        threadsSizer.Add(self.threadsDisplay, 1, wx.EXPAND | wx.ALL, 5)

        # Breakpoints List View
        bpsSizer = wx.BoxSizer(wx.VERTICAL)
        bpsSizer.Add(wx.StaticText(miscPane, label="Breakpoints"), 0, wx.ALL, 5)
        self.breakpointsDisplay = BreakpointsListCtrl(miscPane, console=self)
        self.breakpointsDisplay.SetFont(fontCourier)
        self.breakpointsDisplay.SetMinSize(minRow)
        bpsSizer.Add(self.breakpointsDisplay, 1, wx.EXPAND | wx.ALL, 5)

        miscSizer = wx.BoxSizer(wx.HORIZONTAL)
        miscSizer.Add(consoleSizer, 2, wx.EXPAND | wx.ALL)
        miscSizer.Add(modulesSizer, 4, wx.EXPAND | wx.ALL)
        miscSizer.Add(threadsSizer, 2, wx.EXPAND | wx.ALL)
        miscSizer.Add(bpsSizer, 2, wx.EXPAND | wx.ALL)
        miscPane.SetSizer(miscSizer)

        # Gravity 1.0: the views absorb everything a window resize adds, so the row stays the
        # height it was dragged to instead of growing with the window.
        self.outerSplitter.SplitHorizontally(self.paneSplitter, miscPane)
        self.outerSplitter.SetSashGravity(1.0)
        mainSizer.Add(self.outerSplitter, 1, wx.EXPAND | wx.ALL, 5)

        # Input box
        inputSizer = wx.BoxSizer(wx.HORIZONTAL)
        inputSizer.Add(wx.StaticText(self, label="Command Input:"), 0, wx.LEFT | wx.ALIGN_CENTER_VERTICAL, 5)
        inputField = ui.Field(self, style=wx.TE_PROCESS_ENTER)
        # The hint text, history and key handling all drive the TextCtrl, so inputBox keeps
        # pointing at it.
        self.inputBox = inputField.ctrl
        self.inputBox.Bind(wx.EVT_TEXT_ENTER, self.OnEnter)
        self.inputBox.Bind(wx.EVT_KEY_DOWN, self.OnInputKey)
        self.inputBox.Bind(wx.EVT_SET_FOCUS, self.OnInputFocus)
        self.inputBox.Bind(wx.EVT_KILL_FOCUS, self.OnInputBlur)
        inputSizer.Add(inputField, 1, wx.EXPAND | wx.ALL, 5)

        # Debugging Controls
        debugButtons = wx.BoxSizer(wx.HORIZONTAL)
        self.runUntilBtn = ui.Button(self, label="Run Until (F4)")
        self.stepIntoBtn = ui.Button(self, label="Step Into (F7)")
        self.stepOverBtn = ui.Button(self, label="Step Over (F8)")
        self.stepOutBtn = ui.Button(self, label="Step Out (F9)")
        self.continueBtn = ui.Button(self, label="Continue (F10)", variant=ui.PRIMARY)
        self.runUntilBtn.SetMinSize(wx.Size(MAX_BTN_W, -1))
        self.runUntilBtn.Bind(wx.EVT_BUTTON, self.OnRunUntilAccel)
        debugButtons.Add(self.runUntilBtn, 0, wx.LEFT | wx.BOTTOM, 5)
        for btn, cmd in (
            (self.stepIntoBtn, CMD_STEP_INTO),
            (self.stepOverBtn, CMD_STEP_OVER),
            (self.stepOutBtn, CMD_STEP_OUT),
            (self.continueBtn, CMD_CONTINUE),
        ):
            btn.SetMinSize(wx.Size(MAX_BTN_W, -1))
            btn.Bind(wx.EVT_BUTTON, lambda evt, c=cmd: self.SendCommand(c))
            debugButtons.Add(btn, 0, wx.LEFT | wx.BOTTOM, 5)

        inputSizer.Add(debugButtons, 0, wx.ALIGN_CENTER_VERTICAL | wx.LEFT, 10)

        # Status Bar
        self.statusBar = wx.StaticText(self, label="Status: Disconnected")
        inputSizer.AddStretchSpacer()
        inputSizer.Add(self.statusBar, 0, wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, 5)

        mainSizer.Add(inputSizer, 0, wx.EXPAND)

        self.SetSizer(mainSizer)
        apply_theme(self)
        # SplitterWindow is not a wx.Panel, so apply_theme leaves the sash the native grey.
        for splitter in (self.outerSplitter, self.paneSplitter, self.topSplitter, self.bottomSplitter):
            splitter.SetBackgroundColour(BG_CARD)

        # After apply_theme, which sets every TextCtrl's foreground to FG_PRIMARY and would
        # otherwise repaint the placeholder as though it were typed input.
        self.ShowInputHint()

        self.Bind(wx.EVT_SIZE, self.OnSize)

    def OnSize(self, event):
        """Place the sashes on the first real size event, then leave them to the user.

        Sash positions cannot be set meaningfully in InitGUI because the panel has no size
        yet, and re-applying them on every resize would fight whatever the user has dragged.
        """
        event.Skip()
        if self.sashesPlaced:
            return

        # Measured on the outermost splitter, and the inner sashes are derived from the height
        # left above its sash rather than re-measured: setting a sash resizes the child
        # splitters, and reading their size back in the same handler would depend on when wx
        # has got round to that.
        width, height = self.outerSplitter.GetClientSize()
        if width <= MIN_PANE * 2 or height <= MIN_PANE * 4:
            return

        self.sashesPlaced = True
        viewsHeight = height - int(height * MISC_ROW_FRACTION)
        self.outerSplitter.SetSashPosition(viewsHeight)
        self.paneSplitter.SetSashPosition(int(viewsHeight * 0.5))
        # One position for both, so Disassembly lines up with Memory Dump and Registers with
        # Stack. The Memory Dump sash used to start at 0.7 and sat proud of the one above it.
        self.topSplitter.SetSashPosition(int(width * LEFT_PANE_FRACTION))
        self.bottomSplitter.SetSashPosition(int(width * LEFT_PANE_FRACTION))

    def IsAddressKnown(self, addr: int) -> bool:
        pageMap = getattr(self.disassemblyConsole, "pageMap", None)
        if not pageMap:
            return False

        return FindRegion(pageMap, addr) is not None

    def PromptBreakpoint(self, address=""):
        """Ask for breakpoint details and set it. Shared by every entry point."""
        if isinstance(address, int):
            address = f"{address:#x}"

        dlg = BreakpointDialog(self, address or "")
        try:
            if dlg.ShowModal() != wx.ID_OK:
                return

            values = dlg.GetValues()
        finally:
            dlg.Destroy()

        if values is None:
            return

        slot, bpType, size, addr = values
        self.SendCommand(CMD_SET_BREAKPOINT, f"{slot}|{addr:#X}|{bpType}|{size}")

    def OnRunUntilAccel(self, event):
        row = self.disassemblyConsole.GetNextItem(-1, wx.LIST_NEXT_ALL, wx.LIST_STATE_SELECTED)
        if row == -1:
            row = self.disassemblyConsole.GetCipRow(self.cip)

        if row == -1:
            ui.message("No valid address to Run Until.", "Error", wx.OK | wx.ICON_ERROR)
            return

        self.disassemblyConsole.OnRunUntil(row)

    def OnAddressEnter(self, event):
        self.memAddr = self.memAddressInput.GetValue().strip()
        if self.memAddr:
            self.SendCommand(CMD_MEM_DUMP, self.memAddr, tag=self.NextTag(TAG_DUMP))

        event.Skip()

    def OnDumpToFile(self, event):
        addrStr = wx.GetTextFromUser("Enter starting address (hex or decimal):", "Dump to File")
        if not addrStr:
            return

        try:
            addr = int(addrStr, 0)
        except ValueError:
            ui.message("Invalid address format.", "Error", wx.OK | wx.ICON_ERROR)
            return

        sizeStr = wx.GetTextFromUser("Enter dump size in bytes (hex or decimal):", "Dump to File")
        if not sizeStr:
            return

        try:
            size = int(sizeStr, 0)
        except ValueError:
            ui.message("Invalid size format.", "Error", wx.OK | wx.ICON_ERROR)
            return

        formats = ["Binary file (*.bin)", "Text file (*.txt)"]
        with wx.SingleChoiceDialog(self, "Select output format:", "Dump to File", formats) as choiceDialog:
            if choiceDialog.ShowModal() != wx.ID_OK:
                return
            formatChoice = choiceDialog.GetStringSelection()

        wildcard = "Text files (*.txt)|*.txt"
        if "Binary" in formatChoice:
            wildcard = "Binary files (*.bin)|*.bin"

        with wx.FileDialog(
            self,
            "Save Memory Dump",
            wildcard=wildcard,
            style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT,
        ) as fileDialog:
            if fileDialog.ShowModal() == wx.ID_CANCEL:
                return

            self.dumpFilePath = fileDialog.GetPath()

        self.SendCommand(CMD_MEM_DUMP, f"{addr:#x}|{size:#x}", tag=self.NextTag(TAG_FILE))

    def WriteMemToFile(self, data):
        try:
            if self.dumpFilePath.endswith(".bin"):
                with open(self.dumpFilePath, "wb") as f:
                    f.write(bytes.fromhex(data))
            else:
                with open(self.dumpFilePath, "w", encoding="utf-8") as f:
                    f.write(data)

            ui.message(f"Memory dumped successfully to:\n{self.dumpFilePath}", "Success", wx.OK | wx.ICON_INFORMATION)
        except Exception as e:
            ui.message(f"Failed to dump memory: {e}", "Error", wx.OK | wx.ICON_ERROR)


    def AppendConsole(self, text: str):
        """Appends text to the output console."""
        if not isinstance(text, str):
            return

        self.outputConsole.AppendText(text + "\n")

    def UpdateRegs(self, text):
        """Update registers display."""
        self.regsDisplay.Clear()
        self.regsDisplay.SetValue(text)
        regsText = self.regsDisplay.GetValue()
        m = re.search(r"\b([ER]IP):\s*([0-9A-Fa-f]+)", regsText)
        # Never drop a known-good CIP: this runs on every break, and nulling it here blanks
        # the disassembly highlight and takes GetCipRow/DoHotDecode down with it.
        if m:
            self.cip = int(m.group(2), 16)
        else:
            log.warning("[DEBUG CONSOLE] No instruction pointer in register payload; keeping the previous CIP")
        if not self.bits:
            self.bits = 64 if "RAX" in regsText else 32
            self.assembler = Assembler(self.bits)

    def UpdateStack(self, data):
        """Update stack display."""
        self.stackDisplay.UpdateData(data)

    def UpdateMemDump(self, data):
        """Update memory dump display."""
        self.memDumpDisplay.UpdateData(data)

    def UpdateThreads(self, data):
        """Update memory dump display."""
        self.threadsDisplay.UpdateData(data)

    def UpdateBreakpoints(self, data):
        """Update breakpoints display."""
        self.breakpointsDisplay.UpdateData(data)

    def UpdateModules(self, data):
        """Update modules display."""
        self.modulesDisplay.UpdateData(data)

    def UpdateStatus(self, status):
        self.statusBar.SetLabel(status)

    def InitPipe(self):
        Thread(target=self.WriteLoop, daemon=True).start()
        Thread(target=self.PipeLoop, daemon=True).start()

    def PipeLoop(self):
        try:
            self.pipeHandle = win32file.CreateFile(
                self.pipe,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0,
                None,
                win32file.OPEN_EXISTING,
                win32file.FILE_FLAG_OVERLAPPED,
                None,
            )
            log.info("[DEBUG CONSOLE] Console connected to named pipe.")
        except Exception as e:
            log.error("[DEBUG CONSOLE] Console failed to connect to named pipe: %s", e)

        self.SendInit()
        while True:
            msg = self.ReadResponse()
            if msg is None:
                break

            if not msg:
                continue

            wx.CallAfter(self.ProcessServerOutput, msg)

        # The read failing is usually how this loop ends, and a disconnect is one of the
        # reasons it fails - by which point the handle is already closed and cleared.
        self.ClosePipe()
        log.info("[DEBUG CONSOLE] Reader thread exiting, pipe closed.")

    def SendInit(self):
        if not self.pipeHandle:
            return

        log.info("[DEBUG CONSOLE] Sending init command...")
        self.SendCommand("init")

    def ReadResponse(self):
        """Reads a full response from the pipe in a thread-safe manner."""
        with self.readLock:
            if not self.pipeHandle:
                return None

            try:
                _, data = win32file.ReadFile(self.pipeHandle, BUFFER_SIZE)
                response = data.decode("utf-8").strip()
                return response
            except Exception as e:
                log.error("[DEBUG CONSOLE] Reading response: %s", e)
                return None

    def NextTag(self, purpose: str) -> str:
        """Allocate a request tag; the id disambiguates two requests of the same purpose."""
        self.requestId += 1
        return f"{self.requestId}:{purpose}"

    def SendCommand(self, command, data="", tag=None):
        if command.lower() != "init" and (not self.connected or not self.pipeHandle):
            log.error("[DEBUG CONSOLE] Cannot send command: Not connected to pipe")
            return

        if tag:
            data = f"{tag}|{data}"

        fullCommand = f"{DBGCMD}:{command.upper()}:{data}".encode() + b"\n"
        self.writeQueue.put(fullCommand)

    def WriteLoop(self):
        """Serialise pipe writes.

        A thread per command meant RefreshViewState's five commands raced each other onto the
        same handle, so the debug server received them in an arbitrary order.
        """
        while True:
            buffer = self.writeQueue.get()
            if buffer is None:
                return

            self.BackgroundWrite(buffer, 5000)

    def BackgroundWrite(self, buffer, timeout=win32event.INFINITE):
        if not self.pipeHandle:
            log.error("[DEBUG CONSOLE] Dropping command: pipe is closed")
            return

        overlapped = pywintypes.OVERLAPPED()
        overlapped.hEvent = win32event.CreateEvent(None, 0, 0, None)
        try:
            win32file.WriteFile(self.pipeHandle, buffer, overlapped)
            rc = win32event.WaitForSingleObject(overlapped.hEvent, timeout)
            if rc != win32event.WAIT_OBJECT_0:
                log.error("[DEBUG CONSOLE] Write timed out or failed: %s", rc)
            else:
                win32file.GetOverlappedResult(self.pipeHandle, overlapped, True)
        except pywintypes.error as e:
            log.error("[DEBUG CONSOLE] Pipe write error: %s", e)
        finally:
            if overlapped.hEvent:
                win32file.CloseHandle(overlapped.hEvent)

    def OnEnter(self, event):
        """Run one line from the command box.

        Everything typed is parsed and validated before anything is sent. The box used to
        send the command word alone - the arguments were parsed into a variable and then
        dropped, so `md 0x401000` dumped at CIP and `ru 0x401000` reached the monitor with no
        address - and anything unrecognised was uppercased and sent for the target to reject.
        """
        # The placeholder is real text in the control, so it has to be ruled out here rather
        # than trusted not to arrive: focus events are what normally clear it, and a path that
        # reaches Enter without one would otherwise submit the hint as a command.
        inputText = "" if self.hintShown else self.inputBox.GetValue().strip()
        self.inputBox.Clear()
        event.Skip()
        if not inputText:
            return

        # Re-entering a command moves it to the newest end rather than adding a duplicate, and
        # the list is capped so a long session does not accumulate one entry per keystroke of
        # trial and error. A rejected line is kept: Up is how you fix a typo.
        self.commandHistory = [h for h in self.commandHistory if h != inputText] + [inputText]
        del self.commandHistory[:-MAX_HISTORY]
        self.historyPos = None

        code, payload, error = ParseCommand(inputText)
        if error:
            self.AppendConsole(error)
            return

        if code is None:
            if payload is not None:
                self.RunLocalCommand(payload)

            return

        self.AppendConsole(f"> {inputText}")
        self.SendCommand(code, payload)

    def RunLocalCommand(self, name: str):
        """A command the console answers itself rather than sending to the target."""
        if name == "help":
            self.AppendConsole(HelpText())
        elif name == "clear":
            self.outputConsole.Clear()
        elif name == "disconnect":
            # Cleared before closing, so nothing queues a write against a handle that is
            # about to go.
            self.connected = False
            self.ClosePipe()
            wx.CallAfter(self.statusBar.SetLabel, "Status: Disconnected")
            log.info("[DEBUG CONSOLE] Pipe disconnected successfully.")
        elif name == "quit":
            # Letting the target run on is only possible while there is a pipe to say so on.
            # After a disconnect this used to be attempted anyway and logged a failure to
            # send, which reads like a fault rather than the consequence of disconnecting.
            if self.connected:
                self.SendCommand(CMD_CONTINUE)
            else:
                self.AppendConsole("Already disconnected; the target is left as it is.")

            self.ShutdownConsole()

    def ShowInputHint(self):
        """Put the placeholder in the command box, in muted text, when it is empty.

        Done by hand rather than with SetHint. wx installs its hint by setting the control's
        foreground to the system grey-text colour, and apply_theme runs afterwards and sets
        every TextCtrl's foreground to FG_PRIMARY - so the placeholder came out the same
        colour as real input, reading like something you had to delete before typing.

        Using the theme's own muted colour also keeps it consistent with the other things
        this UI greys out: a freed region in the memory view, an exited process in the tree.
        """
        if self.inputBox.GetValue():
            # Real content. Normally the focus that preceded it cleared the hint, but a value
            # set without one - history recall, anything programmatic - would otherwise leave
            # the muted colour on text the user actually typed.
            if self.hintShown:
                self.hintShown = False
                self.inputBox.SetForegroundColour(FG_PRIMARY)

            return

        self.hintShown = True
        self.inputBox.SetForegroundColour(FG_SECONDARY)
        # ChangeValue, not SetValue: this must not look like the user typing.
        self.inputBox.ChangeValue(COMMAND_HINT)

    def ClearInputHint(self):
        if not self.hintShown:
            return

        self.hintShown = False
        self.inputBox.ChangeValue("")
        self.inputBox.SetForegroundColour(FG_PRIMARY)

    def OnInputFocus(self, event):
        self.ClearInputHint()
        event.Skip()

    def OnInputBlur(self, event):
        self.ShowInputHint()
        event.Skip()

    def OnInputKey(self, event):
        """Up and Down walk the command history, as a command box is expected to."""
        key = event.GetKeyCode()
        if key not in (wx.WXK_UP, wx.WXK_DOWN) or not self.commandHistory:
            event.Skip()
            return

        if key == wx.WXK_UP:
            self.historyPos = len(self.commandHistory) - 1 if self.historyPos is None else max(0, self.historyPos - 1)
        elif self.historyPos is None:
            return
        else:
            self.historyPos += 1
            if self.historyPos >= len(self.commandHistory):
                # Past the newest entry is the empty line you started from.
                self.historyPos = None
                self.inputBox.SetValue("")
                self.inputBox.SetInsertionPointEnd()
                return

        self.inputBox.SetValue(self.commandHistory[self.historyPos])
        self.inputBox.SetInsertionPointEnd()

    def ShutdownConsole(self):
        """Handles graceful shutdown of the console."""
        self.close()
        self.parent.Close()

    def ClosePipe(self):
        """Close the pipe handle, once, if it is still open.

        The only place that closes it. Three places used to, with three degrees of care: the
        disconnect command closed the handle and left it set, so close() went on to close it
        again and PipeLoop's teardown did the same with no guard at all. One disconnect
        followed by one quit logged several errors between them.

        The handle is taken and cleared in one step because the reader thread tears down at
        the same time as whatever asked it to, and only one of them should do the closing.
        """
        handle, self.pipeHandle = self.pipeHandle, None
        if not handle:
            return

        try:
            win32file.CloseHandle(handle)
        except Exception as e:
            log.error("[DEBUG CONSOLE] Error closing pipe handle: %s", e)
        else:
            log.info("[DEBUG CONSOLE] Pipe handle closed")

    def close(self):
        """Stops the reading thread."""
        self.connected = False
        self.writeQueue.put(None)
        self.ClosePipe()

    def RefreshViewState(self):
        if self.inspectedTid is not None:
            self.inspectedTid = None
            self.ShowThreadBanner(None)

        self.SendCommand(CMD_REG_UPDATE)
        if self.initMemDump:
            self.SendCommand(CMD_MEM_DUMP, tag=self.NextTag(TAG_DUMP))
            self.initMemDump = False
        else:
            # Re-dump whatever region is on screen. This used to overwrite the address box
            # and fire a synthetic EVT_TEXT_ENTER, which blanked the field on every break.
            addr = self.memDumpDisplay.GetFirstHexAddress()
            if addr is not None:
                self.SendCommand(CMD_MEM_DUMP, addr, tag=self.NextTag(TAG_DUMP))

        self.SendCommand(CMD_STACK_UPDATE)
        self.SendCommand(CMD_CALL_STACK)
        self.SendCommand(CMD_THREADS)
        self.SendCommand(CMD_BREAKPOINT_LIST)

    def RefreshPageMap(self):
        """Start a fresh page map walk at page 0, abandoning any that was part-way through."""
        self.pageMapPage = 0
        self.pageMapPages = []
        self.SendCommand(CMD_PAGE_MAP, "0")

    def RefreshModuleList(self):
        self.SendCommand(CMD_MODULE_LIST)

    def DispatchCommand(self, command, payload):
        """Dispatch commands to their respective handlers."""
        handlers = {
            CMD_PAGE_MAP: self.HandlePageMap,
            CMD_PAGE_LOAD: self.HandlePageLoad,
            CMD_REG_UPDATE: self.HandleRegUpdate,
            CMD_MEM_DUMP: self.HandleMemDump,
            CMD_READ_POINTERS: self.HandleReadPointers,
            CMD_STACK_UPDATE: self.HandleStackUpdate,
            CMD_CALL_STACK: self.HandleCallStack,
            CMD_THREAD_INSPECT: self.HandleThreadInspect,
            CMD_SET_BREAKPOINT: self.HandleSetBreakpoint,
            CMD_DELETE_BREAKPOINT: self.HandleDeleteBreakpoint,
            CMD_BREAKPOINT_LIST: self.HandleBreakpointsList,
            CMD_THREADS: self.HandleThreads,
            CMD_MODULE_LIST: self.HandleModules,
            CMD_EXPORTS: self.HandleExports,
            CMD_SET_REGISTER: self.HandleSetRegister,
            CMD_MOD_FLAG: self.HandleModFlag,
            CMD_NOP_INSTRUCTION: self.HandleNopInstruction,
            CMD_PATCH_BYTES: self.HandlePatchBytes,
        }

        if command in CMD_CONSOLE:
            self.HandleConsoleOutput(payload)
            return

        if command in CMD_EXECUTION:
            self.HandleExecution(payload)
            return

        handler = handlers.get(command)
        if handler:
            handler(payload)
        else:
            log.warning("[DEBUG CONSOLE] Unknown command '%s' received", command)

    def RequestPage(self, pageBase: int):
        tag = self.NextTag(TAG_PAGE)
        self.pendingPages[tag] = pageBase
        self.SendCommand(CMD_PAGE_LOAD, hex(pageBase), tag=tag)

    def JumpTo(self, address: int):
        """Use pageMap to find page."""
        self.cip = address
        if not self.AddressInModules(address):
            self.RefreshModuleList()

        region = self.disassemblyConsole.FindPage(address)
        if region is None:
            self.RefreshPageMap()
            return

        pages = SelectWindowPages(self.disassemblyConsole.pageMap, self.cip, PAGE_SIZE, CHUNK_SIZE)
        if not pages:
            log.error("[DEBUG CONSOLE] No valid pages found for address %#x", address)
            return

        # Landing outside every buffered page means a jump to a different region, so nothing
        # held is worth keeping. Within a region the cache is retained: re-reading the whole
        # 36 KB window took ~9 pipe round-trips to advance one instruction.
        regionChange = not CoversAddress(self.pageBuffers, self.cip, PAGE_SIZE)
        hot = set(HotPages(self.cip, PAGE_SIZE)) & set(pages)
        if regionChange:
            self.pageBuffers.clear()

        for page in DistantPages(list(self.pageBuffers), self.cip, PAGE_SIZE, KEEP_PAGES):
            del self.pageBuffers[page]
            self.pageHashes.pop(page, None)

        # Bounded on the same window as the buffers: a page that far from CIP will not be
        # re-requested, so remembering that it failed has no use and only grows the set.
        for page in DistantPages(list(self.unreadablePages), self.cip, PAGE_SIZE, KEEP_PAGES):
            self.unreadablePages.discard(page)

        # Same bound BoundInstructions uses, so a name is dropped exactly when the instruction
        # it belongs to leaves the retained stream. ResolveCallSlots adds an entry per indirect
        # call and now runs on every decode instead of on request, so without this the dict
        # grows for as long as the session does. A pinned instruction that outlives its entry
        # is simply asked about again on the next decode.
        span = KEEP_PAGES * PAGE_SIZE
        for instAddr in [a for a in self.resolvedExports if not self.cip - span <= a <= self.cip + span]:
            del self.resolvedExports[instAddr]

        # Drop the hot pages so a stale copy can never be decoded if the re-read fails.
        for page in hot:
            self.pageBuffers.pop(page, None)

        # HotPages always contributes CIP's own page, so this is never empty and a page
        # load response is always coming to trigger the decode.
        for page in sorted(page for page in pages if page not in self.pageBuffers):
            self.RequestPage(page)

        self.RefreshViewState()

    def DoHotDecode(self):
        """Decode the contiguous buffered span from CIP forward and update the view."""
        if self.cip is None:
            log.warning("[DEBUG CONSOLE] Hot decode skipped: no current instruction pointer")
            return

        spanData = ContiguousSpan(self.pageBuffers, self.cip, PAGE_SIZE, CHUNK_SIZE)
        if not spanData:
            # Refreshing the map cannot make an unreadable page readable, and the refresh
            # re-requests it, so this is the second half of the same loop as HandlePageLoad's.
            if PageBase(self.cip, PAGE_SIZE) in self.unreadablePages:
                log.warning("[DEBUG CONSOLE] CIP page for %#x is unreadable; nothing to disassemble", self.cip)
                return

            log.warning("[DEBUG CONSOLE] No contiguous page data at CIP %#x; refreshing page map", self.cip)
            self.RefreshPageMap()
            return

        cache = self.disassemblyConsole.decodeCache
        # pageHashes still holds the hashes from before this break's re-read (HandlePageLoad
        # records the new ones after this returns), so this asks whether the code changed.
        rewritten = any(
            PageChanged(self.pageHashes, page, self.pageBuffers.get(page))
            for page in PagesOfSpan(self.cip, len(spanData), PAGE_SIZE)
        )
        # A plain step usually decodes the same instructions with the split moved along by
        # one, so when the bytes are untouched and CIP is already a known boundary there is
        # nothing to decode and nothing to re-render - just move the highlight.
        if not rewritten and self.disassemblyConsole.GetCipRow() != -1:
            self.disassemblyConsole.HighlightCip(self.disassemblyConsole.GetCipRow())
            return

        # Keep anywhere the user can navigate back to, or has marked, regardless of distance.
        pinned = set(self.disassemblyConsole.backHistory)
        pinned |= self.disassemblyConsole.bpAddrs
        pinned |= set(self.patchHistoryByAddr)
        prefix = BoundInstructions(
            [ins for ins in cache if ins.address < self.cip], self.cip, KEEP_PAGES * PAGE_SIZE, pinned
        )
        mode = Decode64Bits if self.bits == 64 else Decode32Bits
        insts: list[DecodedInstruction] = []
        for address, size, text, hexBytes in Decode(self.cip, spanData, mode):
            patchText = self.PatchDisasmText(address, text)
            insts.append(DecodedInstruction(address, hexBytes, patchText))

        # SetInstructions owns decodeCache: assigning it here first would make the incremental
        # diff see the new stream as already rendered and skip every row.
        self.disassemblyConsole.SetInstructions(prefix + insts)
        self.ResolveCallSlots()

    def RenderDisassembly(self):
        """Re-run the annotation over the decoded stream, without re-fetching anything.

        Already-annotated text is left alone: an operand replaced by a symbol no longer looks
        like an address to either regex, so a second pass over it is a no-op and a name once
        applied is not lost by a later pass.
        """
        insts: list[DecodedInstruction] = []
        cache = getattr(self.disassemblyConsole, "decodeCache", [])
        for inst in cache:
            patchText = self.PatchDisasmText(inst.address, inst.text)
            insts.append(DecodedInstruction(inst.address, inst.bytes, patchText))

        self.disassemblyConsole.SetInstructions(insts)

    def UpdateDisassemblyView(self):
        self.RenderDisassembly()
        self.RefreshViewState()

    def ResolveCallSlots(self):
        """Name the indirect calls in the current view, one request per batch of slots.

        Runs by default after a decode, which the batch is what makes affordable: capemon
        sleeps 100ms between commands, so the per-slot memory dump this replaces cost ~110ms
        each and a window's worth of calls took seconds.

        Only calls through a slot the instruction alone determines are collected, so this
        neither evaluates registers nor reads the register pane - which ParseOperandAddress
        does per call, and which is the other reason the old bulk resolve had to be manual.

        Each site is recorded with an empty name as it is asked about. That is what keeps the
        next decode from asking again about a slot that turned out to hold something other
        than an export, or that could not be read at all - neither of which comes back with
        anything to show. Resolve Symbol re-asks on demand if a slot is populated later.
        """
        # Nothing to match a slot's contents against until the export table is complete, and
        # asking now would mark every site as having no name to show. LoadNextModuleExports
        # calls back here once the load drains.
        if self.currentExportsModule is not None:
            return

        slots: dict[int, list[int]] = {}
        for inst in getattr(self.disassemblyConsole, "decodeCache", []):
            if inst.address in self.resolvedExports:
                continue

            m = JMP_CALL_ADDR_RX.search(inst.text)
            if not m or m.group("mnemonic").lower() != "call":
                continue

            ripBase = inst.address + len(inst.bytes) // 2
            slot = StaticSlotAddress(m.group("operand"), ripBase)
            if slot is not None:
                slots.setdefault(slot, []).append(inst.address)

        if not slots:
            return

        for slot, sites in slots.items():
            for instAddr in sites:
                self.resolvedExports[instAddr] = {slot: ""}

        addrs = list(slots)
        for start in range(0, len(addrs), MAX_READ_BATCH):
            batch = addrs[start : start + MAX_READ_BATCH]
            self.SendCommand(
                CMD_READ_POINTERS, ",".join(f"{addr:#x}" for addr in batch), tag=self.NextTag(TAG_PTRS)
            )

    def SitesBySlot(self) -> dict[int, list[int]]:
        """slot address -> the instruction addresses referring to it, from resolvedExports.

        Built once per reply rather than scanned per slot: a batch answers up to a few hundred
        slots, and the per-address scan this replaces was O(resolvedExports) for each one.
        """
        sites: dict[int, list[int]] = {}
        for instAddr, exportMap in self.resolvedExports.items():
            for slot in exportMap:
                sites.setdefault(slot, []).append(instAddr)

        return sites

    def HandleReadPointers(self, payload):
        """Apply a batch of slot reads: `<tag>|<slot>,<value>|<slot>,<value>|...`.

        A slot capemon could not read is absent from the reply rather than flagged, and a
        value that is not an export has no name to show; both leave the instruction showing
        its operand, which is what the empty name recorded at request time already does.
        """
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] Read pointers: %s", payload)
            return

        try:
            tag, entries = payload.split("|", 1)
        except ValueError:
            log.error("[DEBUG CONSOLE] Read pointers payload invalid: %s", payload)
            return

        # A slot's value is a fact about an address rather than about this break, so a late
        # reply is not wrong in itself - but the sites it would name are found by walking the
        # current decode, and rewritten bytes can put a different instruction at one of them.
        if tag.split(":", 1)[-1] != TAG_PTRS:
            log.debug("[DEBUG] Ignoring pointer read response with foreign tag %s", tag)
            return

        resolved = {}
        for entry in entries.split("|"):
            if not entry:
                continue

            try:
                slotStr, valueStr = entry.split(",", 1)
                slot, value = int(slotStr, 16), int(valueStr, 16)
            except ValueError:
                continue

            export = self.exports.get(value)
            if export:
                resolved[slot] = export

        if not resolved:
            return

        sites = self.SitesBySlot()
        for slot, export in resolved.items():
            for instAddr in sites.get(slot, ()):
                self.resolvedExports[instAddr] = {slot: export}

        # Rows only: a batch can arrive several times per decode, and RefreshViewState would
        # put its six commands on the wire for each one.
        self.RenderDisassembly()

    def GetCip(self, data):
        m = re.search(r"0x[0-9a-fA-F]+", data)
        if m:
            cip = int(m.group(0), 16)
            self.cip = cip

    def ResolveRef(self, addr):
        addrStr = addr
        if isinstance(addr, int):
            addrStr = f"{addr:#x}"

        if addrStr and IsValidHexAddress(addrStr):
            size = 4 if self.bits == 32 else 8
            self.SendCommand(CMD_MEM_DUMP, f"{addrStr}|{hex(size)}", tag=self.NextTag(TAG_DEREF))

    def ResolveString(self, addr: int):
        addrStr = addr
        if isinstance(addr, int):
            addrStr = f"{addr:#x}"

        if addrStr and IsValidHexAddress(addrStr):
            self.SendCommand(CMD_MEM_DUMP, f"{addrStr}|{hex(MAX_LEN)}", tag=self.NextTag(TAG_STR))

    @staticmethod
    def ProcessStringDump(raw: bytes, secondPass: bool = False) -> str:
        s = None
        if not secondPass:
            pos = raw.find(b"\x00")
            if pos != -1:
                with suppress(UnicodeDecodeError, LookupError):
                    s = raw[:pos].decode("utf-8")
        else:
            term = raw.find(b"\x00\x00")
            if term != -1:
                with suppress(UnicodeDecodeError, LookupError):
                    s = raw[:term].decode("utf-16le")

        return s

    def OperandName(self, addr: int, operand: str) -> str | None:
        """The symbol to show in place of `operand`, or None to leave the operand alone.

        `addr` is the instruction's address and `operand` its reference, as the regexes below
        captured it: a bracketed expression for an indirect reference, a bare 0x literal for a
        direct one.

        A direct target is in the instruction itself, so naming it is a lookup in the export
        table that is already fully loaded - no pipe traffic, which is why it is done for every
        instruction rather than on request. An indirect one names the memory holding the
        target, not the target, so it can only be answered by reading that memory; those stay
        on the Resolve menu items, which record what they learn in resolvedExports.

        Each kind consults only its own source. resolvedExports is keyed by instruction
        address, so it outlives the bytes it describes: if the sample rewrites an indirect
        call into a direct one, the entry from before the rewrite is still there and would
        name the new target after the old one.
        """
        if not operand.startswith("0x"):
            exportMap = self.resolvedExports.get(addr)
            if exportMap:
                return next(iter(exportMap.values()), None) or None

            return None

        return self.exports.get(int(operand, 16))

    def PatchDisasmText(self, addr: int, disasmText: str) -> str:
        m = JMP_CALL_ADDR_RX.search(disasmText)
        if m:
            mnemonic = m.group("mnemonic")
            dest = None
            operand = m.group("operand")
        else:
            m2 = LEA_MOV_ADDR_RX.search(disasmText)
            if not m2:
                return disasmText

            mnemonic = m2.group("mnemonic")
            dest = m2.group("dest")
            operand = m2.group("source")

        # Keyed on the operand, not on `addr`. Looking the instruction's own address up in the
        # export table answers "is this the entry point of an export", which is a label and
        # not what the operand refers to: direct calls therefore never got named, and an
        # import thunk - sitting at an export, and a jmp - was rewritten to its own name
        # rather than its target's.
        name = self.OperandName(addr, operand)
        if not name:
            return disasmText

        return f"{mnemonic} {dest}, {name}" if dest else f"{mnemonic} {name}"

    def GetAllExports(self, modules: list[tuple[str, str, str, str]]):
        """Queue export loading for the modules not already covered.

        HandleModules runs on every module list refresh - seven call sites reach it, two of
        them during startup - and this used to replace the queue with the full list each
        time. Every refresh therefore re-read every module's exports from scratch at ~110ms
        per 512-symbol page, and reset the module that was mid-flight so its remaining pages
        were requested under the next module's name. A load that takes several seconds kept
        being restarted before it could finish.
        """
        queued = {modName for _, _, modName, _ in self.exportModules}
        for module in modules:
            modName = module[2]
            if modName in self.exportsLoaded or modName in queued:
                continue

            self.exportModules.append(module)
            queued.add(modName)

        if self.currentExportsModule is None:
            self.LoadNextModuleExports()

    def LoadNextModuleExports(self):
        if not self.exportModules:
            if self.currentExportsModule is not None:
                self.currentExportsModule = None
                # The view is decoded long before the table exists: exports cost a command per
                # page and the first break renders within a second. Nothing re-read the table
                # once it arrived, which is why direct call targets were never named even
                # though naming them needs no pipe traffic at all.
                log.info("[DEBUG CONSOLE] Exports loaded for %d modules", len(self.exportsLoaded))
                self.RenderDisassembly()
                # Direct targets are named by the render above; the indirect ones were held
                # back while there was nothing to name them from.
                self.ResolveCallSlots()

            return

        _, _, modName, _ = self.exportModules.pop(0)
        self.exportsPage = 0
        self.currentExportsModule = modName
        self.RequestNextExportsPage()

    def RequestNextExportsPage(self):
        data = f"{self.currentExportsModule}|{self.exportsPage}"
        self.SendCommand(CMD_EXPORTS, data)

    def ProcessServerOutput(self, data):
        """Process server output by parsing command and payload, then dispatching."""
        if not data or ":" not in data:
            log.error("[DEBUG CONSOLE] Invalid data format: %s", data)
            return

        try:
            command, payload = data.split(":", 1)
        except ValueError:
            log.error("[DEBUG CONSOLE] Failed to parse data: %s", data)
            return

        if not command or not payload:
            log.error("[DEBUG CONSOLE] Empty command = '%s' or payload = '%s'", command, payload)
            return

        if command == "INIT" and not self.connected:
            self.GetCip(payload)
            self.HandleConnection(payload)
            return

        self.DispatchCommand(command, payload)

    def BuildModuleRanges(self, modules: list[tuple[str, str, str, str]]) -> bool:
        """Rebuild the sorted module ranges, returning whether the set changed.

        This used to append without clearing, so every module list refresh duplicated every
        entry and unloaded modules were never dropped - AddressInModules kept reporting freed
        ranges as live.
        """
        ranges = []
        for modBase, modSize, modName, modPath in modules:
            start = int(modBase, 16)
            end = start + int(modSize, 16)
            ranges.append((start, end, modName))

        ranges.sort()
        changed = ranges != self.moduleRanges
        self.moduleRanges = ranges
        return changed

    def AddressInModules(self, cip: int) -> bool:
        idx = bisect.bisect_right(self.moduleRanges, (cip,))
        if idx:
            start, end, modName = self.moduleRanges[idx - 1]
            if start <= cip < end:
                return True

        return False

    def OnDialogSearch(self):
        dlg = getattr(self.modulesDisplay, "dlg", None)
        if dlg and dlg.IsShown():
            dlg.OnSearch()

    def HandleConnection(self, payload):
        """Handle initial connection logic."""
        self.connected = True
        self.UpdateStatus("Status: Connected")
        if not self.parent.IsShown():
            self.parent.Show()
            self.parent.Layout()

        self.AppendConsole(payload)
        self.SendCommand(CMD_REG_UPDATE)
        self.RefreshModuleList()

    def HandleSetBreakpoint(self, payload):
        self.AppendConsole(payload)
        if "Failed" in payload:
            return

        m = re.search(r"0x[0-9a-fA-F]+", payload)
        if m:
            addr = int(m.group(0), 16)
            self.disassemblyConsole.SetBpBackground(addr)
            self.SendCommand(CMD_BREAKPOINT_LIST)

    def HandleDeleteBreakpoint(self, payload):
        self.AppendConsole(payload)
        if "Failed" in payload:
            return

        m = re.search(r"0x[0-9a-fA-F]+", payload)
        if m:
            addr = int(m.group(0), 16)
            self.disassemblyConsole.ClearBpBackground(addr)
            self.SendCommand(CMD_BREAKPOINT_LIST)

    def HandleBreakpointsList(self, payload):
        if payload.startswith("Failed"):
            return

        bps: list[tuple[str, str]] = []
        if "No" in payload:
            self.UpdateBreakpoints("")
            return

        for bp in payload.split("|"):
            # str.split never raises, so the old `except ValueError` here was dead and a
            # short entry reached UpdateData, where unpacking it killed the whole handler.
            # Entries are "dr,address,type,size"; older monitors sent only the first two.
            parts = [part.strip() for part in bp.split(",")]
            if len(parts) == 2:
                parts += ["x", "1"]

            if len(parts) != 4:
                log.warning("[DEBUG CONSOLE] Skipping malformed breakpoint entry: %r", bp)
                continue

            bps.append(tuple(parts))
        if bps:
            self.UpdateBreakpoints(bps)

    def HandleThreads(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] Threads: %s", payload)
            return

        curThread = None
        tmpThreads: list[tuple[str, str]] = []
        threads: list[tuple[str, str]] = []
        for line in payload.splitlines():
            parts = [p.strip() for p in line.split("|")]
            if len(parts) != 3:
                continue

            entry = (parts[1], parts[2])
            if parts[0] == "+":
                curThread = entry
            else:
                tmpThreads.append(entry)

        if curThread:
            threads.append(curThread)
        threads.extend(tmpThreads)
        self.UpdateThreads(threads)

    def HandleModules(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] Modules: %s", payload)
            return

        modules: list[tuple[str, str, str, str]] = []
        if "|" not in payload:
            return

        for mod in payload.split("|"):
            try:
                modBaseAddr, modSize, modName, modPath = mod.split(",")
                modules.append((modBaseAddr, modSize, modName, modPath))
            except ValueError:
                continue

        if modules:
            # A load or unload changes what is mapped, so retained pages can no longer be
            # trusted; drop them and let the next JumpTo re-read the window.
            if self.BuildModuleRanges(modules):
                self.pageBuffers.clear()

            self.GetAllExports(modules)
            self.UpdateModules(modules)

        if self.AddressInModules(self.cip) or self.firstBreak:
            self.firstBreak = False
            self.JumpTo(self.cip)

    def HandleExports(self, payload):
        # Every exit from here has to advance the queue. Two of these used to return without
        # doing so, which left currentExportsModule set and the queue parked: one module
        # capemon could not snapshot stopped every later module from ever being read.
        if payload.startswith("Failed") or "||" not in payload:
            log.warning("[DEBUG CONSOLE] Exports for %s: %s", self.currentExportsModule, payload)
            self.MarkExportsLoaded(self.currentExportsModule)
            wx.CallAfter(self.LoadNextModuleExports)
            return

        try:
            modName, *data, status = payload.split("||", 2)
        except ValueError:
            self.MarkExportsLoaded(self.currentExportsModule)
            wx.CallAfter(self.LoadNextModuleExports)
            return

        if data[0] and modName:
            exports = data[0].split("|")
            for entry in exports:
                if not entry:
                    continue

                try:
                    absAddr, symName = entry.split(",", 1)
                    self.exports[int(absAddr)] = f"{modName}!{symName}"
                except ValueError:
                    continue

        if status == "MORE":
            self.exportsPage += 1
            wx.CallAfter(self.RequestNextExportsPage)
        else:
            self.MarkExportsLoaded(modName or self.currentExportsModule)
            wx.CallAfter(self.LoadNextModuleExports)

    def MarkExportsLoaded(self, modName: str | None):
        """Record that a module has been read, successfully or not.

        Recording a failure too is deliberate: without it the module goes back on the queue on
        every module list refresh and is re-requested for the life of the session.
        """
        if modName:
            self.exportsLoaded.add(modName)

    def CollectPageMap(self, payload: str) -> str | None:
        """Accumulate one page of the memory map, returning the whole map or None if not done.

        The wire shape is `<page>||<entries>||MORE|END`. Entries are joined by a single '|' and
        are never empty, so '||' only ever delimits these three fields. A reply with no '||'
        at all is a monitor that predates paging and is taken as a complete map, which is what
        it was.

        The page number is echoed so a reply belonging to a walk that RefreshPageMap has since
        restarted can be dropped rather than spliced into the new one: the page map is
        re-requested from several recovery paths, any of which can fire mid-walk.
        """
        parts = payload.split("||")
        if len(parts) != 3:
            return payload

        pageStr, entries, status = parts
        try:
            page = int(pageStr)
        except ValueError:
            log.error("[DEBUG CONSOLE] PageMap page number invalid: %s", pageStr)
            return None

        if page != self.pageMapPage:
            log.debug("[DEBUG] Ignoring page map page %d, walk is on page %d", page, self.pageMapPage)
            return None

        self.pageMapPages.append(entries)
        if status == "MORE":
            self.pageMapPage += 1
            self.SendCommand(CMD_PAGE_MAP, str(self.pageMapPage))
            return None

        collected = "|".join(part for part in self.pageMapPages if part)
        self.pageMapPages = []
        return collected

    def HandlePageMap(self, payload):
        """Take a new page map: report what moved, and invalidate only what it invalidated.

        Runs once per break now, so it can no longer clear the whole page cache and re-read
        the window every time - that is ~9 round trips to advance one instruction, which is
        the cost the cache exists to avoid. Only pages whose covering region actually changed
        are dropped; a heap region appearing nowhere near the code being stepped leaves the
        buffers alone.
        """
        if payload.startswith("Failed"):
            # Without this the map would be replaced by nothing, the diff would report every
            # region freed, and StalePages would throw away the whole page cache.
            log.warning("[DEBUG CONSOLE] PageMap: %s", payload)
            return

        payload = self.CollectPageMap(payload)
        if payload is None:
            return

        changed = self.disassemblyConsole.LoadPageMap(payload)
        oldMap = self.disassemblyConsole.prevPageMap
        newMap = self.disassemblyConsole.pageMap
        if changed:
            self.memoryDisplay.AddChanges(DiffRegions(oldMap, newMap))
            stale = StalePages(list(self.pageBuffers), oldMap, newMap, PAGE_SIZE)
            for page in stale:
                del self.pageBuffers[page]
                self.pageHashes.pop(page, None)
                self.unreadablePages.discard(page)

        cip = self.cip
        if not self.IsAddressKnown(cip):
            log.debug(f"[DEBUG] CIP 0x{cip:X} is not present in the new PageMap; waiting for next execution update.")
            return

        pagesToRequest = SelectWindowPages(newMap, cip, PAGE_SIZE, CHUNK_SIZE)
        if not pagesToRequest:
            self.JumpTo(cip)
            return

        missing = [page for page in sorted(pagesToRequest) if page not in self.pageBuffers]
        if not missing:
            # Nothing to fetch means no page load response is coming, so there is nothing to
            # wait for and nothing to refresh. Returning here is also what stops a per-break
            # page map from looping through RefreshViewState.
            return

        self.pendingPages.clear()
        for pageBase in missing:
            self.RequestPage(pageBase)

        self.RefreshViewState()

    def HandlePageLoad(self, payload):
        if "Failed" in payload:
            log.debug(f"[DEBUG] PageLoad reported failure: {payload}")
            self.RefreshPageMap()
            self.RefreshModuleList()
            return

        try:
            requestAddr, tag, pageData = payload.split("|", 2)
            pageBase = int(requestAddr, 16)
        except ValueError as e:
            log.error("[DEBUG CONSOLE] Page load payload invalid: %s (%s)", payload, str(e))
            log.error("[DEBUG CONSOLE] %s", STALE_MONITOR_MSG)
            # This branch cannot name the page, so let the page map round-trip clear the set
            # rather than leaving a request outstanding and the view frozen.
            self.RefreshPageMap()
            return

        # A tag from an earlier break is not an answer to the current request: dropping it
        # here is what keeps a stale page out of the buffers when stepping quickly.
        if self.pendingPages.pop(tag, None) is None:
            log.debug("[DEBUG] Ignoring unsolicited or stale page response for 0x%X (tag %s)", pageBase, tag)
            return

        # The target has answered that it cannot read this page, which is a fact about the
        # page and not evidence the map is stale. Refreshing the map here was a loop: the
        # refreshed map re-selected the same page, which failed again. Record it and fall
        # through to the drain below so the decode still runs on the pages that did arrive -
        # ContiguousSpan stops at the first gap, so the window just comes up short.
        if pageData in ("UNREADABLE", "NODATA"):
            log.debug("[DEBUG] PageLoad returned %s for page 0x%X; leaving it out of the window.", pageData, pageBase)
            self.unreadablePages.add(pageBase)
            pageData = ""

        validPages = False
        if pageData:
            with suppress(ValueError):
                pageData = bytes.fromhex(pageData)
                validPages = True

        if validPages:
            self.unreadablePages.discard(pageBase)
            region = self.disassemblyConsole.FindPage(pageBase)
            if not region:
                # The map cannot place this page, so its true extent is unknown and trimming
                # is impossible; buffering it would let a decode run past the region.
                log.debug("[DEBUG] Page 0x%X is not in the page map; discarding and refreshing.", pageBase)
                self.RefreshPageMap()
                return

            expected = min(PAGE_SIZE, region[1] - (pageBase - region[0]))
            if len(pageData) > expected:
                pageData = pageData[:expected]

            self.pageBuffers[pageBase] = pageData

        if not self.pendingPages:
            # DoHotDecode compares against the hashes from before this read to decide whether
            # the code was rewritten, so it has to run before they are replaced.
            self.DoHotDecode()
            for page, data in self.pageBuffers.items():
                self.pageHashes[page] = PageHash(data)

    def HandleRegUpdate(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] Registers: %s", payload)
            return

        self.UpdateRegs(payload)

    def HandleModFlag(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] Flag: %s", payload)
            return

        self.UpdateRegs(payload)

    def HandleSetRegister(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] Set register: %s", payload)
            return

        self.UpdateRegs(payload)

    def GetExport(self, payload):
        try:
            buffer = bytes.fromhex(payload)
            if len(buffer) == 4:
                unpackFmt = "<I"
            elif len(buffer) == 8:
                unpackFmt = "<Q"
            else:
                return

            leaddr = struct.unpack(unpackFmt, buffer)[0]
            return self.exports.get(leaddr, "")
        except ValueError:
            return None

    def HandleMemDump(self, payload):
        if payload.startswith("Failed"):
            log.debug("[DEBUG] MemDump fault detected, refreshing PageMap + ModuleList")
            self.RefreshPageMap()
            self.RefreshModuleList()
            return

        # The response carries back the tag of the request that caused it, so the purpose is
        # known rather than inferred from len(data). Under the old scheme a "Dump Memory to
        # File" of 4, 8, 256 or 512 bytes was indistinguishable from a pointer or string read.
        try:
            requestAddr, tag, data = payload.split("|", 2)
            addr = int(requestAddr, 16)
        except ValueError:
            log.error("[DEBUG CONSOLE] Memory dump payload invalid: %s", payload)
            log.error("[DEBUG CONSOLE] %s", STALE_MONITOR_MSG)
            self.AppendConsole(STALE_MONITOR_MSG)
            return

        purpose = tag.split(":", 1)[-1]

        if data in ("UNREADABLE", "NODATA"):
            log.debug(f"[DEBUG] MemDump returned {data} for 0x{addr:X}.")
            if purpose == TAG_FILE:
                self.AppendConsole(f"Memory dump to file failed: {addr:#x} is {data}")

            # The panel's dump is re-issued for the same address on every break, and the
            # address only moves when a dump succeeds, so refreshing here looped: the refresh
            # ran RefreshViewState, which asked for the same dead address again. Nothing is
            # printed either, for the same reason - it would print on every break. The other
            # purposes are one-shot user actions and cannot re-trigger themselves.
            if purpose == TAG_DUMP:
                return

            self.RefreshPageMap()
            self.RefreshModuleList()
            return

        if purpose == TAG_FILE:
            if self.dumpFilePath:
                self.WriteMemToFile(data)

            return

        # One slot, read because Resolve Symbol asked about an operand the automatic pass does
        # not cover: a register-dependent one, or a slot populated since. Bulk resolution goes
        # through CMD_READ_POINTERS instead, so there is no run to count down any more - this
        # renders straight away, which a single resolve never used to do.
        if purpose == TAG_DEREF:
            export = self.GetExport(data)
            for instAddr in self.SitesBySlot().get(addr, ()):
                self.resolvedExports[instAddr] = {addr: export or ""}

            self.AppendConsole(export or f"No export at the address in {addr:#x}")
            self.RenderDisassembly()
            return

        if purpose == TAG_STR:
            raw = b""
            with suppress(ValueError):
                raw = bytes.fromhex(data)

            s = self.ProcessStringDump(raw, secondPass=False)
            if not s:
                self.SendCommand(CMD_MEM_DUMP, f"{addr:#x}|{hex(MAX_LEN * 2)}", tag=self.NextTag(TAG_STRW))
                return

            self.AppendConsole(s)
            self.resolvedStrings[addr] = s

            return

        if purpose == TAG_STRW:
            raw = b""
            with suppress(ValueError):
                raw = bytes.fromhex(data)

            s = self.ProcessStringDump(raw, secondPass=True)
            if s:
                self.AppendConsole(s)
                self.resolvedStrings[addr] = s

            # A raw hex blob from a string lookup, not the formatted dump the panel parses.
            return

        if purpose != TAG_DUMP:
            log.warning("[DEBUG CONSOLE] Unknown memory dump purpose %r for %#x", purpose, addr)
            return

        self.UpdateMemDump(data)

    def DecodeCallSite(self, returnAddr: int, hexBytes: str) -> str:
        """Find the CALL that ends exactly where a frame returns to.

        capemon sends the bytes preceding the return address so this costs no extra round
        trip. Decoding backwards is ambiguous, so every start offset is tried and only an
        instruction that ends precisely at the return address is accepted.
        """
        try:
            data = bytes.fromhex(hexBytes)
        except ValueError:
            return ""

        if not data:
            return ""

        mode = Decode64Bits if self.bits == 64 else Decode32Bits
        base = returnAddr - len(data)
        for offset in range(len(data)):
            decoded = Decode(base + offset, data[offset:], mode)
            if not decoded:
                continue

            address, size, text, _ = decoded[0]
            if address + size == returnAddr and text.lower().startswith("call"):
                return text

        return ""

    def ParseFrames(self, payload: str):
        """Turn 'index,returnAddress,framePointer,callBytes' entries into display rows."""
        frames = []
        for entry in payload.split("|"):
            parts = [part.strip() for part in entry.split(",")]
            if len(parts) != 4:
                log.warning("[DEBUG CONSOLE] Skipping malformed call stack frame: %r", entry)
                continue

            index, returnAddr, framePtr, callBytes = parts
            try:
                callSite = self.DecodeCallSite(int(returnAddr, 16), callBytes)
            except ValueError:
                callSite = ""

            frames.append((index, returnAddr, framePtr, callSite))

        return frames

    def HandleCallStack(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] Call stack: %s", payload)
            return

        self.callStackDisplay.UpdateData(self.ParseFrames(payload))

    def InspectThread(self, tid: str):
        """Snapshot another thread. Stepping still drives the thread that broke."""
        self.SendCommand(CMD_THREAD_INSPECT, str(tid))

    def ReturnToHaltedThread(self):
        """Drop the inspection view and repopulate from the thread that is actually halted."""
        if self.inspectedTid is None:
            return

        self.inspectedTid = None
        self.ShowThreadBanner(None)
        self.RefreshViewState()

    def ShowThreadBanner(self, tid):
        """Make it unmissable that the panes are not showing the halted thread."""
        if tid is None:
            self.threadBanner.SetLabel("")
            self.threadBanner.Hide()
        else:
            self.threadBanner.SetLabel(f"Viewing thread {tid} - not the halted thread. Double-click the top thread to return.")
            self.threadBanner.SetForegroundColour(ACCENT_ORANGE)
            self.threadBanner.Show()

        self.threadBanner.GetParent().Layout()

    def HandleThreadInspect(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] Thread inspect: %s", payload)
            self.AppendConsole(payload)
            return

        sections = {}
        current = None
        for line in payload.splitlines():
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                current = stripped[1:-1]
                sections[current] = []
            elif current is not None:
                sections[current].append(line)

        body = {name: "\n".join(lines).strip() for name, lines in sections.items()}
        tid = body.get("TID", "").strip()
        if not tid:
            log.warning("[DEBUG CONSOLE] Thread inspect payload has no TID: %r", payload[:80])
            return

        self.inspectedTid = tid
        # Deliberately not UpdateRegs: that parses RIP into self.cip, and this is another
        # thread's instruction pointer. The disassembly must keep tracking the halted thread.
        self.regsDisplay.SetValue(body.get("REGS", ""))
        if body.get("STACK"):
            self.stackDisplay.UpdateData(body["STACK"])

        self.callStackDisplay.UpdateData(self.ParseFrames(body.get("FRAMES", "")))
        self.ShowThreadBanner(tid)

    def NearestExport(self, addr: int) -> str:
        """Nearest export at or below `addr` as module!symbol+offset, or "".

        Bisects a sorted address list rather than scanning the exports map: this runs for
        every call stack frame on every break, and a fully loaded process has tens of
        thousands of exports.
        """
        if not self.exports:
            return ""

        if len(self.exportAddrs) != len(self.exports):
            self.exportAddrs = sorted(self.exports)

        exact = self.exports.get(addr)
        if exact:
            return exact

        idx = bisect.bisect_right(self.exportAddrs, addr)
        if not idx:
            return ""

        base = self.exportAddrs[idx - 1]
        if addr - base >= 0x10000:
            return ""

        return f"{self.exports[base]}+{addr - base:#x}"

    def ModuleNameFor(self, addr: int) -> str:
        """The module containing `addr`, for frames with no matching export."""
        idx = bisect.bisect_right(self.moduleRanges, (addr,))
        if idx:
            start, end, modName = self.moduleRanges[idx - 1]
            if start <= addr < end:
                return modName

        return ""

    def HandleStackUpdate(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] Stack: %s", payload)
            return

        self.UpdateStack(payload)
        # Here rather than after the decode: the decode runs while the page loads drain, which
        # is before this break's registers have arrived, so it would annotate the call with
        # the previous break's argument values. The stack reply is the last of the pair.
        self.ShowCallArguments()

    def AnnotateArgument(self, value: int) -> str:
        """A call argument value, plus whatever can be said about it for free.

        Only lookups that cost nothing: the export table is already loaded, and a protection
        constant is arithmetic. Reading what a pointer points at would be a memory round trip
        per argument per break, so a value that is merely plausible as a pointer is left as a
        number - the Dump Address action is one click away.
        """
        export = self.exports.get(value)
        if export:
            return export

        if value in PROTECT_VALUES:
            return f"{value:#x} {ProtectText(value)}"

        # Small values read better as decimal; a size or a count is the common case.
        if value < 0x10000:
            return f"{value:#x} ({value})"

        return f"{value:#x}"

    def ShowCallArguments(self):
        """Put the current call's outgoing arguments in the comment column, and nowhere else.

        Only the CIP row gets them, because only there are they knowable: the values a call
        forty rows down will pass depend on register state execution has not reached. The
        instruction has to be a call and CIP has to be on it - one step later the arguments
        have moved.
        """
        disasm = self.disassemblyConsole
        row = disasm.GetCipRow()
        if disasm.commentRow is not None:
            if disasm.commentRow < disasm.GetItemCount():
                disasm.SetItem(disasm.commentRow, COMMENT_COL, "")

            disasm.commentRow = None

        if row == -1 or self.bits is None:
            return

        text = disasm.GetItemText(row, 2)
        if not text.lower().startswith("call"):
            return

        regVals = ParseRegisters(self.regsDisplay.GetValue())
        # The register pane has to describe the instruction being annotated. Between the
        # execution reply, which sets cip, and the register reply, which fills the pane, it
        # still holds the previous break - and this runs on every render, so without the check
        # a re-render in that window would label the new call with the old values.
        if regVals.get("rip", regVals.get("eip")) != self.cip:
            return

        proto = self.PrototypeFor(text)
        argCount = len(proto.params) if proto else None
        args = CallArguments(self.bits, regVals, self.stackDisplay.StackWords(), argCount)
        if proto and not proto.params:
            # A void prototype is an answer, not a failure to find one.
            disasm.SetItem(row, COMMENT_COL, f"{proto.name}()")
            disasm.commentRow = row
            return

        if not args:
            return

        # Positional: the prototype's Nth parameter names the Nth argument. Where the count
        # runs out - no prototype, or a mismatch - the register or slot name is used, so a
        # label is never borrowed from the wrong position.
        names = [p.name for p in proto.params] if proto else []
        parts = []
        for i, (slot, value) in enumerate(args):
            label = names[i] if i < len(names) else slot
            parts.append(f"{label}={self.AnnotateArgument(value)}")

        disasm.SetItem(row, COMMENT_COL, ", ".join(parts))
        disasm.commentRow = row

    def PrototypeFor(self, disasmText: str):
        """The prototype for the API a call goes to, or None.

        Read off the disassembly text, which by this point already carries the symbol that
        export resolution put there - so no second lookup, and an unresolved call simply has
        no name to match. Decorations are trimmed: stdcall exports arrive as `_Name@16`, and
        the A/W pair are separate declarations because their parameter types differ.
        """
        m = CALL_SYMBOL_RX.match(disasmText)
        if not m:
            return None

        symbol = m.group("symbol").lstrip("_").split("@")[0]
        return self.prototypes.get(symbol)

    def AddPrototype(self):
        """Ask for a declaration, store it, and re-annotate with it straight away."""
        dlg = PrototypeDialog(self)
        try:
            if dlg.ShowModal() != wx.ID_OK:
                return

            text = dlg.GetDeclaration()
        finally:
            dlg.Destroy()

        protos = ParsePrototypes(text)
        if not protos:
            self.AppendConsole("Could not read a function declaration from that.")
            return

        AppendUserPrototype(text)
        self.prototypes.update(protos)
        for name, proto in protos.items():
            self.AppendConsole(f"Prototype added: {name} ({len(proto.params)} parameters)")

        self.ShowCallArguments()

    def HandleConsoleOutput(self, payload):
        self.AppendConsole(payload)

    def HandleExecution(self, payload):
        if "TIMEOUT" in payload:
            self.AppendConsole(payload)
            self.disassemblyConsole.ClearHighlight()
            log.debug("[DEBUG] Execution fault detected, refreshing PageMap...")
            # The layout the retained pages were read under is no longer trustworthy.
            self.pageBuffers.clear()

            self.RefreshPageMap()
            self.RefreshModuleList()
            return

        m = re.search(r"0x[0-9a-fA-F]+", payload)
        if m:
            cip = int(m.group(0), 16)
            self.cip = cip
            self.AppendConsole(payload)
            if not self.IsAddressKnown(cip):
                self.RefreshPageMap()
                self.RefreshModuleList()
                return

            self.JumpTo(cip)
            # After JumpTo, so the page map lands once this break's pages are already in and
            # HandlePageMap has nothing to re-request in the common case. Sent from here and
            # not from RefreshViewState: HandlePageMap ends in RefreshViewState, so a page map
            # request inside it would ask for another page map forever.
            self.RefreshPageMap()
        else:
            log.error("[DEBUG CONSOLE] Failed to parse CIP from payload: %s", payload)

    def HandleNopInstruction(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] NopInstruction: %s", payload)

        self.JumpTo(self.cip)

    def HandlePatchBytes(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] PatchBytes: %s", payload)

        self.JumpTo(self.cip)
