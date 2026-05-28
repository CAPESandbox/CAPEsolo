import bisect
import logging
import re
import struct
import zlib
from collections import defaultdict
from contextlib import suppress
from threading import Condition, Lock, Thread
from typing import Dict, List, Tuple

import pywintypes
import win32event
import win32file
import wx
from distorm3 import Decode, Decode32Bits, Decode64Bits

from CAPEsolo.capelib.cmdconsts import *
from CAPEsolo.lib.core.pipe import PipeDispatcher, PipeServer, disconnect_pipes
from .debug_controls import (
    BreakpointsListCtrl,
    DecodedInstruction,
    DisassemblyListCtrl,
    IsValidHexAddress,
    MemDumpListCtrl,
    ModulesListCtrl,
    RegsTextCtrl,
    StackListCtrl,
    ThreadListCtrl,
)
from .debug_pipe import CommandPipeHandler
from .patch_assembler import Assembler
from .patch_models import PatchEntry
from .theme import FONT_CODE, apply_theme

log = logging.getLogger(__name__)

MAX_LEN = 256
PAGE_SIZE = 4 * 1024
BUFFER_SIZE = 65 * 1024
CHUNK_SIZE = BUFFER_SIZE // 2
DBGCMD = "DBGCMD"
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
        self.ID_PATCH = wx.NewIdRef()

        accels = wx.AcceleratorTable(
            [
                (wx.ACCEL_NORMAL, wx.WXK_F4, self.ID_RUN_UNTIL),
                (wx.ACCEL_NORMAL, wx.WXK_F7, self.ID_STEP_INTO),
                (wx.ACCEL_NORMAL, wx.WXK_F8, self.ID_STEP_OVER),
                (wx.ACCEL_NORMAL, wx.WXK_F9, self.ID_STEP_OUT),
                (wx.ACCEL_NORMAL, wx.WXK_F10, self.ID_CONTINUE),
                (wx.ACCEL_NORMAL, wx.WXK_ESCAPE, self.ID_BACK),
                (wx.ACCEL_NORMAL, wx.WXK_SPACE, self.ID_PATCH),
                (wx.ACCEL_CTRL, ord("Q"), self.ID_STOP),
                (wx.ACCEL_CMD, ord("F"), self.ID_SEARCH),
            ]
        )
        self.SetAcceleratorTable(accels)
        self.Bind(wx.EVT_MENU, self.consolePanel.OnRunUntilAccel, id=self.ID_RUN_UNTIL)
        self.Bind(wx.EVT_MENU, self.consolePanel.OnPatchAccel, id=self.ID_PATCH)
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
        while ctrl and not isinstance(ctrl, (DisassemblyListCtrl, MemDumpListCtrl)):
            ctrl = ctrl.GetParent()

        if hasattr(ctrl, "OnBack"):
            ctrl.OnBack(event)


class ConsolePanel(wx.Panel):
    """A wxPython panel that supports multi-threaded debugging with labeled sections, hotkeys, and logging."""

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.pipe = parent.pipe
        self.pipeHandle = None
        self.connected = False
        self.readLock = Lock()
        self.slotCount = 512
        self.prevHighlight = None
        self.initMemDump = True
        self.cip = None
        self.bits = None
        self.pageBuffers: Dict[int, bytes] = {}
        self.requestedPages = set()
        self.pageLock = Lock()
        self.pageHashes = {}
        self.idleDecodeQueue = []
        self.exports: Dict[int, str] = {}
        self.exportModules = []
        self.export = None
        self.resolvedExports: Dict[int, Dict[int, str]] = {}
        self.resolvedStrings: Dict[int, str] = {}
        self.currentExportsModule = None
        self.exportsPage = 0
        self.moduleRanges = []
        self.patchHistory: list[PatchEntry] = []
        self.patchHistoryByAddr: dict[int, list[PatchEntry]] = defaultdict(list)
        self.derefCount = 0
        self.derefPending: set[int] = set()
        self.dumpFilePath = None
        self.dumpMemFile = False
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

        # Disassembly
        consoleSizer = wx.BoxSizer(wx.VERTICAL)
        consoleSizer.Add(wx.StaticText(self, label="Disassembly Console"), 0, wx.ALL, 5)
        self.disassemblyConsole = DisassemblyListCtrl(self)
        self.disassemblyConsole.SetFont(fontCourier)
        consoleSizer.Add(self.disassemblyConsole, 2, wx.EXPAND | wx.ALL, 5)

        # Registers
        regsSizer = wx.BoxSizer(wx.VERTICAL)
        regsSizer.Add(wx.StaticText(self, label="Registers"), 0, wx.ALL, 5)
        self.regsDisplay = RegsTextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.regsDisplay.SetFont(fontCourier)
        regsSizer.Add(self.regsDisplay, 1, wx.EXPAND | wx.ALL, 5)

        topSizer = wx.BoxSizer(wx.HORIZONTAL)
        topSizer.Add(consoleSizer, 6, wx.EXPAND)
        topSizer.Add(regsSizer, 4, wx.EXPAND)
        mainSizer.Add(topSizer, 1, wx.EXPAND)

        # Memory Dump
        memSizer = wx.BoxSizer(wx.VERTICAL)
        memSizer.Add(wx.StaticText(self, label="Memory Dump"), 0, wx.ALL, 5)
        self.memDumpDisplay = MemDumpListCtrl(self)
        self.memDumpDisplay.SetFont(fontCourier)
        memSizer.Add(self.memDumpDisplay, 2, wx.EXPAND | wx.ALL, 5)

        # Address input field
        memInput = wx.BoxSizer(wx.HORIZONTAL)
        memInput.Add(wx.StaticText(self, label="Memory Dump Address:"), 0, wx.LEFT | wx.ALIGN_CENTER_VERTICAL, 5)
        self.memAddressInput = wx.TextCtrl(self, style=wx.TE_PROCESS_ENTER)
        self.memAddressInput.SetFont(fontCourier)
        memInput.Add(self.memAddressInput, 1, wx.EXPAND | wx.ALL, 5)
        self.memAddressInput.Bind(wx.EVT_TEXT_ENTER, self.OnAddressEnter)

        # Dump to File button
        btnDumpToFile = wx.Button(self, label="Dump Memory to File")
        btnDumpToFile.Bind(wx.EVT_BUTTON, self.OnDumpToFile)
        memInput.Add(btnDumpToFile, 0, wx.LEFT | wx.ALIGN_CENTER_VERTICAL, 5)
        memSizer.Add(memInput, 0, wx.EXPAND | wx.ALL, 5)

        # Stack
        stackSizer = wx.BoxSizer(wx.VERTICAL)
        stackSizer.Add(wx.StaticText(self, label="Stack"), 0, wx.ALL, 5)
        self.stackDisplay = StackListCtrl(self)
        self.stackDisplay.SetFont(fontCourier)
        stackSizer.Add(self.stackDisplay, 1, wx.EXPAND | wx.ALL, 5)

        bottomSizer = wx.BoxSizer(wx.HORIZONTAL)
        bottomSizer.Add(memSizer, 7, wx.EXPAND)
        bottomSizer.Add(stackSizer, 3, wx.EXPAND)
        mainSizer.Add(bottomSizer, 1, wx.EXPAND)

        # Console box
        consoleSizer = wx.BoxSizer(wx.VERTICAL)
        self.outputConsole = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.outputConsole.SetFont(fontCourier)
        charH = self.outputConsole.GetCharHeight()
        self.outputConsole.SetMinSize(wx.Size(-1, charH * 7))
        consoleSizer.Add(wx.StaticText(self, label="Console Output"), 0, wx.ALL, 5)
        consoleSizer.Add(self.outputConsole, 1, wx.EXPAND | wx.ALL, 5)

        # Modules List View
        modulesSizer = wx.BoxSizer(wx.VERTICAL)
        modulesSizer.Add(wx.StaticText(self, label="Modules"), 0, wx.ALL, 5)
        self.modulesDisplay = ModulesListCtrl(self)
        self.modulesDisplay.SetFont(fontCourier)
        self.modulesDisplay.SetMinSize(wx.Size(-1, charH * 7))
        modulesSizer.Add(self.modulesDisplay, 1, wx.EXPAND | wx.ALL, 5)

        # Threads List View
        threadsSizer = wx.BoxSizer(wx.VERTICAL)
        threadsSizer.Add(wx.StaticText(self, label="Threads"), 0, wx.ALL, 5)
        self.threadsDisplay = ThreadListCtrl(self)
        self.threadsDisplay.SetFont(fontCourier)
        self.threadsDisplay.SetMinSize(wx.Size(-1, charH * 7))
        threadsSizer.Add(self.threadsDisplay, 1, wx.EXPAND | wx.ALL, 5)

        # Breakpoints List View
        bpsSizer = wx.BoxSizer(wx.VERTICAL)
        bpsSizer.Add(wx.StaticText(self, label="Breakpoints"), 0, wx.ALL, 5)
        self.breakpointsDisplay = BreakpointsListCtrl(self)
        self.breakpointsDisplay.SetFont(fontCourier)
        self.breakpointsDisplay.SetMinSize(wx.Size(-1, charH * 7))
        bpsSizer.Add(self.breakpointsDisplay, 1, wx.EXPAND | wx.ALL, 5)

        miscSizer = wx.BoxSizer(wx.HORIZONTAL)
        miscSizer.Add(consoleSizer, 2, wx.EXPAND | wx.ALL)
        miscSizer.Add(modulesSizer, 4, wx.EXPAND | wx.ALL)
        miscSizer.Add(threadsSizer, 2, wx.EXPAND | wx.ALL)
        miscSizer.Add(bpsSizer, 2, wx.EXPAND | wx.ALL)
        mainSizer.Add(miscSizer, 0, wx.EXPAND)

        # Input box
        inputSizer = wx.BoxSizer(wx.HORIZONTAL)
        inputSizer.Add(wx.StaticText(self, label="Command Input:"), 0, wx.LEFT | wx.ALIGN_CENTER_VERTICAL, 5)
        self.inputBox = wx.TextCtrl(self, style=wx.TE_PROCESS_ENTER)
        self.inputBox.Bind(wx.EVT_TEXT_ENTER, self.OnEnter)
        inputSizer.Add(self.inputBox, 1, wx.EXPAND | wx.ALL, 5)

        # Debugging Controls
        debugButtons = wx.BoxSizer(wx.HORIZONTAL)
        self.runUntilBtn = wx.Button(self, label="Run Until (F4)")
        self.stepIntoBtn = wx.Button(self, label="Step Into (F7)")
        self.stepOverBtn = wx.Button(self, label="Step Over (F8)")
        self.stepOutBtn = wx.Button(self, label="Step Out (F9)")
        self.continueBtn = wx.Button(self, label="Continue (F10)")
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

    def OnRunUntilAccel(self, event):
        row = self.disassemblyConsole.GetNextItem(-1, wx.LIST_NEXT_ALL, wx.LIST_STATE_SELECTED)
        if row == -1:
            row = self.disassemblyConsole.GetCipRow(self.cip)

        if row == -1:
            wx.MessageBox("No valid address to Run Until.", "Error", wx.OK | wx.ICON_ERROR)
            return

        self.disassemblyConsole.OnRunUntil(row)

    def OnPatchAccel(self, event):
        if self.inputBox.HasFocus():
            self.inputBox.WriteText(" ")
            return

        row = self.disassemblyConsole.GetNextItem(-1, wx.LIST_NEXT_ALL, wx.LIST_STATE_SELECTED)
        if row == -1:
            wx.MessageBox("No valid address to patch.", "Error", wx.OK | wx.ICON_ERROR)
            return

        self.disassemblyConsole.OnPatchBytes(row)

    def OnKeyDown(self, event):
        if self.FindFocus() == self.inputBox:
            event.Skip()
            return

        if self.FindFocus() == self.memAddressInput:
            event.Skip()
            return

        if event.GetKeyCode() == wx.WXK_F7 and event.ControlDown():
            self.SendCommand(CMD_STEP_INTO)
        elif event.GetKeyCode() == wx.WXK_F8 and event.ControlDown():
            self.SendCommand(CMD_STEP_OVER)
        elif event.GetKeyCode() == wx.WXK_F10 and event.ControlDown():
            self.SendCommand(CMD_CONTINUE)
        else:
            event.Skip()

    def OnAddressEnter(self, event):
        self.memAddr = self.memAddressInput.GetValue().strip()
        if self.memAddr:
            self.SendCommand(CMD_MEM_DUMP, self.memAddr)

        self.memAddressInput.Clear()
        event.Skip()

    def OnDumpToFile(self, event):
        addrStr = wx.GetTextFromUser("Enter starting address (hex or decimal):", "Dump to File")
        if not addrStr:
            return

        try:
            addr = int(addrStr, 0)
        except ValueError:
            wx.MessageBox("Invalid address format.", "Error", wx.OK | wx.ICON_ERROR)
            return

        sizeStr = wx.GetTextFromUser("Enter dump size in bytes (hex or decimal):", "Dump to File")
        if not sizeStr:
            return

        try:
            size = int(sizeStr, 0)
        except ValueError:
            wx.MessageBox("Invalid size format.", "Error", wx.OK | wx.ICON_ERROR)
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

        self.dumpMemFile = True
        self.SendCommand(CMD_MEM_DUMP, f"{addr:#x}|{size:#x}")

    def WriteMemToFile(self, data):
        try:
            if self.dumpFilePath.endswith(".bin"):
                with open(self.dumpFilePath, "wb") as f:
                    f.write(bytes.fromhex(data))
            else:
                with open(self.dumpFilePath, "w", encoding="utf-8") as f:
                    f.write(data)

            wx.MessageBox(f"Memory dumped successfully to:\n{self.dumpFilePath}", "Success", wx.OK | wx.ICON_INFORMATION)
        except Exception as e:
            wx.MessageBox(f"Failed to dump memory: {e}", "Error", wx.OK | wx.ICON_ERROR)

        return

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
        self.cip = int(m.group(2), 16) if m else None
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

        win32file.CloseHandle(self.pipeHandle)
        self.pipeHandle = None
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
                return ""

    def SendCommand(self, command, data=""):
        if command.lower() != "init" and (not self.connected or not self.pipeHandle):
            log.error("[DEBUG CONSOLE] Cannot send command: Not connected to pipe")
            return

        fullCommand = f"{DBGCMD}:{command.upper()}:{data}".encode("utf-8") + b"\n"
        Thread(target=self.BackgroundWrite, args=(fullCommand, 5000), daemon=True).start()

    def BackgroundWrite(self, buffer, timeout=win32event.INFINITE):
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
        """Handles user input and processes commands."""
        inputText = self.inputBox.GetValue().strip()
        try:
            cmd, data = inputText.split(" ", 1)
        except ValueError:
            cmd = inputText
            data = ""

        cmd = cmd.lower()
        if cmd == "disconnect":
            wx.CallAfter(self.statusBar.SetLabel, "Status: Disconnected")
            win32file.CloseHandle(self.pipeHandle)
            self.connected = False
            log.info("[DEBUG CONSOLE] Pipe disconnected successfully.")
        elif cmd == "quit":
            self.SendCommand(CMD_CONTINUE)
            self.ShutdownConsole()
        elif cmd == "clear":
            self.outputConsole.Clear()
        elif cmd in ("",):
            pass
        else:
            self.SendCommand(cmd)

        self.inputBox.Clear()
        event.Skip()

    def ShutdownConsole(self):
        """Handles graceful shutdown of the console."""
        self.close()
        self.parent.Close()

    def close(self):
        """Stops the reading thread."""
        self.connected = False
        if self.pipeHandle:
            try:
                win32file.CloseHandle(self.pipeHandle)
            except Exception as e:
                log.error("[DEBUG CONSOLE] Error closing pipe handle: %s", e)
            finally:
                self.pipeHandle = None
                log.info("[DEBUG CONSOLE] Pipe handle closed")

    def RefreshViewState(self):
        self.SendCommand(CMD_REG_UPDATE)
        if self.initMemDump:
            self.SendCommand(CMD_MEM_DUMP)
            self.initMemDump = False
        else:
            addr = self.memDumpDisplay.GetFirstHexAddress()
            if addr is not None:
                self.memAddressInput.SetValue(addr)
                self.OnAddressEnter(wx.CommandEvent(wx.EVT_TEXT_ENTER.typeId, self.memAddressInput.GetId()))

        self.SendCommand(CMD_STACK_UPDATE)
        self.SendCommand(CMD_THREADS)
        self.SendCommand(CMD_BREAKPOINT_LIST)

    def DispatchCommand(self, command, payload):
        """Dispatch commands to their respective handlers."""
        handlers = {
            CMD_PAGE_MAP: self.HandlePageMap,
            CMD_PAGE_LOAD: self.HandlePageLoad,
            CMD_REG_UPDATE: self.HandleRegUpdate,
            CMD_MEM_DUMP: self.HandleMemDump,
            CMD_STACK_UPDATE: self.HandleStackUpdate,
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
        self.SendCommand(CMD_PAGE_LOAD, hex(pageBase))

    def JumpTo(self, address: int):
        """Use pageMap to find page."""
        self.cip = address
        if not self.AddressInModules(address):
            self.SendCommand(CMD_MODULE_LIST)

        region = self.disassemblyConsole.FindPage(address)
        if region is None:
            self.SendCommand(CMD_PAGE_MAP)
            return

        desiredStart = self.cip
        desiredEnd = self.cip + CHUNK_SIZE
        pageMap = self.disassemblyConsole.pageMap
        pages = set()
        for base, size, prot in pageMap:
            regionEnd = base + size
            if regionEnd < desiredStart or base > desiredEnd:
                continue

            firstPage = (base // PAGE_SIZE) * PAGE_SIZE
            lastPage = ((base + size - 1) // PAGE_SIZE) * PAGE_SIZE
            page = firstPage
            while page <= lastPage:
                if desiredStart - PAGE_SIZE <= page <= desiredEnd:
                    pages.add(page)
                page += PAGE_SIZE

        if not pages:
            log.error("[DEBUG CONSOLE] No valid pages found for address %#x", address)
            return

        with self.pageLock:
            self.pageBuffers.clear()
            self.requestedPages.clear()
            for page in sorted(pages):
                self.requestedPages.add(page)
                self.RequestPage(page)

        self.RefreshViewState()

    def DoHotDecode(self):
        """Decode only the first PAGE_SIZE bytes from CIP and update the view."""
        cache = getattr(self.disassemblyConsole, "decodeCache", [])
        prefix = [ins for ins in cache if ins.address < self.cip]
        sortedPages = sorted(self.pageBuffers.keys())
        baseAddress = self.cip
        hotData = bytearray()
        for page in sortedPages:
            pageData = self.pageBuffers[page]
            start = max(self.cip, page)
            end = min(self.cip + PAGE_SIZE, page + len(pageData))
            if start < end:
                hotData.extend(pageData[start - page : end - page])

        mode = Decode64Bits if self.bits == 64 else Decode32Bits
        insts: List[DecodedInstruction] = []
        for address, size, text, hexBytes in Decode(baseAddress, bytes(hotData), mode):
            patchText = self.PatchDisasmText(address, text)
            insts.append(DecodedInstruction(address, hexBytes, patchText))

        insts = prefix + insts
        self.disassemblyConsole.decodeCache = insts
        self.disassemblyConsole.SetInstructions(insts)

    def ProcessNextIdlePage(self):
        """Decode one page at a time in idle to fill out the rest of the context."""
        if not self.idleDecodeQueue:
            return

        pageBase = self.idleDecodeQueue.pop(0)
        pageData = self.pageBuffers.get(pageBase)
        if pageData:
            mode = Decode64Bits if self.bits == 64 else Decode32Bits
            insts = []
            for address, size, text, hexBytes in Decode(pageBase, pageData, mode):
                patchText = self.PatchDisasmText(address, text)
                insts.append(DecodedInstruction(address, hexBytes, patchText))

            self.disassemblyConsole.SetInstructions(insts, append=True)

        if self.idleDecodeQueue:
            wx.CallLater(1, self.ProcessNextIdlePage)

    def UpdateDisassemblyView(self):
        insts: List[DecodedInstruction] = []
        cache = getattr(self.disassemblyConsole, "decodeCache", [])
        for inst in cache:
            patchText = self.PatchDisasmText(inst.address, inst.text)
            insts.append(DecodedInstruction(inst.address, inst.bytes, patchText))

        self.disassemblyConsole.SetInstructions(insts)
        self.RefreshViewState()

    def DereferenceCalls(self):
        cache = getattr(self.disassemblyConsole, "decodeCache", [])
        for inst in cache:
            if "call" not in inst.text.lower():
                continue

            try:
                ripBase = inst.address + len(inst.bytes) // 2
                targetAddr = self.disassemblyConsole.ParseOperandAddress(inst.text, ripBase)
            except Exception:
                continue

            if targetAddr is None:
                continue

            with self.pageLock:
                if targetAddr not in self.derefPending:
                    self.derefPending.add(targetAddr)
                    self.derefCount += 1

                self.resolvedExports[inst.address] = {targetAddr: ""}

            wx.CallLater(1, self.ResolveRef, targetAddr)

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
            self.SendCommand(CMD_MEM_DUMP, f"{addrStr}|{hex(size)}")

    def ResolveString(self, addr: int):
        addrStr = addr
        if isinstance(addr, int):
            addrStr = f"{addr:#x}"

        if addrStr and IsValidHexAddress(addrStr):
            self.SendCommand(CMD_MEM_DUMP, f"{addrStr}|{hex(MAX_LEN)}")

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

    def PatchDisasmText(self, addr: int, disasmText: str) -> str:
        export = None
        with self.pageLock:
            exportMap = self.resolvedExports.get(addr)
            if exportMap:
                export = next(iter(exportMap.values()), None)

        name = export or self.exports.get(addr) or self.resolvedStrings.get(addr)
        if name:
            m = JMP_CALL_ADDR_RX.search(disasmText)
            if m:
                mnemonic = m.group("mnemonic")
                dest = None
                raw = m.group("operand")
            else:
                m2 = LEA_MOV_ADDR_RX.search(disasmText)
                if not m2:
                    return disasmText

                mnemonic = m2.group("mnemonic")
                dest = m2.group("dest")
                raw = m2.group("source")

            return f"{mnemonic} {dest}, {name}" if dest else f"{mnemonic} {name}"

        return disasmText

    def GetAllExports(self, modules: List[Tuple[str, str, str, str]]):
        self.exportModules = list(modules)
        self.LoadNextModuleExports()

    def LoadNextModuleExports(self):
        if not self.exportModules:
            # log.info("[DEBUG CONSOLE] Finished loading all exports.")
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

    def PageCrcChanged(self, pageBase: int) -> bool:
        """Return if the bytes at `pageBase` have changed since the last check."""
        pageData = self.pageBuffers.get(pageBase)
        if pageData is None:
            return False

        newHash = zlib.adler32(pageData) & 0xFFFFFFFF
        oldHash = self.pageHashes.get(pageBase)
        if newHash != oldHash:
            self.pageHashes[pageBase] = newHash
            return True

        return False

    def BuildModuleRanges(self, modules: List[Tuple[str, str, str, str]]):
        for modBase, modSize, modName, modPath in modules:
            start = int(modBase, 16)
            end = start + int(modSize, 16)
            self.moduleRanges.append((start, end, modName))

        self.moduleRanges.sort()

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
        self.SendCommand(CMD_MODULE_LIST)

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

        bps: List[Tuple[str, str]] = []
        if "No" in payload:
            self.UpdateBreakpoints("")
            return

        for bp in payload.split("|"):
            try:
                bps.append(bp.split(","))
            except ValueError:
                continue
        if bps:
            self.UpdateBreakpoints(bps)

    def HandleThreads(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] Threads: %s", payload)
            return

        curThread = None
        tmpThreads: List[Tuple[str, str]] = []
        threads: List[Tuple[str, str]] = []
        for line in payload.splitlines():
            parts = [p.strip() for p in line.split("|")]
            if len(parts) != 3:
                continue

            entry = (parts[1], parts[2])
            if parts[0] == "+":
                curThread = entry
            else:
                tmpThreads.append(entry)

        threads.append(curThread)
        threads.extend(tmpThreads)
        self.UpdateThreads(threads)

    def HandleModules(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] Modules: %s", payload)
            return

        modules: List[Tuple[str, str, str, str]] = []
        if "|" not in payload:
            return

        for mod in payload.split("|"):
            try:
                modBaseAddr, modSize, modName, modPath = mod.split(",")
                modules.append((modBaseAddr, modSize, modName, modPath))
            except ValueError:
                continue

        if modules:
            self.BuildModuleRanges(modules)
            self.GetAllExports(modules)
            self.UpdateModules(modules)

        if self.AddressInModules(self.cip) or self.firstBreak:
            self.firstBreak = False
            self.JumpTo(self.cip)

    def HandleExports(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] Exports: %s", payload)
            return

        if "||" not in payload:
            return

        try:
            modName, *data, status = payload.split("||", 2)
        except ValueError:
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
            wx.CallAfter(self.LoadNextModuleExports)

    def HandlePageMap(self, payload):
        self.disassemblyConsole.LoadPageMap(payload)
        self.JumpTo(self.cip)

    def HandlePageLoad(self, payload):
        """Process page load response."""
        if "Failed" in payload:
            return

        try:
            requestAddr, pageData = payload.split("|", 1)
            pageBase = int(requestAddr, 16)
        except ValueError as e:
            log.error("[DEBUG CONSOLE] Page load payload invalid: %s (%s)", payload, str(e))
            return

        validPages = False
        if pageData and pageData not in ("UNREADABLE", "NODATA"):
            with suppress(ValueError):
                pageData = bytes.fromhex(pageData)
                validPages = True

        if validPages:
            region = self.disassemblyConsole.FindPage(pageBase)
            if region:
                expected = min(PAGE_SIZE, region[1] - (pageBase - region[0]))
                if len(pageData) > expected:
                    pageData = pageData[:expected]

            with self.pageLock:
                self.pageBuffers[pageBase] = pageData

        with self.pageLock:
            self.requestedPages.discard(pageBase)
            complete = not self.requestedPages

        if complete:
            self.DoHotDecode()
            self.idleDecodeQueue.clear()
            self.idleDecodeQueue = [p for p in self.pageBuffers if p >= self.cip + PAGE_SIZE and self.PageCrcChanged(p)]
            wx.CallLater(1, self.ProcessNextIdlePage)

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
            # log.warning("[DEBUG CONSOLE] Memdump: %s", payload)
            return

        data = ""
        addr = None
        if "|" in payload:
            requestAddr, data = payload.split("|", 1)
            addr = int(requestAddr, 16)

        if "Failed" in data:
            if addr in self.derefPending:
                self.derefPending.remove(addr)
                if self.derefCount > 0:
                    self.derefCount -= 1
                    print(f"Failed: {self.derefCount}")

            return

        if self.dumpMemFile and self.dumpFilePath:
            self.WriteMemToFile(data)
            return

        datalen = len(data)
        if datalen > MAX_LEN * 4:
            self.UpdateMemDump(data)
            return

        if datalen in (8, 16):
            export = self.GetExport(data)
            with self.pageLock:
                instAddrs = [instAddr for instAddr, exportMap in self.resolvedExports.items() if addr in exportMap]
                for instAddr in instAddrs:
                    if export:
                        self.resolvedExports[instAddr][addr] = export
                    else:
                        del self.resolvedExports[instAddr]

                if addr in self.derefPending:
                    self.derefPending.remove(addr)
                    if self.derefCount > 0:
                        self.derefCount -= 1

            if export:
                self.AppendConsole(export)

            if self.derefCount == 0:
                self.AppendConsole("Completed resolving calls.")
                self.UpdateDisassemblyView()
                self.disassemblyConsole.resolveAllRefsStatus = True

            return

        if datalen == MAX_LEN * 2:
            raw = b""
            with suppress(ValueError):
                raw = bytes.fromhex(data)

            s = self.ProcessStringDump(raw, secondPass=False)
            if not s:
                self.SendCommand(CMD_MEM_DUMP, f"{addr:#x}|{hex(MAX_LEN * 2)}")
                return

            self.AppendConsole(s)
            with self.pageLock:
                self.resolvedStrings[addr] = s

            return

        if datalen == MAX_LEN * 4:
            raw = b""
            with suppress(ValueError):
                raw = bytes.fromhex(data)

            s = self.ProcessStringDump(raw, secondPass=True)
            if s:
                self.AppendConsole(s)
                with self.pageLock:
                    self.resolvedStrings[addr] = s

    def HandleStackUpdate(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] Stack: %s", payload)
            return

        self.UpdateStack(payload)

    def HandleConsoleOutput(self, payload):
        self.AppendConsole(payload)

    def HandleExecution(self, payload):
        """Handle execution commands by parsing CIP and updating disassembly."""
        if "TIMEOUT" in payload:
            self.AppendConsole(payload)
            self.disassemblyConsole.ClearHighlight()
            return

        m = re.search(r"0x[0-9a-fA-F]+", payload)
        if m:
            cip = int(m.group(0), 16)
            self.cip = cip
            self.AppendConsole(payload)
            self.JumpTo(cip)
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
