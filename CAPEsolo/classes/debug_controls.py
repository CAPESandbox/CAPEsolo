import ast
import logging
import operator
import re
import threading
from collections import namedtuple
from pathlib import Path

import wx

from CAPEsolo.capelib.cmdconsts import *
from CAPEsolo.capelib.api_protos import user_prototypes_path
from CAPEsolo.capelib.flow_arrows import GUTTER_WIDTH, BranchLanes
from CAPEsolo.capelib.page_cache import (
    REGION_FREED,
    REGION_NEW,
    REGION_REPROTECTED,
    CommonPrefixLength,
    FindRegion,
    RegionChange,
)

from . import ui_kit as ui
from .patch_dialog import ConfirmPatchDialog, PatchDialog, PatchHistoryDialog
from .patch_models import PatchEntry
from .search_dialog import SearchDialog
from .theme import (
    ACCENT_CALL,
    ACCENT_ERROR,
    ACCENT_GREEN,
    ACCENT_JUMP,
    ACCENT_ORANGE,
    BG_INPUT,
    FG_SECONDARY,
    FONT_CODE,
    apply_theme,
    band_rows,
)

log = logging.getLogger(__name__)

# Mirrors debug_console.TAG_DUMP; importing it would be circular.
TAG_DUMP = "DUMP"
# Breakpoint types as sent to capemon, and how they read in the Breakpoints pane.
BP_EXEC, BP_WRITE, BP_READWRITE = "x", "w", "rw"
BP_TYPE_LABELS = {BP_EXEC: "exec", BP_WRITE: "write", BP_READWRITE: "r/w"}
BP_SIZES = (1, 2, 4, 8)
COLOR_LIGHT_YELLOW = ACCENT_ORANGE
COLOR_LIGHT_RED = ACCENT_ERROR
MAX_IDLE = 1

DecodedInstruction = namedtuple("DecodedInstruction", ["address", "bytes", "text"])
# Logical index of the branch arrow column. Appended after the three columns that
# existing code reads by index, then shown first via SetColumnsOrder.
FLOW_COL = 3
# Call argument annotation, shown after the disassembly.
COMMENT_COL = 4
# Indirect operands whose slot address the instruction alone determines, as distorm writes
# them: "[0x405000]" and "[RIP+0x3af9]". See StaticSlotAddress.
ABS_SLOT_RX = re.compile(r"^\[(0x[0-9A-Fa-f]+)\]$")
RIP_SLOT_RX = re.compile(r"^\[RIP\s*([+-])\s*(0x[0-9A-Fa-f]+)\]$", re.IGNORECASE)

def IsValidHexAddress(s: str) -> bool:
    try:
        if not s.lower().startswith("0x"):
            s = "0x" + s

        value = int(s, 16)
    except ValueError:
        return False

    return value > 0x1000

def ProtectText(prot: int | None) -> str:
    """A VirtualQuery Protect value as rwx flags, for the memory view.

    Protect is 0 for free and reserved regions, and Windows documents it as undefined there
    rather than promising 0, so "none" covers both without claiming which.
    """
    if prot is None:
        return ""

    if not prot & 0xFF:
        return "none"

    read = "R" if prot & (0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80) else "-"
    write = "W" if prot & (0x04 | 0x08 | 0x40 | 0x80) else "-"
    execute = "X" if prot & (0x10 | 0x20 | 0x40 | 0x80) else "-"
    copy = "c" if prot & (0x08 | 0x80) else ""
    guard = "g" if prot & 0x100 else ""
    return f"{read}{write}{execute}{copy}{guard}"

def StaticSlotAddress(operand: str, ripBase: int) -> int | None:
    """The address an indirect operand reads, when the instruction alone determines it.

    Covers the two forms an import slot is reached through - `[0x405000]` as distorm renders
    32-bit absolute addressing, and `[RIP+0x3af9]` as it renders 64-bit rip-relative, where
    the displacement is against the end of the instruction - and deliberately nothing else.

    `[RAX+0x8]` is a vtable or a computed call: its slot depends on register values at this
    break, so an answer cached against the instruction would be wrong at the next one. Those
    stay on the Resolve Symbol menu item, where the user is asking about this break.
    """
    m = ABS_SLOT_RX.match(operand)
    if m:
        return int(m.group(1), 16)

    m = RIP_SLOT_RX.match(operand)
    if m:
        displacement = int(m.group(2), 16)
        return ripBase + displacement if m.group(1) == "+" else ripBase - displacement

    return None

def SetClipboard(text: str):
    clipboard = wx.TheClipboard
    textObj = wx.TextDataObject(text)
    if clipboard.Open():
        try:
            wx.TheClipboard.Clear()
            clipboard.SetData(textObj)
            clipboard.Flush()
        finally:
            clipboard.Close()


def GetClipboardText():
    data = wx.TextDataObject()
    if wx.TheClipboard.Open():
        try:
            if wx.TheClipboard.IsSupported(wx.DataFormat(wx.DF_TEXT)):
                wx.TheClipboard.GetData(data)
                return data.GetText()
        finally:
            wx.TheClipboard.Close()

    return ""


class DisassemblyListCtrl(wx.ListCtrl):
    def __init__(self, parent, console=None):
        super().__init__(parent, style=wx.LC_REPORT)
        # `console` separates the wx parent from the ConsolePanel these controls call
        # back into: with the splitter layout the wx parent is a splitter pane.
        self.parent = console or parent
        self.lastTipRow = None
        self.InsertColumn(0, "Address", width=150)
        self.InsertColumn(1, "Hex bytes", width=180)
        self.InsertColumn(2, "Disassembly", width=400)
        # Added last and then moved to the front for display. Inserting it at index 0 would
        # renumber the seventeen places that read a column by index - the address at 0, the
        # bytes at 1, the disassembly at 2 - for a column nothing looks up by index at all.
        self.InsertColumn(FLOW_COL, "", width=8 * GUTTER_WIDTH)
        # Call arguments for the current instruction, set by ConsolePanel once registers and
        # the stack for this break have arrived. Last, where a comment belongs.
        self.InsertColumn(COMMENT_COL, "Comment", width=320)
        self.SetColumnsOrder([FLOW_COL, 0, 1, 2, COMMENT_COL])
        # Parallel to decodeCache. Not folded into DecodedInstruction because it is a property
        # of a row's neighbours rather than of the instruction, and is recomputed whenever the
        # decoded stream changes.
        self.gutters: list[str] = []
        self.pageMap: list[tuple[int, int, int]] = []
        # The map as it was before the current one, for the memory view's diff.
        self.prevPageMap: list[tuple[int, int, int]] = []
        self.decodeCache: list[DecodedInstruction] = []
        self.cacheLock = threading.Lock()
        self.backHistory: list[int] = []
        self.fontItalic = wx.Font(10, wx.FONTFAMILY_MODERN, wx.FONTSTYLE_ITALIC, wx.FONTWEIGHT_NORMAL)
        # Rows are rebuilt on every break, which drops their colours, so breakpoint addresses
        # are kept here and re-applied. cipRow is the one row holding the CIP highlight.
        self.bpAddrs: set[int] = set()
        self.cipRow = None
        # The one row currently carrying a call argument comment, so it can be cleared
        # when CIP moves rather than leaving a stale annotation behind.
        self.commentRow = None
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)
        self.Bind(wx.EVT_MOTION, self.OnOperandHover)
        self.Bind(wx.EVT_KEY_DOWN, self.OnKeyDown)

    def LoadPageMap(self, data: str) -> bool:
        """Replace the page map, keeping the previous one, and report whether it changed.

        The previous map is what the memory view diffs against, and `changed` is what lets a
        refresh on every break skip the cache invalidation when nothing actually moved. Same
        shape as BuildModuleRanges, for the same reason.
        """
        if not data:
            return False

        regions = []
        for entry in data.split("|"):
            if not entry:
                continue

            try:
                base, size, protect = entry.split(",")
                baseAddr = int(base, 16)
                regionSize = int(size)
                protect = int(protect, 16)
                regions.append((baseAddr, regionSize, protect))
            except (ValueError, AttributeError) as e:
                log.error("[DEBUG CONSOLE] Failed to parse entry '%s': %s", entry, e)
                continue

        regions.sort(key=lambda x: x[0])
        changed = regions != self.pageMap
        self.prevPageMap = self.pageMap
        self.pageMap = regions
        return changed

    def FindPage(self, addr: int) -> tuple[int, int, int] | None:
        return FindRegion(self.pageMap, addr)

    def SetInstructions(self, insts: list[DecodedInstruction]):
        """Render `insts`, reusing every row the new stream shares with the old one.

        A single step normally decodes the same instructions split at a different CIP, so the
        shared prefix is the whole list and no row is touched at all. The previous version
        called DeleteAllItems and re-inserted every row on every break.

        The diff runs over instruction and gutter together. A gutter glyph depends on the
        rows around it, so a branch coming into view changes rows whose instruction is
        untouched; comparing instructions alone would leave those arrows stale.
        """
        gutters = BranchLanes(insts)
        self.Freeze()
        try:
            with self.cacheLock:
                firstChanged = CommonPrefixLength(
                    list(zip(self.decodeCache, self.gutters)), list(zip(insts, gutters))
                )
                self.decodeCache = list(insts)
                self.gutters = gutters
                for row in range(self.GetItemCount() - 1, firstChanged - 1, -1):
                    self.DeleteItem(row)

                if self.cipRow is not None and self.cipRow >= firstChanged:
                    self.cipRow = None

                # Same reasoning as cipRow: a rebuilt row is inserted without its comment, so
                # a commentRow at or past the rebuild no longer refers to an annotated row.
                if self.commentRow is not None and self.commentRow >= firstChanged:
                    self.commentRow = None

                for row in range(firstChanged, len(self.decodeCache)):
                    self._InsertRow(row, self.decodeCache[row])
        finally:
            self.Thaw()

        self.Refresh()
        self.HighlightCip(self.GetCipRow())

    def _InsertRow(self, row: int, inst: DecodedInstruction):
        row = self.InsertItem(row, f"{inst.address:016X}")
        self.SetItem(row, 1, inst.bytes.upper())
        self.SetItem(row, 2, inst.text)
        self.SetItem(row, FLOW_COL, self.gutters[row] if row < len(self.gutters) else "")
        mnemonic = inst.text.split()[0].lower()
        if mnemonic == "call":
            self.SetItemTextColour(row, ACCENT_CALL)
        elif mnemonic in ("jmp", "je", "jne", "jg", "jl"):
            self.SetItemTextColour(row, ACCENT_JUMP)

        if inst.address in self.parent.patchHistoryByAddr:
            self.SetItemFont(row, self.fontItalic)

        if inst.address in self.bpAddrs:
            self.SetItemBackgroundColour(row, COLOR_LIGHT_RED)

    def GetCipRow(self, cip=None):
        row = -1
        if cip is None:
            cip = self.parent.cip
        if cip is None:
            return row

        with self.cacheLock:
            for i, inst in enumerate(self.decodeCache):
                if inst.address == cip:
                    row = i
                    break

        return row

    def GetInstructionRow(self, addr: int):
        row = -1
        with self.cacheLock:
            for i, inst in enumerate(self.decodeCache):
                if inst.address == addr:
                    row = i
                    break
        return row

    def ClearHighlight(self):
        """Repaint only the previously highlighted row; the rest were never recoloured."""
        if self.cipRow is None:
            return

        if 0 <= self.cipRow < self.GetItemCount():
            with self.cacheLock:
                inst = self.decodeCache[self.cipRow] if self.cipRow < len(self.decodeCache) else None

            bp = inst is not None and inst.address in self.bpAddrs
            self.SetItemBackgroundColour(self.cipRow, COLOR_LIGHT_RED if bp else BG_INPUT)

        self.cipRow = None

    def HighlightCip(self, row):
        """Move the CIP highlight, and re-derive the call argument annotation with it.

        Both are properties of where CIP is rather than of a particular fetch, and this is the
        one place every path through the view passes: a re-render, Escape coming back from a
        followed address, Go To EIP/RIP. Annotating only when the stack reply arrived meant
        following an address dropped the arguments and nothing put them back, because
        returning is not a break and fetches nothing.
        """
        self.ClearHighlight()
        if row < 0:
            cip = self.parent.cip
            log.warning("[DEBUG CONSOLE] Instruction %s not found in disassembly", f"{cip:#x}" if cip else "(unknown)")
            self.Refresh()
            self.parent.ShowCallArguments()
            return

        self.cipRow = row
        self.SetItemBackgroundColour(row, ACCENT_GREEN)
        self.CenterRow(row)
        self.Refresh()
        self.parent.ShowCallArguments()

    def CenterRow(self, row):
        """Center the specified row in the view with a single scroll."""
        count = self.GetItemCount()
        if row < 0 or count == 0:
            return

        visRows = self.GetCountPerPage()
        if visRows <= 0:
            self.EnsureVisible(row)
            return

        # Two EnsureVisible calls scroll twice, which shows as a jump on every step.
        target = max(0, min(row - visRows // 2, count - visRows))
        self.ScrollLines(target - self.GetTopItem())
        if not self.IsVisible(row):
            self.EnsureVisible(row)

    def TopRow(self, row):
        """Scroll the specified row so it becomes the topmost visible row."""
        visRows = self.GetCountPerPage()
        if visRows <= 0:
            rowH = 15
            rect = self.GetItemRect(0, wx.LIST_RECT_BOUNDS)
            if rect and rect.height > 0:
                rowH = rect.height
            visRows = self.GetClientSize().height // rowH

        maxTop = max(0, len(self.decodeCache) - visRows)
        row = max(0, min(row, maxTop))

        self.EnsureVisible(row)
        row = row + visRows - 1
        if row < self.GetItemCount():
            self.EnsureVisible(row)

    def OnKeyDown(self, event):
        """Spacebar patches the selected instruction.

        This was a frame-wide accelerator, so it fired wherever the focus was - pressing
        Space after clicking a step button opened the patch dialog instead of stepping.
        """
        if event.ControlDown() and event.GetKeyCode() == ord("C"):
            self.OnCopy(event)
            return

        if event.GetKeyCode() != wx.WXK_SPACE:
            event.Skip()
            return

        row = self.GetNextItem(-1, wx.LIST_NEXT_ALL, wx.LIST_STATE_SELECTED)
        if row == -1:
            return

        self.OnPatchBytes(row)

    def OnContextMenu(self, event):
        pos = event.GetPosition()
        pos = self.ScreenToClient(pos)
        row, flags = self.HitTest(pos)
        if row == wx.NOT_FOUND:
            return

        menu = wx.Menu()
        miCopy = menu.Append(wx.ID_ANY, "Copy")
        miGoTo = menu.Append(wx.ID_ANY, "Go To")
        miGoToCIP = menu.Append(wx.ID_ANY, "Go To EIP/RIP")
        miSetCIP = menu.Append(wx.ID_ANY, "Set EIP/RIP")
        menu.AppendSeparator()
        miNopInstruction = menu.Append(wx.ID_ANY, "NOP Instruction")
        miPatchBytes = menu.Append(wx.ID_ANY, "Patch Bytes")
        miPatchHistory = menu.Append(wx.ID_ANY, "Patch History")
        menu.AppendSeparator()
        miDumpAddress = menu.Append(wx.ID_ANY, "Dump Address")
        miResolveSymbol = menu.Append(wx.ID_ANY, "Resolve Symbol")
        miResolveString = menu.Append(wx.ID_ANY, "Resolve String")
        miAddPrototype = menu.Append(wx.ID_ANY, "Add API Prototype...")
        self.Bind(wx.EVT_MENU, lambda e: self.parent.AddPrototype(), miAddPrototype)
        menu.AppendSeparator()
        miStepInto = menu.Append(wx.ID_ANY, "Step Into")
        miStepOver = menu.Append(wx.ID_ANY, "Step Over")
        miStepOut = menu.Append(wx.ID_ANY, "Step Out")
        miRunUntil = menu.Append(wx.ID_ANY, "Run Until")
        menu.AppendSeparator()
        bpMenu = wx.Menu()
        for slot in ("Next", "0", "1", "2", "3"):
            bpId = wx.NewIdRef()
            bpMenu.Append(bpId, slot)
            self.Bind(wx.EVT_MENU, lambda e, s=slot: self.OnSetBreakpoint(row, s), id=bpId)

        menu.AppendSubMenu(bpMenu, "Set Breakpoint")
        miDataBp = menu.Append(wx.ID_ANY, "Set Data Breakpoint...")
        self.Bind(wx.EVT_MENU, lambda e, r=row: self.OnDataBreakpoint(r), miDataBp)

        self.Bind(wx.EVT_MENU, self.OnCopy, miCopy)
        self.Bind(wx.EVT_MENU, self.OnGoTo, miGoTo)
        self.Bind(wx.EVT_MENU, self.OnGoToCip, miGoToCIP)
        self.Bind(wx.EVT_MENU, lambda e: self.OnSetCip(row), miSetCIP)
        self.Bind(wx.EVT_MENU, lambda e: self.OnNopInstruction(row), miNopInstruction)
        self.Bind(wx.EVT_MENU, lambda e: self.OnPatchBytes(row), miPatchBytes)
        self.Bind(wx.EVT_MENU, self.OnPatchHistory, miPatchHistory)
        self.Bind(wx.EVT_MENU, lambda e, r=row: self.OnDumpAddress(r), miDumpAddress)
        self.Bind(wx.EVT_MENU, lambda e, r=row: self.OnResolveSymbol(r), miResolveSymbol)
        self.Bind(wx.EVT_MENU, lambda e, r=row: self.OnResolveString(r), miResolveString)
        self.Bind(wx.EVT_MENU, self.OnStepInto, miStepInto)
        self.Bind(wx.EVT_MENU, self.OnStepOver, miStepOver)
        self.Bind(wx.EVT_MENU, self.OnStepOut, miStepOut)
        self.Bind(wx.EVT_MENU, lambda e: self.OnRunUntil(row), miRunUntil)
        self.PopupMenu(menu, pos)
        menu.Destroy()

    def OnCopy(self, event):
        rows = []
        row = -1
        while True:
            row = self.GetNextItem(row, wx.LIST_NEXT_ALL, wx.LIST_STATE_SELECTED)
            if row == -1:
                break

            rows.append(row)

        if not rows:
            return

        lines = []
        for row in rows:
            cols = []
            for col in range(self.GetColumnCount()):
                cols.append(self.GetItemText(row, col))

            lines.append("\t".join(cols))

        text = "\n".join(lines)
        SetClipboard(text)

    def OnGoTo(self, event):
        addr = GetClipboardText().strip()
        dialog = wx.TextEntryDialog(self, "Enter hex address (e.g., 0x12345678) or Register:", "Go To Address", addr)
        if dialog.ShowModal() == wx.ID_OK:
            entry = dialog.GetValue().strip()
            target = None
            regsText = self.parent.regsDisplay.GetValue()
            reg = entry.upper()
            m = re.search(rf"\b{reg}\b\s*:\s*([0-9A-Fa-f]+)", regsText)
            if m:
                target = m.group(1)

            if target is None:
                target = entry.lower()
                if not target.startswith("0x"):
                    target = "0x" + target

                try:
                    int(target, 16)
                except ValueError:
                    ui.message(f"Invalid hex address: {entry}", "Error", wx.OK | wx.ICON_ERROR)
                    dialog.Destroy()
                    return

            try:
                # NavigateTo pushes history itself, and pushes where we came from: this used
                # to push the target, so Escape went to the address just navigated to.
                self.NavigateTo(int(target, 16))
            except Exception:
                ui.message(f"Invalid register or hex address: {entry}", "Error", wx.OK | wx.ICON_ERROR)

        dialog.Destroy()

    def OnGoToCip(self, event):
        row = self.GetCipRow(self.parent.cip)
        self.HighlightCip(row)

    def OnSetCip(self, row):
        addrStr = self.GetItemText(row, 0).strip()
        try:
            addr = int(addrStr, 16)
            cip = "RIP"
            if self.parent.bits == 32:
                cip = "EIP"

            payload = f"{cip}|{addr:#X}"
            self.parent.SendCommand(CMD_SET_REGISTER, payload)
        except ValueError:
            ui.message(f"Invalid address for Set EIP/RIP: {addrStr}", "Error", wx.OK | wx.ICON_ERROR)

    def OnStepInto(self, event):
        self.parent.SendCommand(CMD_STEP_INTO)

    def OnStepOver(self, event):
        self.parent.SendCommand(CMD_STEP_OVER)

    def OnStepOut(self, event):
        self.parent.SendCommand(CMD_STEP_OUT)

    def OnRunUntil(self, row):
        addrStr = self.GetItemText(row, 0).strip()
        try:
            addr = int(addrStr, 16)
            payload = f"{addr:#X}"
            self.parent.SendCommand(CMD_RUN_UNTIL, payload)
        except ValueError:
            ui.message(f"Invalid address for Run Until: {addrStr}", "Error", wx.OK | wx.ICON_ERROR)

    def OnSetBreakpoint(self, row, slot):
        addrStr = self.GetItemText(row, 0).strip()
        try:
            addr = int(addrStr, 16)
            payload = f"{slot.lower()}|{addr:#X}"
            self.parent.SendCommand(CMD_SET_BREAKPOINT, payload)
        except ValueError:
            ui.message(f"Invalid address for Set Breakpoint: {addrStr}", "Error", wx.OK | wx.ICON_ERROR)

    def OnDataBreakpoint(self, row):
        """Prefill with the address the instruction references, else its own address."""
        addr = self.OperandAddressAt(row)
        if addr is None:
            addr = self.GetItemText(row, 0).strip()

        self.parent.PromptBreakpoint(addr)

    def ClearBpBackground(self, addr):
        self.bpAddrs.discard(addr)
        row = self.GetInstructionRow(addr)
        if row == wx.NOT_FOUND:
            return

        self.SetItemBackgroundColour(row, ACCENT_GREEN if row == self.cipRow else BG_INPUT)
        self.Refresh()

    def SetBpBackground(self, addr):
        self.bpAddrs.add(addr)
        row = self.GetInstructionRow(addr)
        if row == wx.NOT_FOUND:
            return

        if row != self.cipRow:
            self.SetItemBackgroundColour(row, COLOR_LIGHT_RED)
            self.Refresh()

    def GoToInstruction(self, addr):
        addr = int(addr, 16)
        row = self.GetInstructionRow(addr)
        if row == wx.NOT_FOUND:
            return row

        self.CenterRow(row)
        self.Select(row)
        self.Focus(row)
        self.Refresh()
        return row

    def NavigateTo(self, addr: int) -> bool:
        """Show `addr` in the view, fetching its region if it is not decoded yet.

        GoToInstruction only searches the instructions already decoded, which is the ~36 KB
        window around CIP. Every caller used it on its own and so could only follow an
        address that happened to be on screen already - following a register into a region
        nobody had disassembled reported "address not found" rather than going there.

        History is pushed either way, so Escape comes back from a followed address the same
        way it comes back from a jump.
        """
        if self.GetInstructionRow(addr) != wx.NOT_FOUND:
            self.PushHistory(self.parent.cip)
            self.GoToInstruction(f"{addr:#x}")
            return True

        if not self.parent.IsAddressKnown(addr):
            self.parent.AppendConsole(f"{addr:#x} is not mapped.")
            return False

        # Not decoded but mapped: JumpTo fetches the pages and the decode lands on it.
        self.PushHistory(self.parent.cip)
        self.parent.JumpTo(addr)
        return True

    def GetColumnAtX(self, x):
        """The logical column at client x, walking the columns in the order they are drawn.

        Column widths have to be accumulated in display order, not logical order: the flow
        gutter is logical column 3 shown first, so summing 0,1,2,3 puts every boundary out by
        the gutter's width and reports the gutter itself as whatever is last on screen.
        """
        offset = 0
        for order in range(self.GetColumnCount()):
            col = self.GetColumnIndexFromOrder(order)
            width = self.GetColumnWidth(col)
            if offset <= x < offset + width:
                return col

            offset += width
        return -1

    @staticmethod
    def SafeEval(expr: str) -> int:
        ops = {
            ast.Add: operator.add,
            ast.Sub: operator.sub,
            ast.Mult: operator.mul,
            ast.Div: operator.floordiv,
            ast.FloorDiv: operator.floordiv,
            ast.USub: operator.neg,
        }

        def _eval(node):
            if isinstance(node, ast.Constant):
                return node.value
            elif isinstance(node, ast.Num):
                return node.n
            elif isinstance(node, ast.BinOp):
                return ops[type(node.op)](_eval(node.left), _eval(node.right))
            elif isinstance(node, ast.UnaryOp):
                return ops[type(node.op)](_eval(node.operand))
            else:
                raise ValueError("Unsupported expression")

        tree = ast.parse(expr, mode="eval")
        return _eval(tree.body)

    @staticmethod
    def ParseRegisters(regsText):
        registers = {}
        general = re.findall(r"\b([A-Z0-9]{2,3}):\s*([0-9A-Fa-f]{8,16})", regsText)
        for name, value in general:
            registers[name.upper()] = int(value, 16)

        xmm = re.findall(r"\bXMM(\d{1,2})\s*\.(Low|High)\s*:\s*([0-9A-Fa-f]{8,16})", regsText)
        for num, part, value in xmm:
            key = f"XMM{int(num):02}.{part}"
            registers[key.upper()] = int(value, 16)

        return registers

    def ParseOperandAddress(self, inst: str, ripBase: int) -> int | None:
        m = re.search(r"\[([A-Za-z]{2}:)?([^\]]+)\]", inst)
        if m:
            seg = m.group(1).lower()[:-1] if m.group(1) else None
            expr = m.group(2).replace(" ", "").lower()
            regsText = self.parent.regsDisplay.GetValue()
            regVals = {g.group(1).lower(): int(g.group(2), 16) for g in
                re.finditer(r"([A-Za-z0-9]+):\s*([0-9A-Fa-f]+)", regsText)}
            regVals["rip"] = ripBase
            for reg in sorted(regVals, key=len, reverse=True):
                expr = re.sub(rf"\b{reg}\b", str(regVals[reg]), expr)

            try:
                addr = self.SafeEval(expr)
            except Exception:
                return None

            if seg and seg in regVals:
                addr += regVals[seg]
            return addr

        # Accept any 0x literal that is plausibly an address, rather than counting digits.
        # The old bound was {8,16}, so a 32-bit target based at 0x400000 - where a direct call
        # disassembles as `CALL 0x401000`, six digits - resolved no operands at all.
        # IsValidHexAddress is the project's own notion of plausible, and still rejects the
        # small immediates the digit count was there to exclude.
        for match in re.finditer(r"\b0x[0-9A-Fa-f]+\b", inst):
            if IsValidHexAddress(match.group(0)):
                return int(match.group(0), 16)

        return None

    def OnOperandHover(self, event):
        x, y = event.GetPosition()
        row, flags = self.HitTest(wx.Point(x, y))
        if row == wx.NOT_FOUND or row == self.lastTipRow:
            if row == wx.NOT_FOUND:
                self.SetToolTip(None)
                self.lastTipRow = None

            return event.Skip()

        col = self.GetColumnAtX(x)
        if col != 2:
            return event.Skip()

        inst = self.GetItemText(row, 2)
        instLen = len(self.GetItemText(row, 1)) // 2
        ripBase = int(self.GetItemText(row, 0), 16) + instLen
        addr = self.ParseOperandAddress(inst, ripBase)
        if addr is None:
            self.SetToolTip(None)
            self.lastTipRow = None
            return event.Skip()

        # Tooltip only: hover used to overwrite the clipboard on every row change.
        self.SetToolTip(f"{addr:#x}")
        self.lastTipRow = row
        return event.Skip()

    def PushHistory(self, addr: int):
        self.backHistory.append(addr)

    def OnBack(self, event):
        """Handle ESC: go back to previous address in history or home CIP."""
        if self.backHistory:
            addr = self.backHistory.pop()
        else:
            addr = self.parent.cip

        if addr is None:
            return

        row = self.GetInstructionRow(addr)
        if row != -1:
            self.HighlightCip(row)
            return

        # History addresses are pinned against eviction, so this only happens when the region
        # itself was flushed (module unload, fault, page map change). Re-fetching here would
        # mean calling JumpTo, which sets self.cip and would highlight this address as the
        # current instruction when it is not.
        ui.message(f"Address {addr:#x} is no longer mapped.", "Info", wx.OK | wx.ICON_INFORMATION)

    def OperandAddressAt(self, row: int) -> int | None:
        """The address the instruction on `row` references, or None if it references none.

        These actions used to take their operand from the clipboard, which hover happened to
        fill in. That made the clipboard a load-bearing data channel: copying anything else
        between hovering and right-clicking silently redirected the action, and OnResolveRef
        additionally used the last *hovered* row rather than the one you clicked.
        """
        if row < 0 or row >= self.GetItemCount():
            return None

        try:
            instLen = len(self.GetItemText(row, 1)) // 2
            ripBase = int(self.GetItemText(row, 0), 16) + instLen
        except ValueError:
            return None

        return self.ParseOperandAddress(self.GetItemText(row, 2), ripBase)

    def OnDumpAddress(self, row):
        addr = self.OperandAddressAt(row)
        if addr is None:
            self.parent.AppendConsole("No address operand on this instruction.")
            return

        self.parent.SendCommand(CMD_MEM_DUMP, f"{addr:#x}", tag=self.parent.NextTag(TAG_DUMP))

    def OnResolveSymbol(self, row):
        """Name what this instruction's operand refers to.

        Replaces the old From Address / From Dereference pair. Those asked the user to
        classify the operand as the target or as memory holding the target, which the
        disassembly already states: brackets or no brackets. Getting it wrong silently gave
        a wrong answer - From Dereference on a direct call read the callee's first bytes and
        looked those up as a pointer.

        Direct operands are named for every instruction as it is decoded, so reaching for
        this on one means the export table has no entry; say so rather than nothing. Indirect
        ones need the slot read, which is also how a slot populated after the automatic pass
        gets picked up.
        """
        addr = self.OperandAddressAt(row)
        if addr is None:
            self.parent.AppendConsole("No address operand on this instruction.")
            return

        if "[" not in self.GetItemText(row, 2):
            export = self.parent.exports.get(addr)
            self.parent.AppendConsole(export or f"No export known at {addr:#x}")
            return

        try:
            instAddr = int(self.GetItemText(row, 0), 16)
        except ValueError:
            return

        self.parent.resolvedExports[instAddr] = {addr: ""}
        self.parent.ResolveRef(addr)

    def OnResolveString(self, row):
        """Read what this instruction's operand points at and show it as a string.

        One item, where there were From Address and From Dereference: the cached-lookup half
        was only ever the read half's result, so asking for the string now reports the cached
        one if there is one and reads it if there is not.
        """
        addr = self.OperandAddressAt(row)
        if addr is None:
            self.parent.AppendConsole("No address operand on this instruction.")
            return

        string = self.parent.resolvedStrings.get(addr)
        if string:
            self.parent.AppendConsole(string)
            return

        self.parent.ResolveString(addr)

    def OnNopInstruction(self, row):
        addrStr = self.GetItemText(row, 0)
        if addrStr and IsValidHexAddress(addrStr):
            self.parent.SendCommand(CMD_NOP_INSTRUCTION, addrStr)

    def GetOriginalBytes(self, row: int, numBytes: int) -> str:
        hexStr = ""
        collectedBytes = 0
        currentRow = row
        totalRows = self.GetItemCount()
        while collectedBytes < numBytes and currentRow < totalRows:
            rowHex = self.GetItemText(currentRow, 1)
            hexStr += rowHex
            collectedBytes = len(hexStr) // 2
            currentRow += 1

        return hexStr[: numBytes * 2]

    def AssemblePatch(self, asmText: str, baseAddress: str) -> tuple[str, list[PatchEntry]]:
        addr = int(baseAddress, 16)
        return self.parent.assembler.AssembleAt(asmText, addr)

    def UpdatePatchHistory(self, newEntries: list[PatchEntry], row: int):
        for entry in newEntries:
            numBytes = len(entry.patchedBytes) // 2
            orig = self.GetOriginalBytes(row, numBytes)
            entry.originalBytes = orig
            self.parent.patchHistory.append(entry)
            self.parent.patchHistoryByAddr[entry.address].append(entry)

    def OnPatchBytes(self, row):
        addrStr = self.GetItemText(row, 0)
        instrStr = self.GetItemText(row, 2)
        if addrStr and IsValidHexAddress(addrStr):
            dlg = PatchDialog(self, instrStr)
            if dlg.ShowModal() == wx.ID_OK:
                asmText = dlg.GetAsmText()
                dlg.Destroy()
                codeHex, newEntries = self.AssemblePatch(asmText, addrStr)
                if codeHex and not "error" in codeHex:
                    previewTxt = f"{codeHex}    {asmText}"
                    confirmDlg = ConfirmPatchDialog(self, previewTxt)
                    if confirmDlg.ShowModal() == wx.ID_OK:
                        confirmDlg.Destroy()
                        data = f"{int(addrStr, 16):#x}|{codeHex}"
                        self.UpdatePatchHistory(newEntries, row)
                        self.parent.SendCommand(CMD_PATCH_BYTES, data)
                else:
                    ui.message(f"Instructions were not assembled: {codeHex}", "Info", wx.OK | wx.ICON_INFORMATION)
            else:
                dlg.Destroy()

    def OnPatchHistory(self, event):
        dlg = PatchHistoryDialog(self, self.parent.patchHistory)
        dlg.ShowModal()
        dlg.Destroy()


class RegsTextCtrl(wx.TextCtrl):
    def __init__(self, parent, style, console=None):
        """TextCtrl subclass"""
        super().__init__(parent, style=style)
        # `console` separates the wx parent from the ConsolePanel these controls call
        # back into: with the splitter layout the wx parent is a splitter pane.
        self.parent = console or parent
        # Where the context menu was opened, so an action can use the register under the
        # cursor when nothing is selected. See ClickedAddress.
        self.lastClickPos = wx.Point(0, 0)
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

    def ClickedAddress(self) -> str:
        """The address an action should act on: the selection, else the register clicked on.

        Every action here used to read GetStringSelection alone, so right-clicking a register
        and picking Follow Address did nothing at all unless the hex digits had been dragged
        over first - no message, no movement. Falling back to the line under the cursor makes
        the obvious gesture work and leaves an explicit selection winning where there is one.
        """
        selected = self.GetStringSelection().strip()
        if selected:
            return selected

        # HitTestPos gives an offset into the whole text, which GetLineText's row index does
        # not: the pane wraps, so with the splitter dragged narrow a row is a display line and
        # "RAX: 0000000140001374" is two of them, neither matching a register line.
        _result, offset = self.HitTestPos(self.lastClickPos)
        if offset < 0:
            return ""

        text = self.GetValue()
        start = text.rfind("\n", 0, offset) + 1
        end = text.find("\n", offset)
        line = text[start:] if end == -1 else text[start:end]
        m = re.match(r"\s*[A-Za-z][A-Za-z0-9]*\s*:\s*([0-9A-Fa-f]+)", line)
        return m.group(1) if m else ""

    def OnContextMenu(self, event):
        self.lastClickPos = self.ScreenToClient(event.GetPosition())
        menu = wx.Menu()
        miCopy = menu.Append(wx.ID_ANY, "Copy")
        miDumpAddress = menu.Append(wx.ID_ANY, "Dump Memory Address")
        miDataBp = menu.Append(wx.ID_ANY, "Set Data Breakpoint...")
        miFollowAddress = menu.Append(wx.ID_ANY, "Follow Address")
        miExportAddress = menu.Append(wx.ID_ANY, "Resolve Export Name From Address")
        miExportDeref = menu.Append(wx.ID_ANY, "Resolve Export Name From Dereference")
        menu.AppendSeparator()
        miClearZeroFlag = menu.Append(wx.ID_ANY, "Clear Zero Flag")
        miSetZeroFlag = menu.Append(wx.ID_ANY, "Set Zero Flag")
        miFlipZeroFlag = menu.Append(wx.ID_ANY, "Flip Zero Flag")
        menu.AppendSeparator()
        miClearSignFlag = menu.Append(wx.ID_ANY, "Clear Sign Flag")
        miSetSignFlag = menu.Append(wx.ID_ANY, "Set Sign Flag")
        miFlipSignFlag = menu.Append(wx.ID_ANY, "Flip Sign Flag")
        menu.AppendSeparator()
        miClearCarryFlag = menu.Append(wx.ID_ANY, "Clear Carry Flag")
        miSetCarryFlag = menu.Append(wx.ID_ANY, "Set Carry Flag")
        miFlipCarryFlag = menu.Append(wx.ID_ANY, "Flip Carry Flag")

        self.Bind(wx.EVT_MENU, self.OnDumpAddress, miDumpAddress)
        self.Bind(wx.EVT_MENU, lambda e: self.parent.PromptBreakpoint(self.ClickedAddress()), miDataBp)
        self.Bind(wx.EVT_MENU, self.OnFollowAddress, miFollowAddress)
        self.Bind(wx.EVT_MENU, self.OnResolveAddress, miExportAddress)
        self.Bind(wx.EVT_MENU, self.OnResolveRef, miExportDeref)
        self.Bind(wx.EVT_MENU, self.ClearZeroFlag, miClearZeroFlag)
        self.Bind(wx.EVT_MENU, self.SetZeroFlag, miSetZeroFlag)
        self.Bind(wx.EVT_MENU, self.FlipZeroFlag, miFlipZeroFlag)
        self.Bind(wx.EVT_MENU, self.ClearSignFlag, miClearSignFlag)
        self.Bind(wx.EVT_MENU, self.SetSignFlag, miSetSignFlag)
        self.Bind(wx.EVT_MENU, self.FlipSignFlag, miFlipSignFlag)
        self.Bind(wx.EVT_MENU, self.ClearCarryFlag, miClearCarryFlag)
        self.Bind(wx.EVT_MENU, self.SetCarryFlag, miSetCarryFlag)
        self.Bind(wx.EVT_MENU, self.FlipCarryFlag, miFlipCarryFlag)
        self.Bind(wx.EVT_MENU, self.OnCopy, miCopy)

        menu.AppendSeparator()
        regMenu = wx.Menu()
        regs = ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RSP", "RBP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"]
        if self.parent.bits == 32:
            regs = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "ESP", "EBP"]

        for reg in regs:
            miName = f"miSet{reg}"
            mi = regMenu.Append(wx.ID_ANY, f"Set {reg}")
            setattr(self, miName, mi)
            self.Bind(wx.EVT_MENU, lambda e, r=reg: self.OnSetRegister(r), mi)

        menu.AppendSubMenu(regMenu, "Set Register")

        pos = event.GetPosition()
        pos = self.ScreenToClient(pos)
        self.PopupMenu(menu, pos)
        menu.Destroy()

    def OnDumpAddress(self, event):
        sel = self.ClickedAddress()
        if sel:
            self.parent.memAddressInput.SetValue(sel)
            evt = wx.CommandEvent(wx.EVT_TEXT_ENTER.typeId, self.parent.memAddressInput.GetId())
            self.parent.OnAddressEnter(evt)

    def OnFollowAddress(self, event):
        addrStr = self.ClickedAddress()
        if not addrStr or not IsValidHexAddress(addrStr):
            self.parent.AppendConsole("No address to follow.")
            return

        self.parent.disassemblyConsole.NavigateTo(int(addrStr, 16))

    def OnCopy(self, event):
        text = self.GetStringSelection().strip()
        SetClipboard(text)

    def ClearZeroFlag(self, event):
        self.FlagCommand("ClearZeroFlag")

    def SetZeroFlag(self, event):
        self.FlagCommand("SetZeroFlag")

    def FlipZeroFlag(self, event):
        self.FlagCommand("FlipZeroFlag")

    def ClearSignFlag(self, event):
        self.FlagCommand("ClearSignFlag")

    def SetSignFlag(self, event):
        self.FlagCommand("SetSignFlag")

    def FlipSignFlag(self, event):
        self.FlagCommand("FlipSignFlag")

    def ClearCarryFlag(self, event):
        self.FlagCommand("ClearCarryFlag")

    def SetCarryFlag(self, event):
        self.FlagCommand("SetCarryFlag")

    def FlipCarryFlag(self, event):
        self.FlagCommand("FlipCarryFlag")

    def FlagCommand(self, cmd):
        self.parent.SendCommand(CMD_MOD_FLAG, cmd)

    def OnSetRegister(self, reg):
        prompt = f"Enter new value for {reg} (decimal or 0x-prefixed hex):"
        valueStr = wx.GetTextFromUser(prompt, "Set Register", "", self)
        if not valueStr:
            return

        try:
            val = int(valueStr, 0)
        except ValueError:
            ui.message(f"'{valueStr}' is not a valid number.", "Error", wx.ICON_ERROR)
            return

        payload = f"{reg}|{val:#X}"
        self.parent.SendCommand(CMD_SET_REGISTER, payload)

    def OnResolveAddress(self, event):
        addrStr = self.ClickedAddress()
        try:
            addrInt = int(addrStr, 16)
        except ValueError:
            return

        export = self.parent.exports.get(addrInt)
        self.parent.AppendConsole(export)
        return

    def OnResolveRef(self, event):
        addrStr = self.ClickedAddress()
        self.parent.ResolveRef(addrStr)


class StackListCtrl(wx.ListCtrl):
    def __init__(self, parent, console=None):
        super().__init__(parent, style=wx.LC_REPORT)
        # `console` separates the wx parent from the ConsolePanel these controls call
        # back into: with the splitter layout the wx parent is a splitter pane.
        self.parent = console or parent
        self.spVal = None
        # Which of ESP/RSP the target has, so the menu names the register the analyst sees.
        self.spName = "RSP"
        self.InsertColumn(0, "Address", width=170)
        self.InsertColumn(1, "Value", width=170)
        self.InsertColumn(2, "", width=70)
        self.data = []
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

    def UpdateData(self, data):
        """Populate the list with rows and highlight."""
        rows = []
        for line in data.splitlines():
            parts = [p.strip() for p in line.split(",", 1)]

            if len(parts) < 2:
                continue

            addr, val = parts[0], parts[1]
            rows.append((addr, val))

        regsText = self.parent.regsDisplay.GetValue()
        m = re.search(r"\b([ER]SP):\s*([0-9A-Fa-f]+)", regsText)
        self.spVal = m.group(2) if m else None
        self.spName = m.group(1).upper() if m else "RSP"
        self.DeleteAllItems()
        self.data = rows
        row = self.SpRow()
        if row == wx.NOT_FOUND:
            row = len(rows) // 2

        for i, (addr, val) in enumerate(rows):
            self.InsertItem(i, str(addr))
            self.SetItem(i, 1, str(val))
            self.SetItem(i, 2, "")

            if i == row:
                self.SetItemBackgroundColour(i, COLOR_LIGHT_YELLOW)

        self.Refresh()
        self.CenterRow(row)

    def StackWords(self) -> list[tuple[int, int]]:
        """(address, value) for the stack window, ascending, as CallArguments expects."""
        words = []
        for addr, val in self.data:
            try:
                words.append((int(addr, 16), int(val, 16)))
            except ValueError:
                continue

        words.sort()
        return words

    def SpRow(self) -> int:
        """The row holding the stack pointer, or wx.NOT_FOUND."""
        if not self.spVal:
            return wx.NOT_FOUND

        target = self.spVal.lower()
        for i, (addr, _) in enumerate(self.data):
            if addr.lower() == target:
                return i

        return wx.NOT_FOUND

    def OnBack(self, event=None):
        """Escape: put the stack pointer back in the middle of the view.

        The same key does the same job in the other views - Disassembly goes back to CIP or
        the last address jumped from, Memory Dump to where it was - so scrolling the stack
        away from the frame you are reading is recoverable the way they are.
        """
        row = self.SpRow()
        if row == wx.NOT_FOUND:
            self.parent.AppendConsole(f"{self.spName} is not in the stack window.")
            return

        self.CenterRow(row)
        self.Select(row)
        self.Focus(row)

    @staticmethod
    def GetAscii(dataBytes) -> str:
        """Inspect an 8-byte qword for printable ASCII; return '.' for non-printable."""
        buf = dataBytes[:8].ljust(8, b"\x00")
        asciiStr = "".join(chr(b) if 32 <= b < 127 else "." for b in buf)
        return asciiStr

    def OnContextMenu(self, event):
        pos = event.GetPosition()
        pos = self.ScreenToClient(pos)
        row, flags = self.HitTest(pos)

        menu = wx.Menu()
        # Offered whether or not a row was hit: having scrolled away from the stack pointer,
        # there may well be no row under the cursor worth clicking.
        miGoToSp = menu.Append(wx.ID_ANY, f"Go To {self.spName}")
        self.Bind(wx.EVT_MENU, self.OnBack, miGoToSp)
        if row == wx.NOT_FOUND:
            self.PopupMenu(menu, pos)
            menu.Destroy()
            return

        menu.AppendSeparator()
        miCopy = menu.Append(wx.ID_ANY, "Copy")
        miFollowAddr = menu.Append(wx.ID_ANY, "Dump Address")
        miFollowVal = menu.Append(wx.ID_ANY, "Dump Value")
        miExportAddress = menu.Append(wx.ID_ANY, "Export Name From Address")
        miExportValue = menu.Append(wx.ID_ANY, "Export Name From Value")
        miExportValueRef = menu.Append(wx.ID_ANY, "Export Name From Value Dereference")

        self.Bind(wx.EVT_MENU, self.OnCopy, miCopy)
        self.Bind(
            wx.EVT_MENU,
            lambda e, r=row: (
                self.parent.memAddressInput.SetValue(self.data[r][0]),
                self.parent.OnAddressEnter(wx.CommandEvent(wx.EVT_TEXT_ENTER.typeId, self.parent.memAddressInput.GetId())),
            ),
            miFollowAddr,
        )
        self.Bind(
            wx.EVT_MENU,
            lambda e, r=row: (
                self.parent.memAddressInput.SetValue(self.data[r][1]),
                self.parent.OnAddressEnter(wx.CommandEvent(wx.EVT_TEXT_ENTER.typeId, self.parent.memAddressInput.GetId())),
            ),
            miFollowVal,
        )
        self.Bind(wx.EVT_MENU, lambda e: self.OnResolveAddress(row), miExportAddress)
        self.Bind(wx.EVT_MENU, lambda e: self.OnResolveValue(row), miExportValue)
        self.Bind(wx.EVT_MENU, lambda e: self.OnResolveValueRef(row), miExportValueRef)

        self.PopupMenu(menu, pos)
        menu.Destroy()

    def OnCopy(self, event):
        rows = []
        row = -1
        while True:
            row = self.GetNextItem(row, wx.LIST_NEXT_ALL, wx.LIST_STATE_SELECTED)
            if row == -1:
                break

            rows.append(row)

        if not rows:
            return

        lines = []
        for row in rows:
            cols = []
            for col in range(self.GetColumnCount()):
                cols.append(self.GetItemText(row, col))

            lines.append("\t".join(cols))

        text = "\n".join(lines)
        SetClipboard(text)

    def CenterRow(self, row):
        """Center the specified row in the view."""
        if not self.data or row < 0 or row >= len(self.data):
            return

        visRows = self.GetCountPerPage()
        if visRows <= 0:
            rowH = 15
            rect = self.GetItemRect(0, wx.LIST_RECT_BOUNDS)
            rowH = rect.height if rect and rect.height > 0 else rowH
            clientH = self.GetClientSize().height
            visRows = clientH // rowH

        visRows = min(visRows, len(self.data))
        if visRows <= 0:
            visRows = 15

        anchor = max(0, row + (visRows // 2))
        maxTop = max(0, len(self.data) - visRows)
        anchor = min(anchor, maxTop)

        self.EnsureVisible(row)
        self.EnsureVisible(anchor)

    def OnResolveAddress(self, row):
        addrStr = self.data[row][0]
        try:
            addrInt = int(addrStr, 16)
        except ValueError:
            return

        export = self.parent.exports.get(addrInt)
        self.parent.AppendConsole(export)
        return

    def OnResolveValue(self, row):
        addrStr = self.data[row][1]
        try:
            addrInt = int(addrStr, 16)
        except ValueError:
            return

        export = self.parent.exports.get(addrInt)
        self.parent.AppendConsole(export)
        return

    def OnResolveValueRef(self, row):
        addrStr = self.data[row][1]
        self.parent.ResolveRef(addrStr)


class MemDumpListCtrl(wx.ListCtrl):
    def __init__(self, parent, console=None):
        super().__init__(parent, style=wx.LC_REPORT)
        # `console` separates the wx parent from the ConsolePanel these controls call
        # back into: with the splitter layout the wx parent is a splitter pane.
        self.parent = console or parent
        self.InsertColumn(0, "Address", width=170)
        self.InsertColumn(1, "Hex Dump", width=400)
        self.InsertColumn(2, "Ascii", width=150)
        self.data = []
        self.addr = None
        self.backHistory: list[int] = []
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

    def UpdateData(self, data):
        """Populate the list control from a string of lines."""
        if self.GetItemCount() > 0:
            target = self.GetItemText(0, 0)
            self.PushHistory(int(target, 16))

        self.DeleteAllItems()
        self.data.clear()

        for i, line in enumerate(data.splitlines()):
            parts = [p.strip() for p in line.split(",", 1)]
            if not parts:
                continue

            addr = parts[0]
            hexStr = parts[1] if len(parts) > 1 else ""
            asciiChars = []
            for byteToken in hexStr.split():
                try:
                    val = int(byteToken, 16)
                    asciiChars.append(chr(val) if 32 <= val < 127 else ".")
                except ValueError:
                    asciiChars.append(".")

            asciiStr = "".join(asciiChars)
            self.data.append((addr, hexStr, asciiStr))
            row = self.InsertItem(i, addr)
            self.SetItem(row, 1, hexStr)
            self.SetItem(row, 2, asciiStr)

    def GetFirstHexAddress(self):
        """Return the address string from the first row, or None if empty."""
        return self.data[0][0] if self.data else None

    def OnContextMenu(self, event):
        pos = event.GetPosition()
        pos = self.ScreenToClient(pos)
        row, _ = self.HitTest(pos)
        menu = wx.Menu()
        miCopy = menu.Append(wx.ID_ANY, "Copy")
        miSaveToFile = menu.Append(wx.ID_ANY, "Save Memory To File...")
        self.Bind(wx.EVT_MENU, self.OnCopy, miCopy)
        self.Bind(wx.EVT_MENU, self.OnSaveMemoryToFile, miSaveToFile)
        if row != wx.NOT_FOUND and row < len(self.data):
            menu.AppendSeparator()
            miDataBp = menu.Append(wx.ID_ANY, "Set Data Breakpoint...")
            self.Bind(wx.EVT_MENU, lambda e, r=row: self.parent.PromptBreakpoint(self.data[r][0]), miDataBp)
        self.PopupMenu(menu, pos)
        menu.Destroy()

    def OnCopy(self, event):
        rows = []
        row = -1
        while True:
            row = self.GetNextItem(row, wx.LIST_NEXT_ALL, wx.LIST_STATE_SELECTED)
            if row == -1:
                break

            rows.append(row)

        if not rows:
            return

        lines = []
        for row in rows:
            cols = []
            for col in range(self.GetColumnCount()):
                cols.append(self.GetItemText(row, col))

            lines.append("\t".join(cols))

        text = "\n".join(lines)
        SetClipboard(text)

    def OnDumpAddress(self, event):
        if isinstance(self.addr, int):
            self.addr = f"{self.addr:x}"
        self.parent.memAddressInput.SetValue(self.addr)
        evt = wx.CommandEvent(wx.EVT_TEXT_ENTER.typeId, self.parent.memAddressInput.GetId())
        self.parent.OnAddressEnter(evt)

    def PushHistory(self, addr: int):
        self.backHistory.append(addr)

    def OnBack(self, event):
        """Handle ESC: go back to previous address"""
        if not self.backHistory:
            return
        self.addr = self.backHistory[-1]
        if len(self.backHistory) > 1:
            self.addr = self.backHistory.pop()

        self.OnDumpAddress(event)

    def DumpFormatDialog(self):
        dlg = wx.SingleChoiceDialog(
            None,
            "Select the format to save:",
            "Save Format",
            ["Full View (Address + Hex + ASCII)", "Hex Dump Only", "ASCII Only", "Raw Bytes", "C Style", "Intel Hex"],
        )
        if dlg.ShowModal() == wx.ID_OK:
            return dlg.GetStringSelection()

        return None

    def OnSaveMemoryToFile(self, event):
        selection = self.DumpFormatDialog()
        if not selection:
            return

        dlg = wx.FileDialog(self, "Save Memory Dump", wildcard="All files (*.*)|*.*", style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT)
        if dlg.ShowModal() != wx.ID_OK:
            return

        path = dlg.GetPath()

        format_to_ext = {
            "Full View (Address + Hex + ASCII)": ".txt",
            "Hex Dump Only": ".txt",
            "ASCII Only": ".txt",
            "Raw Bytes": ".bin",
            "C Style": ".c",
            "Intel Hex": ".hex",
        }
        default_ext = format_to_ext.get(selection, ".txt")
        if not Path(path).suffix:
            path += default_ext

        ext = Path(path).suffix.lower()
        is_binary = ext == ".bin"

        try:
            with open(path, "wb" if is_binary else "w", encoding=None if is_binary else "utf-8") as f:
                if selection == "Full View (Address + Hex + ASCII)":
                    for row in range(self.GetItemCount()):
                        addr = self.GetItemText(row, 0)
                        hexpart = self.GetItemText(row, 1)
                        asciipart = self.GetItemText(row, 2)
                        f.write(f"{addr}  {hexpart:<48}  {asciipart}\n")

                elif selection == "Hex Dump Only":
                    for row in range(self.GetItemCount()):
                        hexpart = self.GetItemText(row, 1)
                        f.write(f"{hexpart}\n")

                elif selection == "ASCII Only":
                    for row in range(self.GetItemCount()):
                        asciipart = self.GetItemText(row, 2)
                        f.write(f"{asciipart}\n")

                elif selection == "Raw Bytes":
                    for row in range(self.GetItemCount()):
                        hexpart = self.GetItemText(row, 1).strip()
                        hexbytes = bytes.fromhex(hexpart)
                        f.write(hexbytes)

                elif selection == "C Style":
                    all_bytes = bytearray()
                    for row in range(self.GetItemCount()):
                        hexpart = self.GetItemText(row, 1).strip()
                        all_bytes.extend(bytes.fromhex(hexpart))

                    f.write("unsigned char dump[] = {\n")
                    for i in range(0, len(all_bytes), 12):
                        line = ", ".join(f"0x{b:02X}" for b in all_bytes[i : i + 12])
                        f.write(f"    {line},\n")

                    f.write("};\n")

                elif selection == "Intel Hex":
                    all_bytes = bytearray()
                    for row in range(self.GetItemCount()):
                        hexpart = self.GetItemText(row, 1).strip()
                        all_bytes.extend(bytes.fromhex(hexpart))

                    addr = 0
                    for i in range(0, len(all_bytes), 16):
                        chunk = all_bytes[i : i + 16]
                        record = bytearray()
                        record.append(len(chunk))
                        record.append((addr >> 8) & 0xFF)
                        record.append(addr & 0xFF)
                        record.append(0x00)
                        record.extend(chunk)
                        checksum = (-sum(record)) & 0xFF
                        hexline = ":" + "".join(f"{b:02X}" for b in record) + f"{checksum:02X}\n"
                        f.write(hexline)
                        addr += len(chunk)

                    f.write(":00000001FF\n")

                else:
                    ui.message("Unknown format selected.", "Error", wx.ICON_ERROR)

        except Exception as e:
            ui.message(f"Failed to save file:\n{e}", "Error", wx.ICON_ERROR)


class ThreadListCtrl(wx.ListCtrl):
    """List control to display threads with columns: TID, Start Address."""

    def __init__(self, parent, console=None):
        super().__init__(parent, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        # `console` separates the wx parent from the ConsolePanel these controls call
        # back into: with the splitter layout the wx parent is a splitter pane.
        self.parent = console or parent
        self.data: list[tuple[str, str]] = []
        self.InsertColumn(0, "TID", width=60)
        self.InsertColumn(1, "Start Address", width=160)
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)
        self.Bind(wx.EVT_MOTION, self.OnMouseOver)
        self.Bind(wx.EVT_LIST_ITEM_ACTIVATED, self.OnActivated)

    def UpdateData(self, threadEntries: list[tuple[str, str]]):
        """Populate the list with thread info: (tid, start address)."""
        self.DeleteAllItems()
        self.data = threadEntries
        for i, (tid, addr) in enumerate(threadEntries):
            row = self.InsertItem(i, tid)
            self.SetItem(row, 1, addr)
            if i == 0:
                font = self.GetFont()
                boldFont = wx.Font(font.GetPointSize(), font.GetFamily(), font.GetStyle(), wx.FONTWEIGHT_BOLD)
                self.SetItemFont(row, boldFont)

        band_rows(self)

    def OnContextMenu(self, event):
        pos = event.GetPosition()
        pos = self.ScreenToClient(pos)
        row, flags = self.HitTest(pos)
        if row == wx.NOT_FOUND:
            return

        menu = wx.Menu()
        miFollowStartAddress = menu.Append(wx.ID_ANY, "Follow Start Address")
        self.Bind(wx.EVT_MENU, lambda e: self.OnFollowStartAddress(row), miFollowStartAddress)
        miInspect = menu.Append(wx.ID_ANY, "Inspect Thread" if row else "Return To Halted Thread")
        self.Bind(wx.EVT_MENU, lambda e, r=row: self.OnInspectThread(r), miInspect)
        self.PopupMenu(menu, pos)
        menu.Destroy()

    def OnActivated(self, event):
        self.OnInspectThread(event.GetIndex())

    def OnInspectThread(self, row):
        """Row 0 is the halted thread - HandleThreads always sorts it first."""
        if row == 0:
            self.parent.ReturnToHaltedThread()
            return

        tid = self.GetItemText(row, 0).strip()
        if tid:
            self.parent.InspectThread(tid)

    def OnFollowStartAddress(self, row):
        addrStr = self.GetItemText(row, 1).strip()
        if addrStr and IsValidHexAddress(addrStr):
            self.parent.disassemblyConsole.NavigateTo(int(addrStr, 16))

    def OnMouseOver(self, event):
        x, y = event.GetPosition()
        row, flags = self.HitTest(wx.Point(x, y))
        if row == wx.NOT_FOUND:
            if row == wx.NOT_FOUND:
                self.SetToolTip(None)
            return event.Skip()

        tid = self.GetItemText(row, 0)
        if not tid:
            self.SetToolTip(None)
            return event.Skip()

        tidStr = f"{int(tid):#x}"
        self.SetToolTip(tidStr)
        return event.Skip()


class BreakpointsListCtrl(wx.ListCtrl):
    """List control to display breakpoints with columns: dr, Address."""

    def __init__(self, parent, console=None):
        super().__init__(parent, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        # `console` separates the wx parent from the ConsolePanel these controls call
        # back into: with the splitter layout the wx parent is a splitter pane.
        self.parent = console or parent
        self.InsertColumn(0, "DR", width=40)
        self.InsertColumn(1, "Address", width=160)
        self.InsertColumn(2, "Type", width=50)
        self.InsertColumn(3, "Size", width=45)
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

    def UpdateData(self, bps: list[tuple[str, str, str, str]]):
        """Populate the list with (dr, address, type, size)."""
        self.DeleteAllItems()
        for i, (dr, addr, bpType, size) in enumerate(bps):
            row = self.InsertItem(i, dr)
            self.SetItem(row, 1, addr)
            self.SetItem(row, 2, BP_TYPE_LABELS.get(bpType, bpType))
            self.SetItem(row, 3, size)

    def OnContextMenu(self, event):
        pos = event.GetPosition()
        pos = self.ScreenToClient(pos)
        row, flags = self.HitTest(pos)

        menu = wx.Menu()
        # Available on empty space too, so a breakpoint can be added with nothing selected.
        miAddBreakpoint = menu.Append(wx.ID_ANY, "Add Breakpoint...")
        self.Bind(wx.EVT_MENU, lambda e: self.parent.PromptBreakpoint(), miAddBreakpoint)
        if row != wx.NOT_FOUND:
            menu.AppendSeparator()
            miDeleteBreakpoint = menu.Append(wx.ID_ANY, "Delete Breakpoint")
            miFollowBreakpoint = menu.Append(wx.ID_ANY, "Follow Address")
            self.Bind(wx.EVT_MENU, lambda e: self.OnDeleteBreakpoint(row), miDeleteBreakpoint)
            self.Bind(wx.EVT_MENU, lambda e: self.OnFollowBreakpoint(row), miFollowBreakpoint)
        self.PopupMenu(menu, pos)
        menu.Destroy()

    def OnDeleteBreakpoint(self, row):
        index = self.GetItemText(row, 0).strip()
        self.parent.SendCommand(CMD_DELETE_BREAKPOINT, index)

    def OnFollowBreakpoint(self, row):
        addrStr = self.GetItemText(row, 1).strip()
        if addrStr and IsValidHexAddress(addrStr):
            self.parent.disassemblyConsole.NavigateTo(int(addrStr, 16))


class ModulesListCtrl(wx.ListCtrl):
    """List control to display modules with columns: Address, Name."""

    def __init__(self, parent, console=None):
        super().__init__(parent, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        # `console` separates the wx parent from the ConsolePanel these controls call
        # back into: with the splitter layout the wx parent is a splitter pane.
        self.parent = console or parent
        self.dlg = None
        self.lastHoverRow = None
        self.InsertColumn(0, "Address", width=160)
        self.InsertColumn(1, "Size", width=80)
        self.InsertColumn(2, "Name", width=160)
        self.InsertColumn(3, "Path", width=160)
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

    def UpdateData(self, modules: list[tuple[str, str, str, str]]):
        """Populate the list"""
        self.DeleteAllItems()
        for i, (addr, size, name, path) in enumerate(modules):
            row = self.InsertItem(i, addr)
            self.SetItem(row, 1, size)
            self.SetItem(row, 2, name)
            self.SetItem(row, 3, path)

        band_rows(self)

    def OnContextMenu(self, event):
        pos = event.GetPosition()
        pos = self.ScreenToClient(pos)
        row, _ = self.HitTest(pos)
        if row == wx.NOT_FOUND:
            return

        menu = wx.Menu()
        mi = menu.Append(wx.ID_ANY, "Exports")
        self.Bind(wx.EVT_MENU, lambda e: self.OnShowExports(row), mi)
        self.PopupMenu(menu, pos)
        menu.Destroy()

    def OnShowExports(self, row):
        modName = self.GetItemText(row, 2)
        matches = []
        for addr, full in self.parent.exports.items():
            if full.startswith(modName + "!"):
                _, sym = full.split("!", 1)
                matches.append((sym, addr))

        if not matches:
            ui.message(f"No exports for module {modName}", "Info", wx.OK | wx.ICON_INFORMATION)
            return

        self.dlg = ExportsDialog(self, modName, matches)
        self.dlg.ShowModal()
        self.dlg.Destroy()
        self.dlg = None


class MemoryListCtrl(wx.ListCtrl):
    """Regions that have appeared, been reprotected, grown or gone, newest first.

    A running log rather than a snapshot of everything mapped. The question this answers is
    "what just changed", which a thousand-row list of every region does not, and re-inserting
    every region on every break would cost more than the diff it is built from. What is mapped
    right now is still in DisassemblyListCtrl.pageMap, which this is derived from.

    Sourced from the PM page map, so no hooking and no extra command: an allocation, a mapped
    section, a heap segment growing and an unpacked region's RW->RX flip all show up as
    changes to what VirtualQueryEx reports.
    """

    # Enough to cover a long unpacking run without the list growing for the whole session.
    MAX_ENTRIES = 500

    def __init__(self, parent, console=None):
        super().__init__(parent, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        # `console` separates the wx parent from the ConsolePanel these controls call
        # back into: with the splitter layout the wx parent is a splitter pane.
        self.parent = console or parent
        self.entries: list[RegionChange] = []
        self.InsertColumn(0, "Base", width=140)
        self.InsertColumn(1, "Size", width=90)
        self.InsertColumn(2, "Protect", width=90)
        self.InsertColumn(3, "Change", width=90)
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)
        self.Bind(wx.EVT_LIST_ITEM_ACTIVATED, self.OnActivated)

    def AddChanges(self, changes: list[RegionChange]):
        """Prepend this break's changes, keeping the newest MAX_ENTRIES."""
        if not changes:
            return

        self.entries = (changes + self.entries)[: self.MAX_ENTRIES]
        self.Rebuild()

    def Rebuild(self):
        self.DeleteAllItems()
        for i, change in enumerate(self.entries):
            row = self.InsertItem(i, f"{change.base:016X}")
            self.SetItem(row, 1, f"{change.size:#x}")
            if change.kind == REGION_REPROTECTED:
                self.SetItem(row, 2, f"{ProtectText(change.prevProt)}->{ProtectText(change.prot)}")
            else:
                self.SetItem(row, 2, ProtectText(change.prot))

            self.SetItem(row, 3, change.kind)
            if change.kind == REGION_NEW:
                self.SetItemBackgroundColour(row, ACCENT_GREEN)
            elif change.kind == REGION_REPROTECTED:
                self.SetItemBackgroundColour(row, COLOR_LIGHT_YELLOW)
            elif change.kind == REGION_FREED:
                # Nothing to go and look at any more, so it reads as history, not a lead.
                self.SetItemTextColour(row, FG_SECONDARY)

    def OnContextMenu(self, event):
        pos = self.ScreenToClient(event.GetPosition())
        row, flags = self.HitTest(pos)
        if row == wx.NOT_FOUND:
            return

        menu = wx.Menu()
        miDisassemble = menu.Append(wx.ID_ANY, "Disassemble")
        miDump = menu.Append(wx.ID_ANY, "Dump Address")
        self.Bind(wx.EVT_MENU, lambda e, r=row: self.OnDisassemble(r), miDisassemble)
        self.Bind(wx.EVT_MENU, lambda e, r=row: self.OnDump(r), miDump)
        self.PopupMenu(menu, pos)
        menu.Destroy()

    def OnActivated(self, event):
        self.OnDisassemble(event.GetIndex())

    def RowAddress(self, row: int) -> int | None:
        try:
            return int(self.GetItemText(row, 0), 16)
        except ValueError:
            return None

    def OnDisassemble(self, row):
        addr = self.RowAddress(row)
        if addr is None:
            return

        if self.entries[row].kind == REGION_FREED:
            self.parent.AppendConsole(f"{addr:#x} is no longer mapped.")
            return

        self.parent.disassemblyConsole.NavigateTo(addr)

    def OnDump(self, row):
        addr = self.RowAddress(row)
        if addr is not None:
            self.parent.SendCommand(CMD_MEM_DUMP, f"{addr:#x}", tag=self.parent.NextTag(TAG_DUMP))


class ExportsDialog(ui.Dialog):
    def __init__(self, parent, mod_name, exports):
        super().__init__(
            parent, title=f"Exports for {mod_name}", size=wx.Size(500, 600), style=wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER
        )
        self.parent = parent
        self.exports = exports
        self.listCtrl = wx.ListCtrl(self, style=wx.LC_REPORT | wx.BORDER_SUNKEN | wx.LC_SINGLE_SEL)
        self.listCtrl.InsertColumn(0, "Address", width=120)
        self.listCtrl.InsertColumn(1, "Name", width=350)
        self.exports.sort(key=lambda x: x[1])
        for i, (symName, addr) in enumerate(self.exports):
            row = self.listCtrl.InsertItem(i, f"{int(addr):#x}")
            self.listCtrl.SetItem(row, 1, symName)

        band_rows(self.listCtrl)

        self.listCtrl.Bind(wx.EVT_KEY_DOWN, self.OnKeyDown)
        self.listCtrl.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

        self.ID_SEARCH = wx.NewIdRef()
        accels = wx.AcceleratorTable(
            [
                (wx.ACCEL_CTRL, ord("F"), self.ID_SEARCH),
            ]
        )

        self.SetAcceleratorTable(accels)
        self.Bind(wx.EVT_MENU, self.OnSearch, id=self.ID_SEARCH)

        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self.listCtrl, 1, wx.EXPAND | wx.ALL, 10)
        btn = ui.Button(self, wx.ID_OK, "Close", variant=ui.PRIMARY)
        sizer.Add(btn, 0, wx.ALIGN_CENTER | wx.ALL, 10)
        self.SetSizer(sizer)
        self.Layout()
        # A dialog is a top-level window, so the panel's construction-time apply_theme never
        # reached it: it has to theme its own tree, including its title bar.
        apply_theme(self)

    def OnKeyDown(self, event):
        if event.ControlDown() and event.GetKeyCode() == ord("C"):
            self.OnCopyItem(event)
        else:
            event.Skip()

    def OnContextMenu(self, event):
        menu = wx.Menu()
        copyItem = menu.Append(wx.ID_COPY, "Copy")
        self.Bind(wx.EVT_MENU, self.OnCopyItem, copyItem)
        self.PopupMenu(menu)
        menu.Destroy()

    def OnCopyItem(self, event):
        index = self.listCtrl.GetFirstSelected()
        if index == -1:
            return

        address = self.listCtrl.GetItemText(index)
        name = self.listCtrl.GetItem(index, 1).GetText()
        text = f"{address}\t{name}"
        if wx.TheClipboard.Open():
            wx.TheClipboard.SetData(wx.TextDataObject(text))
            wx.TheClipboard.Close()

    def OnSearch(self, event):
        dlg = SearchDialog(self)
        dlg.ShowModal()
        dlg.Destroy()


class PrototypeDialog(ui.Dialog):
    """Paste a function declaration, in the form the documentation gives it.

    Deliberately free-text rather than a field per parameter: a declaration can be copied
    straight off a docs page, and re-typing one into separate fields is how the parameter
    count ends up wrong - which mislabels every argument after the mistake.
    """

    HINT = (
        "Paste a declaration, e.g.\n\n"
        "DWORD GetProcessVersion(\n"
        "  [in] DWORD ProcessId\n"
        ");"
    )

    def __init__(self, parent):
        super().__init__(
            parent,
            title="Add API Prototype",
            size=wx.Size(620, 360),
            style=wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER,
        )
        outer = wx.BoxSizer(wx.VERTICAL)
        outer.Add(wx.StaticText(self, label=self.HINT), 0, wx.ALL, 10)
        self.textCtrl = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.HSCROLL)
        self.textCtrl.SetFont(FONT_CODE)
        outer.Add(self.textCtrl, 1, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        outer.Add(
            wx.StaticText(self, label=f"Saved to {user_prototypes_path()}"),
            0,
            wx.ALL,
            10,
        )
        outer.Add(ui.dialog_buttons(self), 0, wx.EXPAND | wx.ALL, 10)
        self.SetSizer(outer)
        apply_theme(self)
        self.textCtrl.SetFocus()

    def GetDeclaration(self) -> str:
        return self.textCtrl.GetValue()


class BreakpointDialog(ui.Dialog):
    """Address, type, size and slot for a hardware breakpoint.

    Data watches are what debug registers are actually good at - break when a buffer is
    written rather than when code runs - but the debugger only ever set BP_EXEC before.
    """

    def __init__(self, parent, address: str = ""):
        super().__init__(parent, title="Set Breakpoint")
        self.types = [BP_EXEC, BP_WRITE, BP_READWRITE]

        grid = wx.FlexGridSizer(rows=0, cols=2, hgap=8, vgap=8)
        grid.AddGrowableCol(1, 1)

        grid.Add(wx.StaticText(self, label="Address:"), flag=wx.ALIGN_CENTER_VERTICAL)
        addressField = ui.Field(self, value=address)
        # GetValues() reads the TextCtrl, so keep addressCtrl pointing at it.
        self.addressCtrl = addressField.ctrl
        grid.Add(addressField, flag=wx.EXPAND)

        grid.Add(wx.StaticText(self, label="Type:"), flag=wx.ALIGN_CENTER_VERTICAL)
        self.typeCtrl = ui.Picker(self, choices=[BP_TYPE_LABELS[t] for t in self.types])
        self.typeCtrl.SetSelection(0)
        self.typeCtrl.Bind(wx.EVT_CHOICE, self.OnTypeChanged)
        grid.Add(self.typeCtrl, flag=wx.EXPAND)

        grid.Add(wx.StaticText(self, label="Size:"), flag=wx.ALIGN_CENTER_VERTICAL)
        self.sizeCtrl = ui.Picker(self, choices=[str(s) for s in BP_SIZES])
        self.sizeCtrl.SetSelection(0)
        grid.Add(self.sizeCtrl, flag=wx.EXPAND)

        grid.Add(wx.StaticText(self, label="Slot:"), flag=wx.ALIGN_CENTER_VERTICAL)
        self.slotCtrl = ui.Picker(self, choices=["next", "0", "1", "2", "3"])
        self.slotCtrl.SetSelection(0)
        grid.Add(self.slotCtrl, flag=wx.EXPAND)

        outer = wx.BoxSizer(wx.VERTICAL)
        outer.Add(grid, 1, wx.EXPAND | wx.ALL, 10)
        buttons = ui.dialog_buttons(self)
        outer.Add(buttons, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 10)
        self.SetSizerAndFit(outer)

        self.OnTypeChanged(None)
        self.Bind(wx.EVT_BUTTON, self.OnOk, id=wx.ID_OK)
        apply_theme(self)

    def OnTypeChanged(self, event):
        # An execute breakpoint must keep LEN at one byte, so size is not a choice there.
        self.sizeCtrl.Enable(self.SelectedType() != BP_EXEC)

    def SelectedType(self) -> str:
        return self.types[self.typeCtrl.GetSelection()]

    def OnOk(self, event):
        values = self.GetValues()
        if values is None:
            return

        self.EndModal(wx.ID_OK)

    def GetValues(self):
        """Return (slot, type, size, address) or None, reporting why if it is invalid."""
        text = self.addressCtrl.GetValue().strip()
        if not IsValidHexAddress(text):
            ui.message(f"'{text}' is not a valid address.", "Set Breakpoint", wx.OK | wx.ICON_ERROR)
            return None

        address = int(text, 16)
        bpType = self.SelectedType()
        size = BP_SIZES[self.sizeCtrl.GetSelection()] if bpType != BP_EXEC else 1
        # x86 requires a data breakpoint's address to be aligned to its length; a misaligned
        # one silently watches the wrong bytes rather than failing.
        if bpType != BP_EXEC and address % size:
            ui.message(
                f"A {size}-byte watch needs a {size}-byte aligned address.\n"
                f"{address:#x} is not aligned; try {address - (address % size):#x}.",
                "Set Breakpoint",
                wx.OK | wx.ICON_ERROR,
            )
            return None

        return self.slotCtrl.GetStringSelection(), bpType, size, address


class CallStackListCtrl(wx.ListCtrl):
    """Walked call frames: where each one returns to, and the call that made it.

    The Stack pane beside this one shows raw stack words, which is what you want for
    arguments and locals; this answers the different question of how execution got here.
    """

    def __init__(self, parent, console=None):
        super().__init__(parent, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.parent = console or parent
        self.data: list[tuple[str, str, str, str]] = []
        self.InsertColumn(0, "#", width=35)
        self.InsertColumn(1, "Return To", width=150)
        self.InsertColumn(2, "Symbol", width=200)
        self.InsertColumn(3, "Frame", width=150)
        self.InsertColumn(4, "Call Site", width=220)
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)
        self.Bind(wx.EVT_LIST_ITEM_ACTIVATED, self.OnActivated)

    def UpdateData(self, frames: list[tuple[str, str, str, str]]):
        """Populate from (index, returnAddress, framePointer, callSite)."""
        self.DeleteAllItems()
        self.data = frames
        for i, (index, returnAddr, framePtr, callSite) in enumerate(frames):
            row = self.InsertItem(i, index)
            self.SetItem(row, 1, returnAddr)
            self.SetItem(row, 2, self.ResolveSymbol(returnAddr))
            self.SetItem(row, 3, framePtr)
            self.SetItem(row, 4, callSite)

    def ResolveSymbol(self, addrStr: str) -> str:
        """Nearest known export, falling back to the containing module's name."""
        try:
            addr = int(addrStr, 16)
        except ValueError:
            return ""

        return self.parent.NearestExport(addr) or self.parent.ModuleNameFor(addr)

    def OnActivated(self, event):
        self.FollowFrame(event.GetIndex())

    def OnContextMenu(self, event):
        pos = self.ScreenToClient(event.GetPosition())
        row, _ = self.HitTest(pos)
        if row == wx.NOT_FOUND:
            return

        menu = wx.Menu()
        miFollow = menu.Append(wx.ID_ANY, "Follow Return Address")
        miCopy = menu.Append(wx.ID_ANY, "Copy")
        self.Bind(wx.EVT_MENU, lambda e, r=row: self.FollowFrame(r), miFollow)
        self.Bind(wx.EVT_MENU, lambda e, r=row: SetClipboard("\t".join(self.data[r])), miCopy)
        self.PopupMenu(menu, pos)
        menu.Destroy()

    def FollowFrame(self, row: int):
        if row < 0 or row >= len(self.data):
            return

        addrStr = self.data[row][1]
        if addrStr and IsValidHexAddress(addrStr):
            self.parent.disassemblyConsole.NavigateTo(int(addrStr, 16))
