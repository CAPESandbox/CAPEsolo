import ast
import logging
import operator
import re
import threading
from collections import namedtuple
from pathlib import Path
from typing import List, Optional, Tuple

import wx

from CAPEsolo.capelib.cmdconsts import *
from .patch_dialog import ConfirmPatchDialog, PatchDialog, PatchHistoryDialog
from .patch_models import PatchEntry
from .search_dialog import SearchDialog
from .theme import ACCENT_ERROR, ACCENT_GREEN, ACCENT_ORANGE, BG_INPUT

log = logging.getLogger(__name__)

COLOR_LIGHT_YELLOW = ACCENT_ORANGE
COLOR_LIGHT_RED = ACCENT_ERROR
MAX_IDLE = 1

DecodedInstruction = namedtuple("DecodedInstruction", ["address", "bytes", "text"])

def IsValidHexAddress(s: str) -> bool:
    try:
        if not s.lower().startswith("0x"):
            s = "0x" + s

        value = int(s, 16)
    except ValueError:
        return False

    return value > 0x1000

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
    def __init__(self, parent):
        super().__init__(parent, style=wx.LC_REPORT)
        self.parent = parent
        self.lastTipRow = None
        self.InsertColumn(0, "Address", width=150)
        self.InsertColumn(1, "Hex bytes", width=180)
        self.InsertColumn(2, "Disassembly", width=400)
        self.pageMap: List[Tuple[int, int, int]] = []
        self.decodeCache: List[DecodedInstruction] = []
        self.cacheLock = threading.Lock()
        self.backHistory: List[int] = []
        self.resolveAllRefsStatus = True
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)
        self.Bind(wx.EVT_MOTION, self.OnOperandHover)

    def LoadPageMap(self, data: str):
        if not data:
            return

        self.pageMap.clear()
        for entry in data.split("|"):
            if not entry:
                continue

            try:
                base, size, protect = entry.split(",")
                baseAddr = int(base, 16)
                regionSize = int(size)
                protect = int(protect, 16)
                self.pageMap.append((baseAddr, regionSize, protect))
            except (ValueError, AttributeError) as e:
                log.error("[DEBUG CONSOLE] Failed to parse entry '%s': %s", entry, e)
                continue

        self.pageMap.sort(key=lambda x: x[0])

    def FindPage(self, addr: int) -> Optional[Tuple[int, int, int]]:
        for base, size, prot in self.pageMap:
            if base <= addr < base + size:
                return base, size, prot

        # log.warning("[DEBUG CONSOLE] Address: 0x%x not in page map, fetching update page map", addr)
        return None

    def SetInstructions(self, insts: List[DecodedInstruction], append: bool = False):
        fontItalic = wx.Font(10, wx.FONTFAMILY_MODERN, wx.FONTSTYLE_ITALIC, wx.FONTWEIGHT_NORMAL)
        self.Freeze()
        try:
            with self.cacheLock:
                if not append:
                    self.decodeCache = []
                    self.DeleteAllItems()

                startRow = len(self.decodeCache)
                self.decodeCache.extend(insts)
                for offset, inst in enumerate(insts):
                    row = startRow + offset
                    row = self.InsertItem(row, f"{inst.address:016X}")
                    self.SetItem(row, 1, inst.bytes.upper())
                    self.SetItem(row, 2, inst.text)
                    mnemonic = inst.text.split()[0].lower()
                    if mnemonic == "call":
                        self.SetItemTextColour(row, wx.BLUE)
                    elif mnemonic in ("jmp", "je", "jne", "jg", "jl"):
                        self.SetItemTextColour(row, wx.GREEN)

                    if inst.address in self.parent.patchHistoryByAddr:
                        self.SetItemFont(row, fontItalic)

        finally:
            self.Thaw()

        self.Refresh()
        if not append:
            cipRow = self.GetCipRow()
            if cipRow != -1:
                self.HighlightCip(cipRow)

    def GetCipRow(self, cip=None):
        row = -1
        if not cip:
            cip = self.parent.cip
        if cip is None:
            return

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
        for i in range(self.GetItemCount()):
            if self.GetItemBackgroundColour(i) != COLOR_LIGHT_RED:
                self.SetItemBackgroundColour(i, BG_INPUT)

    def HighlightCip(self, row):
        if row >= 0:
            self.ClearHighlight()
            self.SetItemBackgroundColour(row, ACCENT_GREEN)
            self.CenterRow(row)
        else:
            log.warning("[DEBUG CONSOLE] Instruction %#x not found in disassembly", self.parent.cip)

        self.Refresh()

    def CenterRow(self, row):
        """Center the specified row in the view."""
        visRows = self.GetCountPerPage()
        if visRows <= 0:
            rowH = 15
            rect = self.GetItemRect(0, wx.LIST_RECT_BOUNDS)
            rowH = rect.height if rect and rect.height > 0 else rowH
            clientH = self.GetClientSize().height
            visRows = clientH // rowH

        visRows = min(visRows, len(self.decodeCache))
        if visRows <= 0:
            visRows = 15

        anchor = max(0, row + (visRows // 2))
        maxTop = max(0, len(self.decodeCache) - visRows)
        anchor = min(anchor, maxTop)

        self.EnsureVisible(row)
        self.EnsureVisible(anchor)

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
        miResolveAddress = menu.Append(wx.ID_ANY, "Resolve Export Name From Address")
        miResolveRef = menu.Append(wx.ID_ANY, "Resolve Export Name From Dereference")
        if self.resolveAllRefsStatus:
            miResolveAllRefs = menu.Append(wx.ID_ANY, "Resolve All Export Names for Calls")
            self.Bind(wx.EVT_MENU, self.OnResolveAllRefs, miResolveAllRefs)

        miStringAddress = menu.Append(wx.ID_ANY, "Resolve String From Address")
        miStringRef = menu.Append(wx.ID_ANY, "Resolve String From Dereference")
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

        self.Bind(wx.EVT_MENU, self.OnCopy, miCopy)
        self.Bind(wx.EVT_MENU, self.OnGoTo, miGoTo)
        self.Bind(wx.EVT_MENU, self.OnGoToCip, miGoToCIP)
        self.Bind(wx.EVT_MENU, lambda e: self.OnSetCip(row), miSetCIP)
        self.Bind(wx.EVT_MENU, lambda e: self.OnNopInstruction(row), miNopInstruction)
        self.Bind(wx.EVT_MENU, lambda e: self.OnPatchBytes(row), miPatchBytes)
        self.Bind(wx.EVT_MENU, self.OnPatchHistory, miPatchHistory)
        self.Bind(wx.EVT_MENU, self.OnDumpAddress, miDumpAddress)
        self.Bind(wx.EVT_MENU, self.OnResolveAddress, miResolveAddress)
        self.Bind(wx.EVT_MENU, self.OnResolveRef, miResolveRef)
        self.Bind(wx.EVT_MENU, self.OnStringAddress, miStringAddress)
        self.Bind(wx.EVT_MENU, self.OnStringRef, miStringRef)
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
                    wx.MessageBox(f"Invalid hex address: {entry}", "Error", wx.OK | wx.ICON_ERROR)
                    dialog.Destroy()
                    return

            try:
                row = self.GoToInstruction(target)
                if row == wx.NOT_FOUND:
                    wx.MessageBox(f"Instruction address not found: {entry}", "Warning", wx.OK | wx.ICON_WARNING)
                else:
                    self.PushHistory(int(target, 16))
            except Exception as e:
                wx.MessageBox(f"Invalid register or hex address: {entry}", "Error", wx.OK | wx.ICON_ERROR)

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
        except ValueError as e:
            wx.MessageBox(f"Invalid address for Set EIP/RIP: {addrStr}", "Error", wx.OK | wx.ICON_ERROR)

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
        except ValueError as e:
            wx.MessageBox(f"Invalid address for Run Until: {addrStr}", "Error", wx.OK | wx.ICON_ERROR)

    def OnSetBreakpoint(self, row, slot):
        addrStr = self.GetItemText(row, 0).strip()
        try:
            addr = int(addrStr, 16)
            payload = f"{slot.lower()}|{addr:#X}"
            self.parent.SendCommand(CMD_SET_BREAKPOINT, payload)
        except ValueError as e:
            wx.MessageBox(f"Invalid address for Set Breakpoint: {addrStr}", "Error", wx.OK | wx.ICON_ERROR)

    def ClearBpBackground(self, addr):
        row = self.GetInstructionRow(addr)
        if row == wx.NOT_FOUND:
            return

        self.SetItemBackgroundColour(row, BG_INPUT)
        self.Refresh()

    def SetBpBackground(self, addr):
        row = self.GetInstructionRow(addr)
        if row == wx.NOT_FOUND:
            return

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

    def GetColumnAtX(self, x):
        offset = 0
        for col in range(self.GetColumnCount()):
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

    def ParseOperandAddress(self, inst: str, ripBase: int) -> Optional[int]:
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

        m2 = re.search(r"\b0x[0-9A-Fa-f]{8,16}\b", inst)
        if m2:
            try:
                return self.SafeEval(m2.group(0))
            except ValueError:
                return None

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

        addrStr = f"{addr:#x}"
        self.SetToolTip(f"{addrStr} copied.")
        SetClipboard(addrStr)
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

        row = self.GetInstructionRow(addr)
        if row != -1:
            self.HighlightCip(row)
        else:
            wx.MessageBox(f"Address {addr:#x} not in history.", "Info", wx.OK | wx.ICON_INFORMATION)

    def OnDumpAddress(self, event):
        sel = GetClipboardText().strip()
        if sel and IsValidHexAddress(sel):
            self.parent.SendCommand(CMD_MEM_DUMP, sel)

    def OnResolveAddress(self, event):
        addrStr = GetClipboardText().strip()
        try:
            addrInt = int(addrStr, 16)
        except ValueError:
            return

        export = self.parent.exports.get(addrInt)
        self.parent.AppendConsole(export)

    def OnResolveRef(self, event):
        targetAddrStr = GetClipboardText().strip()
        targetAddrInt = int(targetAddrStr, 16)
        addrStr = self.GetItemText(self.lastTipRow, 0)
        addrInt = int(addrStr, 16)
        if addrInt not in self.parent.resolvedExports:
            self.parent.resolvedExports[addrInt] = {targetAddrInt: ""}
            self.parent.ResolveRef(targetAddrStr)

    def OnResolveAllRefs(self, event):
        self.resolveAllRefsStatus = False
        self.parent.DereferenceCalls()

    def OnStringAddress(self, event):
        addrStr = GetClipboardText().strip()
        return

    def OnStringRef(self, event):
        addrStr = GetClipboardText().strip()
        addrInt = int(addrStr, 16)
        if addrInt not in self.parent.resolvedStrings:
            self.parent.ResolveString(addrStr)

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
                    wx.MessageBox(f"Instructions were not assembled: {codeHex}", "Info", wx.OK | wx.ICON_INFORMATION)
            else:
                dlg.Destroy()

    def OnPatchHistory(self, event):
        dlg = PatchHistoryDialog(self, self.parent.patchHistory)
        dlg.ShowModal()
        dlg.Destroy()


class RegsTextCtrl(wx.TextCtrl):
    def __init__(self, parent, style):
        """TextCtrl subclass"""
        super().__init__(parent, style=style)
        self.parent = parent
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

    def OnContextMenu(self, event):
        menu = wx.Menu()
        miCopy = menu.Append(wx.ID_ANY, "Copy")
        miDumpAddress = menu.Append(wx.ID_ANY, "Dump Memory Address")
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
        sel = self.GetStringSelection().strip()
        if sel:
            self.parent.memAddressInput.SetValue(sel)
            evt = wx.CommandEvent(wx.EVT_TEXT_ENTER.typeId, self.parent.memAddressInput.GetId())
            self.parent.OnAddressEnter(evt)

    def OnFollowAddress(self, event):
        addrStr = self.GetStringSelection().strip()
        if addrStr and IsValidHexAddress(addrStr):
            row = self.parent.disassemblyConsole.GoToInstruction(addrStr)
            if row == wx.NOT_FOUND:
                self.parent.UpdateConsole("Address not found")

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
            wx.MessageBox(f"'{valueStr}' is not a valid number.", "Error", wx.ICON_ERROR)
            return

        payload = f"{reg}|{val:#X}"
        self.parent.SendCommand(CMD_SET_REGISTER, payload)

    def OnResolveAddress(self, event):
        addrStr = self.GetStringSelection().strip()
        try:
            addrInt = int(addrStr, 16)
        except ValueError:
            return

        export = self.parent.exports.get(addrInt)
        self.parent.AppendConsole(export)
        return

    def OnResolveRef(self, event):
        addrStr = self.GetStringSelection().strip()
        self.parent.ResolveRef(addrStr)


class StackListCtrl(wx.ListCtrl):
    def __init__(self, parent):
        super().__init__(parent, style=wx.LC_REPORT)
        self.parent = parent
        self.spVal = None
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
        row = len(rows) // 2
        if self.spVal:
            for i, (addr, _) in enumerate(rows):
                if addr.lower() == self.spVal.lower():
                    row = i
                    break

        self.DeleteAllItems()
        self.data = rows

        for i, (addr, val) in enumerate(rows):
            self.InsertItem(i, str(addr))
            self.SetItem(i, 1, str(val))
            self.SetItem(i, 2, "")

            if i == row:
                self.SetItemBackgroundColour(i, COLOR_LIGHT_YELLOW)

        self.Refresh()
        self.CenterRow(row)

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
        if row == wx.NOT_FOUND:
            return

        menu = wx.Menu()
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
    def __init__(self, parent):
        super().__init__(parent, style=wx.LC_REPORT)
        self.parent = parent
        self.InsertColumn(0, "Address", width=170)
        self.InsertColumn(1, "Hex Dump", width=400)
        self.InsertColumn(2, "Ascii", width=150)
        self.data = []
        self.addr = None
        self.backHistory: List[int] = []
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
        menu = wx.Menu()
        miCopy = menu.Append(wx.ID_ANY, "Copy")
        miSaveToFile = menu.Append(wx.ID_ANY, "Save Memory To File...")
        self.Bind(wx.EVT_MENU, self.OnCopy, miCopy)
        self.Bind(wx.EVT_MENU, self.OnSaveMemoryToFile, miSaveToFile)
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
                    wx.MessageBox("Unknown format selected.", "Error", wx.ICON_ERROR)

        except Exception as e:
            wx.MessageBox(f"Failed to save file:\n{e}", "Error", wx.ICON_ERROR)


class ThreadListCtrl(wx.ListCtrl):
    """List control to display threads with columns: TID, Start Address."""

    def __init__(self, parent):
        super().__init__(parent, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.parent = parent
        self.data: List[Tuple[str, str]] = []
        self.InsertColumn(0, "TID", width=60)
        self.InsertColumn(1, "Start Address", width=160)
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)
        self.Bind(wx.EVT_MOTION, self.OnMouseOver)

    def UpdateData(self, threadEntries: List[Tuple[str, str]]):
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

    def OnContextMenu(self, event):
        pos = event.GetPosition()
        pos = self.ScreenToClient(pos)
        row, flags = self.HitTest(pos)
        if row == wx.NOT_FOUND:
            return

        menu = wx.Menu()
        miFollowStartAddress = menu.Append(wx.ID_ANY, "Follow Start Address")
        self.Bind(wx.EVT_MENU, lambda e: self.OnFollowStartAddress(row), miFollowStartAddress)
        self.PopupMenu(menu, pos)
        menu.Destroy()

    def OnFollowStartAddress(self, row):
        addrStr = self.GetItemText(row, 1).strip()
        row = self.parent.disassemblyConsole.GoToInstruction(addrStr)
        if row == wx.NOT_FOUND:
            self.parent.UpdateConsole("Address not found")

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

    def __init__(self, parent):
        super().__init__(parent, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.parent = parent
        self.data: List[Tuple[str, str]] = []
        self.InsertColumn(0, "DR", width=40)
        self.InsertColumn(1, "Address", width=160)
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

    def UpdateData(self, bps: List[Tuple[str, str]]):
        """Populate the list with thread info: (dr, address)."""
        self.DeleteAllItems()
        if not bps:
            return

        self.data = bps
        for i, (dr, addr) in enumerate(bps):
            row = self.InsertItem(i, dr)
            self.SetItem(row, 1, addr)

    def OnContextMenu(self, event):
        pos = event.GetPosition()
        pos = self.ScreenToClient(pos)
        row, flags = self.HitTest(pos)
        if row == wx.NOT_FOUND:
            return

        menu = wx.Menu()
        miDeleteBreakpoint = menu.Append(wx.ID_ANY, "Delete Breakpoint")
        menu.AppendSeparator()
        miFollowBreakpoint = menu.Append(wx.ID_ANY, "Follow Address")

        self.Bind(wx.EVT_MENU, lambda e: self.OnDeleteBreakpoint(row), miDeleteBreakpoint)
        self.Bind(wx.EVT_MENU, lambda e: self.OnFollowBreakpoint(row), miFollowBreakpoint)
        self.PopupMenu(menu, pos)
        menu.Destroy()

    def OnDeleteBreakpoint(self, row):
        index = self.parent.breakpointsDisplay.GetItemText(row, 0).strip()
        payload = f"{index}"
        self.parent.SendCommand(CMD_DELETE_BREAKPOINT, payload)

    def OnFollowBreakpoint(self, row):
        addrStr = self.GetItemText(row, 1).strip()
        row = self.parent.disassemblyConsole.GoToInstruction(addrStr)
        if row == wx.NOT_FOUND:
            self.parent.UpdateConsole("Address not found")


class ModulesListCtrl(wx.ListCtrl):
    """List control to display modules with columns: Address, Name."""

    def __init__(self, parent):
        super().__init__(parent, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.parent = parent
        self.dlg = None
        self.lastHoverRow = None
        self.InsertColumn(0, "Address", width=160)
        self.InsertColumn(1, "Size", width=80)
        self.InsertColumn(2, "Name", width=160)
        self.InsertColumn(3, "Path", width=160)
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

    def UpdateData(self, modules: List[Tuple[str, str, str, str]]):
        """Populate the list"""
        self.DeleteAllItems()
        for i, (addr, size, name, path) in enumerate(modules):
            row = self.InsertItem(i, addr)
            self.SetItem(row, 1, size)
            self.SetItem(row, 2, name)
            self.SetItem(row, 3, path)

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
            wx.MessageBox(f"No exports for module {modName}", "Info", wx.OK | wx.ICON_INFORMATION)
            return

        self.dlg = ExportsDialog(self, modName, matches)
        self.dlg.ShowModal()
        self.dlg.Destroy()
        self.dlg = None


class ExportsDialog(wx.Dialog):
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
        btn = wx.Button(self, wx.ID_OK, "Close")
        sizer.Add(btn, 0, wx.ALIGN_CENTER | wx.ALL, 10)
        self.SetSizer(sizer)
        self.Layout()

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
