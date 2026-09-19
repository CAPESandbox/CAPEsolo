from contextlib import suppress

import wx

from CAPEsolo.capelib.cmdconsts import CMD_PATCH_BYTES

from . import ui_kit as ui
from .patch_models import PatchEntry
from .theme import apply_theme, band_rows


class PatchDialog(ui.Dialog):
    def __init__(self, parent, instrStr):
        super().__init__(parent, title="Assemble Instructions", size=(400,300))
        vbox = wx.BoxSizer(wx.VERTICAL)
        self.textCtrl = wx.TextCtrl(self, style=wx.TE_MULTILINE)
        vbox.Add(self.textCtrl, 1, wx.EXPAND|wx.ALL, 5)
        vbox.Add(ui.dialog_buttons(self), 0, wx.EXPAND|wx.ALL, 5)
        self.textCtrl.SetValue(instrStr)
        self.SetSizer(vbox)
        apply_theme(self)

    def GetAsmText(self) -> str:
        return self.textCtrl.GetValue()


class ConfirmPatchDialog(ui.Dialog):
    """
    Dialog to confirm assembled patch code before applying.
    """
    def __init__(self, parent, codeHex: str):
        super().__init__(parent, title="Confirm Patch", size=(500, 350))
        vbox = wx.BoxSizer(wx.VERTICAL)
        label = wx.StaticText(self, label="The assembled machine code (hex) is shown below.\nSubmit to apply patch or Cancel to return.")
        vbox.Add(label, 0, wx.EXPAND | wx.ALL, 5)
        self.codeCtrl = wx.TextCtrl(self, value=codeHex, style=wx.TE_MULTILINE | wx.TE_READONLY)
        vbox.Add(self.codeCtrl, 1, wx.EXPAND | wx.ALL, 5)
        vbox.Add(ui.dialog_buttons(self, ok="Submit"), 0, wx.EXPAND | wx.ALL, 5)
        self.SetSizer(vbox)
        apply_theme(self)


class PatchHistoryDialog(ui.Dialog):
    """
    Dialog to display the global patch history.
    """
    def __init__(self, parent, patchHistory: list[PatchEntry]):
        super().__init__(parent, title="Patch History", size=(700, 400))
        self.parent = parent
        self.patchHistory = patchHistory
        vbox = wx.BoxSizer(wx.VERTICAL)

        self.historyCtrl = wx.ListCtrl(self, style=wx.LC_REPORT | wx.BORDER_SUNKEN)
        self.historyCtrl.InsertColumn(0, "Address", width=120)
        self.historyCtrl.InsertColumn(1, "Original Bytes", width=150)
        self.historyCtrl.InsertColumn(2, "Patched Bytes", width=150)
        self.historyCtrl.InsertColumn(3, "Instruction", width=200)
        self.historyCtrl.InsertColumn(4, "Timestamp", width=150)

        for entry in self.patchHistory:
            idx = self.historyCtrl.InsertItem(self.historyCtrl.GetItemCount(), f"0x{entry.address:08X}")
            self.historyCtrl.SetItem(idx, 1, entry.originalBytes)
            self.historyCtrl.SetItem(idx, 2, entry.patchedBytes)
            self.historyCtrl.SetItem(idx, 3, entry.instruction)
            ts = entry.timeStamp.strftime("%Y-%m-%d %H:%M:%S")
            self.historyCtrl.SetItem(idx, 4, ts)

        band_rows(self.historyCtrl)

        vbox.Add(self.historyCtrl, 1, wx.EXPAND | wx.ALL, 5)
        btn = ui.Button(self, wx.ID_CLOSE, label="Close", variant=ui.PRIMARY)
        vbox.Add(btn, 0, wx.ALIGN_CENTER | wx.ALL, 5)
        self.SetSizer(vbox)

        btn.Bind(wx.EVT_BUTTON, lambda evt: self.Close())
        self.historyCtrl.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)
        self.Bind(wx.EVT_BUTTON, lambda evt: self.Close(), id=wx.ID_CLOSE)
        apply_theme(self)

    def OnContextMenu(self, event):
        pos = event.GetPosition()
        pos = self.historyCtrl.ScreenToClient(pos)
        row, flags = self.historyCtrl.HitTest(pos)
        if row < 0:
            return

        menu = wx.Menu()
        miUndo = menu.Append(wx.ID_ANY, "Undo Patch")
        self.Bind(wx.EVT_MENU,lambda e: self.OnUndoPatch(row), miUndo)
        self.PopupMenu(menu)
        menu.Destroy()

    def OnUndoPatch(self, row):
        entry = self.patchHistory[row]
        historyByAddr = self.parent.parent.patchHistoryByAddr
        addrStr = f"0x{entry.address:08X}"
        self.patchHistory.remove(entry)
        addrList = historyByAddr.get(entry.address)
        if addrList:
            with suppress(ValueError):
                addrList.remove(entry)

            if not addrList:
                del historyByAddr[entry.address]

        data = f"{addrStr}|{entry.originalBytes}"
        self.parent.parent.SendCommand(CMD_PATCH_BYTES, data)
        self.historyCtrl.DeleteItem(row)
