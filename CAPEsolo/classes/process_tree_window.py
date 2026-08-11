import logging

import wx

from .theme import apply_theme

log = logging.getLogger(__name__)

# The resultserver __process__ record (resultserver.py:625). Match the format string and
# read record.args = (pid, ppid, procname, modulepath) -> no string parsing, fails safe.
PROCESS_LOG_MSG = "Process %d (parent %d): %s, path %s"


class ProcessLogHandler(logging.Handler):
    """Feed live __process__ events into the tree. The ResultServer runs on a background
    thread, so updates are marshalled to the GUI thread with wx.CallAfter (same mechanism
    as WxTextCtrlHandler in logger_window.py)."""

    def __init__(self, window):
        super().__init__()
        self.window = window

    def emit(self, record):
        if record.msg != PROCESS_LOG_MSG or not record.args or len(record.args) != 4:
            return
        pid, ppid, name, path = record.args
        wx.CallAfter(self.window.AddProcess, pid, ppid, name, path)


class ProcessTreeWindow(wx.Frame):
    def __init__(self, parent, title, position):
        super().__init__(parent, title=title)
        self.startPanel = parent
        self.nodes = {}     # pid -> wx.TreeItemId
        self.pending = {}   # ppid -> [pids placed at root awaiting this parent]
        self.InitUI(position)
        self.Bind(wx.EVT_CLOSE, self.OnClose)
        # Attach after LoggerWindow's basicConfig so it coexists with the file/text handlers.
        self.handler = ProcessLogHandler(self)
        logging.getLogger().addHandler(self.handler)

    def InitUI(self, position):
        panel = wx.Panel(self)
        vbox = wx.BoxSizer(wx.VERTICAL)
        self.tree = wx.TreeCtrl(
            panel,
            style=wx.TR_DEFAULT_STYLE | wx.TR_HIDE_ROOT | wx.TR_HAS_BUTTONS | wx.TR_LINES_AT_ROOT,
        )
        self.root = self.tree.AddRoot("Processes")
        self.tree.Bind(wx.EVT_TREE_ITEM_GETTOOLTIP, self.OnItemTooltip)
        vbox.Add(self.tree, proportion=1, flag=wx.EXPAND | wx.ALL, border=5)
        panel.SetSizer(vbox)
        apply_theme(self)
        self.SetSize(wx.Size(520, 640))
        self.SetPosition(wx.Point(position.x + 40, position.y + 40))

    def AddProcess(self, pid, ppid, name, path):
        if isinstance(name, bytes):
            name = name.decode(errors="replace")
        if isinstance(path, bytes):
            path = path.decode(errors="replace")
        if pid in self.nodes:       # __process__ may repeat for a pid; keep the first node
            return
        parentItem = self.nodes.get(ppid, self.root)
        item = self.tree.AppendItem(parentItem, f"{name} ({pid})")
        self.tree.SetItemData(item, path)
        self.nodes[pid] = item
        self.tree.Expand(parentItem)
        for cpid in self.pending.pop(pid, []):     # adopt orphans that arrived before us
            # Only move a leaf: Delete() would destroy an orphan's own subtree and leave
            # its descendants' TreeItemIds dangling (-> crash on the next AppendItem). An
            # orphan that already has children stays at top level.
            if not self.tree.ItemHasChildren(self.nodes[cpid]):
                self._Reparent(cpid, item)
        if ppid not in self.nodes:                 # remember, in case our parent appears later
            self.pending.setdefault(ppid, []).append(pid)

    def _Reparent(self, pid, newParentItem):
        # Leaf-only (see caller): re-parenting is a delete + re-add of the single node.
        old = self.nodes[pid]
        label, data = self.tree.GetItemText(old), self.tree.GetItemData(old)
        self.tree.Delete(old)
        new = self.tree.AppendItem(newParentItem, label)
        self.tree.SetItemData(new, data)
        self.nodes[pid] = new
        self.tree.Expand(newParentItem)

    def OnItemTooltip(self, event):
        data = self.tree.GetItemData(event.GetItem())
        if data:
            event.SetToolTip(data)

    def OnClose(self, event):
        logging.getLogger().removeHandler(self.handler)
        self.startPanel.processTreeWindow = None
        self.Destroy()
