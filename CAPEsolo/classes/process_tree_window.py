import logging
import os
import re
from pathlib import Path
from threading import Thread

import wx

from . import ui_kit as ui
from .process_tools import (
    dump_process_memory,
    resume_process,
    snapshot_processes,
    suspend_process,
    terminate_process,
)
from .theme import FG_SECONDARY, SP_XS, apply_theme, dip

log = logging.getLogger(__name__)

REFRESH_MS = 1500
# Exited processes are de-emphasised, not disabled: the muted text token is contrast-checked
# against every surface, unlike the flat grey this used to hardcode. theme.py mutates its
# colours in place on a palette switch, so aliasing the token here still follows the theme.
EXITED_COLOUR = FG_SECONDARY
WINDOW_SIZE = wx.Size(520, 640)
# Gap left between the window and the edges of the screen it is parked against.
SCREEN_MARGIN = 12

# The ResultServer's process line as written to analysis.log (resultserver.py:625):
#   "Process <pid> (parent <ppid>): <name>, path <module_path>"
# This is the authoritative, parented set of monitored processes and is exactly what the analyst
# sees in the log, so parsing the log file (rather than the .bson logs or a logging handler that may
# not receive the record) makes the tree match the log. Read straight from the text file - no
# injecting/hooking, so capemon is undisturbed.
PROC_RE = re.compile(r"Process (\d+) \(parent (\d+)\): (.+?), path (.+?)\s*$")
# capemon's per-process command-line line in analysis.log: "<pid>: Commandline: <cmdline>".
CMDLINE_RE = re.compile(r"(\d+): Commandline: (.+?)\s*$")
CMDLINE_MAX = 300  # cap the tooltip command line


class ProcessTreeWindow(wx.Frame):
    """The analysis process tree, sourced from analysis.log's process lines so it matches the log
    and the Behavior tab. A periodic external snapshot only flips live nodes to [exited]. Right-click
    a live process to suspend/resume, terminate (cooperatively via capemon first) or memory-dump it."""

    def __init__(self, parent, title, position):
        super().__init__(parent, title=title)
        self.startPanel = parent
        self.model = {}         # pid -> {"ppid","name","path","alive"}
        self.itemByPid = {}     # pid -> wx.TreeItemId
        self._cmdlines = {}     # pid -> command line, for the tooltip (from analysis.log)
        self.suspended = set()
        self._structSig = None
        self._collapsed = set()  # pids the user collapsed, so a rebuild doesn't re-expand them
        self._building = False   # suppress collapse/expand event handling during a programmatic rebuild
        self.logPath = Path(parent.analysisDir) / "analysis.log"
        self._logPos = 0        # byte offset consumed so far (complete lines only)
        self.InitUI(position)
        self.Bind(wx.EVT_CLOSE, self.OnClose)
        self.timer = wx.Timer(self)
        self.Bind(wx.EVT_TIMER, self.OnTimer)
        self.timer.Start(REFRESH_MS)
        wx.CallAfter(self._Tick)

    def InitUI(self, position):
        panel = wx.Panel(self)
        vbox = wx.BoxSizer(wx.VERTICAL)
        self.tree = wx.TreeCtrl(
            panel,
            style=wx.TR_DEFAULT_STYLE | wx.TR_HIDE_ROOT | wx.TR_HAS_BUTTONS | wx.TR_LINES_AT_ROOT,
        )
        self.root = self.tree.AddRoot("Processes")
        self.tree.Bind(wx.EVT_TREE_ITEM_GETTOOLTIP, self.OnItemTooltip)
        self.tree.Bind(wx.EVT_TREE_ITEM_RIGHT_CLICK, self.OnRightClick)
        self.tree.Bind(wx.EVT_TREE_ITEM_COLLAPSED, self.OnItemCollapsed)
        self.tree.Bind(wx.EVT_TREE_ITEM_EXPANDED, self.OnItemExpanded)
        vbox.Add(self.tree, proportion=1, flag=wx.EXPAND | wx.ALL, border=dip(self, SP_XS))
        panel.SetSizer(vbox)
        apply_theme(self)
        # The native Explorer-themed tree draws its expander arrows only on hover and they wash out
        # against the dark theme. Dropping the visual style gives classic, always-visible +/- buttons.
        # Must run after apply_theme(): _style_widget() applies DarkMode_Explorer to every native
        # control it walks, including this tree, which would silently overwrite this override.
        try:
            import ctypes

            ctypes.windll.uxtheme.SetWindowTheme(ctypes.c_void_p(self.tree.GetHandle()), "", "")
        except Exception:
            pass
        self.SetSize(WINDOW_SIZE)
        self.SetPosition(self.StartPosition(position))

    def StartPosition(self, mainPosition: wx.Point) -> wx.Point:
        """Bottom right of the work area belonging to the display the main window is on.

        This used to open at the main window's position offset by (40, 40), which dropped a
        520x640 frame squarely on top of the analysis tabs. Nor is there a gap beside the main
        frame to use: LoggerWindow is created just before this one and takes the full width to
        its right, so the bottom right corner is the nearest clear space.

        Measured against GetClientArea rather than DisplaySize so the taskbar is excluded, and
        against the display under the main window rather than the primary one, so the tree
        follows the main window instead of jumping to another monitor.
        """
        index = wx.Display.GetFromPoint(mainPosition)
        if index == wx.NOT_FOUND:
            index = 0

        area = wx.Display(index).GetClientArea()
        width, height = self.GetSize()
        # max() keeps the window on-screen if it is larger than the work area, where the
        # subtraction would otherwise place its top left corner off the top or left edge.
        return wx.Point(
            area.x + max(0, area.width - width - SCREEN_MARGIN),
            area.y + max(0, area.height - height - SCREEN_MARGIN),
        )

    # --- data ---------------------------------------------------------------
    def _analyzer(self):
        return getattr(self.startPanel, "analyzer", None)

    def _blocked(self):
        analyzer = self._analyzer()
        blocked = set(getattr(analyzer, "CRITICAL_PROCESS_LIST", None) or [])
        blocked.add(os.getpid())
        return blocked

    def _ScanLog(self):
        """Read new complete lines from analysis.log and add a node per 'Process N (parent M)' line."""
        try:
            size = self.logPath.stat().st_size
        except OSError:
            return
        if size < self._logPos:  # rotated/truncated - start over
            self._logPos = 0
        if size <= self._logPos:
            return
        try:
            with self.logPath.open("rb") as f:
                f.seek(self._logPos)
                chunk = f.read()
        except OSError:
            return
        # Only consume up to the last newline so a half-written final line is re-read next tick.
        lastNl = chunk.rfind(b"\n")
        if lastNl == -1:
            return
        self._logPos += lastNl + 1
        for line in chunk[: lastNl + 1].decode("utf-8", errors="replace").splitlines():
            m = PROC_RE.search(line)
            if m:
                pid, ppid = int(m.group(1)), int(m.group(2))
                if pid not in self.model:  # keep the first sighting; never resurrect an exited pid
                    self.model[pid] = {
                        "ppid": ppid, "name": m.group(3), "path": m.group(4), "alive": True,
                    }
                continue
            m = CMDLINE_RE.search(line)
            if m:
                self._cmdlines[int(m.group(1))] = m.group(2)

    def OnTimer(self, event):
        self._Tick()

    def _Tick(self):
        self._ScanLog()
        # Membership comes from the log; the snapshot only says which known pids are still alive.
        # Only flip alive -> exited (never resurrect), so a reused PID can't revive an exited node.
        snap = snapshot_processes()
        for pid, entry in self.model.items():
            if entry["alive"] and pid not in snap:
                entry["alive"] = False
        self._Render()

    # --- rendering ----------------------------------------------------------
    def _Render(self):
        sig = frozenset(
            (pid, e["ppid"] if e["ppid"] in self.model else 0) for pid, e in self.model.items()
        )
        if sig != self._structSig:
            self._structSig = sig
            self._Rebuild()
        else:
            for pid, entry in self.model.items():
                item = self.itemByPid.get(pid)
                if item and item.IsOk():
                    self._StyleItem(item, pid, entry)

    def _StyleItem(self, item, pid, entry):
        label = f'{entry["name"]} ({pid})'
        if not entry["alive"]:
            label += " [exited]"
        elif pid in self.suspended:
            label += " [suspended]"
        self.tree.SetItemText(item, label)
        colour = self.tree.GetForegroundColour() if entry["alive"] else EXITED_COLOUR
        self.tree.SetItemTextColour(item, colour)

    def OnItemCollapsed(self, event):
        if self._building:
            return
        pid = self.tree.GetItemData(event.GetItem())
        if pid is not None:
            self._collapsed.add(pid)

    def OnItemExpanded(self, event):
        if self._building:
            return
        pid = self.tree.GetItemData(event.GetItem())
        if pid is not None:
            self._collapsed.discard(pid)

    def _Rebuild(self):
        sel = self.tree.GetSelection()
        selPid = self.tree.GetItemData(sel) if sel.IsOk() else None
        self._building = True
        self.tree.Freeze()
        try:
            self.tree.DeleteAllItems()
            self.root = self.tree.AddRoot("Processes")
            self.itemByPid = {}
            # Add parents before children so every node has a real parent item.
            remaining = dict(self.model)
            progress = True
            while remaining and progress:
                progress = False
                for pid in list(remaining):
                    ppid = remaining[pid]["ppid"]
                    if ppid in self.model and ppid not in self.itemByPid:
                        continue  # parent not placed yet
                    parent = self.itemByPid.get(ppid, self.root)
                    self._AddNode(parent, pid, remaining.pop(pid))
                    progress = True
            for pid in list(remaining):  # orphans/cycles: attach to root
                self._AddNode(self.root, pid, remaining.pop(pid))

            # Fully expanded by default so the whole tree is visible; honor user-collapsed nodes.
            for pid, item in self.itemByPid.items():
                if self.tree.ItemHasChildren(item) and pid not in self._collapsed:
                    self.tree.Expand(item)
            if selPid is not None and selPid in self.itemByPid:
                self.tree.SelectItem(self.itemByPid[selPid])
        finally:
            self.tree.Thaw()
            self._building = False

    def _AddNode(self, parent, pid, entry):
        item = self.tree.AppendItem(parent, "")
        self.tree.SetItemData(item, pid)
        self.itemByPid[pid] = item
        self._StyleItem(item, pid, entry)

    def OnItemTooltip(self, event):
        pid = self.tree.GetItemData(event.GetItem())
        entry = self.model.get(pid)
        if not entry:
            return
        lines = []
        if entry.get("path"):
            lines.append(entry["path"])
        cmdline = self._cmdlines.get(pid)
        if cmdline:
            if len(cmdline) > CMDLINE_MAX:
                cmdline = cmdline[:CMDLINE_MAX] + " ...(truncated)"
            lines.append(cmdline)
        if lines:
            event.SetToolTip("\n".join(lines))

    # --- actions ------------------------------------------------------------
    def _actionable(self, pid, entry):
        return entry["alive"] and pid not in self._blocked()

    def OnRightClick(self, event):
        item = event.GetItem()
        if not item.IsOk():
            return
        self.tree.SelectItem(item)
        pid = self.tree.GetItemData(item)
        entry = self.model.get(pid)
        if not entry:
            return
        enabled = self._actionable(pid, entry)

        menu = wx.Menu()
        suspendItem = menu.Append(wx.ID_ANY, "Resume" if pid in self.suspended else "Suspend")
        terminateItem = menu.Append(wx.ID_ANY, "Terminate")
        dumpItem = menu.Append(wx.ID_ANY, "Memory Dump")
        for mi in (suspendItem, terminateItem, dumpItem):
            mi.Enable(enabled)
        menu.Bind(wx.EVT_MENU, lambda evt: self._OnSuspendResume(pid), suspendItem)
        menu.Bind(wx.EVT_MENU, lambda evt: self._OnTerminate(pid), terminateItem)
        menu.Bind(wx.EVT_MENU, lambda evt: self._OnDump(pid), dumpItem)
        self.tree.PopupMenu(menu)
        menu.Destroy()

    def _OnSuspendResume(self, pid):
        try:
            if pid in self.suspended:
                resume_process(pid)
                self.suspended.discard(pid)
                self._SetStatus(f"Resumed pid {pid}")
            else:
                suspend_process(pid)
                self.suspended.add(pid)
                self._SetStatus(f"Suspended pid {pid}")
        except OSError as e:
            ui.message(str(e), "Process Tree", wx.OK | wx.ICON_ERROR)
        self._Render()

    def _subtree(self, pid):
        """pid plus all its descendants in the model (cycle-safe), parent before children."""
        children = {}
        for p, entry in self.model.items():
            children.setdefault(entry["ppid"], []).append(p)
        out, stack, seen = [], [pid], set()
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            out.append(cur)
            stack.extend(children.get(cur, []))
        return out

    def _OnTerminate(self, pid):
        # Terminate the whole subtree: the selected process and every live, non-critical descendant.
        blocked = self._blocked()
        targets = [
            p for p in self._subtree(pid) if self.model[p]["alive"] and p not in blocked
        ]
        if not targets:
            return
        name = self.model.get(pid, {}).get("name", str(pid))
        childCount = len(targets) - 1
        if childCount:
            msg = (
                f"Terminate {name} ({pid}) and its {childCount} child process(es)?\n\nCapemon is "
                "asked to shut each down cleanly first; any that do not exit are force-killed. "
                "Monitoring of these processes ends."
            )
        else:
            msg = (
                f"Terminate {name} ({pid})?\n\nCapemon is asked to shut it down cleanly first; if it "
                "does not exit it is force-killed. Monitoring of this process ends."
            )
        if ui.message(msg, "Terminate Process", wx.YES_NO | wx.ICON_WARNING, self) != wx.YES:
            return
        self._SetStatus(
            f"Terminating {name} ({pid})" + (f" +{childCount} child(ren)..." if childCount else "...")
        )

        def worker():
            errors = []
            for target in targets:
                try:
                    terminate_process(target)
                except OSError as e:
                    errors.append(f"pid {target}: {e}")
            wx.CallAfter(self._AfterTerminate, targets, errors)

        Thread(target=worker, daemon=True).start()

    def _AfterTerminate(self, targets, errors):
        for p in targets:
            self.suspended.discard(p)
        if errors:
            self._SetStatus("Terminate: some processes failed")
            ui.message(
                "Some processes could not be terminated:\n" + "\n".join(errors),
                "Process Tree",
                wx.OK | wx.ICON_ERROR,
            )
        else:
            self._SetStatus(f"Terminated {len(targets)} process(es)")

    def _OnDump(self, pid):
        name = self.model.get(pid, {}).get("name", str(pid))
        dest = Path(self.startPanel.analysisDir) / "memory" / f"{pid}.dmp"
        self._SetStatus(f"Dumping {name} ({pid})...")

        def worker():
            try:
                path = dump_process_memory(pid, dest)
                wx.CallAfter(self._AfterDump, path, None)
            except OSError as e:
                wx.CallAfter(self._AfterDump, None, str(e))

        Thread(target=worker, daemon=True).start()

    def _AfterDump(self, path, err):
        if err:
            self._SetStatus("Memory dump failed")
            ui.message(err, "Process Tree", wx.OK | wx.ICON_ERROR)
        else:
            self._SetStatus(f"Memory dumped to {path}")

    def _SetStatus(self, message):
        getMainFrame = getattr(self.startPanel, "GetMainFrame", None)
        mainFrame = getMainFrame() if getMainFrame else None
        if mainFrame and getattr(mainFrame, "statusBar", None):
            mainFrame.statusBar.SetMessage(message)

    def OnClose(self, event):
        self.timer.Stop()
        self.startPanel.processTreeWindow = None
        self.Destroy()
