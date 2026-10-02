"""Graph view for the interactive debugger: a function's basic blocks drawn as a flow graph.

The blocks come from capelib.cfg; this window fetches the code they need through the console's
page cache, draws the layout, and overlays where execution is (CIP), the breakpoints and the
last trace. A separate window rather than a mode of the disassembly pane: that pane is a native
list control, which cannot draw graphics.
"""

import re

import wx

from CAPEsolo.capelib.cfg import EDGE_FALL, EDGE_TAKEN, BuildCfg, LayoutCfg
from CAPEsolo.capelib.flow_arrows import JumpTarget

from . import ui_kit as ui
from .theme import (
    ACCENT_CALL,
    ACCENT_ERROR,
    ACCENT_GREEN,
    ACCENT_JUMP,
    BG_CARD,
    BG_MAIN,
    BG_SELECT,
    BG_SURFACE,
    BORDER_STRONG,
    FG_PRIMARY,
    FG_RED_ALERT,
    FG_SECONDARY,
    FONT_CODE,
    apply_theme,
)

PAGE_SIZE = 0x1000
MARGIN = 30
PAD = 6
H_GAP, V_GAP = 40, 60
LANE_GAP = 14
MAX_TEXT = 60
CALL_RX = re.compile(r"^\s*CALL\s+(0x[0-9A-Fa-f]+)\s*$", re.IGNORECASE)


def CallTarget(text: str) -> int | None:
    """A direct call's target, or None."""
    m = CALL_RX.match(text)
    return int(m.group(1), 16) if m else None


class CfgWindow(wx.Frame):
    """One graph at a time; graphing another address replaces it (Back returns)."""

    def __init__(self, console):
        super().__init__(console.GetTopLevelParent(), title="Graph", size=wx.Size(1000, 760))
        self.console = console
        self.entry = None
        self.history: list[int] = []
        self.pages: dict[int, bytes] = {}
        self.requested: set[int] = set()
        self.unreadable: set[int] = set()
        self.rebuildPending = False
        self.centered = False

        panel = wx.Panel(self)
        self.summary = wx.StaticText(panel, label="")
        buttons = []
        for label, handler in (
            ("Back", lambda e: self.Back()),
            ("Go to CIP", lambda e: self.canvas.CenterOn(self.canvas.BlockOf(self.console.cip))),
            ("Zoom -", lambda e: self.canvas.Zoom(1 / 1.25)),
            ("Zoom +", lambda e: self.canvas.Zoom(1.25)),
            ("Fit", lambda e: self.canvas.Fit()),
            ("Refresh", lambda e: self.Reload()),
        ):
            btn = ui.Button(panel, label=label)
            btn.Bind(wx.EVT_BUTTON, handler)
            buttons.append(btn)

        top = wx.BoxSizer(wx.HORIZONTAL)
        for btn in buttons:
            top.Add(btn, 0, wx.RIGHT, 5)
        top.Add(self.summary, 1, wx.ALIGN_CENTER_VERTICAL | wx.LEFT, 10)

        self.canvas = GraphCanvas(panel, self)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(top, 0, wx.EXPAND | wx.ALL, 6)
        sizer.Add(self.canvas, 1, wx.EXPAND)
        panel.SetSizer(sizer)
        apply_theme(self)

    # --- graph lifetime ------------------------------------------------------------------
    def Start(self, entry: int, remember: bool = True):
        """Graph the function at `entry`."""
        if remember and self.entry is not None and self.entry != entry:
            self.history.append(self.entry)
        self.entry = entry
        self.centered = False
        self.SetTitle(f"Graph - {self.console.SymbolFor(entry) or f'{entry:#x}'}")
        self.Rebuild()

    def Back(self):
        if self.history:
            self.Start(self.history.pop(), remember=False)

    def Reload(self):
        """Read the code again: it may have been unpacked or patched since."""
        self.pages.clear()
        self.requested.clear()
        self.unreadable.clear()
        self.Rebuild()

    def ReadBytes(self, addr: int, count: int) -> bytes:
        out = b""
        while len(out) < count:
            cursor = addr + len(out)
            base = cursor - cursor % PAGE_SIZE
            data = self.pages.get(base)
            if data is None:
                data = self.console.pageBuffers.get(base)
                if data is not None:
                    # The console drops distant pages as execution moves; keep what was read.
                    self.pages[base] = data
            offset = cursor - base
            if not data or offset >= len(data):
                break
            out += data[offset:offset + count - len(out)]
        return out

    def Rebuild(self):
        # Also reached through CallLater, which can fire after the window has been closed.
        if not self:
            return
        self.rebuildPending = False
        if self.entry is None:
            return

        cfg = BuildCfg(self.entry, self.ReadBytes, self.console.bits or 64)
        waiting = 0
        for page in sorted({addr - addr % PAGE_SIZE for addr in cfg.missing}):
            if page in self.unreadable:
                continue
            if page not in self.requested:
                self.requested.add(page)
                if not self.console.RequestGraphPage(page):
                    self.unreadable.add(page)
                    continue
            # A page that arrived but is short (the region ends) is not still on its way.
            if page not in self.pages:
                waiting += 1

        notes = []
        if waiting:
            notes.append(f"reading {waiting} page{'s' if waiting != 1 else ''}...")
        if cfg.stubs:
            notes.append(f"{len(cfg.stubs)} target{'s' if len(cfg.stubs) != 1 else ''} not readable")
        if cfg.truncated:
            notes.append("stopped at the size limit")
        self.summary.SetLabel(
            f"{len(cfg.blocks)} blocks from {self.entry:#x}" + (" - " + ", ".join(notes) if notes else "")
        )
        self.canvas.SetGraph(cfg)
        # The indirect calls are named the way the disassembly names them, by reading the
        # import slots they go through; the replies come back through NamesChanged.
        self.console.ResolveCallSlots(self.Instructions())
        # Once, when the entry first has a block: its page may only arrive on a later rebuild.
        if not self.centered and cfg.entry in cfg.blocks:
            self.centered = True
            self.canvas.CenterOn(cfg.entry)

    def PageArrived(self, page: int, data: bytes | None):
        """A page the console read, or could not; rebuild if the graph was waiting for it."""
        if page not in self.requested:
            return
        if data:
            self.pages[page] = data
        else:
            self.unreadable.add(page)
        if not self.rebuildPending:
            # Pages arrive in a burst; one rebuild for the lot.
            self.rebuildPending = True
            wx.CallLater(50, self.Rebuild)

    def Instructions(self):
        cfg = self.canvas.cfg
        return [ins for block in cfg.blocks.values() for ins in block.instructions] if cfg else []

    def NamesChanged(self):
        """Exports finished loading or import slots were read: rename, and lay out again, since
        a name changes a block's width."""
        if not self or not self.canvas.cfg:
            return
        self.console.ResolveCallSlots(self.Instructions())
        self.canvas.SetGraph(self.canvas.cfg)

    def OnBreak(self):
        """Execution moved: redraw the CIP, breakpoint and trace overlays."""
        self.canvas.Refresh()


class GraphCanvas(wx.ScrolledWindow):
    def __init__(self, parent, window: CfgWindow):
        super().__init__(parent, style=wx.HSCROLL | wx.VSCROLL)
        self.window = window
        self.console = window.console
        self.cfg = None
        self.layout = None
        self.lanes: dict[tuple[int, int], int] = {}
        # Each block's text, built once per layout: naming runs regexes per instruction, and
        # dragging repaints constantly. SetGraph clears it, which every name change goes through.
        self.lineCache: dict[int, list[str]] = {}
        self.scale = 1.0
        self.selected = None
        self.dragFrom = None
        self.SetBackgroundStyle(wx.BG_STYLE_PAINT)
        self.SetScrollRate(1, 1)

        dc = wx.ClientDC(self)
        dc.SetFont(FONT_CODE)
        self.charW, self.lineH = dc.GetTextExtent("M")
        self.lineH += 2

        self.Bind(wx.EVT_PAINT, self.OnPaint)
        self.Bind(wx.EVT_LEFT_DOWN, self.OnLeftDown)
        self.Bind(wx.EVT_LEFT_UP, lambda e: setattr(self, "dragFrom", None))
        self.Bind(wx.EVT_MOTION, self.OnMotion)
        self.Bind(wx.EVT_LEFT_DCLICK, self.OnDoubleClick)
        self.Bind(wx.EVT_MOUSEWHEEL, self.OnWheel)

    # --- geometry --------------------------------------------------------------------------
    def Lines(self, node) -> list[str]:
        lines = self.lineCache.get(node)
        if lines is None:
            lines = self.lineCache[node] = self.BuildLines(node)
        return lines

    def BuildLines(self, node) -> list[str]:
        block = self.cfg.blocks.get(node)
        if block is None:
            return [f"{node:#x} (not read)"]
        lines = []
        name = self.console.SymbolFor(node)
        if name:
            lines.append(f"{name}:")
        for ins in block.instructions:
            # Named as the disassembly names it: a call shows kernel32!Sleep, not 0x7ffe...
            text = f"{ins.address:X}  {self.console.PatchDisasmText(ins.address, ins.text)}"
            lines.append(text if len(text) <= MAX_TEXT else text[:MAX_TEXT - 3] + "...")
        if block.end in ("indirect", "missing", "limit", "stop"):
            lines.append(f"; ends: {block.end}")
        return lines

    def Measure(self, node):
        lines = self.Lines(node)
        return (max(len(line) for line in lines) * self.charW + 2 * PAD, len(lines) * self.lineH + 2 * PAD)

    def SetGraph(self, cfg):
        self.cfg = cfg
        self.lineCache = {}
        self.layout = LayoutCfg(cfg, self.Measure, H_GAP, V_GAP)
        backs = [(s, d) for s, d, _, back in self.layout.edges if back]
        self.lanes = {edge: i for i, edge in enumerate(backs)}
        self.UpdateVirtualSize()
        self.Refresh()

    def TotalSize(self):
        if not self.layout:
            return 0, 0
        return (self.layout.width + 2 * MARGIN + LANE_GAP * (len(self.lanes) + 1),
                self.layout.height + 2 * MARGIN)

    def UpdateVirtualSize(self):
        w, h = self.TotalSize()
        self.SetVirtualSize(int(w * self.scale), int(h * self.scale))

    def Zoom(self, factor):
        self.scale = min(3.0, max(0.15, self.scale * factor))
        self.UpdateVirtualSize()
        self.Refresh()

    def Fit(self):
        w, h = self.TotalSize()
        cw, ch = self.GetClientSize()
        if w and h:
            self.scale = min(cw / w, ch / h, 1.0)
            self.UpdateVirtualSize()
            self.Scroll(0, 0)
            self.Refresh()

    def BlockOf(self, addr):
        """The block containing `addr`, or None."""
        if not self.cfg or addr is None:
            return None
        for start, block in self.cfg.blocks.items():
            last = block.instructions[-1]
            if start <= addr < last.address + last.size:
                return start
        return None

    def CenterOn(self, node):
        if not self.layout or node not in self.layout.nodes:
            return
        x, y, w, h = self.layout.nodes[node]
        cw, ch = self.GetClientSize()
        cx = (MARGIN + x + w / 2) * self.scale - cw / 2
        cy = (MARGIN + y) * self.scale - ch / 4
        self.Scroll(max(0, int(cx)), max(0, int(cy)))
        self.Refresh()

    def HitTest(self, pos):
        """(node, instruction address or None) under a client position."""
        if not self.layout:
            return None, None
        ux, uy = self.CalcUnscrolledPosition(pos.x, pos.y)
        lx, ly = ux / self.scale - MARGIN, uy / self.scale - MARGIN
        for node, (x, y, w, h) in self.layout.nodes.items():
            if x <= lx < x + w and y <= ly < y + h:
                block = self.cfg.blocks.get(node)
                if block is None:
                    return node, None
                row = int((ly - y - PAD) // self.lineH) - (1 if self.console.SymbolFor(node) else 0)
                if 0 <= row < len(block.instructions):
                    return node, block.instructions[row].address
                return node, None
        return None, None

    # --- input -----------------------------------------------------------------------------
    def OnLeftDown(self, event):
        node, addr = self.HitTest(event.GetPosition())
        if addr is not None:
            self.selected = addr
            self.console.disassemblyConsole.NavigateTo(addr)
            self.Refresh()
        elif node is None:
            self.dragFrom = (event.GetPosition(), self.GetViewStart())
        event.Skip()

    def OnMotion(self, event):
        if self.dragFrom and event.LeftIsDown():
            start, (vx, vy) = self.dragFrom
            delta = event.GetPosition() - start
            self.Scroll(vx - delta.x, vy - delta.y)
            self.Refresh()
        event.Skip()

    def OnDoubleClick(self, event):
        node, addr = self.HitTest(event.GetPosition())
        if addr is None:
            return
        text = next(i.text for i in self.cfg.blocks[node].instructions if i.address == addr)
        target = JumpTarget(text)
        if target is not None and target in self.layout.nodes:
            self.CenterOn(target)
            return
        callee = CallTarget(text)
        if callee is not None:
            self.window.Start(callee)

    def OnWheel(self, event):
        if event.ControlDown():
            self.Zoom(1.15 if event.GetWheelRotation() > 0 else 1 / 1.15)
        else:
            event.Skip()

    # --- drawing ---------------------------------------------------------------------------
    def OnPaint(self, event):
        dc = wx.BufferedPaintDC(self)
        self.DoPrepareDC(dc)
        dc.SetBackground(wx.Brush(BG_MAIN))
        dc.Clear()
        if not self.layout:
            return
        dc.SetUserScale(self.scale, self.scale)
        dc.SetFont(FONT_CODE)
        self.DrawEdges(dc)
        cipBlock = self.BlockOf(self.console.cip)
        for node in self.layout.nodes:
            self.DrawBlock(dc, node, node == cipBlock)

    def DrawEdges(self, dc):
        nodes = self.layout.nodes
        colours = {EDGE_TAKEN: ACCENT_JUMP, EDGE_FALL: FG_RED_ALERT}
        for src, dst, kind, back in self.layout.edges:
            sx0, sy0, sw, sh = nodes[src]
            dx0, dy0, dw, dh = nodes[dst]
            block = self.cfg.blocks[src]
            share = 0.5 if len(block.edges) == 1 else (0.3 if kind == EDGE_TAKEN else 0.7)
            sx, sy = MARGIN + sx0 + sw * share, MARGIN + sy0 + sh
            dx, dy = MARGIN + dx0 + dw / 2, MARGIN + dy0
            if back:
                lane = MARGIN + self.layout.width + LANE_GAP * (self.lanes[(src, dst)] + 1)
                points = [(sx, sy), (sx, sy + 12), (lane, sy + 12), (lane, dy - 12), (dx, dy - 12), (dx, dy)]
            else:
                mid = sy + V_GAP / 2
                points = [(sx, sy), (sx, mid), (dx, mid), (dx, dy)]
            dc.SetPen(wx.Pen(colours.get(kind, ACCENT_CALL), 2))
            dc.DrawLines([wx.Point(int(px), int(py)) for px, py in points])
            dc.SetBrush(wx.Brush(colours.get(kind, ACCENT_CALL)))
            dc.DrawPolygon([wx.Point(int(dx), int(dy)), wx.Point(int(dx - 5), int(dy - 8)), wx.Point(int(dx + 5), int(dy - 8))])

    def DrawBlock(self, dc, node, isCipBlock: bool):
        x, y, w, h = self.layout.nodes[node]
        x, y = MARGIN + x, MARGIN + y
        block = self.cfg.blocks.get(node)
        cip = self.console.cip
        dc.SetPen(wx.Pen(ACCENT_GREEN if isCipBlock else BORDER_STRONG, 3 if isCipBlock else 1,
                         wx.PENSTYLE_SOLID if block is not None else wx.PENSTYLE_SHORT_DASH))
        dc.SetBrush(wx.Brush(BG_CARD))
        dc.DrawRoundedRectangle(int(x), int(y), int(w), int(h), 4)

        lines = self.Lines(node)
        if block is None:
            dc.SetTextForeground(FG_SECONDARY)
            dc.DrawText(lines[0], int(x + PAD), int(y + PAD))
            return

        disasm = self.console.disassemblyConsole
        row = 0
        if self.console.SymbolFor(node):
            dc.SetTextForeground(FG_SECONDARY)
            dc.DrawText(lines[0], int(x + PAD), int(y + PAD))
            row = 1
        for i, ins in enumerate(block.instructions):
            ty = y + PAD + (row + i) * self.lineH
            fill = None
            if ins.address == cip:
                fill = ACCENT_GREEN
            elif ins.address == self.selected:
                fill = BG_SELECT
            elif ins.address in disasm.bpAddrs:
                fill = ACCENT_ERROR
            elif ins.address in disasm.traceAddrs:
                fill = BG_SURFACE
            if fill is not None:
                dc.SetPen(wx.TRANSPARENT_PEN)
                dc.SetBrush(wx.Brush(fill))
                dc.DrawRectangle(int(x + 2), int(ty), int(w - 4), self.lineH)
            mnemonic = ins.text.split()[0].upper() if ins.text else ""
            dc.SetTextForeground(ACCENT_CALL if mnemonic == "CALL" else ACCENT_JUMP if mnemonic.startswith("J") else FG_PRIMARY)
            dc.DrawText(lines[row + i], int(x + PAD), int(ty))
        if block.end in ("indirect", "missing", "limit", "stop"):
            dc.SetTextForeground(FG_SECONDARY)
            dc.DrawText(lines[-1], int(x + PAD), int(y + PAD + (len(lines) - 1) * self.lineH))
