"""Control-flow graph of a function, for the interactive debugger's graph view.

BuildCfg recovers basic blocks and edges from a start address by recursive descent: it follows
conditional and direct jumps, falls through calls, and ends a path at a return, an indirect
jump, or memory it cannot read. LayoutCfg places the blocks in layers, top to bottom, the way
IDA draws them. Pure functions on plain data, free of wx and pipe imports, so both can be
exercised without a GUI or a target (see tests/test_cfg.py).

There are no symbols, so the graph starts where it is asked to: the caller picks the function
entry. Code is read through a callback that may not have every page yet - those addresses are
reported in `missing` so the caller can fetch them and build again.
"""

import re
from collections import namedtuple

from distorm3 import Decode, Decode32Bits, Decode64Bits

from .flow_arrows import JumpTarget

Instruction = namedtuple("Instruction", ["address", "size", "text", "bytes"])

# Indirect operands whose slot address the instruction alone determines, as distorm writes
# them: "[0x405000]" and "[RIP+0x3af9]". See StaticSlotAddress.
ABS_SLOT_RX = re.compile(r"^\[(0x[0-9A-Fa-f]+)\]$")
RIP_SLOT_RX = re.compile(r"^\[RIP\s*([+-])\s*(0x[0-9A-Fa-f]+)\]$", re.IGNORECASE)
# A call's operand, size keywords dropped: "CALL QWORD [RIP+0x3af9]" -> "[RIP+0x3af9]".
CALL_OPERAND_RX = re.compile(r"^\s*CALL\s+(?:[A-Za-z_]+\s+)*?(\[[^\]]+\]|0x[0-9A-Fa-f]+)\s*$", re.IGNORECASE)

# Past these the graph stops growing and says so; a function this size is not read as a graph.
MAX_BLOCKS = 500
MAX_INSTRUCTIONS = 10000
MAX_INSN_LEN = 15

# Edge kinds: the taken and fall-through sides of a conditional jump, an unconditional jump,
# and plain flow into a block that starts there only because something else jumps to it.
EDGE_TAKEN, EDGE_FALL, EDGE_JUMP, EDGE_NEXT = "taken", "fall", "jump", "next"

# Why a block has no successor: a return, an indirect jump (a switch table, a tail call through
# a register), an instruction that does not continue, or the graph's own limits.
END_RET, END_INDIRECT, END_STOP, END_MISSING, END_LIMIT = "ret", "indirect", "stop", "missing", "limit"


class Block:
    __slots__ = ("start", "instructions", "edges", "end")

    def __init__(self, start: int):
        self.start = start
        self.instructions: list[Instruction] = []
        self.edges: list[tuple[int, str]] = []
        self.end: str | None = None


class Cfg:
    __slots__ = ("entry", "blocks", "stubs", "missing", "truncated")

    def __init__(self, entry: int):
        self.entry = entry
        self.blocks: dict[int, Block] = {}
        # Edge targets that are not blocks: unreadable, or past the limits.
        self.stubs: list[int] = []
        self.missing: set[int] = set()
        self.truncated = False


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


def CallOperand(text: str) -> str | None:
    """A CALL's operand - a 0x literal or a bracketed reference - or None for anything else."""
    m = CALL_OPERAND_RX.match(text)
    return m.group(1) if m else None


def Classify(text: str) -> tuple[str, int | None]:
    """How an instruction leaves: (kind, direct target), kind one of next, jump, cond, ret,
    indirect or stop."""
    mnemonic = text.split()[0].upper() if text.strip() else ""
    if mnemonic.startswith(("RET", "IRET")):
        return END_RET, None
    if mnemonic in ("HLT", "UD2", "INT3") or text.strip().upper() == "INT 3":
        return END_STOP, None
    if mnemonic == "JMP":
        target = JumpTarget(text)
        return ("jump", target) if target is not None else (END_INDIRECT, None)
    if mnemonic.startswith("J") or mnemonic.startswith("LOOP"):
        target = JumpTarget(text)
        return ("cond", target) if target is not None else (END_INDIRECT, None)
    return "next", None


def BuildCfg(entry: int, readBytes, bits: int, maxBlocks: int = MAX_BLOCKS, maxInstructions: int = MAX_INSTRUCTIONS) -> Cfg:
    """Recover the blocks reachable from `entry`.

    readBytes(address, count) returns up to `count` bytes at address - fewer where the next
    page is not available - or b"" / None where none are.
    """
    mode = Decode64Bits if bits == 64 else Decode32Bits
    cfg = Cfg(entry)
    insns: dict[int, tuple[Instruction, str, int | None]] = {}
    leaders = {entry}
    # Leaders in the order they were found, so a graph cut short at the block limit keeps the
    # blocks nearest the entry rather than the lowest addresses.
    found = [entry]
    work = [entry]

    def Lead(addr):
        if addr not in leaders:
            leaders.add(addr)
            found.append(addr)

    # Pass 1: every instruction reachable, and where blocks must start.
    while work:
        addr = work.pop()
        while True:
            if addr in insns:
                # Joined a path already decoded: a block has to start here.
                Lead(addr)
                break
            if len(insns) >= maxInstructions:
                cfg.truncated = True
                break

            data = readBytes(addr, MAX_INSN_LEN)
            decoded = next(iter(Decode(addr, data, mode)), None) if data else None
            if decoded is None:
                cfg.missing.add(addr)
                break

            address, size, text, hexBytes = decoded
            if text.startswith("DB "):
                # Not an instruction: either it runs into a page not read yet, or it is junk.
                if len(data) < MAX_INSN_LEN:
                    cfg.missing.add(addr)
                else:
                    insns[addr] = (Instruction(address, size, text, hexBytes.upper()), END_STOP, None)
                break

            kind, target = Classify(text)
            insns[addr] = (Instruction(address, size, text, hexBytes.upper()), kind, target)
            following = addr + size
            if kind == "next":
                addr = following
                continue
            if kind == "jump":
                Lead(target)
                work.append(target)
            elif kind == "cond":
                Lead(target)
                Lead(following)
                work.extend((target, following))
            break

    # Pass 2: cut the instructions into blocks at the leaders.
    for leader in found:
        if leader not in insns:
            continue
        if len(cfg.blocks) >= maxBlocks:
            cfg.truncated = True
            break

        block = Block(leader)
        addr = leader
        while True:
            ins, kind, target = insns[addr]
            block.instructions.append(ins)
            following = addr + ins.size
            if kind == "next":
                if following in insns and following not in leaders:
                    addr = following
                    continue
                if following in insns:
                    block.edges.append((following, EDGE_NEXT))
                else:
                    block.end = END_MISSING if following in cfg.missing else END_LIMIT
            elif kind == "jump":
                block.edges.append((target, EDGE_JUMP))
            elif kind == "cond":
                block.edges.extend(((target, EDGE_TAKEN), (following, EDGE_FALL)))
            else:
                block.end = kind
            break
        cfg.blocks[leader] = block

    targets = {target for block in cfg.blocks.values() for target, _ in block.edges}
    cfg.stubs = sorted(targets - set(cfg.blocks))
    return cfg


Layout = namedtuple("Layout", ["nodes", "edges", "width", "height"])


def LayoutCfg(cfg: Cfg, measure, hGap: int = 40, vGap: int = 60) -> Layout:
    """Place the blocks in layers, entry at the top.

    measure(address) gives a node's (width, height); stubs are measured too. Returns node
    rectangles {address: (x, y, w, h)} and edges [(source, target, kind, back)], back being an
    edge that closes a loop - drawn up the side rather than through the layers.
    """
    succ = {addr: [target for target, _ in block.edges] for addr, block in cfg.blocks.items()}
    for stub in cfg.stubs:
        succ.setdefault(stub, [])

    # Depth-first from the entry: discovery order seeds the in-layer order, an edge back onto
    # the current path is a loop, and the reverse postorder is a topological order of the rest.
    back, order, post = set(), [], []
    state = {}
    stack = [(cfg.entry, iter(succ.get(cfg.entry, ())))] if cfg.entry in succ else []
    if stack:
        state[cfg.entry] = 1
        order.append(cfg.entry)
    while stack:
        node, children = stack[-1]
        child = next(children, None)
        if child is None:
            stack.pop()
            state[node] = 2
            post.append(node)
            continue
        if state.get(child) == 1:
            back.add((node, child))
        elif child not in state:
            state[child] = 1
            order.append(child)
            stack.append((child, iter(succ.get(child, ()))))

    layer = {node: 0 for node in order}
    for node in reversed(post):
        for child in succ[node]:
            if (node, child) not in back and child in layer:
                layer[child] = max(layer[child], layer[node] + 1)

    rows: dict[int, list[int]] = {}
    for node in order:
        rows.setdefault(layer[node], []).append(node)

    preds: dict[int, list[int]] = {node: [] for node in order}
    for node in order:
        for child in succ[node]:
            if (node, child) not in back and child in preds:
                preds[child].append(node)

    # A few barycentre sweeps, down then up, to pull blocks under their neighbours.
    def Position(row):
        return {node: i for i, node in enumerate(row)}

    # The fallback position is taken before each sort: list.sort empties the list while it
    # computes keys, so looking a node up in the list being sorted raises.
    depth = max(rows) if rows else -1
    for _ in range(4):
        for level in range(1, depth + 1):
            above, here = Position(rows[level - 1]), Position(rows[level])
            rows[level].sort(key=lambda n: _Mean([above[p] for p in preds[n] if p in above], here[n]))
        for level in range(depth - 1, -1, -1):
            below, here = Position(rows[level + 1]), Position(rows[level])
            rows[level].sort(key=lambda n: _Mean([below[c] for c in succ[n] if c in below and (n, c) not in back],
                                                here[n]))

    sizes = {node: measure(node) for node in order}
    rowWidths = {level: sum(sizes[n][0] for n in row) + hGap * (len(row) - 1) for level, row in rows.items()}
    width = max(rowWidths.values(), default=0)
    nodes, y = {}, 0
    for level in range(depth + 1):
        row = rows[level]
        x = (width - rowWidths[level]) // 2
        rowHeight = max(sizes[n][1] for n in row)
        for node in row:
            w, h = sizes[node]
            nodes[node] = (x, y, w, h)
            x += w + hGap
        y += rowHeight + vGap

    edges = []
    for addr, block in cfg.blocks.items():
        for target, kind in block.edges:
            if addr in nodes and target in nodes:
                edges.append((addr, target, kind, (addr, target) in back))
    return Layout(nodes, edges, width, max(y - vGap, 0))


def _Mean(values, default):
    return sum(values) / len(values) if values else default
