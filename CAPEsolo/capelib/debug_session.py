import logging
import re
from threading import Condition, Lock
from typing import Any

from distorm3 import Decode, Decode32Bits, Decode64Bits

from CAPEsolo.capelib.cmdconsts import MAX_MEM_REQUEST  # noqa: F401 - read as self._dbg.MAX_MEM_REQUEST
from CAPEsolo.classes.debug_pipe import CommandPipeHandler
from CAPEsolo.lib.core.pipe import PipeDispatcher, PipeServer, disconnect_pipes

log = logging.getLogger(__name__)

DEBUG_PIPE = r"\\.\pipe\debugger_pipe"
DEFAULT_COMMAND_TIMEOUT = 30
DEFAULT_BREAK_TIMEOUT = 120
MAX_TIMEOUT = 3600
MAX_MEM_READ = 0x4000
PAGE_SIZE = 0x1000
MAX_DUMP_SIZE = 0x1000000
# capemon's TS command takes at most 0x10000 steps per request.
MAX_TRACE_STEPS = 0x10000
MAX_INSTRUCTIONS = 256
MAX_INSTRUCTION_LEN = 15
FAILURE_TOKENS = ("Failed", "TIMEOUT", "UNREADABLE", "NODATA")
CIP_RX = re.compile(r"\b([ER]IP):\s*([0-9A-Fa-f]+)")
ADDRESS_RX = re.compile(r"0x[0-9a-fA-F]+")
TID_RX = re.compile(r"\btid (\d+)")
GENERAL_REG_RX = re.compile(r"\b([A-Z0-9]{2,3}):\s*([0-9A-Fa-f]{8,16})")
XMM_REG_RX = re.compile(r"\bXMM(\d{1,2})\s*\.(Low|High)\s*:\s*([0-9A-Fa-f]{8,16})")


def ParseAddress(value: Any) -> int | None:
    """Accept an int or a hex string (with or without 0x) and return an address."""
    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        return value if value >= 0 else None

    if not isinstance(value, str):
        return None

    text = value.strip()
    if not text:
        return None

    try:
        addr = int(text, 16)
    except ValueError:
        return None

    return addr if addr >= 0 else None


def IsFailure(payload: str | None) -> bool:
    """Return whether a debug server payload reports a failure rather than data."""
    if payload is None:
        return True

    return payload.startswith(FAILURE_TOKENS)


def ParseCip(payload: str) -> int | None:
    """Extract the current instruction pointer from a register dump or break payload."""
    m = CIP_RX.search(payload)
    if m:
        return int(m.group(2), 16)

    m = ADDRESS_RX.search(payload)
    if m:
        return int(m.group(0), 16)

    return None


def ParseRegisters(regsText: str) -> dict[str, str]:
    """Parse the register display text into a name to hex value mapping."""
    registers = {}
    for name, value in GENERAL_REG_RX.findall(regsText):
        registers[name.upper()] = f"{int(value, 16):#x}"

    for num, part, value in XMM_REG_RX.findall(regsText):
        key = f"XMM{int(num):02}.{part}".upper()
        registers[key] = f"{int(value, 16):#x}"

    return registers


def ParseStack(payload: str) -> list[dict[str, str]]:
    """Parse 'address, value' stack lines."""
    entries = []
    for line in payload.splitlines():
        parts = [p.strip() for p in line.split(",", 1)]
        if len(parts) < 2:
            continue

        entries.append({"address": parts[0], "value": parts[1]})

    return entries


def ParseMemDump(payload: str) -> tuple[int | None, str]:
    """Split a memory dump payload into its request address and hex data.

    The wire shape is `<addr>|<tag>|<data>`: capemon echoes back the request tag so a reply
    can be matched to the request that caused it. This path is synchronous - one command at a
    time - so the tag is dropped rather than checked, but a two-field payload means the
    monitor DLLs predate tagging and nothing here can be trusted to mean what it says.
    """
    parts = payload.split("|", 2)
    if len(parts) < 3:
        return None, ""

    requestAddr, _tag, data = parts
    try:
        return int(requestAddr, 16), data.strip()
    except ValueError:
        return None, ""


def ParseBreakTid(payload: str | None) -> int | None:
    """The thread id a break report ends with ("... 0x<cip> tid <n>"), where the monitor sends it."""
    m = TID_RX.search(payload or "")
    return int(m.group(1)) if m else None


def ParseDumpRegion(payload: str) -> dict[str, Any]:
    """A DR reply: `<tag>|OK|<guest path>|<bytes written>|<bytes unreadable>` or `<tag>|Failed ...`.

    The failure carries the tag first, so IsFailure (which checks the start) cannot see it.
    """
    parts = payload.split("|", 4)
    if len(parts) == 5 and parts[1] == "OK":
        try:
            return {"ok": True, "path": parts[2], "written": int(parts[3]), "unreadable": int(parts[4])}
        except ValueError:
            pass
    error = parts[1] if len(parts) > 1 and parts[1].startswith("Failed") else payload
    return {"ok": False, "error": error.strip()}


TRACE_REASONS = {
    "stop": "stop_at",
    "max": "max_steps",
    "module": "left_module",
    "monitor": "entered_monitor",
    "bp": "breakpoint",
    "error": "error",
}


def ParseTrace(payload: str) -> dict[str, Any]:
    """A TS reply: `<tag>|<reason>|<steps>|<cip>,<cip>,...|0x<halt cip>|<tid>`, or `<tag>|Failed ...`.

    The CIPs are bare hex in execution order; the list ends with "..." when the monitor recorded
    fewer than it executed (steps is always the true count).
    """
    parts = payload.split("|")
    if len(parts) >= 2 and parts[1].startswith("Failed"):
        return {"ok": False, "error": "|".join(parts[1:]).strip()}
    if len(parts) != 6:
        return {"ok": False, "error": f"Unexpected trace reply: {payload[:120]}"}

    _tag, reason, steps, cips, halt, tid = parts
    truncated = cips.endswith("...")
    try:
        addresses = [int(cip, 16) for cip in cips.split(",") if cip and cip != "..."]
        return {
            "ok": True,
            "reason": TRACE_REASONS.get(reason, reason),
            "steps": int(steps),
            "cips": addresses,
            "truncated": truncated,
            "halt": int(halt, 16),
            "tid": int(tid) if tid.strip().isdigit() else None,
        }
    except ValueError:
        return {"ok": False, "error": f"Unexpected trace reply: {payload[:120]}"}


def ParsePageLoad(payload: str) -> tuple[int | None, bytes | None]:
    """Split a page-load payload, `<pagebase>|<tag>|<hex>`, into the page base and its bytes.

    The bytes are None when the target reports the page UNREADABLE or NODATA. A readable page
    can come back short: capemon stops at the end of the memory region.
    """
    parts = payload.split("|", 2)
    if len(parts) < 3:
        return None, None

    try:
        base = int(parts[0], 16)
    except ValueError:
        return None, None

    data = parts[2].strip()
    if not data or data in ("UNREADABLE", "NODATA"):
        return base, None

    try:
        return base, bytes.fromhex(data)
    except ValueError:
        return base, None


def ModuleOf(modules: list[dict[str, str]], addr: int) -> str:
    """The name of the module containing *addr*, or "" outside every module."""
    for mod in modules:
        try:
            base, size = int(mod["base"], 16), int(mod["size"], 16)
        except (KeyError, ValueError):
            continue
        if base <= addr < base + size:
            return mod.get("name", "")
    return ""


def SummariseTrace(steps: list[dict[str, Any]], lastCount: int = 32) -> dict[str, Any]:
    """Summarise a recorded execution path.

    *steps* holds one entry per executed instruction, in order: address (int), length (int or
    None when the bytes were unreadable), text, and module. A block starts wherever execution
    did not simply fall through from the previous instruction.
    """
    transitions, blocks, calls, steppedOver = [], {}, {}, {}
    previous = None
    for index, step in enumerate(steps):
        addr = step["address"]
        if previous is None or previous["length"] is None or previous["address"] + previous["length"] != addr:
            blocks[addr] = blocks.get(addr, 0) + 1
        if previous is not None:
            if step["module"] != previous["module"]:
                transitions.append({
                    "step": index,
                    "from": previous["module"] or "<unmapped>",
                    "to": step["module"] or "<unmapped>",
                    "address": f"{addr:#x}",
                })
            if (previous["text"] or "").upper().startswith("CALL"):
                # Stepped into, the next address is the call's target; stepped over, it is only
                # the return address, so the call site is what gets counted.
                if previous.get("over"):
                    site = previous["address"]
                    steppedOver[site] = steppedOver.get(site, 0) + 1
                else:
                    calls[addr] = calls.get(addr, 0) + 1
        previous = step

    def ranked(counts):
        return [
            {"address": f"{addr:#x}", "hits": hits}
            for addr, hits in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        ]

    return {
        "module_transitions": transitions,
        "unique_blocks": len(blocks),
        "blocks": ranked(blocks)[:200],
        "calls": ranked(calls)[:200],
        "calls_stepped_over": ranked(steppedOver)[:200],
        "last_instructions": [
            {"address": f'{s["address"]:#x}', "module": s["module"], "text": s["text"]}
            for s in steps[-lastCount:]
        ],
    }


def ParseThreads(payload: str) -> list[dict[str, Any]]:
    """Parse thread lines of the form 'marker|tid|start address'."""
    threads = []
    for line in payload.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 3:
            continue

        threads.append({"tid": parts[1], "start_address": parts[2], "current": parts[0] == "+"})

    threads.sort(key=lambda t: not t["current"])
    return threads


def ParseBreakpoints(payload: str) -> list[dict[str, str]]:
    """Parse breakpoint entries of the form 'dr,address,type,size' joined by '|'.

    Monitors predating data breakpoints sent only 'dr,address'; those are execute
    breakpoints one byte wide. Without the four-field form this returned an empty list
    for every breakpoint, silently.
    """
    if "No" in payload:
        return []

    breakpoints = []
    for bp in payload.split("|"):
        parts = [part.strip() for part in bp.split(",")]
        if len(parts) == 2:
            parts += ["x", "1"]

        if len(parts) != 4:
            continue

        breakpoints.append({"dr": parts[0], "address": parts[1], "type": parts[2], "size": parts[3]})

    return breakpoints


def ParseCallStack(payload: str) -> list[dict[str, str]]:
    """Parse walked frames of the form 'index,returnAddress,framePointer,callSiteBytes'.

    call_bytes is the memory immediately preceding the return address; decoding backwards to
    find the CALL is left to the consumer, which is the only party that knows the bitness.
    """
    frames = []
    for entry in payload.split("|"):
        parts = [part.strip() for part in entry.split(",")]
        if len(parts) != 4:
            continue

        try:
            returnAddress = int(parts[1], 16)
        except ValueError:
            continue

        frames.append(
            {
                "index": parts[0],
                "return_address": f"{returnAddress:#x}",
                "frame_pointer": parts[2],
                "call_bytes": parts[3],
            }
        )

    return frames


def ParseModules(payload: str) -> list[dict[str, str]]:
    """Parse module entries of the form 'base,size,name,path' joined by '|'."""
    modules = []
    for mod in payload.split("|"):
        parts = mod.split(",")
        if len(parts) != 4:
            continue

        modules.append({"base": parts[0], "size": parts[1], "name": parts[2], "path": parts[3]})

    return modules


def Disassemble(base: int, data: bytes, bits: int, count: int) -> list[dict[str, str]]:
    """Decode instructions from raw bytes read at `base`."""
    mode = Decode64Bits if bits == 64 else Decode32Bits
    instructions = []
    for address, _, text, hexBytes in Decode(base, data, mode):
        if len(instructions) >= count:
            break

        instructions.append({"address": f"{address:#x}", "bytes": hexBytes.upper(), "text": text})

    return instructions


class DebuggerSession:
    """Headless driver for the capemon interactive debugger.

    Hosts the same named pipe server as DebugConsole (classes/debug_console.py) but
    drives the CommandPipeHandler rendezvous directly instead of through a client
    handle, because an MCP tool call may block where the wx main thread may not.
    """

    def __init__(self):
        self.breakCondition = Condition()
        self.pendingCommand = None
        self.debuggerResponse = None
        self.commandPipe = None
        self.sendLock = Lock()
        self.connected = False
        self.cip = None
        self.bits = None

    def launch(self):
        """Starts the pipe server and waits for a connection from the debug server."""
        # noinspection PyTypeChecker
        self.commandPipe = PipeServer(
            PipeDispatcher,
            DEBUG_PIPE,
            message=True,
            dispatcher=CommandPipeHandler(self),
        )
        self.commandPipe.daemon = True
        self.commandPipe.start()
        log.info("[DEBUG SESSION] Debugger pipe server started.")

    def shutdown(self):
        """Stops the pipe server and disconnects any open pipes."""
        if self.commandPipe:
            try:
                self.commandPipe.stop()
            except Exception:
                log.exception("[DEBUG SESSION] Failed stopping debugger pipe server")

            self.commandPipe = None

        self.connected = False
        disconnect_pipes()

    def _TakeResponse(self) -> str:
        response = self.debuggerResponse
        self.debuggerResponse = None
        self.connected = True
        return response.decode("utf-8", errors="replace").strip()

    def UpdateCip(self, payload: str) -> int | None:
        """Record the instruction pointer reported by an execution or register payload."""
        cip = ParseCip(payload)
        if cip is not None:
            self.cip = cip

        return self.cip

    def WaitForBreak(self, timeout: float = DEFAULT_BREAK_TIMEOUT) -> str | None:
        """Wait for an unsolicited break notification and return its payload."""
        with self.breakCondition:
            notified = self.breakCondition.wait_for(lambda: self.debuggerResponse is not None, timeout=timeout)
            if not notified:
                return None

            payload = self._TakeResponse()
            self.UpdateCip(payload)
            return payload

    def SendCommand(self, command: str, data: str = "", timeout: float = DEFAULT_COMMAND_TIMEOUT) -> str | None:
        """Send a debugger command and return its payload, or None on timeout.

        Only valid while the target is halted at a break, which is when the debug
        server is waiting for the next command.
        """
        with self.sendLock, self.breakCondition:
            if self.debuggerResponse is not None:
                stale = self._TakeResponse()
                self.UpdateCip(stale)
                log.debug("[DEBUG SESSION] Discarding unconsumed break payload: %s", stale[:64])

            self.pendingCommand = f"{command}:{data}".encode()
            self.breakCondition.notify_all()
            notified = self.breakCondition.wait_for(lambda: self.debuggerResponse is not None, timeout=timeout)
            if not notified:
                self.pendingCommand = None
                log.warning("[DEBUG SESSION] Command %s timed out after %ss", command, timeout)
                return None

            return self._TakeResponse()
