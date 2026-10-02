"""Parsing and validation for the interactive debugger's command box.

Turns what the analyst types into the two-letter command and pipe-delimited payload capemon
expects, or into an error naming what was wrong. Pure functions, free of wx imports (see
tests/test_console_commands.py).

Two things shape this. The box used to split its input into command and arguments and then
send only the command - `md 0x401000` dumped at CIP rather than at the address, and
`ru 0x401000` reached the monitor with no address at all - so the payload has to be built
here and tested. And anything typed was uppercased and sent, so a typo came back as
"Unknown command" from the target rather than being caught before it left: validating locally
is what lets a wrong argument count be reported against a usage string instead.
"""


import re
from collections import namedtuple

from .cmdconsts import (
    CMD_BREAKPOINT_LIST,
    CMD_CALL_STACK,
    CMD_CONTINUE,
    CMD_DELETE_BREAKPOINT,
    CMD_MEM_DUMP,
    CMD_MOD_FLAG,
    CMD_MODULE_LIST,
    CMD_NOP_INSTRUCTION,
    CMD_PATCH_BYTES,
    CMD_REG_UPDATE,
    CMD_RUN_UNTIL,
    CMD_SET_BREAKPOINT,
    CMD_SET_REGISTER,
    CMD_STACK_UPDATE,
    CMD_STEP_INTO,
    CMD_STEP_OUT,
    CMD_STEP_OVER,
    CMD_THREAD_INSPECT,
    CMD_THREADS,
)

# Local actions the console handles itself rather than sending anywhere.
LOCAL_COMMANDS = ("help", "clear", "disconnect", "quit")

BP_TYPES = ("x", "w", "rw")
BP_SIZES = (1, 2, 4, 8)
# "sw" is a software (int3) breakpoint rather than a debug register: execute only, any number.
BP_SLOTS = ("next", "0", "1", "2", "3", "sw")
FLAGS = ("zero", "sign", "carry")
FLAG_ACTIONS = ("set", "clear", "flip")
HEX_RX = re.compile(r"^(?:0[xX])?[0-9A-Fa-f]+$")
HEX_BYTES_RX = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")
REGISTER_RX = re.compile(r"^[A-Za-z][A-Za-z0-9]{1,3}$")

Command = namedtuple("Command", ["code", "names", "usage", "summary"])

# Ordered for the help listing: what you reach for most, first. `IN`, `PM` and `EX` are
# deliberately absent - they are how the view fetches pages, the memory map and exports, and
# issuing one by hand desynchronises the accumulator that collects their replies.
COMMANDS = (
    Command(CMD_STEP_INTO, ("si", "stepi", "step"), "si", "Step one instruction"),
    Command(CMD_STEP_OVER, ("so", "stepover", "next"), "so", "Step over a call"),
    Command(CMD_STEP_OUT, ("ou", "stepout", "finish"), "ou", "Run to the return of this function"),
    Command(CMD_CONTINUE, ("ct", "continue", "go", "g"), "ct", "Continue execution"),
    Command(CMD_RUN_UNTIL, ("ru", "rununtil", "until"), "ru <address>", "Run until an address"),
    Command(CMD_SET_BREAKPOINT, ("bp", "break"), "bp <address> [x|w|rw] [1|2|4|8] [next|0-3|sw]", "Set a breakpoint (bp <address> sw: software)"),
    Command(CMD_DELETE_BREAKPOINT, ("db", "bd", "delete"), "db <0-3> | db sw <address>", "Delete a breakpoint by register or address"),
    Command(CMD_BREAKPOINT_LIST, ("lb", "bl", "breakpoints"), "lb", "List breakpoints"),
    Command(CMD_MEM_DUMP, ("md", "dump", "d"), "md <address> [size]", "Dump memory"),
    Command(CMD_REG_UPDATE, ("rg", "regs", "r"), "rg", "Refresh registers"),
    Command(CMD_SET_REGISTER, ("sr", "setreg"), "sr <register> <value>", "Set a register"),
    Command(CMD_MOD_FLAG, ("fl", "flag"), "fl <set|clear|flip> <zero|sign|carry>", "Modify a flag"),
    Command(CMD_STACK_UPDATE, ("sk", "stack"), "sk", "Refresh the stack view"),
    Command(CMD_CALL_STACK, ("cs", "callstack", "frames"), "cs", "Walk the call stack"),
    Command(CMD_THREADS, ("th", "threads"), "th", "List threads"),
    Command(CMD_THREAD_INSPECT, ("ti", "inspect"), "ti <tid>", "Inspect a thread"),
    Command(CMD_MODULE_LIST, ("lm", "modules"), "lm", "List modules"),
    Command(CMD_NOP_INSTRUCTION, ("ni", "nop"), "ni <address>", "NOP the instruction at an address"),
    Command(CMD_PATCH_BYTES, ("pb", "patch"), "pb <address> <hex bytes>", "Patch bytes at an address"),
)
BY_NAME = {name: command for command in COMMANDS for name in command.names}


def _Hex(token: str) -> int | None:
    """A hex address, with or without the 0x, or None if it is not one."""
    if not HEX_RX.match(token):
        return None

    return int(token, 16)


def _Address(token: str, resolve) -> int | None:
    """A hex address, or, given a resolver, a name it knows (kernel32!VirtualAlloc, a rename).

    Hex is tried first, so a name that also reads as hex (add, dead) means the number.
    """
    addr = _Hex(token)
    if addr is None and resolve is not None:
        addr = resolve(token)
    return addr


def HelpText() -> str:
    """The command list, for `help`."""
    lines = ["Commands (aliases in brackets):"]
    for command in COMMANDS:
        aliases = ", ".join(command.names[1:])
        lines.append(f"  {command.usage:42} {command.summary}" + (f"  [{aliases}]" if aliases else ""))

    lines.append("  " + f"{'help | clear | disconnect | quit':42} Console actions")
    lines.append("Addresses may be written with or without 0x, or as a name (kernel32!VirtualAlloc).")
    lines.append("Up and Down recall history.")
    return "\n".join(lines)


def ParseCommand(text: str, resolve=None):
    """(code, payload, error) for one line of input.

    `resolve`, if given, maps a name to an address or None, letting address arguments be names.
    Exactly one of `code` and `error` is set; `code` is None for a local action, whose name is
    returned as the payload. An empty line is all-None, which is not an error.
    """
    tokens = text.strip().split()
    if not tokens:
        return None, None, None

    name = tokens[0].lower()
    args = tokens[1:]
    if name in LOCAL_COMMANDS:
        return None, name, None

    command = BY_NAME.get(name)
    if command is None:
        return None, None, f"Unknown command '{tokens[0]}'. Type help for the list."

    payload, error = _Payload(command, args, resolve)
    if error:
        return None, None, f"{error}\nUsage: {command.usage}"

    return command.code, payload, None


def _Payload(command: Command, args: list[str], resolve=None):
    """(payload, error) for a command's arguments, in the form capemon parses."""
    code = command.code
    if code in (CMD_STEP_INTO, CMD_STEP_OVER, CMD_STEP_OUT, CMD_CONTINUE, CMD_REG_UPDATE,
                CMD_STACK_UPDATE, CMD_CALL_STACK, CMD_THREADS, CMD_MODULE_LIST, CMD_BREAKPOINT_LIST):
        if args:
            return None, "This command takes no arguments."

        return "", None

    if code in (CMD_RUN_UNTIL, CMD_NOP_INSTRUCTION):
        if len(args) != 1:
            return None, "Expected one address."

        addr = _Address(args[0], resolve)
        if addr is None:
            return None, f"'{args[0]}' is not a hex address or known name."

        return f"{addr:#x}", None

    if code == CMD_MEM_DUMP:
        if not args or len(args) > 2:
            return None, "Expected an address and an optional size."

        addr = _Address(args[0], resolve)
        if addr is None:
            return None, f"'{args[0]}' is not a hex address or known name."

        if len(args) == 1:
            return f"{addr:#x}", None

        size = _Hex(args[1])
        if size is None or size == 0:
            return None, f"'{args[1]}' is not a valid size."

        return f"{addr:#x}|{size:#x}", None

    if code == CMD_SET_BREAKPOINT:
        return _BreakpointPayload(args, resolve)

    if code == CMD_DELETE_BREAKPOINT:
        if len(args) == 2 and args[0].lower() == "sw":
            addr = _Address(args[1], resolve)
            if addr is None:
                return None, f"'{args[1]}' is not a hex address or known name."

            return f"sw|{addr:#X}", None

        if len(args) != 1 or args[0] not in ("0", "1", "2", "3"):
            return None, "Expected a debug register, 0 to 3."

        return args[0], None

    if code == CMD_THREAD_INSPECT:
        if len(args) != 1 or not args[0].isdigit():
            return None, "Expected a decimal thread id."

        return args[0], None

    if code == CMD_SET_REGISTER:
        if len(args) != 2:
            return None, "Expected a register and a value."

        if not REGISTER_RX.match(args[0]):
            return None, f"'{args[0]}' is not a register name."

        value = _Hex(args[1])
        if value is None:
            return None, f"'{args[1]}' is not a hex value."

        return f"{args[0].upper()}|{value:#x}", None

    if code == CMD_MOD_FLAG:
        if len(args) != 2:
            return None, "Expected an action and a flag."

        action, flag = args[0].lower(), args[1].lower()
        if action not in FLAG_ACTIONS:
            return None, f"'{args[0]}' is not an action. Use one of {', '.join(FLAG_ACTIONS)}."

        if flag not in FLAGS:
            return None, f"'{args[1]}' is not a flag. Use one of {', '.join(FLAGS)}."

        # capemon matches the whole directive, e.g. "FlipZeroFlag".
        return f"{action.capitalize()}{flag.capitalize()}Flag", None

    if code == CMD_PATCH_BYTES:
        if len(args) != 2:
            return None, "Expected an address and hex bytes."

        addr = _Address(args[0], resolve)
        if addr is None:
            return None, f"'{args[0]}' is not a hex address or known name."

        data = args[1][2:] if args[1].lower().startswith("0x") else args[1]
        if not HEX_BYTES_RX.match(data):
            return None, f"'{args[1]}' is not a whole number of hex bytes."

        return f"{addr:#x}|{data.upper()}", None

    return "", None


def _BreakpointPayload(args: list[str], resolve=None):
    """`bp <address> [type] [size] [slot]` as capemon's slot|address|type|size."""
    if not args or len(args) > 4:
        return None, "Expected an address, and optionally a type, size and slot."

    addr = _Address(args[0], resolve)
    if addr is None:
        return None, f"'{args[0]}' is not a hex address or known name."

    # `bp <address> sw` shorthand: a software breakpoint has no type or size to give.
    if len(args) == 2 and args[1].lower() == "sw":
        args = [args[0], "x", "1", "sw"]

    bpType = args[1].lower() if len(args) > 1 else "x"
    if bpType not in BP_TYPES:
        return None, f"'{args[1]}' is not a breakpoint type. Use one of {', '.join(BP_TYPES)}."

    size = 1
    if len(args) > 2:
        if not args[2].isdigit() or int(args[2]) not in BP_SIZES:
            return None, f"'{args[2]}' is not a watch size. Use one of {', '.join(map(str, BP_SIZES))}."

        size = int(args[2])

    slot = args[3].lower() if len(args) > 3 else "next"
    if slot not in BP_SLOTS:
        return None, f"'{args[3]}' is not a slot. Use one of {', '.join(BP_SLOTS)}."

    if bpType == "x" and size != 1:
        return None, "An execute breakpoint is always one byte; drop the size."

    if slot == "sw" and bpType != "x":
        return None, "A software breakpoint is execute only; use a debug register for a watch."

    # x86 requires a data breakpoint's address to be aligned to its length, and a misaligned
    # one silently watches the wrong bytes rather than failing.
    if bpType != "x" and addr % size:
        return None, f"A {size}-byte watch needs a {size}-byte aligned address; try {addr - (addr % size):#x}."

    # Uppercase 0X, matching what PromptBreakpoint already sends: capemon parses both, and
    # one wire format for breakpoints is one thing to check when a payload looks wrong.
    return f"{slot}|{addr:#X}|{bpType}|{size}", None
