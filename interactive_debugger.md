# Interactive Debugger User Guide

This guide explains how to use the interactive debugger to analyze a running process. You can control execution, inspect memory and 
registers, set breakpoints, and patch code on the fly. 

Check the Interactive Debugger under Debugger options. The debugger window is opened when the first breakpoint is triggered.

---

## 1. Main Window Overview

The debugger window is organized into several panels, each providing a different view of the process state:

- **Disassembly Console:** Shows disassembled code at the current instruction pointer (EIP/RIP).
- **Registers:** Displays the current CPU general-purpose registers and flags.
- **Memory Dump:** Shows a hexadecimal and ASCII view of a memory region.
- **Stack:** Displays stack contents with the stack pointer (ESP/RSP) highlighted.
- **Modules:** Lists all loaded modules (DLLs, EXEs).
- **Threads:** Lists active threads in the process.
- **Breakpoints:** Displays all set hardware and software breakpoints.
- **Console Output:** Shows status messages, command results, and resolved API names.
- **Command Input:** A text box for entering debugger commands manually.

---

## 2. Core Debugging Actions (Hotkeys & Buttons)

The most common debugging actions are available via buttons and global hotkeys:

| Action        | Hotkey   | Button    | Description                                                                   |
|---------------|----------|-----------|-------------------------------------------------------------------------------|
| Run Until     | F4       | Run Until | Runs until the currently selected instruction in Disassembly view is reached. |
| Step Into     | F7       | Step Into | Executes a single instruction. Steps into CALL instructions.                  |
| Step Over     | F8       | Step Over | Executes a single instruction. Steps over CALL instructions.                  |
| Step Out      | F9       | Step Out  | Executes until the current function returns.                                  |
| Continue      | F10      | Continue  | Resumes execution until a breakpoint or process termination.                  |
| Trace         | (None)   | Trace...  | Single-steps up to N instructions, recording the path (see below).            |
| Patch         | Spacebar | (None)    | Opens the patching dialog for the selected instruction.                       |
| Go Back       | Esc      | (None)    | Navigates to the previously viewed memory dump.                               |
| Stop Debugger | Ctrl+Q   | (None)    | Sends a Continue command and closes the debugger window.                      |

### Trace

**Trace...** single-steps the halted thread inside the monitor, which is far faster than
repeated Step Into, and records every instruction executed. Set a step limit (up to 65536), an
optional **Stop at** address (it defaults to the selected disassembly row), **Step over calls**
to run each CALL without tracing into it, and **Stop on leaving the module** to stop when
execution leaves the image or shellcode region the trace started in. It also stops on entering
monitor code or hitting a breakpoint.

When it stops, the console reports why, the step count, how many distinct instructions ran and
the most-executed addresses (loops), and the traced instructions are tinted in the disassembly.
The tint stays until the next trace or **Clear Trace Highlight** in the disassembly menu.

---

## 3. Interacting with the Panels

### 3.1. Disassembly Console

**Features:**
- **Color Coding:**
  - Green background: Current instruction pointer (CIP).
  - Blue text: CALL instructions.
  - Green text: JMP and conditional jumps.
  - Red background: Instruction with a breakpoint.
  - Italic font: Patched instructions.
- **Hover Feature:** Hovering over a memory address operand or direct address auto-copies it to the clipboard and shows a tooltip.
- **Context Menu Actions:**
  - Copy
  - Go To / Go To EIP/RIP
  - Set EIP/RIP
  - NOP Instruction
  - Patch Bytes
  - Patch History
  - Set Breakpoint (slots 0–3, or Software)
  - Delete Breakpoint
  - Resolve Export...

### 3.2. Registers View

- **Context Menu Actions:**
  - Set Register
  - Modify Flags (Set, Clear, Flip Zero, Sign, Carry)
  - Dump Memory Address
  - Follow Address
  - Resolve Export...

### 3.3. Stack View

- **Highlight:** Stack pointer (ESP/RSP) highlighted in yellow.
- **Context Menu Actions:**
  - Dump Address / Dump Value
  - Resolve Export...

### 3.4. Memory Dump View

- **Usage:** Enter a hex address or register name in the "Memory Dump Address" box and press Enter.
- **History Navigation:** Press Esc to go back to the previously viewed memory address.

### 3.5. Modules, Threads, and Breakpoints Panels

- **Modules:** 
  - Right-click → "Exports" to list all exported functions (Ctrl+F to search).
- **Threads:** 
  - Right-click → "Follow Start Address" to jump to a thread’s entry point.
- **Breakpoints:** 
  - Right-click → "Delete Breakpoint" or "Follow Address".

---

## 4. Command Line Input

For advanced or quick actions, use the command input box at the bottom:

| Command    | Example         | Description                                                   |
|------------|-----------------|---------------------------------------------------------------|
| b          | b next 0x401000 | Sets a hardware breakpoint. Use slot (next, 0–3) and address. |
| bp ... sw  | bp 0x401000 sw  | Sets a software breakpoint (see below).                       |
| db sw      | db sw 0x401000  | Deletes the software breakpoint at an address.                |

### Names instead of addresses

Anywhere an address is typed - the command box (`bp`, `ru`, `md`, `ni`, `pb`, `db sw`), the
Set Breakpoint dialog, Trace's **Stop at** and Dump as Payload - an export (`kernel32!VirtualAlloc`;
`.dll` and the module's case are optional) or a name you gave an address works too. A bare
export name works when only one module exports it. Exports load in the background after the
first break, so a module not read yet is not found. Use a hardware breakpoint for an API:
software breakpoints are refused in system DLLs.

### Graph View

Right-click the disassembly and choose **Graph From Here** (the selected row is taken as the
function's entry - there are no symbols to find it), or press **G** on the selected row (Space
stays Patch), or, on a CALL, **Graph Call Target**.
The graph opens in its own window: basic blocks top to bottom, conditional jumps green when
taken and red when not, unconditional flow blue, loops routed up the right-hand side. The
block holding CIP has a green border; CIP, breakpoint and traced instructions are coloured as
in the disassembly and follow each stop.

Click an instruction to show it in the disassembly; double-click a jump to centre on its
target, or a direct call to graph the callee (**Back** returns). Right-click an instruction for
Set/Delete Breakpoint, Run Until, Rename Address / Operand Target, Dump Address, Copy Address
and Graph From Here. After a **Trace...** through the function, the edges it took are drawn
thick and the rest thin, and blocks it never reached are greyed out - the path at a glance;
Clear Trace Highlight (disassembly menu) removes it. Ctrl+wheel or the zoom buttons
zoom, **Fit** shows the whole graph, dragging empty space pans, and **Save PNG...** writes the
whole graph, overlays included, to an image (scaled down past 8000 pixels a side). The code is read through
the debugger as needed; **Refresh** reads it again after it has been unpacked or patched.
Calls fall through; a path ends at a return, an indirect jump or unreadable memory, and the
graph stops at 500 blocks. Switch tables are followed - a case edge to each distinct target - in
the common compiler shapes (x86 `jmp [reg*4+table]`, x64 MSVC image-base RVA tables, x64
GCC/clang relative tables), when a bounds check before the jump gives the case count; without
one the jump stays indirect rather than guessing the table's size.

### Hit counts

**Break on hit** in the Set Breakpoint dialog (or `hits=N` on `bp`) passes over the first N-1
hits and breaks on the Nth, then on every hit after. The Breakpoints pane's **Skip** column
counts down the hits still to pass over. Works for hardware and software breakpoints.

### History

The **History** tab (beside Modules and Memory) lists every stop of the session, newest first:
address, nearest symbol or module, thread and what stopped it (breakpoint, step, trace).
Double-click a row to go to its address.

### Search Memory

**Search Memory...** (beside Dump Memory to File, or **Search This Region...** in the Memory Map)
finds a pattern in the target: hex bytes with `??` for any byte, ASCII, or UTF-16 text. With no
start address it searches all readable memory, skipping the monitor's own image. The matches
(at most 1000) open in a list with their protection and module; double-click dumps one in the
Memory Dump pane, and right-click offers Disassemble and Copy Address.

### Memory Map

The **Memory** tab (beside Modules) logs regions that appear, change protection, grow or are
freed after the first break - so it starts empty. **Memory Map...** on that tab lists everything
mapped now: base, size, protection and module, filterable by any of them. Regions that are
executable and writable, or executable outside any module (typical of unpacked or injected
code), are highlighted. Double-click to disassemble; right-click for Dump Address, Dump as
Payload and Copy Address. **Refresh** re-reads the map; free and reserved regions are not listed.

### Dump as Payload

Right-click a row in the Memory Dump pane, or a region in the Memory panel, and choose
**Dump as Payload...** to save a range as a CAPE payload of the analysis. The size defaults to
the rest of the region (16 MB at most). Unreadable pages are zero-filled. The payload goes
through YARA and config extraction like any monitor dump and is listed under Payloads once the
analysis is processed.

### Software breakpoints

A software breakpoint writes an `int3` over the instruction. Unlike the four hardware breakpoints
it is unlimited in number and stops every thread, not just the one it was set from. It is
execute only, and it is refused in system DLLs and monitor code, which the debugger itself runs:
use a hardware breakpoint for APIs. Memory, disassembly and dumps show the original byte, but
code that checksums or scans itself can see the `int3`, and code written over it removes it.
| d          | d 0x401000      | Dumps memory at the specified address.                        |
| clear      | clear           | Clears the Console Output panel.                              |
| quit       | quit            | Continues execution and closes the debugger.                  |
| disconnect | disconnect      | Disconnects the debugger from the target.                     |

---
