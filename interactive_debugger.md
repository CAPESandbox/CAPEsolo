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
| Patch         | Spacebar | (None)    | Opens the patching dialog for the selected instruction.                       |
| Go Back       | Esc      | (None)    | Navigates to the previously viewed memory dump.                               |
| Stop Debugger | Ctrl+Q   | (None)    | Sends a Continue command and closes the debugger window.                      |

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
