"""Tests for the debugger command box's parsing and validation.

CAPEsolo.capelib.console_commands is deliberately free of wx imports so these run without a
GUI:

    ./.venv/Scripts/python.exe -m pytest tests/test_console_commands.py
"""

from CAPEsolo.capelib.console_commands import (
    BY_NAME,
    COMMANDS,
    LOCAL_COMMANDS,
    HelpText,
    ParseCommand,
)


def Ok(text):
    code, payload, error = ParseCommand(text)
    assert error is None, error
    return code, payload


def Err(text):
    code, payload, error = ParseCommand(text)
    assert error is not None, f"expected a rejection for {text!r}, got {code}:{payload!r}"
    return error


def test_blank_input_is_not_an_error():
    assert ParseCommand("") == (None, None, None)
    assert ParseCommand("   ") == (None, None, None)


def test_local_actions_are_not_sent_anywhere():
    for name in LOCAL_COMMANDS:
        code, payload, error = ParseCommand(name)
        assert code is None and payload == name and error is None


def test_arguments_actually_reach_the_payload():
    """The regression this module exists for: the box parsed arguments and sent none."""
    assert Ok("md 0x401000") == ("MD", "0x401000")
    assert Ok("ru 0x401000") == ("RU", "0x401000")
    assert Ok("ni 401000") == ("NI", "0x401000")


def test_addresses_may_omit_the_0x():
    assert Ok("md 401000") == ("MD", "0x401000")
    assert Ok("md 0X401000") == ("MD", "0x401000")


def test_memory_dump_size_is_optional():
    assert Ok("md 401000 100") == ("MD", "0x401000|0x100")


def test_memory_dump_rejects_a_bad_size():
    assert "not a valid size" in Err("md 401000 zz")
    assert "not a valid size" in Err("md 401000 0")


def test_no_argument_commands_reject_arguments():
    """Silently dropping them is how `ct 401000` looks like it did something."""
    for text in ("si 1", "ct 401000", "rg x", "lb 1"):
        assert "takes no arguments" in Err(text)


def test_no_argument_commands_send_an_empty_payload():
    assert Ok("si") == ("SI", "")
    assert Ok("ct") == ("CT", "")
    assert Ok("lm") == ("LM", "")


def test_aliases_resolve_to_the_same_command():
    assert Ok("step")[0] == Ok("si")[0]
    assert Ok("go")[0] == Ok("ct")[0]
    assert Ok("regs")[0] == Ok("rg")[0]
    assert Ok("dump 401000")[0] == Ok("md 401000")[0]
    assert Ok("break 401000")[0] == Ok("bp 401000")[0]


def test_command_names_are_case_insensitive():
    assert Ok("MD 401000") == ("MD", "0x401000")
    assert Ok("Step") == ("SI", "")


def test_unknown_command_is_rejected_locally():
    """Rather than uppercased and sent, to come back as the target's "Unknown command"."""
    error = Err("frobnicate 1")
    assert "Unknown command" in error and "help" in error


def test_breakpoint_uses_the_same_wire_form_as_the_breakpoint_dialog():
    """PromptBreakpoint sends an uppercase 0X; capemon takes either, but one form is enough."""
    assert Ok("bp 401000")[1].startswith("next|0X")


def test_breakpoint_defaults_to_a_one_byte_execute_breakpoint():
    assert Ok("bp 401000") == ("BP", "next|0X401000|x|1")


def test_breakpoint_accepts_type_size_and_slot():
    assert Ok("bp 401000 w 4 2") == ("BP", "2|0X401000|w|4")
    assert Ok("bp 401000 rw 8 next") == ("BP", "next|0X401000|rw|8")


def test_breakpoint_rejects_a_misaligned_watch():
    """x86 silently watches the wrong bytes rather than failing, so it has to be caught here."""
    error = Err("bp 401002 w 4")
    assert "aligned" in error and "0x401000" in error


def test_breakpoint_rejects_a_size_on_an_execute_breakpoint():
    assert "always one byte" in Err("bp 401000 x 4")


def test_breakpoint_rejects_bad_type_size_and_slot():
    assert "breakpoint type" in Err("bp 401000 q")
    assert "watch size" in Err("bp 401000 w 3")
    assert "slot" in Err("bp 401000 w 4 9")


def test_software_breakpoint_short_and_full_forms():
    assert Ok("bp 401000 sw") == ("BP", "sw|0X401000|x|1")
    assert Ok("bp 401000 x 1 sw") == ("BP", "sw|0X401000|x|1")


def test_software_breakpoint_rejects_a_watch():
    assert "execute only" in Err("bp 401000 w 4 sw")


def test_delete_software_breakpoint_by_address():
    assert Ok("db sw 401000") == ("DB", "sw|0X401000")
    assert "hex address" in Err("db sw xyz")


def test_delete_breakpoint_takes_a_debug_register():
    assert Ok("db 2") == ("DB", "2")
    assert "0 to 3" in Err("db 4")
    assert "0 to 3" in Err("db 0x2")
    assert "0 to 3" in Err("db")


def test_set_register_builds_the_pipe_form():
    assert Ok("sr rax 401000") == ("SR", "RAX|0x401000")
    assert Ok("sr eip 401000") == ("SR", "EIP|0x401000")


def test_set_register_rejects_a_bad_register_or_value():
    assert "not a register" in Err("sr notaregister 1")
    assert "not a hex value" in Err("sr rax zzz")
    assert "Expected a register and a value" in Err("sr rax")


def test_flag_directive_matches_what_the_monitor_compares():
    """capemon does a string compare against the whole directive."""
    assert Ok("fl flip zero") == ("FL", "FlipZeroFlag")
    assert Ok("fl set carry") == ("FL", "SetCarryFlag")
    assert Ok("fl clear sign") == ("FL", "ClearSignFlag")


def test_flag_directive_rejects_nonsense():
    assert "not an action" in Err("fl toggle zero")
    assert "not a flag" in Err("fl set overflow")
    assert "Expected an action and a flag" in Err("fl set")


def test_thread_inspect_takes_a_decimal_tid():
    assert Ok("ti 4321") == ("TI", "4321")
    assert "decimal thread id" in Err("ti 0x10e1")


def test_patch_bytes_needs_whole_bytes():
    assert Ok("pb 401000 90909090") == ("PB", "0x401000|90909090")
    assert Ok("pb 401000 0x9090") == ("PB", "0x401000|9090")
    assert "whole number of hex bytes" in Err("pb 401000 909")
    assert "whole number of hex bytes" in Err("pb 401000 zz")


def test_page_fetch_commands_are_not_reachable_by_hand():
    """IN, PM and EX drive the view's own fetching; issuing one by hand desynchronises it."""
    for name in ("in", "pm", "ex"):
        assert name not in BY_NAME
        assert "Unknown command" in Err(f"{name} 401000")


def test_every_command_is_reachable_by_its_own_name_and_has_help():
    for command in COMMANDS:
        assert BY_NAME[command.names[0]] is command
        assert command.usage and command.summary


def test_no_alias_is_claimed_twice():
    seen = [name for command in COMMANDS for name in command.names]
    assert len(seen) == len(set(seen))
    assert not set(seen) & set(LOCAL_COMMANDS)


def test_help_lists_every_command():
    text = HelpText()
    for command in COMMANDS:
        assert command.names[0] in text


NAMES = {"kernel32!VirtualAlloc": 0x7FFEB2D41000, "decrypt": 0x401200}


def test_address_arguments_accept_resolved_names():
    assert ParseCommand("bp kernel32!VirtualAlloc", NAMES.get) == ("BP", "next|0X7FFEB2D41000|x|1", None)
    assert ParseCommand("ru decrypt", NAMES.get) == ("RU", "0x401200", None)
    assert ParseCommand("md decrypt 40", NAMES.get) == ("MD", "0x401200|0x40", None)


def test_hex_wins_over_a_name_that_reads_as_hex():
    assert ParseCommand("ru add", {"add": 0x401200}.get) == ("RU", "0xadd", None)


def test_unknown_name_is_rejected():
    code, payload, error = ParseCommand("bp kernel32!Nope", NAMES.get)
    assert code is None and "known name" in error


def test_names_are_not_resolved_without_a_resolver():
    assert "known name" in Err("bp kernel32!VirtualAlloc")
