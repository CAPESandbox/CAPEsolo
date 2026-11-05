"""Tests for the graph view's block recovery and layout (capelib/cfg.py), on hand-assembled x64.

    ./.venv/Scripts/python.exe -m pytest tests/test_cfg.py
"""

from CAPEsolo.capelib.cfg import (
    EDGE_CASE,
    EDGE_FALL,
    EDGE_JUMP,
    EDGE_NEXT,
    EDGE_TAKEN,
    END_INDIRECT,
    END_MISSING,
    END_RET,
    BuildCfg,
    CallOperand,
    LayoutCfg,
    StaticSlotAddress,
)


def Reader(code: dict[int, bytes]):
    """readBytes over a few code fragments; anything else is unreadable."""
    def Read(addr, count):
        for base, data in code.items():
            if base <= addr < base + len(data):
                return data[addr - base:addr - base + count]
        return b""
    return Read


# 0x1000: xor eax,eax / test ecx,ecx / jz 0x1009 / inc eax / nop / ret at 0x1009
DIAMOND = {0x1000: bytes.fromhex("31C0" "85C9" "7403" "FFC0" "90" "C3")}


def test_conditional_jump_splits_into_three_blocks():
    cfg = BuildCfg(0x1000, Reader(DIAMOND), 64)
    assert sorted(cfg.blocks) == [0x1000, 0x1006, 0x1009]
    assert cfg.blocks[0x1000].edges == [(0x1009, EDGE_TAKEN), (0x1006, EDGE_FALL)]
    # inc/nop runs into the ret block only because the jz targets it.
    assert cfg.blocks[0x1006].edges == [(0x1009, EDGE_NEXT)]
    assert cfg.blocks[0x1009].end == END_RET
    assert not cfg.missing and not cfg.stubs


def test_a_loop_is_a_back_edge_and_layout_keeps_the_exit_below():
    # 0x2000: dec ecx / jnz 0x2000 / ret
    cfg = BuildCfg(0x2000, Reader({0x2000: bytes.fromhex("FFC9" "75FC" "C3")}), 64)
    assert cfg.blocks[0x2000].edges == [(0x2000, EDGE_TAKEN), (0x2004, EDGE_FALL)]
    layout = LayoutCfg(cfg, lambda addr: (100, 40))
    assert (0x2000, 0x2000, EDGE_TAKEN, True) in layout.edges
    assert layout.nodes[0x2004][1] > layout.nodes[0x2000][1]


def test_jump_and_indirect_jump():
    # 0x3000: jmp 0x3004 / nop nop / jmp rax
    cfg = BuildCfg(0x3000, Reader({0x3000: bytes.fromhex("EB02" "9090" "FFE0")}), 64)
    assert cfg.blocks[0x3000].edges == [(0x3004, EDGE_JUMP)]
    assert cfg.blocks[0x3004].end == END_INDIRECT
    assert 0x3002 not in cfg.blocks


def test_unreadable_code_is_reported_for_fetching():
    # 0x4000: nop / then the next page is not available
    cfg = BuildCfg(0x4000, Reader({0x4000: bytes.fromhex("90")}), 64)
    assert cfg.blocks[0x4000].end == END_MISSING
    assert cfg.missing == {0x4001}


def test_a_jump_into_unread_memory_becomes_a_stub():
    # 0x5000: jz 0x6000 (rel32) / ret
    cfg = BuildCfg(0x5000, Reader({0x5000: bytes.fromhex("0F84FA0F0000" "C3")}), 64)
    assert cfg.stubs == [0x6000]
    assert 0x6000 in cfg.missing


def test_layout_puts_the_entry_on_top_and_both_branches_below():
    cfg = BuildCfg(0x1000, Reader(DIAMOND), 64)
    layout = LayoutCfg(cfg, lambda addr: (120, 50))
    top = layout.nodes[0x1000][1]
    assert layout.nodes[0x1006][1] > top and layout.nodes[0x1009][1] > layout.nodes[0x1006][1]
    assert not any(back for *_, back in layout.edges)


def test_block_and_instruction_limits_truncate():
    cfg = BuildCfg(0x1000, Reader(DIAMOND), 64, maxBlocks=1)
    assert cfg.truncated and len(cfg.blocks) == 1


def test_layout_orders_a_layer_with_two_blocks():
    # 0x7000: test ecx,ecx / jz 0x700A / inc eax / jmp 0x700C / nop nop / dec eax / ret
    code = {0x7000: bytes.fromhex("85C9" "7406" "FFC0" "EB04" "9090" "FFC8" "C3")}
    cfg = BuildCfg(0x7000, Reader(code), 64)
    assert sorted(cfg.blocks) == [0x7000, 0x7004, 0x700A, 0x700C]
    layout = LayoutCfg(cfg, lambda addr: (100, 40))
    ys = {addr: rect[1] for addr, rect in layout.nodes.items()}
    # both arms share the second layer, side by side; the join sits below them
    assert ys[0x7004] == ys[0x700A] > ys[0x7000]
    assert layout.nodes[0x7004][0] != layout.nodes[0x700A][0]
    assert ys[0x700C] > ys[0x7004]


def test_a_cut_short_graph_keeps_the_entry():
    # the entry at 0x8002 jumps back to a lower address; at one block the entry must survive
    code = {0x8000: bytes.fromhex("90" "C3" "EBFC")}
    cfg = BuildCfg(0x8002, Reader(code), 64, maxBlocks=1)
    assert list(cfg.blocks) == [0x8002]


def test_call_operand_drops_size_keywords():
    assert CallOperand("CALL QWORD [RIP+0x3af9]") == "[RIP+0x3af9]"
    assert CallOperand("CALL 0x140001000") == "0x140001000"
    assert CallOperand("CALL RAX") is None
    assert CallOperand("JMP 0x1000") is None


def test_static_slot_address_reads_absolute_and_rip_relative_slots():
    assert StaticSlotAddress("[0x405000]", 0x401006) == 0x405000
    assert StaticSlotAddress("[RIP+0x3af9]", 0x140001006) == 0x140004AFF
    assert StaticSlotAddress("[RAX+0x8]", 0x1000) is None


def test_x86_absolute_switch_table_becomes_case_edges():
    # cmp eax,2 / ja 0x401010 / jmp dword [eax*4+0x401020]; default and three cases are rets
    code = bytes.fromhex("83F802" "770B" "FF248520104000" "90909090" "C3" "C3" "C3" "C3")
    table = bytes.fromhex("11104000" "12104000" "13104000")
    cfg = BuildCfg(0x401000, Reader({0x401000: code, 0x401020: table}), 32)
    assert cfg.blocks[0x401005].edges == [(0x401011, EDGE_CASE), (0x401012, EDGE_CASE), (0x401013, EDGE_CASE)]
    assert cfg.blocks[0x401000].edges == [(0x401010, EDGE_TAKEN), (0x401005, EDGE_FALL)]


def test_x64_msvc_rva_switch_table_becomes_case_edges():
    # cmp ecx,2 / ja default / lea rdx,[image base] / mov ecx,[rdx+rcx*4+0x2000] / add rcx,rdx / jmp rcx
    code = bytes.fromhex("83F902" "7713" "488D15F4EFFFFF" "8B8C8A00200000" "4801D1" "FFE1" "C3" "C3" "C3" "C3")
    table = bytes.fromhex("19100000" "1A100000" "1B100000")
    cfg = BuildCfg(0x140001000, Reader({0x140001000: code, 0x140002000: table}), 64)
    assert cfg.blocks[0x140001005].edges == [
        (0x140001019, EDGE_CASE), (0x14000101A, EDGE_CASE), (0x14000101B, EDGE_CASE)]


def test_switch_without_a_bounds_check_stays_indirect():
    # lea rdx,[...] / mov ecx,[rdx+rcx*4+0x2000] / add rcx,rdx / jmp rcx - no cmp/ja before it
    code = bytes.fromhex("488D15F9EFFFFF" "8B8C8A00200000" "4801D1" "FFE1")
    cfg = BuildCfg(0x140001000, Reader({0x140001000: code}), 64)
    assert cfg.blocks[0x140001000].end == END_INDIRECT


def test_switch_table_on_an_unread_page_is_fetched():
    code = bytes.fromhex("83F902" "7713" "488D15F4EFFFFF" "8B8C8A00200000" "4801D1" "FFE1" "C3" "C3" "C3" "C3")
    cfg = BuildCfg(0x140001000, Reader({0x140001000: code}), 64)
    assert 0x140002000 in cfg.missing
    assert cfg.blocks[0x140001005].end == END_INDIRECT
