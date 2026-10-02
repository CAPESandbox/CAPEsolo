"""Tests for the wx-free reply parsers in capelib/debug_session.py.

debug_session imports the analyzer's pipe module, which imports `lib.*` as a top-level package -
importable only with the CAPEsolo folder on sys.path, as it is when the GUI or MCP server runs.

    ./.venv/Scripts/python.exe -m pytest tests/test_debug_session_parsers.py
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "CAPEsolo"))
debug_session = pytest.importorskip("CAPEsolo.capelib.debug_session")


def test_parse_memory_search_reads_matches_and_the_truncation_flag():
    reply = debug_session.ParseMemorySearch("3:SEARCH|2|1|401000,7ffe0000\n")
    assert reply == {"ok": True, "count": 2, "truncated": True, "addresses": [0x401000, 0x7FFE0000]}


def test_parse_memory_search_reports_no_matches_and_failures():
    assert debug_session.ParseMemorySearch("3:SEARCH|0|0|")["addresses"] == []
    reply = debug_session.ParseMemorySearch("3:SEARCH|Failed with invalid search range.")
    assert reply == {"ok": False, "error": "Failed with invalid search range."}


def test_parse_breakpoints_reads_the_skip_count_and_defaults_older_forms():
    bps = debug_session.ParseBreakpoints("0,0000000140001000,x,1,4|1,00401000,w,4|2,00402000")
    assert [bp["skip"] for bp in bps] == ["4", "0", "0"]
    assert bps[2]["type"] == "x" and bps[2]["size"] == "1"


def test_parse_xrefs_reads_sites_and_kinds():
    reply = debug_session.ParseXrefs("4:XREFS|2|0|14000101d:call,140001099:jcc\n")
    assert reply == {"ok": True, "count": 2, "truncated": False,
                     "refs": [{"address": 0x14000101D, "kind": "call"}, {"address": 0x140001099, "kind": "jcc"}]}


def test_parse_xrefs_reports_none_and_failures():
    assert debug_session.ParseXrefs("4:XREFS|0|0|")["refs"] == []
    assert debug_session.ParseXrefs("4:XREFS|Failed: 0x10 is not in an allocation.")["ok"] is False
