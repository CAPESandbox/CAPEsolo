"""Tests for the report's consolidated yara section.

report.json used to carry yara hits only as attachments on target and payload entries, so
two things were lost: the CAPE name a rule carries, and every hit on a file with no payload
entry - notably the blobs a config parser dumps, which are scanned after the payload list
has already been built.

    ./.venv/Scripts/python.exe -m pytest tests/test_yara_report.py
"""

import pytest

# json_report reaches the GUI layer for Options/Extract, so it needs wx importable (no
# display required). Skip rather than fail where it is absent.
pytest.importorskip("wx")

from CAPEsolo.classes.json_report import YaraHits


class FakeYara:
    """Stands in for ProcessYara: the only thing YaraHits reads is yara_results."""

    def __init__(self, results):
        self.yara_results = results


def _hit(name, cape_type="", strings=(), addresses=None, description=""):
    meta = {}
    if cape_type:
        meta["cape_type"] = cape_type
    if description:
        meta["description"] = description
    return {"name": name, "meta": meta, "strings": list(strings),
            "addresses": addresses or {}}


def test_hits_are_flattened_per_file():
    yara = FakeYara([
        {"sample.exe": [_hit("Generic", description="a generic rule")]},
        {"CAPE/abc": [_hit("QakbotPayload", cape_type="Qakbot Payload", strings=["a", "b"],
                           addresses={"$s1": 16})]},
    ])
    hits = YaraHits(yara)
    assert [h["file"] for h in hits] == ["sample.exe", "CAPE/abc"]
    assert hits[0]["description"] == "a generic rule"
    assert hits[1]["strings"] == ["a", "b"]
    assert hits[1]["addresses"] == {"$s1": 16}


def test_cape_name_is_recovered_from_the_rule_metadata():
    # This is the field that drives config extraction and never reached the report before.
    yara = FakeYara([{"CAPE/abc": [_hit("QakbotPayload", cape_type="Qakbot Payload")]}])
    assert YaraHits(yara)[0]["capename"] == "Qakbot"


def test_a_rule_without_a_cape_type_has_no_cape_name():
    yara = FakeYara([{"sample.exe": [_hit("Generic")]}])
    assert YaraHits(yara)[0]["capename"] == ""


def test_a_hit_dumped_by_a_parser_is_included():
    # Configs() writes parser blobs into CAPE/ and calls ScanPayload on them, appending to
    # yara_results after Payloads() has run. Those hits have no payload entry to attach to.
    yara = FakeYara([
        {"CAPE/original": [_hit("Loader", cape_type="Qakbot Loader")]},
        {"CAPE/dumped-by-parser": [_hit("Config", cape_type="Qakbot Config")]},
    ])
    files = [h["file"] for h in YaraHits(yara)]
    assert "CAPE/dumped-by-parser" in files


def test_rescanned_files_are_not_duplicated():
    # ScanPayload appends a fresh entry per round, so the same file+rule shows up repeatedly.
    yara = FakeYara([
        {"CAPE/abc": [_hit("Rule1"), _hit("Rule2")]},
        {"CAPE/abc": [_hit("Rule1"), _hit("Rule2")]},
        {"CAPE/abc": [_hit("Rule1")]},
    ])
    hits = YaraHits(yara)
    assert len(hits) == 2
    assert {h["rule"] for h in hits} == {"Rule1", "Rule2"}


def test_same_rule_on_different_files_is_kept():
    yara = FakeYara([{"a.bin": [_hit("Shared")]}, {"b.bin": [_hit("Shared")]}])
    assert len(YaraHits(yara)) == 2


def test_a_hit_without_meta_does_not_raise():
    # get_cape_name_from_yara_hit indexes hit["meta"] directly; this list is built from every
    # scan result, so a malformed hit must degrade rather than kill the whole report.
    yara = FakeYara([{"a.bin": [{"name": "NoMeta", "strings": [], "addresses": {}}]}])
    hits = YaraHits(yara)
    assert hits[0]["capename"] == ""
    assert hits[0]["meta"] == {}


def test_empty_and_missing_results_are_handled():
    assert YaraHits(FakeYara([])) == []
    assert YaraHits(FakeYara([{"a.bin": []}])) == []
    assert YaraHits(FakeYara([{"a.bin": None}])) == []


def test_output_is_json_serialisable():
    import json

    yara = FakeYara([{"CAPE/abc": [_hit("R", cape_type="Fam Payload", strings=["s"],
                                        addresses={"$a": 1})]}])
    json.dumps(YaraHits(yara))       # must not raise
