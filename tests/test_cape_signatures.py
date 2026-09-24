"""Tests for the CAPE view the shipped signatures read, and for the ordering contract.

Two signatures in signatures/cape_extracted.py read results["CAPE"], which CAPEsolo never
built - and the signature pass ran before payloads and configs existed anyway, so no key
rename alone could have fixed it. CAPEv2 gets the order for free (CAPE extraction is a
processing module; signatures run after all of them); here it has to be enforced.

    ./.venv/Scripts/python.exe -m pytest tests/test_cape_signatures.py
"""

import pytest

pytest.importorskip("wx")

from CAPEsolo.classes.json_report import SIGNATURE_PREREQS, CapeView, Signatures
from CAPEsolo.signatures.cape_extracted import CAPEExtractedConfig, CAPEExtractedContent


def _results(**overrides):
    results = {
        "target": {"name": "sample.exe", "category": "file"},
        "behavior": {"processes": []},
        "js_log": {"exists": False},
        "network": {"hosts": []},
        "payloads": [{
            "C:/analysis/CAPE/abc123": {
                "name": "abc123", "cape_type": "Injected PE Image", "sha256": "6" * 64,
                "process_name": "sample.exe", "pid": 100,
                "yara": [{"name": "QakbotPayload", "meta": {"cape_type": "Qakbot Payload"},
                          "strings": ["a"], "addresses": {}}],
            },
        }],
        "configs": [{"C:/analysis/CAPE/abc123": {"C2": ["http://evil.example.com"]}}],
        "detections": ["Qakbot"],
    }
    results.update(overrides)
    return results


# --- the view -----------------------------------------------------------------------------


def test_cape_view_flattens_payloads_and_exposes_path_as_a_field():
    view = CapeView(_results())
    assert len(view["payloads"]) == 1
    payload = view["payloads"][0]
    # CAPEsolo keys payloads by path; upstream signatures expect path as a field.
    assert payload["path"] == "C:/analysis/CAPE/abc123"
    assert payload["name"] == "abc123"


def test_cape_view_aliases_yara_to_cape_yara():
    payload = CapeView(_results())["payloads"][0]
    assert payload["cape_yara"] == payload["yara"]
    assert payload["cape_yara"][0]["name"] == "QakbotPayload"


def test_cape_view_carries_configs_unchanged():
    results = _results()
    assert CapeView(results)["configs"] == results["configs"]


def test_cape_view_survives_an_empty_report():
    assert CapeView({}) == {"payloads": [], "configs": []}


def test_cape_view_does_not_invent_a_cape_yara_key_when_there_are_no_hits():
    results = _results(payloads=[{"C:/x": {"name": "x"}}])
    assert "cape_yara" not in CapeView(results)["payloads"][0]


# --- the signatures now fire ----------------------------------------------------------------


def test_extracted_content_signature_matches_on_a_payload_with_yara():
    results = _results()
    results["CAPE"] = CapeView(results)
    signature = CAPEExtractedContent(results)
    assert signature.run() is True
    assert signature.data == [{"sample_exe": "QakbotPayload"}]


def test_extracted_content_signature_is_quiet_without_hits():
    results = _results(payloads=[{"C:/x": {"name": "x", "process_name": "sample.exe"}}])
    results["CAPE"] = CapeView(results)
    signature = CAPEExtractedContent(results)
    assert not signature.run()


def test_extracted_config_signature_names_the_family_from_detections():
    results = _results()
    results["CAPE"] = CapeView(results)
    signature = CAPEExtractedConfig(results)
    assert signature.run() is True
    assert signature.data == [{"extracted_config": "Qakbot"}]


def test_extracted_config_signature_falls_back_to_the_config_file_name():
    results = _results(detections=[])
    results["CAPE"] = CapeView(results)
    signature = CAPEExtractedConfig(results)
    assert signature.run() is True
    assert signature.data == [{"extracted_config": "abc123"}]


def test_extracted_config_signature_is_quiet_without_configs():
    results = _results(configs=[])
    results["CAPE"] = CapeView(results)
    assert not CAPEExtractedConfig(results).run()


# --- the ordering contract ------------------------------------------------------------------


def test_signatures_refuse_to_run_before_their_inputs_exist():
    # The bug this guards: the pass used to run before payloads/configs/CAPE were built, so
    # signatures reading them matched nothing and reported no error.
    with pytest.raises(RuntimeError) as excinfo:
        Signatures({"target": {}, "behavior": {}}, "C:/analysis")
    message = str(excinfo.value)
    for key in ("js_log", "network", "payloads", "configs", "CAPE"):
        assert key in message


def test_the_prereq_list_names_every_key_a_shipped_signature_reads():
    for key in ("target", "behavior", "network", "payloads", "configs", "CAPE"):
        assert key in SIGNATURE_PREREQS


# --- the GUI path: payloads and yara arrive from different tabs -----------------------------


def _gui_results():
    """What the GUI's shared dict looks like: payloads with no yara attached, and the hits
    published separately by the Yara tab (json_report.YaraHits shape, 'rule' not 'name')."""
    return {
        "behavior": {"processes": []},
        "js_log": {"exists": False},
        "payloads": [{"C:/analysis/CAPE/abc123": {"name": "abc123", "process_name": "sample.exe"}}],
        "configs": [{"C:/analysis/CAPE/abc123": {"C2": ["http://evil.example.com"]}}],
        "detections": ["Qakbot"],
        "yara": [{"file": "CAPE/abc123", "rule": "QakbotPayload", "capename": "Qakbot",
                  "meta": {"cape_type": "Qakbot Payload"}, "description": "",
                  "strings": ["a"], "addresses": {}}],
    }


def test_cape_view_pulls_hits_from_the_yara_section_when_the_payload_has_none():
    view = CapeView(_gui_results())
    payload = view["payloads"][0]
    assert payload["cape_yara"], "hits published as their own section must still reach the payload"
    # The section names the rule "rule"; the signatures read "name".
    assert payload["cape_yara"][0]["name"] == "QakbotPayload"


def test_cape_view_matches_a_relative_hit_to_an_absolute_payload_path():
    view = CapeView(_gui_results())
    assert view["payloads"][0]["path"] == "C:/analysis/CAPE/abc123"
    assert view["payloads"][0]["cape_yara"][0]["file"] == "CAPE/abc123"


def test_a_payloads_own_hits_win_over_the_section():
    results = _gui_results()
    results["payloads"] = [{"C:/analysis/CAPE/abc123": {
        "name": "abc123", "yara": [{"name": "OwnHit", "meta": {}}]}}]
    assert CapeView(results)["payloads"][0]["cape_yara"][0]["name"] == "OwnHit"


def test_the_content_signature_fires_on_gui_shaped_results():
    results = _gui_results()
    results["CAPE"] = CapeView(results)
    signature = CAPEExtractedContent(results)
    assert signature.run() is True
    assert signature.data == [{"sample_exe": "QakbotPayload"}]
