"""Tests for the AI analysis in tools/report_viewer.py.

Every test drives a stub client: nothing here touches the network or spends money, and the
assertions are about the request the engine *builds* - model, adaptive thinking, effort, the
cache breakpoint on the case digest, the refusal fallback, the output schema - plus how it
handles what comes back.

    ./.venv/Scripts/python.exe -m pytest tests/test_report_ai.py
"""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

# report_viewer is a standalone script, not part of the package, and it imports tkinter at
# module scope - skip rather than fail on a box without tk (the Linux CI test job).
pytest.importorskip("tkinter")

VIEWER = Path(__file__).resolve().parents[1] / "tools" / "report_viewer.py"
_spec = importlib.util.spec_from_file_location("report_viewer_under_test", VIEWER)
rv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rv)


REPORT = {
    "target": {"name": "sample.exe", "md5": "0" * 32, "sha256": "2" * 64, "type": "PE32",
               "size": 2048, "pe": {"imphash": "abcd", "sections": [{"name": ".text"}],
                                    "imports": {"kernel32.dll": {"dll": "kernel32.dll",
                                                                 "imports": [{"name": "CreateFileW"}]}}},
               "yara": [{"name": "Rule", "meta": {"description": "d"}}]},
    "detections": ["EvilFamily"],
    "signatures": [{"name": "injection_runpe", "severity": 3, "description": "hollowing",
                    "categories": ["injection"], "data": [{"injection": "a -> b"}],
                    "new_data": [{"process": {"process_name": "sample.exe"},
                                  "signs": [{"type": "api", "value": "WriteProcessMemory"}]}]}],
    "behavior": {
        "processes": [{"process_id": 100, "process_name": "sample.exe", "parent_id": 4,
                       "environ": {"CommandLine": "sample.exe"},
                       "calls": [{"api": "DnsQuery_W", "category": "network", "status": True,
                                  "arguments": [{"name": "Name", "value": "evil.example.com"}]}] * 500}],
        "processtree": [{"name": "sample.exe", "pid": 100, "children": []}],
        "summary": {"mutexes": ["m1"], "resolved_apis": [f"api{i}" for i in range(500)]},
        "anomaly": [{"name": "sample.exe", "pid": 100, "message": "hook removed"}],
        "encryptedbuffers": [{"process_name": "sample.exe", "api_call": "CryptEncrypt",
                              "buffer": "POST /gate.php"}],
        "enhanced": [{"event": "create", "object": "file", "data": {"file": "drop.exe"}}],
    },
    "js_log": {"exists": True, "total_lines": 3, "parsed_lines": 3, "malformed_lines": 0,
               "events": [{"event": "console", "message": "hi"}], "buffers": []},
    "network": {"hosts": [{"ip": "1.2.3.4"}], "domains": [{"domain": "evil.example.com"}],
                "dns": [{"request": "evil.example.com"}],
                "http": [{"method": "POST", "host": "evil.example.com", "uri": "/gate.php",
                          "data": "POST /gate.php", "body": "x" * 5000}],
                "tcp": [{"dst": "1.2.3.4", "dport": 80}],
                "http_ex": [{"host": "evil.example.com", "method": "GET", "uri": "/x",
                             "request": "GET /x", "response": "200 OK"}]},
    "payloads": [{"C:/analysis/CAPE/abc": {"name": "abc", "cape_type": "Injected PE",
                                           "sha256": "6" * 64, "truncated": True,
                                           "yara": [{"name": "PayloadRule"}],
                                           "strings": ["s1", "s2"]}}],
    "configs": [{"C:/analysis/CAPE/abc": {"C2": ["http://evil.example.com"], "Campaign": "one"}}],
    "capture": {"warnings": ["1 artifact(s) truncated at upload_max_size"],
                "transfers": {"complete": 5, "incomplete": 1}},
}

FINDINGS = {"verdict": "Process hollowing into notepad.", "confidence": "high",
            "findings": [{"title": "RunPE", "severity": "critical",
                          "evidence": ["WriteProcessMemory"], "rationale": "classic hollowing"}],
            "iocs": ["evil.example.com"], "gaps": ["no memory dump"]}


def _response(text, stop_reason="end_turn", stop_details=None):
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text=text)],
        stop_reason=stop_reason,
        stop_details=stop_details,
        usage=SimpleNamespace(input_tokens=1000, output_tokens=200,
                              cache_read_input_tokens=900, cache_creation_input_tokens=100),
    )


class StubMessages:
    """Records every request and replays queued responses."""

    def __init__(self, stub):
        self.stub = stub

    def create(self, **kwargs):
        self.stub.requests.append(kwargs)
        if self.stub.raises:
            raise self.stub.raises
        return self.stub.responses.pop(0) if self.stub.responses else _response(json.dumps(FINDINGS))

    def count_tokens(self, **kwargs):
        self.stub.counted.append(kwargs)
        return SimpleNamespace(input_tokens=5000)

    def tool_runner(self, **kwargs):
        self.stub.requests.append(kwargs)
        response = self.stub.responses.pop(0) if self.stub.responses else _response("an answer")
        return SimpleNamespace(until_done=lambda: response)


class StubClient:
    def __init__(self, responses=None, raises=None):
        self.requests = []
        self.counted = []
        self.responses = list(responses or [])
        self.raises = raises
        self.messages = StubMessages(self)
        self.beta = SimpleNamespace(messages=self.messages)


def engine(responses=None, raises=None, config=None):
    return rv.AnalysisEngine(REPORT, config or rv.AIConfig(api_key="k"),
                             client=StubClient(responses, raises))


# --- digest -------------------------------------------------------------------------------


def test_case_digest_is_small_and_json_serialisable():
    digest = rv.case_digest(REPORT)
    text = json.dumps(digest)          # must not raise
    # The digest is the cached prefix of every request; if it grows with the report it stops
    # being a digest. 500 calls and 500 resolved APIs must not show up here.
    assert len(text) < 8000, len(text)
    assert digest["target"]["name"] == "sample.exe"
    assert digest["capture"]["warnings"]


def test_every_agent_has_a_slice_and_declares_what_it_dropped():
    for tab in rv.AGENT_KEYS:
        data = rv.tab_slice(REPORT, tab)
        assert data, tab
        json.dumps(data)               # must not raise
    behavior = rv.tab_slice(REPORT, "Behavior")
    assert "showing 60 of 500" in behavior["omitted"]["summary.resolved_apis"]
    processes = rv.tab_slice(REPORT, "Processes")
    assert "showing 150 of 500" in processes["processes"][0]["omitted"]["calls"]


def test_slice_for_an_unknown_tab_is_empty_not_an_error():
    assert rv.tab_slice(REPORT, "Raw JSON") == {}


# --- request shape ------------------------------------------------------------------------


def test_analyze_builds_the_documented_request():
    eng = engine()
    eng.analyze("Signatures")
    request = eng._client.requests[0]
    assert request["model"] == "claude-opus-5"
    assert request["thinking"] == {"type": "adaptive"}
    assert request["output_config"]["effort"] == "high"
    assert request["output_config"]["format"] == {"type": "json_schema",
                                                  "schema": rv.FINDINGS_SCHEMA}
    assert request["max_tokens"] == rv.ANALYSIS_MAX_TOKENS
    assert request["system"] == rv.SYSTEM_PROMPT


def test_refusal_fallback_is_requested():
    # Malware evidence can trip the cyber classifier; without this a decline is a dead end.
    eng = engine()
    eng.analyze("Network")
    request = eng._client.requests[0]
    assert rv.FALLBACK_BETA in request["betas"]
    assert request["fallbacks"] == "default"


def test_case_digest_carries_the_cache_breakpoint_and_comes_first():
    eng = engine()
    eng.analyze("Payloads")
    blocks = eng._client.requests[0]["messages"][0]["content"]
    assert blocks[0]["text"].startswith("CASE DIGEST")
    assert blocks[0]["cache_control"] == {"type": "ephemeral"}
    # Evidence must come after the breakpoint, or the prefix differs per agent and nothing caches.
    assert "cache_control" not in blocks[1]
    assert blocks[1]["text"].startswith("EVIDENCE - Payloads")


def test_the_cached_prefix_is_identical_across_agents():
    eng = engine(responses=[_response(json.dumps(FINDINGS)) for _ in range(2)])
    eng.analyze("Signatures")
    eng.analyze("Network")
    first, second = (r["messages"][0]["content"][0]["text"] for r in eng._client.requests)
    assert first == second
    assert eng._client.requests[0]["system"] == eng._client.requests[1]["system"]


# --- responses ----------------------------------------------------------------------------


def test_findings_are_parsed_and_stored():
    eng = engine()
    result = eng.analyze("Signatures")
    assert result["findings"][0]["title"] == "RunPE"
    assert eng.results["Signatures"] is result


def test_refusal_is_a_result_not_an_exception():
    refused = _response("", stop_reason="refusal",
                        stop_details=SimpleNamespace(category="cyber", explanation="declined"))
    eng = engine(responses=[refused])
    result = eng.analyze("Behavior")
    assert result == {"refusal": "cyber", "explanation": "declined"}


def test_unparsable_json_is_reported_not_raised():
    eng = engine(responses=[_response("not json at all")])
    assert "error" in eng.analyze("Configs")


def test_usage_and_spend_are_accumulated_from_the_responses():
    eng = engine(responses=[_response(json.dumps(FINDINGS)) for _ in range(2)])
    eng.analyze("Signatures")
    eng.analyze("Static")
    assert eng.usage == {"input": 2000, "output": 400, "cache_read": 1800,
                         "cache_write": 200, "calls": 2}
    # 2000 in @ $5/M + 1800 cached @ 10% + 400 out @ $25/M
    assert eng.spend() == pytest.approx(2000 / 1e6 * 5 + 1800 / 1e6 * 0.5 + 400 / 1e6 * 25)


# --- orchestration ------------------------------------------------------------------------


def test_analyze_all_runs_every_agent_then_synthesises():
    eng = engine(responses=[_response(json.dumps(FINDINGS))
                            for _ in range(len(rv.AGENT_KEYS) + 1)])
    seen = []
    result = eng.analyze_all(progress=lambda step, total, tab: seen.append(tab))
    assert set(eng.results) == set(rv.AGENT_KEYS)
    assert len(eng._client.requests) == len(rv.AGENT_KEYS) + 1
    assert seen[-1] == "Overview"
    assert result is eng.synthesis


def test_one_failing_agent_does_not_sink_the_run():
    class Flaky(StubClient):
        def __init__(self):
            super().__init__()
            self.calls = 0

        class _M(StubMessages):
            def create(self, **kwargs):
                self.stub.calls += 1
                if self.stub.calls == 2:
                    raise RuntimeError("boom")
                return _response(json.dumps(FINDINGS))

        def build(self):
            self.messages = Flaky._M(self)
            self.beta = SimpleNamespace(messages=self.messages)
            return self

    eng = rv.AnalysisEngine(REPORT, rv.AIConfig(api_key="k"), client=Flaky().build())
    eng.analyze_all()
    failed = [tab for tab, result in eng.results.items() if "error" in result]
    assert len(failed) == 1 and "boom" in eng.results[failed[0]]["error"]
    assert len(eng.results) == len(rv.AGENT_KEYS)


def test_cancelling_stops_before_the_next_agent():
    eng = engine(responses=[_response(json.dumps(FINDINGS)) for _ in range(12)])
    calls = {"n": 0}

    def cancelled():
        calls["n"] += 1
        return calls["n"] > 2       # let one agent through, then stop

    assert eng.analyze_all(cancelled=cancelled) is None
    assert eng.synthesis is None
    assert len(eng.results) < len(rv.AGENT_KEYS)


def test_synthesis_reads_the_findings_not_the_report():
    eng = engine(responses=[_response(json.dumps(FINDINGS)), _response(json.dumps(
        {"verdict": "v", "family": "EvilFamily", "confidence": "high",
         "certain": ["a"], "inferred": ["b"], "next_steps": ["c"]}))])
    eng.analyze("Signatures")
    synthesis = eng.synthesize()
    assert synthesis["family"] == "EvilFamily"
    body = eng._client.requests[1]["messages"][0]["content"][1]["text"]
    assert body.startswith("SPECIALIST FINDINGS")
    assert "RunPE" in body


def test_synthesis_without_findings_is_refused_locally():
    with pytest.raises(ValueError):
        engine().synthesize()


# --- ask ----------------------------------------------------------------------------------


def test_ask_uses_the_tool_runner_and_returns_history():
    eng = engine(responses=[_response("because it hollows notepad")])
    answer, history = eng.ask("why is this a dropper?")
    assert answer == "because it hollows notepad"
    assert history[-1] == {"role": "assistant", "content": answer}
    request = eng._client.requests[0]
    assert request["tools"], "the report_query tool must be offered"
    assert request["messages"][0]["content"][0]["cache_control"] == {"type": "ephemeral"}


def test_ask_surfaces_a_refusal_as_text():
    refused = _response("", stop_reason="refusal",
                        stop_details=SimpleNamespace(category="cyber", explanation="no"))
    answer, _history = engine(responses=[refused]).ask("q")
    assert "declined: cyber" in answer


# --- cost ---------------------------------------------------------------------------------


def test_estimate_counts_every_agent_and_prices_it():
    eng = engine()
    estimate = eng.estimate()
    assert estimate["agents"] == len(rv.AGENT_KEYS)
    assert len(eng._client.counted) == len(rv.AGENT_KEYS)
    assert estimate["input_tokens"] == 5000 * len(rv.AGENT_KEYS)
    assert estimate["dollars"] > 0


# --- config and availability ---------------------------------------------------------------


def test_config_prefers_explicit_over_environment(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "from-env")
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-sonnet-5")
    assert rv.AIConfig().api_key == "from-env"
    assert rv.AIConfig().model == "claude-sonnet-5"
    assert rv.AIConfig(api_key="explicit").api_key == "explicit"
    monkeypatch.delenv("ANTHROPIC_MODEL")
    assert rv.AIConfig().model == rv.DEFAULT_MODEL == "claude-opus-5"


def test_missing_sdk_explains_itself(monkeypatch):
    monkeypatch.setattr(rv, "load_anthropic", lambda: None)
    eng = rv.AnalysisEngine(REPORT, rv.AIConfig(api_key="k"))
    with pytest.raises(rv.AIUnavailable) as excinfo:
        eng.client()
    assert "pip install anthropic" in str(excinfo.value)


def test_missing_key_explains_itself(monkeypatch):
    monkeypatch.setattr(rv, "load_anthropic", lambda: SimpleNamespace(Anthropic=lambda **kw: None))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    eng = rv.AnalysisEngine(REPORT, rv.AIConfig())
    with pytest.raises(rv.AIUnavailable) as excinfo:
        eng.client()
    assert "ANTHROPIC_API_KEY" in str(excinfo.value)
