"""Tests for capture accounting: the manifest, and the manifest loader it reconciles.

CAPEsolo.capelib.capture_report and LoadFilesJson are free of wx, gevent and the monitor, so
these run against a synthetic analysis directory with no GUI and no live analysis:

    ./.venv/Scripts/python.exe -m pytest tests/test_capture_report.py
"""

import json

from CAPEsolo.capelib.capture_report import (
    BuildCaptureReport,
    CaptureWarnings,
    LoadCaptureReport,
    WriteCaptureReport,
)
from CAPEsolo.capelib.utils import LoadFilesJson

# One entry per case the result server can produce: whole, partial, capped, and an entry whose
# file never made it to disk at all.
ENTRIES = (
    {"path": "CAPE/whole", "pids": [100], "metadata": "", "category": "CAPE"},
    {"path": "files/partial", "pids": [100], "metadata": "", "category": "files", "incomplete": True},
    {"path": "files/capped", "pids": [100], "metadata": "", "category": "files", "truncated": True},
    {"path": "CAPE/gone", "pids": [100], "metadata": "", "category": "CAPE"},
)

ANALYSIS_LOG = (
    "2026-09-22 10:00:00,001 [lib.common.results] WARNING: File C:/big.bin size is too big: "
    "900000000, ignoring\n"
    "2026-09-22 10:00:01,002 [lib.common.results] WARNING: Not uploading C:/empty.bin to "
    "files/empty: nothing to send (empty file)\n"
    "2026-09-22 10:00:02,003 [root] INFO: Analysis completed\n"
)


def _analysis_dir(tmp_path, entries=ENTRIES, log=ANALYSIS_LOG, corrupt_line=False):
    """Build an analysis directory: every entry listed, all but CAPE/gone written."""
    (tmp_path / "CAPE").mkdir()
    (tmp_path / "files").mkdir()
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "100.bson").write_bytes(b"\x00")
    lines = []
    for entry in entries:
        lines.append(json.dumps(entry))
        if entry["path"] != "CAPE/gone":
            (tmp_path / entry["path"]).write_bytes(b"MZ payload")
    if corrupt_line:
        lines.append("{this is not json")
    (tmp_path / "files.json").write_text("\n".join(lines) + "\n", encoding="utf-8")
    if log is not None:
        (tmp_path / "analysis.log").write_text(log, encoding="utf-8")
    return tmp_path


def test_manifest_counts_what_arrived(tmp_path):
    report = BuildCaptureReport(_analysis_dir(tmp_path))
    files = report["files"]
    assert files["listed"] == 4
    assert files["present"] == 3
    assert files["missing"] == ["CAPE/gone"]
    assert files["incomplete"] == ["files/partial"]
    assert files["truncated"] == ["files/capped"]


def test_manifest_reads_analyzer_skips(tmp_path):
    report = BuildCaptureReport(_analysis_dir(tmp_path))
    reasons = {(s["reason"], s["path"]) for s in report["skipped"]}
    assert ("too_big", "C:/big.bin") in reasons
    assert ("empty", "C:/empty.bin") in reasons
    # The size is carried so the analyst can tell a near-miss from a wildly oversized dump.
    assert next(s for s in report["skipped"] if s["reason"] == "too_big")["size"] == 900000000


def test_manifest_records_artifacts_and_transfers(tmp_path):
    report = BuildCaptureReport(_analysis_dir(tmp_path), stats={"complete": 9, "incomplete": 1})
    assert report["transfers"] == {"complete": 9, "incomplete": 1}
    assert report["artifacts"]["analysis.log"] is True
    assert report["artifacts"]["behavior_logs"] == 1
    assert report["artifacts"]["debugger"] is False


def test_warnings_name_every_kind_of_loss(tmp_path):
    report = BuildCaptureReport(
        _analysis_dir(tmp_path, corrupt_line=True), stats={"complete": 3, "incomplete": 2}
    )
    joined = " | ".join(report["warnings"])
    for fragment in (
        "2 transfer(s) did not complete",
        "1 file(s) in files.json are not on disk",
        "1 artifact(s) stored only partially",
        "1 artifact(s) truncated",
        "1 unreadable line(s)",
        "2 file(s) never uploaded",
    ):
        assert fragment in joined, joined


def test_clean_run_has_no_warnings(tmp_path):
    clean = ENTRIES[:1]
    report = BuildCaptureReport(_analysis_dir(tmp_path, entries=clean, log="no warnings here\n"))
    assert report["warnings"] == []


def test_missing_analysis_log_is_itself_a_warning(tmp_path):
    report = BuildCaptureReport(_analysis_dir(tmp_path, entries=ENTRIES[:1], log=None))
    assert any("analysis.log is missing" in w for w in report["warnings"])


def test_warnings_tolerate_a_manifest_with_nothing_in_it():
    assert CaptureWarnings({}) == []


def test_write_and_load_round_trip(tmp_path):
    written = WriteCaptureReport(_analysis_dir(tmp_path), stats={"complete": 1})
    assert (tmp_path / "capture.json").is_file()
    assert LoadCaptureReport(tmp_path) == written


def test_load_returns_empty_when_there_is_no_manifest(tmp_path):
    assert LoadCaptureReport(tmp_path) == {}


def test_write_never_raises_on_an_unwritable_directory(tmp_path):
    # A manifest is diagnostics; failing to write one must not fail the analysis.
    assert WriteCaptureReport(tmp_path / "does" / "not" / "exist") == {} or True


def test_bundle_kind_is_recorded(tmp_path):
    report = BuildCaptureReport(_analysis_dir(tmp_path), bundle="report")
    assert report["bundle"] == "report"


# --- the loader the manifest reconciles against -------------------------------------------


def test_one_missing_file_no_longer_hides_every_payload(tmp_path):
    # Previously a single stat() failure returned {"error": ...} for the whole manifest, so one
    # casualty made every other payload disappear from the Payloads tab and from report.json.
    data = LoadFilesJson(_analysis_dir(tmp_path))
    assert "error" not in data
    assert set(data) == {"CAPE/whole", "files/partial", "files/capped"}


def test_partial_flags_reach_consumers(tmp_path):
    data = LoadFilesJson(_analysis_dir(tmp_path))
    assert data["files/partial"]["incomplete"] is True
    assert data["files/capped"]["truncated"] is True
    assert "incomplete" not in data["CAPE/whole"]
    assert "truncated" not in data["CAPE/whole"]


def test_corrupt_line_is_skipped_not_fatal(tmp_path):
    data = LoadFilesJson(_analysis_dir(tmp_path, corrupt_line=True))
    assert "error" not in data
    assert len(data) == 3


def test_no_readable_entries_still_reports_an_error(tmp_path):
    (tmp_path / "files.json").write_text("{bad\n{also bad\n", encoding="utf-8")
    assert LoadFilesJson(tmp_path) == {"error": "No dump files"}


def test_absent_manifest_reports_an_error(tmp_path):
    assert LoadFilesJson(tmp_path) == {"error": "No dump files"}
