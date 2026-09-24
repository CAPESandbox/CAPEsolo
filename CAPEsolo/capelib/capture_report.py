"""Build capture.json: what the analysis actually captured, and what it lost.

Every piece of evidence here already existed, and all of it was invisible: the result server
counts transfers but only logs one line at shutdown (resultserver.TransferStats), files.json
flags partial artifacts but LoadFilesJson used to drop the flags, and the analyzer's "file too
big, ignoring" warnings sat unread in analysis.log. A run that lost payloads therefore looked
exactly like a quiet one.

This assembles those sources into a single manifest written next to the results, so the GUI can
say something went missing, report.json can carry it off the machine, and the standalone viewer
can show it on the host.
"""

import json
import logging
import re
from datetime import datetime
from pathlib import Path

log = logging.getLogger(__name__)

CAPTURE_FILE = "capture.json"

# Directories the analyzer populates when the corresponding feature ran. Absence is not an
# error - most analyses produce only some of these - so they are reported as a presence map
# rather than as missing artifacts.
EXPECTED_DIRS = (
    "logs",
    "files",
    "CAPE",
    "procdump",
    "aux_",
    "debugger",
    "tlsdump",
    "shots",
)

# Analyzer-side skips, logged by lib/common/results.py before anything is sent. These never
# reach files.json, because the upload never happened.
SKIP_PATTERNS = (
    (
        "too_big",
        re.compile(r"File (?P<path>.+?) size is too big: (?P<size>\d+), ignoring"),
    ),
    (
        "trim_failed",
        re.compile(r"PE File (?P<path>.+?) size is too big: (?P<size>\d+), trim failed"),
    ),
    (
        "empty",
        re.compile(r"Not uploading (?P<path>.+?) to .+?: nothing to send"),
    ),
)


def _ReadFilesJson(analysisDir):
    """Read files.json as recorded, without touching the filesystem.

    Deliberately not LoadFilesJson: that one skips entries whose file is missing, which is
    exactly what this manifest needs to report.
    """
    path = Path(analysisDir) / "files.json"
    entries = []
    unreadable = 0
    if not path.is_file():
        return entries, unreadable

    try:
        lines = path.read_bytes().splitlines()
    except OSError as e:
        log.warning("capture: could not read files.json: %s", e)
        return entries, unreadable

    for line in lines:
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except ValueError:
            unreadable += 1

    return entries, unreadable


def _ScanAnalysisLog(analysisDir):
    """Pull the analyzer's own "this was not uploaded" warnings out of analysis.log."""
    path = Path(analysisDir) / "analysis.log"
    skipped = []
    if not path.is_file():
        return skipped

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        log.warning("capture: could not read analysis.log: %s", e)
        return skipped

    for line in text.splitlines():
        for reason, pattern in SKIP_PATTERNS:
            match = pattern.search(line)
            if match:
                entry = {"reason": reason, "path": match.group("path")}
                if "size" in match.groupdict():
                    entry["size"] = int(match.group("size"))
                if entry not in skipped:
                    skipped.append(entry)
                break

    return skipped


def _Limits(analysisDir):
    """The caps that were actually in force, so a short result set can be explained."""
    limits = {}
    # The analyzer reads analysis.conf from its own directory; a copy may also sit in the
    # analysis dir (signatures.py reads it from there).
    for candidate in (
        Path(analysisDir) / "analysis.conf",
        Path(__file__).resolve().parent.parent / "analysis.conf",
    ):
        if not candidate.is_file():
            continue
        try:
            for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines():
                key, _, value = line.partition("=")
                if key.strip() in ("upload_max_size", "do_upload_max_size", "enable_trim"):
                    limits[f"analyzer_{key.strip()}"] = value.strip()
        except OSError:
            pass
        break

    try:
        from .resultserver import read_resultserver_settings

        limits["resultserver"] = read_resultserver_settings()
    except Exception as e:  # noqa: BLE001 - the manifest must never be the thing that fails
        log.debug("capture: could not read resultserver settings: %s", e)

    return limits


def BuildCaptureReport(analysisDir, stats=None, bundle=""):
    """Assemble the capture manifest for *analysisDir*.

    @param stats: TransferStats.snapshot() taken before the result server shut down, if the
                  caller has it; the counters are reset on shutdown, so it cannot be read back.
    @param bundle: "report" or "full" when this manifest is being written into a bundle.
    """
    analysisDir = str(analysisDir)
    entries, unreadable = _ReadFilesJson(analysisDir)

    missing, incomplete, truncated = [], [], []
    present = 0
    for entry in entries:
        relPath = entry.get("path", "")
        if not relPath:
            continue
        if (Path(analysisDir) / relPath).is_file():
            present += 1
        else:
            missing.append(relPath)
        if entry.get("incomplete"):
            incomplete.append(relPath)
        if entry.get("truncated"):
            truncated.append(relPath)

    artifacts = {name: (Path(analysisDir) / name).is_dir() for name in EXPECTED_DIRS}
    artifacts["analysis.log"] = (Path(analysisDir) / "analysis.log").is_file()
    behaviorLogs = Path(analysisDir) / "logs"
    artifacts["behavior_logs"] = len(list(behaviorLogs.glob("*.bson"))) if behaviorLogs.is_dir() else 0

    skipped = _ScanAnalysisLog(analysisDir)

    report = {
        # Local time with its UTC offset: a bundle is read on a machine in another
        # timezone, where a naive stamp is ambiguous.
        "generated": datetime.now().astimezone().isoformat(timespec="seconds"),
        "transfers": stats or {},
        "files": {
            "listed": len(entries),
            "present": present,
            "unreadable_lines": unreadable,
            "missing": missing,
            "incomplete": incomplete,
            "truncated": truncated,
        },
        "artifacts": artifacts,
        "skipped": skipped,
        "limits": _Limits(analysisDir),
    }
    if bundle:
        report["bundle"] = bundle
    report["warnings"] = CaptureWarnings(report)
    return report


def CaptureWarnings(report):
    """One line per thing the analyst should know, or an empty list for a clean run."""
    warnings = []
    files = report.get("files") or {}
    transfers = report.get("transfers") or {}

    if transfers.get("incomplete"):
        warnings.append(f"{transfers['incomplete']} transfer(s) did not complete")
    if files.get("missing"):
        warnings.append(f"{len(files['missing'])} file(s) in files.json are not on disk")
    if files.get("incomplete"):
        warnings.append(f"{len(files['incomplete'])} artifact(s) stored only partially")
    if files.get("truncated"):
        warnings.append(f"{len(files['truncated'])} artifact(s) truncated at upload_max_size")
    if files.get("unreadable_lines"):
        warnings.append(f"{files['unreadable_lines']} unreadable line(s) in files.json")
    if report.get("skipped"):
        warnings.append(f"{len(report['skipped'])} file(s) never uploaded (too big or empty)")
    # Only when the presence map was actually built: "no data" is not the same claim as
    # "the log is missing", and saying the latter from the former is a false alarm.
    artifacts = report.get("artifacts")
    if artifacts is not None and not artifacts.get("analysis.log"):
        warnings.append("analysis.log is missing - the analyzer log never reached the result server")

    return warnings


def WriteCaptureReport(analysisDir, stats=None, bundle=""):
    """Build the manifest and write it into the analysis directory. Never raises."""
    report = {}
    try:
        report = BuildCaptureReport(analysisDir, stats=stats, bundle=bundle)
        path = Path(analysisDir) / CAPTURE_FILE
        with open(path, "w", encoding="utf-8", errors="replace") as f:
            json.dump(report, f, indent=4)
    except Exception as e:  # noqa: BLE001 - a missing manifest must not fail an analysis
        log.warning("Could not write %s: %s", CAPTURE_FILE, e)
    return report


def LoadCaptureReport(analysisDir):
    """Read back a previously written manifest, or {} when there is none."""
    path = Path(analysisDir) / CAPTURE_FILE
    if not path.is_file():
        return {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception as e:  # noqa: BLE001
        log.warning("Could not read %s: %s", CAPTURE_FILE, e)
        return {}


__all__ = [
    "CAPTURE_FILE",
    "BuildCaptureReport",
    "CaptureWarnings",
    "LoadCaptureReport",
    "WriteCaptureReport",
]
