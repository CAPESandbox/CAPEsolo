import logging
import os
from json import dump
from pathlib import Path

from CAPEsolo.capelib.behavior import BehaviorAnalysis
from CAPEsolo.capelib.cape_utils import get_cape_name_from_yara_hit, metadata_processing
from CAPEsolo.capelib.capture_report import (
    BuildCaptureReport,
    CaptureWarnings,
    LoadCaptureReport,
)
from CAPEsolo.capelib.js_log import JsLog
from CAPEsolo.capelib.network import NetworkData
from CAPEsolo.capelib.network_decrypt import DecryptStreams
from CAPEsolo.capelib.network_summary import NetworkSummary
from CAPEsolo.capelib.objects import File
from CAPEsolo.capelib.parse_pe import PortableExecutable
from CAPEsolo.capelib.path_utils import path_exists
from CAPEsolo.capelib.signatures import RunSignatures
from CAPEsolo.capelib.utils import LoadFilesJson, extract_strings

from .behavior_panel import Options
from .configs_panel import Extract
from .process_yara import ProcessYara

log = logging.getLogger(__name__)


def TargetInfo(targetFile):
    fileObj = File(str(targetFile))
    fileinfo = fileObj.get_all()[0]
    peData = PortableExecutable(str(targetFile)).run()
    fileinfo["pe"] = peData
    # The signature runner skips any signature declaring filter_analysistypes unless this
    # matches (signatures.py:1263). Nothing set it, so 8 of the 29 community signatures -
    # including network_http and network_cnc_http - were never even evaluated. CAPEsolo
    # always analyses a file.
    fileinfo["category"] = "file"
    return fileinfo


def BehaviorResults(analysisDir):
    options = Options()
    options.analysis_call_limit = 0
    options.ram_boost = True
    behavior = BehaviorAnalysis()
    behavior.set_path(analysisDir)
    behavior.set_options(options)
    results = behavior.run()

    # Materialise each process's OWN lazy calls (ParseProcessLog) into a plain, JSON-serialisable
    # list. A prior version shared one accumulator across processes, so every process ended up
    # with the cumulative calls of all processes - which made report.json's per-process calls
    # (and any per-process signature reading them) unusable.
    for proc in results.get("processes", []):
        try:
            proc["calls"] = list(proc.get("calls", []))
        except Exception:
            return None

    return results


# Everything a signature may read must already be in results before the pass runs. CAPEv2
# gets this for free - CAPE extraction is a processing module and signatures run after all of
# them - but CAPEsolo assembles the report inline, so the order is only a convention unless it
# is enforced. Two shipped signatures read the payload/config data and silently matched nothing
# because the pass ran before either existed.
SIGNATURE_PREREQS = ("target", "behavior", "js_log", "network", "payloads", "configs", "CAPE")


def Signatures(results, analysisDir):
    missing = [key for key in SIGNATURE_PREREQS if key not in results]
    if missing:
        raise RuntimeError(
            "Signatures ran before their inputs existed - missing "
            f"{', '.join(missing)}. Build the full results dict first; a signature that reads "
            "a key added later matches nothing and reports no error."
        )

    RunSignatures(results=results, analysis_path=analysisDir).run()
    return results.get("signatures")


def CapeView(results):
    """The payload/config view the shipped CAPE signatures read, in CAPEsolo's own terms.

    CAPEv2 publishes results["CAPE"] = {"payloads": [...], "configs": [...]} from its CAPE
    processing module, and its payload entries are flat dicts with "path" as a field and yara
    hits under "cape_yara". CAPEsolo keys payloads by path instead and calls the hits "yara",
    so this re-keys the same objects rather than rebuilding them.

    Deliberately not a full CAPEv2 mirror: upstream splits results by target type (file, url,
    static, procmemory), and CAPEsolo only ever analyses a file. Only the two fields the
    signatures actually read are aliased; no upstream field CAPEsolo does not produce is
    invented.
    """
    # The Yara tab publishes hits as their own section rather than attaching them to each
    # payload, so a payload assembled in the GUI has no "yara" key. Index the section by the
    # trailing "CAPE/<name>" of each path - the same join json_report uses to match a payload
    # to its scan - so a signature sees the hits either way round.
    hitsByFile = {}
    for hit in results.get("yara") or []:
        key = "/".join(Path(str(hit.get("file", ""))).parts[-2:])
        # The section calls the rule "rule"; a payload's own hits call it "name", which is
        # what the signatures read.
        hitsByFile.setdefault(key, []).append(dict(hit, name=hit.get("rule", "")))

    payloads = []
    for entry in results.get("payloads") or []:
        for path, data in (entry.items() if isinstance(entry, dict) else []):
            payload = dict(data or {})
            payload["path"] = str(path)
            if payload.get("yara"):
                payload["cape_yara"] = payload["yara"]
            else:
                fromSection = hitsByFile.get("/".join(Path(str(path)).parts[-2:]))
                if fromSection:
                    payload["cape_yara"] = fromSection
            payloads.append(payload)

    return {"payloads": payloads, "configs": results.get("configs") or []}


def Payloads(analysisDir):
    data = LoadFilesJson(analysisDir)
    if "error" in data:
        return []
    else:
        data = dict(sorted(data.items(), key=lambda x: x[1]["size"], reverse=True))

    results = []
    for key, value in data.items():
        payloadData = {}
        if key.startswith("aux_"):
            continue

        path = Path(analysisDir) / key
        fileinfo = File(str(path)).get_all()[0]
        metadata = data[key].get("metadata", "")
        if metadata:
            payloadData = metadata_processing(metadata, data[key].get("pids"))

        # Carried from files.json: the artifact is on disk but was not stored whole, so a
        # consumer does not analyse a partial payload believing it is the complete one.
        for flag in ("incomplete", "truncated"):
            if value.get(flag):
                payloadData[flag] = True

        for key, value in fileinfo.items():
            if key not in "path" and value:
                payloadData[key] = value

        results.append({str(path): payloadData})

    return results


def Configs(yara, analysisDir):
    """Extract a config for every CAPE name yara matched, draining parser-dumped files.

    Takes the ProcessYara instance rather than its results because a parser can hand files
    back via "dump_files". Yara has already run by the time configs are extracted, so each
    dumped file is scanned on its own and its CAPE names parsed in the next round, mirroring
    the Configs tab (configs_panel.ExtractConfigs).
    """
    configs = []
    configHits = []
    # Persists across rounds so a hit parsed in an earlier round is not parsed again, which
    # is what makes re-flattening the whole hit list each round cheap.
    processed = set()
    while True:
        configHits = []
        for filehits in yara.yara_results:
            paths = filehits.keys()
            for file in paths:
                for hit in filehits[file]:
                    capename = get_cape_name_from_yara_hit(hit)
                    if capename:
                        configHits.append({file: capename})

        newPayloads = []
        configs += Extract(
            configHits,
            analysisDir,
            jsonResults=True,
            newPayloads=newPayloads,
            seen=processed,
        )
        # Terminates because the writes are content addressed -- DumpParserFiles appends to
        # newPayloads only when it actually writes a file it has not seen before.
        if not newPayloads:
            break

        # ScanPayload appends to yara_results, so the next round sees these hits.
        for relPath in newPayloads:
            yara.ScanPayload(relPath)

    # Built from the final round, so a family detected only in a dumped file is included.
    detections = []
    for hit in configHits:
        capename = next(iter(hit.values()))
        if not capename in detections:
            detections.append(capename)

    return configs, detections


def WriteJsonFile(results, analysisDir=""):
    """Write report.json to the Desktop, and into the analysis directory when known.

    The Desktop copy is where CAPEsolo has always put it. The analysis-directory copy is what
    makes a results bundle self-contained: Zip Results archives that directory, so without it
    the archive carried every artifact except the report.
    """
    try:
        desktop = Path(os.path.expanduser("~/Desktop"))
        filepath = desktop / "report.json"
        with open(filepath, "w", encoding="utf-8", errors="replace") as f:
            dump(results, f, indent=4)

        if analysisDir:
            # Best-effort: a failure here must not lose the Desktop copy the caller expects.
            try:
                with open(Path(analysisDir) / "report.json", "w", encoding="utf-8", errors="replace") as f:
                    dump(results, f, indent=4)
            except Exception as e:
                log.warning("Could not write report.json into the analysis directory: %s", e)

        return True, ""
    except Exception as e:
        return False, e


def GetYara(yara, path):
    for hit in yara:
        data = hit.get(path)
        if data:
            return data

    return None


def YaraHits(yara):
    """Flatten every scan into one file-by-file hit list, the way the Yara tab shows them.

    Attaching hits to target/payload entries alone loses two things: the CAPE name a rule
    carries (which is what drives config extraction), and any hit on a file that has no
    payload entry to hang off - notably the blobs a config parser dumps, which are scanned
    after the payload list was built.

    Mirrors YaraPanel.AddHits so both views describe a hit the same way. Deduplicated on
    (file, rule): a parser-dump round re-scans files already in yara_results.
    """
    hits = []
    seen = set()
    for filehits in yara.yara_results:
        for file, matches in filehits.items():
            for hit in matches or []:
                rule = hit.get("name", "")
                key = (str(file), rule)
                if key in seen:
                    continue

                seen.add(key)
                meta = hit.get("meta") or {}
                # get_cape_name_from_yara_hit indexes hit["meta"] directly; this list is
                # built from every scan result, so do not assume the key is there.
                capename = get_cape_name_from_yara_hit(hit) if "meta" in hit else ""
                hits.append(
                    {
                        "file": str(file),
                        "rule": rule,
                        "capename": capename or "",
                        "meta": meta,
                        "description": " ".join(str(meta.get("description", "")).split()),
                        "strings": hit.get("strings") or [],
                        "addresses": hit.get("addresses") or {},
                    }
                )

    return hits


def Network(analysisDir, results, pcapPath=""):
    """Build the network summary the signatures and reports read.

    Works with no capture at all - the behaviour log and the JS console log are enough for
    hosts, DNS lookups and HTTP requests. A capture adds the wire view, and TLS secrets from
    the analysis add the decrypted plaintext on top of that.
    """
    capture = None
    decrypted = None
    if pcapPath and path_exists(str(pcapPath)):
        try:
            capture = NetworkData(analysisDir, pcapPath)
        except Exception as e:
            log.warning("Could not parse the capture %s: %s", pcapPath, e)

        try:
            decrypted = DecryptStreams(analysisDir, pcapPath)
        except Exception as e:
            log.warning("Could not decrypt streams in %s: %s", pcapPath, e)

    return NetworkSummary(
        behavior=results.get("behavior"),
        jsLog=results.get("js_log"),
        capture=capture,
        decrypted=decrypted,
    )


def GetResults(targetFile, analysisDir, writeFile=True, includeStrings=True, pcapPath=""):
    """Build the full analysis report.

    includeStrings=False skips string extraction entirely rather than extracting and then
    discarding: it is the expensive part on an analysis with many payloads.

    pcapPath is the capture the user supplied on the Network tab, if any.
    """
    results = {}
    results["target"] = TargetInfo(targetFile)
    results["behavior"] = BehaviorResults(analysisDir)
    # js_log and network are built before the signatures, which read both: 14 of the shipped
    # network signatures look up results["network"], and previously js_log was populated
    # after they had already run.
    results["js_log"] = JsLog(analysisDir)
    results["network"] = Network(analysisDir, results, pcapPath)

    yara = ProcessYara(analysisDir)
    yara.Scan(str(targetFile))
    yara.ScanPayloads()
    yaraData = GetYara(yara.yara_results, str(targetFile))
    if yaraData:
        results["target"]["yara"] = yaraData

    if includeStrings:
        extracted = extract_strings(str(targetFile), dedup=True, minchars=4)
        if extracted:
            results["target"]["strings"] = sorted(list(set(extracted)), key=lambda x: (len(x), x))

    # Configs first, then payloads: a parser hands back blobs that are written into CAPE/ and
    # scanned (Configs -> DumpParserFiles -> ScanPayload). Building the payload list before
    # that ran left those files out of the report entirely, and their yara hits with them -
    # there was no payload entry to attach them to. No signature reads results["payloads"],
    # so nothing upstream depends on the old order.
    results["configs"], results["detections"] = Configs(yara, analysisDir)
    results["payloads"] = Payloads(analysisDir)

    for payload in results.get("payloads", []):
        for path in payload.keys():
            subpath = "/".join(Path(path).parts[-2:])
            yaraData = GetYara(yara.yara_results, subpath)

            if yaraData:
                payload[path]["yara"] = yaraData

            if includeStrings:
                extracted = extract_strings(path, dedup=True, minchars=4)
                if extracted:
                    payload[path]["strings"] = sorted(list(set(extracted)), key=lambda x: (len(x), x))

    # Additive top-level section: every hit on every scanned file, including the ones no
    # payload entry covers. This is what the Yara tab shows and what the report was missing.
    results["yara"] = YaraHits(yara)

    # Signatures run last, over everything - the order CAPEv2 gets from running its processing
    # modules before the signature stage. The CAPE view exists only for that pass: CAPEsolo's
    # own payloads/configs keys are the canonical ones, so it is dropped before serialising
    # rather than shipping the same payload data twice.
    results["CAPE"] = CapeView(results)
    results["signatures"] = Signatures(results, analysisDir)
    results.pop("CAPE", None)
    # Additive key: what the run actually captured and what it lost, so a thin report can be
    # told apart from a quiet analysis - on this machine and after the bundle is copied off it.
    # Reconciled fresh (artifacts can arrive after the run, e.g. files reconstructed from the
    # JS streams), but the transfer counters can only come from the manifest written when the
    # result server shut down - STATS is reset by the next run and gone in a later session.
    capture = BuildCaptureReport(analysisDir)
    stored = LoadCaptureReport(analysisDir)
    if stored.get("transfers") and not capture.get("transfers"):
        capture["transfers"] = stored["transfers"]
        capture["warnings"] = CaptureWarnings(capture)
    results["capture"] = capture
    if writeFile:
        return WriteJsonFile(results, analysisDir)
    else:
        return results
