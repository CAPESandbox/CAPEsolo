"""Focused queries over a finished analysis's results, for the MCP tools.

Each returns a small, JSON-safe answer instead of whole report sections: the calls a filter
matches, one process's activity, the evidence behind signature hits, and the differences
between two runs. Kept free of wx and of the MCP server so they can be tested on their own.
"""

import json
import zipfile
from collections import Counter
from pathlib import Path

from .call_filter import CallFilter, FilterAllCalls, ProcessLabel

# Argument names that carry the object a call acts on, per kind of activity.
FILE_ARGS = ("FileName", "HandleName", "ExistingFileName", "NewFileName", "DirectoryName", "FilePath", "PathToFile")
REGISTRY_ARGS = ("FullName", "Regkey", "KeyName")
NETWORK_ARGS = ("URL", "Url", "ServerName", "HostName", "NodeName", "Host", "IP", "Address")
ACTIVITY_CAP = 200
DIFF_CAP = 200


def Processes(results):
    return (results.get("behavior") or {}).get("processes") or []


def CompactCall(proc, call, index=None):
    record = {
        "pid": proc.get("process_id"),
        "process": proc.get("process_name"),
        "timestamp": call.get("timestamp"),
        "tid": call.get("thread_id"),
        "api": call.get("api"),
        "category": call.get("category"),
        "status": bool(call.get("status")),
        "return": call.get("pretty_return") or call.get("return"),
        "arguments": {arg.get("name"): arg.get("pretty_value") or arg.get("value") for arg in call.get("arguments") or []},
        "repeated": call.get("repeated", 0),
    }
    if index is not None:
        record["cid"] = index
    return record


def QueryCalls(results, api="", tid="", process="", argument="", category="all", regex=False, offset=0, limit=100):
    """The calls matching the filter (capelib/call_filter rules) across every process, paged.

    Raises re.error for an invalid pattern when regex is set.
    """
    callFilter = CallFilter(api=api, tid=tid, process=process, argument=argument, category=category, regex=regex)
    # cid is the call's position in its process's list - what a signature's mark_call records.
    positions = {}
    for proc in Processes(results):
        for index, call in enumerate(proc.get("calls") or []):
            positions[id(call)] = index
    matches = FilterAllCalls(Processes(results), callFilter)
    page = matches[offset:offset + limit]
    return {
        "total": len(matches),
        "offset": offset,
        "limit": limit,
        "calls": [CompactCall(proc, call, positions.get(id(call))) for proc, call in page],
    }


def _Activity(calls, names):
    seen = []
    for call in calls:
        for arg in call.get("arguments") or []:
            if arg.get("name") in names:
                value = str(arg.get("pretty_value") or arg.get("value") or "").strip()
                if value and value not in seen:
                    seen.append(value)
                    if len(seen) >= ACTIVITY_CAP:
                        return seen
    return seen


def _TreeNode(tree, pid):
    for node in tree or []:
        if node.get("pid") == pid:
            return node
        found = _TreeNode(node.get("children"), pid)
        if found:
            return found
    return None


def ProcessView(results, pid, top=25):
    """One process: identity, place in the tree, call counts, and what it touched."""
    processes = Processes(results)
    proc = next((p for p in processes if str(p.get("process_id")) == str(pid)), None)
    if proc is None:
        return None
    calls = proc.get("calls") or []
    byPid = {p.get("process_id"): p for p in processes}
    parents, parentId = [], proc.get("parent_id")
    while parentId in byPid and len(parents) < 32:
        parents.append(ProcessLabel(byPid[parentId]))
        parentId = byPid[parentId].get("parent_id")
    node = _TreeNode((results.get("behavior") or {}).get("processtree"), proc.get("process_id"))
    environ = proc.get("environ") or {}
    return {
        "pid": proc.get("process_id"),
        "name": proc.get("process_name"),
        "parent_id": proc.get("parent_id"),
        "module_path": proc.get("module_path"),
        "command_line": environ.get("CommandLine"),
        "first_seen": proc.get("first_seen"),
        "threads": proc.get("threads"),
        "ancestors": parents,
        "children": [f'{child.get("pid")} {child.get("name")}' for child in (node or {}).get("children") or []],
        "call_count": len(calls),
        "calls_by_category": dict(Counter(call.get("category") for call in calls).most_common()),
        "top_apis": dict(Counter(call.get("api") for call in calls).most_common(top)),
        "files": _Activity([c for c in calls if c.get("category") == "filesystem"], FILE_ARGS),
        "registry": _Activity([c for c in calls if c.get("category") == "registry"], REGISTRY_ARGS),
        "network": _Activity([c for c in calls if c.get("category") in ("network", "socket", "browser")], NETWORK_ARGS),
        "signatures": [
            sig.get("name") for sig in results.get("signatures") or []
            if any(_MentionsPid(item, proc.get("process_id")) for item in (sig.get("data") or []) + (sig.get("new_data") or []))
        ],
    }


def _MentionsPid(item, pid):
    if not isinstance(item, dict):
        return False
    if str(item.get("pid", "")) == str(pid):
        return True
    process = item.get("process")
    return isinstance(process, dict) and str(process.get("process_id", "")) == str(pid)


def SignatureEvidence(results, name=""):
    """Matched signatures with their evidence; marked calls are resolved to the calls themselves."""
    byPid = {str(p.get("process_id")): p for p in Processes(results)}
    out = []
    for sig in results.get("signatures") or []:
        if name and sig.get("name") != name:
            continue
        evidence = []
        for item in sig.get("data") or []:
            if isinstance(item, dict) and item.get("type") == "call":
                proc = byPid.get(str(item.get("pid")))
                calls = (proc or {}).get("calls") or []
                cid = item.get("cid")
                if isinstance(cid, int) and 0 <= cid < len(calls):
                    evidence.append({"type": "call", "call": CompactCall(proc, calls[cid], cid)})
                    continue
            evidence.append(item)
        out.append({
            "name": sig.get("name"),
            "description": sig.get("description"),
            "severity": sig.get("severity"),
            "categories": sig.get("categories"),
            "families": sig.get("families"),
            "evidence": evidence,
            "matches": sig.get("new_data") or [],
        })
    return out


def LoadReport(path):
    """A report.json, or the report.json inside a Zip Results bundle, read in place."""
    path = Path(path)
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as archive:
            member = next((n for n in archive.namelist() if Path(n).name == "report.json"), None)
            if member is None:
                raise FileNotFoundError(f"No report.json in {path}")
            return json.loads(archive.read(member))
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def _Facets(results):
    """The comparable sets of one run."""
    summary = (results.get("behavior") or {}).get("summary") or {}
    network = results.get("network") or {}
    payloads = {}
    for payload in results.get("payloads") or []:
        for path, record in payload.items():
            if record.get("sha256"):
                payloads[record["sha256"]] = f'{record.get("cape_type") or record.get("type") or ""} {Path(path).name}'.strip()
    target = results.get("target") or {}
    yara = {hit.get("name") for hit in target.get("yara") or []}
    for payload in results.get("payloads") or []:
        for record in payload.values():
            yara.update(hit.get("name") for hit in record.get("yara") or [])
    return {
        "signatures": {sig.get("name") for sig in results.get("signatures") or []},
        "detections": set(results.get("detections") or []),
        "yara": {name for name in yara if name},
        "payloads": payloads,
        "processes": {p.get("process_name") for p in Processes(results)},
        "domains": {d.get("domain") if isinstance(d, dict) else d for d in network.get("domains") or []},
        "hosts": {h.get("ip") if isinstance(h, dict) else h for h in network.get("hosts") or []},
        "http": {h.get("uri") or h.get("url") if isinstance(h, dict) else h for h in network.get("http") or []},
        "mutexes": set(summary.get("mutexes") or []),
        "executed_commands": set(summary.get("executed_commands") or []),
        "write_files": set(summary.get("write_files") or []),
        "write_keys": set(summary.get("write_keys") or []),
    }


def DiffResults(a, b):
    """{facet: {"only_in_a": [...], "only_in_b": [...]}} for the facets that differ."""
    fa, fb = _Facets(a), _Facets(b)
    diff = {}
    for facet in fa:
        if facet == "payloads":
            onlyA = [f"{sha} {fa[facet][sha]}" for sha in sorted(set(fa[facet]) - set(fb[facet]))]
            onlyB = [f"{sha} {fb[facet][sha]}" for sha in sorted(set(fb[facet]) - set(fa[facet]))]
        else:
            onlyA = sorted(str(v) for v in fa[facet] - fb[facet] if v)
            onlyB = sorted(str(v) for v in fb[facet] - fa[facet] if v)
        if onlyA or onlyB:
            diff[facet] = {"only_in_a": onlyA[:DIFF_CAP], "only_in_b": onlyB[:DIFF_CAP]}
            if len(onlyA) > DIFF_CAP or len(onlyB) > DIFF_CAP:
                diff[facet]["truncated"] = True
    return diff
