import os
from json import dump
from pathlib import Path

from CAPEsolo.capelib.behavior import BehaviorAnalysis
from CAPEsolo.capelib.cape_utils import get_cape_name_from_yara_hit, metadata_processing
from CAPEsolo.capelib.objects import File
from CAPEsolo.capelib.parse_pe import PortableExecutable
from CAPEsolo.capelib.signatures import RunSignatures
from CAPEsolo.capelib.utils import LoadFilesJson, extract_strings

from .behavior_panel import Options
from .configs_panel import Extract
from .process_yara import ProcessYara


def TargetInfo(targetFile):
    fileObj = File(str(targetFile))
    fileinfo = fileObj.get_all()[0]
    peData = PortableExecutable(str(targetFile)).run()
    fileinfo["pe"] = peData
    return fileinfo


def BehaviorResults(analysisDir):
    options = Options()
    options.analysis_call_limit = 0
    options.ram_boost = True
    behavior = BehaviorAnalysis()
    behavior.set_path(analysisDir)
    behavior.set_options(options)
    results = behavior.run()

    mycalls = []
    procs = results.get("processes", [])
    n = 0
    for proc in procs:
        try:
            for call in proc.get("calls", []):
                mycalls.append(call)

            procs[n]["calls"] = mycalls
        except Exception:
            return None

        n += 1

    return results


def Signatures(results, analysisDir):
    RunSignatures(results=results, analysis_path=analysisDir).run()
    return results.get("signatures")


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
            payloadData = metadata_processing(metadata)

        for key, value in fileinfo.items():
            if key not in "path" and value:
                payloadData[key] = value

        results.append({str(path): payloadData})

    return results


def Configs(yara, analysisDir):
    configHits = []
    detections = []
    for filehits in yara:
        paths = filehits.keys()
        for file in paths:
            for hit in filehits[file]:
                capename = get_cape_name_from_yara_hit(hit)
                if capename:
                    configHits.append({file: capename})
                    if not capename in detections:
                        detections.append(capename)

    configs = Extract(configHits, analysisDir, jsonResults=True)

    return configs, detections


def WriteJsonFile(results):
    try:
        desktop = Path(os.path.expanduser("~/Desktop"))
        filepath = desktop / "report.json"
        with open(filepath, "w", encoding="utf-8", errors="replace") as f:
            dump(results, f, indent=4)

        return True, ""
    except Exception as e:
        return False, e


def GetYara(yara, path):
    for hit in yara:
        data = hit.get(path)
        if data:
            return data

    return None


def GetResults(targetFile, analysisDir, writeFile=True):
    results = {}
    results["target"] = TargetInfo(targetFile)
    results["behavior"] = BehaviorResults(analysisDir)
    results["signatures"] = Signatures(results, analysisDir)
    results["payloads"] = Payloads(analysisDir)

    yara = ProcessYara(analysisDir)
    yara.Scan(str(targetFile))
    yara.ScanPayloads()
    yaraData = GetYara(yara.yara_results, str(targetFile))
    if yaraData:
        results["target"]["yara"] = yaraData

    extracted = extract_strings(str(targetFile), dedup=True, minchars=4)
    if extracted:
        results["target"]["strings"] = sorted(list(set(extracted)), key=lambda x: (len(x), x))

    for payload in results.get("payloads", []):
        for path in payload.keys():
            subpath = "/".join(Path(path).parts[-2:])
            yaraData = GetYara(yara.yara_results, subpath)

            if yaraData:
                payload[path]["yara"] = yaraData

            extracted = extract_strings(path, dedup=True, minchars=4)
            if extracted:
                payload[path]["strings"] = sorted(list(set(extracted)), key=lambda x: (len(x), x))

    results["configs"], results["detections"] = Configs(yara.yara_results, analysisDir)
    if writeFile:
        return WriteJsonFile(results)
    else:
        return results
