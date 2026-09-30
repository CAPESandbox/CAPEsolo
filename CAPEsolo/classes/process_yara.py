import os

from CAPEsolo.capelib.utils import LoadFilesJson
from CAPEsolo.capelib.yaralib import YaraProcessor


class ProcessYara:
    def __init__(self, analysisDir):
        self.yara = YaraProcessor()
        self.yara_results = []
        self.analysisDir = analysisDir

    def Scan(self, target):
        hits = {}
        hits[target] = self.yara.get_yara(target)
        self.yara_results.append({target: hits[target]})

    def ScanPayload(self, relPath):
        path = os.path.join(self.analysisDir, relPath)
        hits = self.yara.get_yara(path)
        self.yara_results.append({relPath: hits})
        return hits

    def ScanPayloads(self):
        hits = {}
        content = LoadFilesJson(self.analysisDir)
        if "error" not in content.keys():
            for file in content.keys():
                category = content[file].get("category", "")
                # Archive/zip extraction uploads candidate samples under files/ without a
                # category, so fall back to the storage directory when it is missing.
                normalized = file.replace("\\", "/")
                if category in ("files", "CAPE", "procdump") or normalized.startswith(
                    ("files/", "CAPE/", "procdump/")
                ):
                    path = os.path.join(self.analysisDir, file)
                    hits[file] = self.yara.get_yara(path)
                    self.yara_results.append({file: hits[file]})
