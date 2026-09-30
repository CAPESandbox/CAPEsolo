"""Run CAPEv2 / CAPESandbox community signatures unmodified.

Community signatures are not shipped. The user drops them into a signatures folder beside
cfg.ini (user_signatures_dir), for example a copy of community's modules/signatures, and
RunSignatures loads them next to CAPEsolo's own. Two things separate a CAPEv2 signature from
CAPEsolo, and both are bridged here rather than by editing the files:

  * imports - CAPEv2 modules (lib.cuckoo.common.*) are registered as stand-ins that point at
    CAPEsolo's equivalents (install_shims). A signature needing anything else is skipped
    with a warning naming the missing module.
  * result shapes - a CAPEv2 signature reads results["target"]["file"], results["info"] and
    results["dropped"], which CAPEsolo lays out differently or not at all. SignatureView adds
    them for the signature pass only and takes them back out afterwards, the way the CAPE
    view is handled, so report.json keeps CAPEsolo's own schema.
"""

import configparser
import importlib
import importlib.util
import logging
import os
import sys
import types
from datetime import datetime
from pathlib import Path

from .config_paths import user_config_path
from .utils import LoadFilesJson, convert_to_printable

log = logging.getLogger(__name__)

# Module names the user's signatures are imported under, so they can be told apart from the
# shipped ones (a user signature replaces a shipped one of the same name).
USER_PACKAGE = "capesolo_user_signatures"
# The signatures/community subfolder Update fills; the user's own files elsewhere beat it.
COMMUNITY_PACKAGE = USER_PACKAGE + ".community."
# Folders of community's modules/signatures that are not Windows detections.
SKIP_DIRS = {"__pycache__", "deprecated", "linux"}

# path -> (mtime, module name) of every user signature file imported so far.
_imported = {}


def user_signatures_dir():
    return user_config_path().parent / "signatures"


def add_family_detection(results, family, detected_by, detected_on):
    """lib.cuckoo.common.utils.add_family_detection for CAPEsolo, whose results["detections"]
    is a list of family names rather than CAPEv2's {family, details} records."""
    detections = results.setdefault("detections", [])
    if family and family not in detections:
        detections.append(family)


def install_shims():
    """Register the CAPEv2 modules community signatures import. Idempotent."""
    if "lib.cuckoo.common.abstracts" in sys.modules:
        return

    from .signatures import Signature

    def module(name, package=False, **attrs):
        mod = types.ModuleType(name)
        if package:
            mod.__path__ = []
        mod.__dict__.update(attrs)
        sys.modules[name] = mod
        return mod

    # lib itself is the analyzer's package when CAPEsolo's root is importable (the GUI, the
    # MCP server); only stubbed when it is not, so the real one is never shadowed.
    try:
        lib = importlib.import_module("lib")
    except ImportError:
        lib = module("lib", package=True)
    cuckoo = module("lib.cuckoo", package=True)
    common = module("lib.cuckoo.common", package=True)
    # CUCKOO_ROOT only locates optional data files (extra/msft-public-ips.csv, data/dga.bloom),
    # each checked for existence first: the folder beside cfg.ini is where a user can put them.
    common.abstracts = module("lib.cuckoo.common.abstracts", Signature=Signature)
    common.constants = module("lib.cuckoo.common.constants", CUCKOO_ROOT=str(user_config_path().parent))
    common.utils = module(
        "lib.cuckoo.common.utils",
        convert_to_printable=convert_to_printable,
        add_family_detection=add_family_detection,
    )
    cuckoo.common = common
    lib.cuckoo = cuckoo


def load_user_signatures():
    """Import the signatures under user_signatures_dir(), new and changed files only.

    Returns the Signature classes they define. Re-scanned on every signature pass, so a file
    added or edited mid-session is picked up without a restart.
    """
    from .signatures import load_plugins, list_plugins

    root = user_signatures_dir()
    found = {}
    if root.is_dir():
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for filename in sorted(filenames):
                if filename.endswith(".py") and filename != "__init__.py":
                    path = Path(dirpath) / filename
                    found[path] = path.stat().st_mtime

    registered = list_plugins(group="signatures")
    for path in list(_imported):
        if path not in found or found[path] != _imported[path][0]:
            # Gone or edited: forget the classes the old copy registered.
            name = _imported.pop(path)[1]
            registered[:] = [cls for cls in registered if cls.__module__ != name]
            sys.modules.pop(name, None)

    if found:
        install_shims()
    for path, mtime in found.items():
        if path in _imported:
            continue
        rel = path.relative_to(root).with_suffix("")
        name = ".".join([USER_PACKAGE, *(part.replace(".", "_") for part in rel.parts)])
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
            load_plugins(module)
        except Exception as e:
            sys.modules.pop(name, None)
            log.warning("Skipping user signature %s: %s", path, e)
            continue
        _imported[path] = (mtime, name)

    return [cls for cls in registered if cls.__module__.startswith(USER_PACKAGE + ".")]


class SignatureView:
    """CAPEv2's result shapes, present only while the signatures run.

    Each is added only when absent, and exactly what was added is taken back out on exit,
    along with the original flat target - so nothing here reaches report.json.
    """

    def __init__(self, results, analysisDir):
        self.results = results
        self.analysisDir = analysisDir
        self.added = []
        self.target = None

    def __enter__(self):
        target = self.results.get("target")
        if isinstance(target, dict) and "file" not in target:
            # CAPEv2 nests the file record under target.file; CAPEsolo's target is that record.
            # The flat keys stay, for CAPEsolo's own signatures.
            self.target = target
            self.results["target"] = {**target, "file": target}
        for key, build in (("info", self.Info), ("dropped", self.Dropped)):
            if key not in self.results:
                self.results[key] = build()
                self.added.append(key)
        return self

    def __exit__(self, *exc):
        for key in self.added:
            self.results.pop(key, None)
        if self.target is not None:
            self.results["target"] = self.target
        return False

    def Info(self):
        """results["info"] from the analysis.conf the run was started with."""
        info = {"category": "file", "package": "", "options": "", "timeout": 0}
        config = configparser.ConfigParser(strict=False, interpolation=None)
        try:
            config.read(Path(self.analysisDir) / "analysis.conf")
            section = config["analysis"]
        except (configparser.Error, KeyError):
            return info
        info["package"] = section.get("package", "")
        info["options"] = section.get("options", "")
        try:
            info["timeout"] = int(section.get("timeout", 0))
        except ValueError:
            pass
        try:
            info["started"] = datetime.strptime(section.get("clock", ""), "%Y%m%dT%H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
        return info

    def Dropped(self):
        """results["dropped"]: the files the sample wrote (files.json category "files"), with
        the payload record CAPEsolo already built for each where there is one."""
        data = LoadFilesJson(self.analysisDir)
        if "error" in data:
            return []
        payloads = {}
        for payload in self.results.get("payloads") or []:
            for path, record in payload.items():
                payloads[os.path.normcase(os.path.normpath(path))] = record
        dropped = []
        for rel, entry in data.items():
            if entry.get("category", "") != "files" and not rel.replace("\\", "/").startswith("files/"):
                continue
            path = str(Path(self.analysisDir) / rel)
            record = dict(payloads.get(os.path.normcase(os.path.normpath(path)), {}))
            record["path"] = path
            record.setdefault("name", Path(rel).name)
            record["guest_paths"] = [entry["filepath"]] if entry.get("filepath") else []
            pids = entry.get("pids") or []
            record["pids"] = pids
            if pids:
                record.setdefault("pid", pids[0])
            dropped.append(record)
        return dropped
