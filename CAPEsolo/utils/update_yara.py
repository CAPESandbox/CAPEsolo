"""Refresh YARA rules and community signatures.

CAPEsolo and CAPEv2 feed the packaged rules: yara/CAPE, which the processing tabs scan, and
data/yara, the monitor rules capemon loads in the guest. The packaged folders are rebuilt from
whichever of the two are picked, and CAPEsolo's copy wins where both have a file of the same
name.

Community content never goes into the package. It lands in the user's folders beside cfg.ini:
the YARA rules in yara/community (scanned with the CAPE rules by capelib/yaralib.py), and the
signatures in signatures/community (loaded, unmodified, by capelib/cape_compat.py). Each of those
subfolders is replaced as a unit; the user's own files one level up are never touched.
"""

import shutil
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

import requests

from CAPEsolo.capelib.config_paths import user_config_path

# The GitHub contents API rather than scraping the tree page: the page's markup changes, and a
# failed scrape used to leave the folder emptied with nothing downloaded.
CONTENTS_API = "https://api.github.com/repos/{repo}/contents/{path}?ref={ref}"
RULE_SUFFIXES = (".yar", ".yara")
# Rules written locally rather than downloaded, which an update never removes. DebuggerRule.yar
# is the Debugger tab's saved rule, in data/yara.
KEEP = {"DebuggerRule.yar"}

# Packaged target -> repository folder, per source.
SOURCES = {
    "capesolo": {
        "repo": "CAPESandbox/CAPEsolo",
        "ref": "main",
        "paths": {"yara/CAPE": "CAPEsolo/yara/CAPE", "data/yara": "CAPEsolo/data/yara"},
    },
    "capev2": {
        "repo": "kevoreilly/CAPEv2",
        "ref": "master",
        "paths": {"yara/CAPE": "data/yara/CAPE", "data/yara": "analyzer/windows/data/yara"},
    },
}
# Lowest precedence first: a later source's file replaces an earlier one's of the same name.
PRECEDENCE = ("capev2", "capesolo")
YARA_SOURCES = ("capesolo", "capev2", "community")
DEFAULT_SOURCES = ("capesolo",)

# The community repository comes as one archive - its signatures alone are several hundred files.
COMMUNITY_ARCHIVE = "https://codeload.github.com/CAPESandbox/community/zip/refs/heads/master"
COMMUNITY_YARA = "data/yara/CAPE"
# The Windows signature folders; deprecated/ and linux/ are left out, as the loader skips them.
COMMUNITY_SIGNATURES = ("modules/signatures/windows", "modules/signatures/all")


def ListRules(repo, ref, path):
    resp = requests.get(CONTENTS_API.format(repo=repo, path=path, ref=ref), timeout=30)
    resp.raise_for_status()
    entries = [
        entry for entry in resp.json()
        if entry.get("type") == "file" and entry.get("name", "").endswith(RULE_SUFFIXES)
    ]
    if not entries:
        raise RuntimeError(f"No YARA rules listed in {repo}/{path}")
    return entries


def ReplaceRules(target, staging):
    """Swap *target*'s rule files for *staging*'s. Files that are not rules, and the KEEP
    files, stay."""
    target.mkdir(parents=True, exist_ok=True)
    for old in target.iterdir():
        if old.is_file() and old.suffix in RULE_SUFFIXES and old.name not in KEEP:
            old.unlink()
    for new in staging.iterdir():
        shutil.move(str(new), str(target / new.name))


def ReplaceFolder(target, staging):
    """Swap the whole of *target* for *staging*: a folder the updater owns outright."""
    if target.exists():
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(staging), str(target))


def ExtractCommunity(archivePath, yaraFolder=None, signaturesFolder=None):
    """Copy the community rules (flat) and signatures (keeping windows/ and all/) out of the
    repository archive into the staging folders given."""
    with zipfile.ZipFile(archivePath) as archive:
        for member in archive.infolist():
            if member.is_dir():
                continue
            # "community-master/data/yara/CAPE/x.yar" -> "data/yara/CAPE/x.yar"
            parts = PurePosixPath(member.filename).parts[1:]
            rel = PurePosixPath(*parts) if parts else None
            if rel is None:
                continue
            if yaraFolder is not None and str(rel.parent) == COMMUNITY_YARA and rel.suffix in RULE_SUFFIXES:
                (yaraFolder / rel.name).write_bytes(archive.read(member))
            elif signaturesFolder is not None and rel.suffix == ".py":
                for root in COMMUNITY_SIGNATURES:
                    if str(rel).startswith(root + "/"):
                        dest = signaturesFolder / PurePosixPath(root).name / rel.relative_to(root)
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(archive.read(member))
                        break
    for folder, what in ((yaraFolder, "YARA rules"), (signaturesFolder, "signatures")):
        if folder is not None and not any(folder.rglob("*")):
            raise RuntimeError(f"No community {what} found in the archive")


def Update(RootPath, yaraSources=DEFAULT_SOURCES, signatures=False):
    """Download the YARA rules of *yaraSources* and, if *signatures*, the community signatures.

    Returns {what: file count}. Everything is downloaded into staging folders before anything is
    replaced, so a failed listing or download raises and leaves every existing file in place.
    """
    unknown = set(yaraSources) - set(YARA_SOURCES)
    if unknown:
        raise ValueError(f"Unknown YARA source(s): {', '.join(sorted(unknown))}")
    RootPath = Path(RootPath)
    userRoot = user_config_path().parent

    results = {}
    with tempfile.TemporaryDirectory() as staging:
        staging = Path(staging)
        # (label, destination, staging folder, replace function)
        swaps = []

        packaged = {}
        for source in PRECEDENCE:
            if source in yaraSources:
                for target, path in SOURCES[source]["paths"].items():
                    packaged.setdefault(target, []).append((SOURCES[source], path))
        for target, feeds in packaged.items():
            folder = staging / target.replace("/", "_")
            folder.mkdir()
            for feed, path in feeds:
                for entry in ListRules(feed["repo"], feed["ref"], path):
                    rule = requests.get(entry["download_url"], timeout=60)
                    rule.raise_for_status()
                    # Written in precedence order, so the higher-precedence copy is the one left.
                    (folder / entry["name"]).write_bytes(rule.content)
            swaps.append((target, RootPath / target, folder, ReplaceRules))

        if "community" in yaraSources or signatures:
            archivePath = staging / "community.zip"
            with requests.get(COMMUNITY_ARCHIVE, timeout=300, stream=True) as resp:
                resp.raise_for_status()
                with open(archivePath, "wb") as f:
                    for chunk in resp.iter_content(1 << 20):
                        f.write(chunk)
            yaraFolder = signaturesFolder = None
            if "community" in yaraSources:
                yaraFolder = staging / "community_yara"
                yaraFolder.mkdir()
                swaps.append(("community YARA", userRoot / "yara" / "community", yaraFolder, ReplaceRules))
            if signatures:
                signaturesFolder = staging / "community_signatures"
                signaturesFolder.mkdir()
                swaps.append(("community signatures", userRoot / "signatures" / "community", signaturesFolder, ReplaceFolder))
            ExtractCommunity(archivePath, yaraFolder, signaturesFolder)

        # Nothing below runs unless every download above succeeded.
        for label, destination, folder, replace in swaps:
            results[label] = sum(1 for p in folder.rglob("*") if p.is_file())
            replace(destination, folder)

    return results


if __name__ == "__main__":
    import CAPEsolo

    Update(Path(CAPEsolo.__file__).parent)
