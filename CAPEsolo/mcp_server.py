import configparser
import hashlib
import logging
import os
import shutil
import sys
import threading
import traceback
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from sflock.abstracts import File as SflockFile
from sflock.ident import identify as sflock_identify
from sflock.main import unpack as sflock_unpack

from CAPEsolo.capelib.resultserver import ResultServer
from CAPEsolo.capelib.utils import sanitize_filename
from CAPEsolo.capelib.utils import LoadFilesJson
from CAPEsolo.classes.html_report import ReportHTML
from CAPEsolo.classes.json_report import GetResults
from CAPEsolo.lib.common.hashing import hash_file
from CAPEsolo.utils.update_yara import UpdateYara

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    FastMCP = None

log = logging.getLogger(__name__)

CAPESOLO_ROOT = Path(__file__).resolve().parent
ANALYSIS_CONF = CAPESOLO_ROOT / "analysis.conf"
CFG_INI = CAPESOLO_ROOT / "cfg.ini"
MCP_STAGING_DIR = "mcp_staging"
DEFAULT_ANALYSIS_ID = 2
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 14400
MAX_OPTIONS_LENGTH = 8192
SANDBOXPACKAGES = (
    "Shellcode",
    "Shellcode_trace",
    "Shellcode_x64",
    "Shellcode_x64_trace",
    "archive",
    "chm",
    "dll",
    "doc",
    "exe",
    "hta",
    "iso",
    "jar",
    "js",
    "lnk",
    "mht",
    "msi",
    "msix",
    "nsis",
    "ps1",
    "pub",
    "python",
    "rar",
    "regsvr",
    "sct",
    "service",
    "service_dll",
    "udf",
    "vbs",
    "vhd",
    "xls",
    "xps",
    "xslt",
    "zip",
)

if not log.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


def _read_analysis_dir() -> Path:
    config = configparser.ConfigParser()
    config.read(CFG_INI)
    path = config.get("analysis_directory", "analysis", fallback=r"C:\Users\Public\CAPEsolo\analysis")
    return Path(path)


def _read_default_analysis_id() -> int:
    config = configparser.ConfigParser()
    config.read(CAPESOLO_ROOT / "analysis_conf.default")
    try:
        return config.getint("analysis", "id", fallback=DEFAULT_ANALYSIS_ID)
    except Exception:
        return DEFAULT_ANALYSIS_ID


def _termination_folder_for_analysis_id(analysis_id: int) -> Path:
    kill_hash = hashlib.md5(f"cape-{analysis_id}".encode()).hexdigest()
    return Path(os.environ["TMP"]) / kill_hash


def _get_available_packages() -> set[str]:
    packages_dir = CAPESOLO_ROOT / "modules" / "packages"
    packages = set()
    if packages_dir.exists():
        for path in packages_dir.glob("*.py"):
            if path.stem != "__init__":
                packages.add(path.stem)
    return packages


def _identify_package(target: Path) -> str:
    package = ""
    f = SflockFile.from_path(str(target).encode("utf-8"))
    try:
        tmp_package = sflock_identify(f, check_shellcode=True)
    except Exception:
        log.exception("Failed to detect package for %s", target)
        tmp_package = ""

    if tmp_package and tmp_package in SANDBOXPACKAGES:
        if tmp_package in ("iso", "udf", "vhd"):
            package = "archive"
        else:
            package = tmp_package
    return package


def _build_analysis_conf(
    target_for_execution: Path,
    package: str,
    options: str,
    timeout: int,
    enforce_timeout: bool,
    run_from_current_directory: bool,
) -> str:
    conf = (CAPESOLO_ROOT / "analysis_conf.default").read_text()
    current_datetime = datetime.now().strftime("%Y%m%dT%H:%M:%S")
    user_options = options.strip()
    sep = "," if user_options else ""

    if run_from_current_directory:
        user_options += f"{sep}curdir={target_for_execution.parent}"

    conf += f"\nenforce_timeout = {enforce_timeout}"
    conf += f"\ntimeout = {timeout}"
    conf += f"\nfile_name = {target_for_execution}"
    conf += f"\nclock = {current_datetime}"
    conf += f"\npackage = {package}"
    conf += f"\noptions = {user_options}"
    return conf


def _cleanup_analyzer(analyzer: Any, resultserver: ResultServer | None) -> None:
    from CAPEsolo.analyzer import Files, disconnect_logger, disconnect_pipes, upload_files

    try:
        files = Files()
        files.dump_files()
        upload_files("debugger")
        upload_files("tlsdump")
    except Exception:
        log.exception("Post-run file handling failed")

    try:
        if analyzer and hasattr(analyzer, "command_pipe"):
            analyzer.command_pipe.stop()
    except Exception:
        log.exception("Failed to stop analyzer command pipe")

    try:
        if analyzer and hasattr(analyzer, "log_pipe_server"):
            analyzer.log_pipe_server.stop()
    except Exception:
        log.exception("Failed to stop analyzer log pipe server")

    try:
        disconnect_pipes()
        disconnect_logger()
    except Exception:
        log.exception("Failed disconnecting analyzer pipes/logger")

    if resultserver:
        try:
            resultserver.shutdown_server()
        except Exception:
            log.exception("Failed shutting down result server")


def _extract_single_file_from_password_zip(
    zip_path: Path,
    zip_password: str,
    extract_root: Path,
    archive_member_path: str = "",
) -> Path:
    password = (zip_password or "").strip() or "infected"

    extract_root.mkdir(parents=True, exist_ok=True)
    extract_dir = extract_root / f"zip_{uuid.uuid4().hex}"
    extract_dir.mkdir(parents=True, exist_ok=True)

    root_archive = None
    try:
        root_archive = sflock_unpack(filepath=str(zip_path).encode("utf-8"), password=password, check_shellcode=False)
        members: list[tuple[str, SflockFile]] = []
        for child in root_archive.children:
            relapath = child.relapath or child.filename
            if not relapath:
                continue
            member_path = relapath.decode("utf-8", errors="replace") if isinstance(relapath, bytes) else str(relapath)
            members.append((member_path.replace("\\", "/"), child))

        if not members:
            raise ValueError("ZIP archive does not contain any files or could not be decrypted.")

        selected_member = None
        member_request = archive_member_path.strip().replace("\\", "/")
        if member_request:
            for member_path, member in members:
                if member_path == member_request:
                    selected_member = member
                    break
            if not selected_member:
                raise ValueError(f"archive_member_path '{archive_member_path}' not found in ZIP archive.")
        else:
            if len(members) != 1:
                raise ValueError(
                    "ZIP archive contains multiple files. Provide archive_member_path to select one."
                )
            selected_member = members[0][1]

        selected_name = selected_member.filename or selected_member.relapath or b""
        if isinstance(selected_name, bytes):
            selected_name = selected_name.decode("utf-8", errors="replace")
        extracted_name = sanitize_filename(Path(str(selected_name)).name)
        if not extracted_name:
            extracted_name = f"sample_{uuid.uuid4().hex}"

        extracted_path = extract_dir / extracted_name
        with selected_member.stream as zf_member, extracted_path.open("wb") as out:
            shutil.copyfileobj(zf_member, out)
        return extracted_path
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Failed to unpack ZIP archive with SFlock2: {zip_path}") from exc
    finally:
        if root_archive:
            root_archive.close()


class AnalysisJobManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._jobs: dict[str, dict[str, Any]] = {}
        self._active_job_id: str | None = None
        self.analysis_dir = _read_analysis_dir()
        self.default_analysis_id = _read_default_analysis_id()
        self.available_packages = _get_available_packages()
        self.analysis_dir.mkdir(parents=True, exist_ok=True)

    def _set_job(self, job_id: str, **fields: Any) -> None:
        with self._lock:
            self._jobs[job_id].update(fields)
            if fields.get("state") in {"completed", "failed"} and self._active_job_id == job_id:
                self._active_job_id = None

    def _validate_job_id(self, job_id: Any) -> tuple[bool, str, str]:
        if not isinstance(job_id, str) or not job_id.strip():
            return False, "", "job_id must be a non-empty string."
        return True, job_id.strip(), ""

    def submit(
        self,
        sample_path: str,
        package: str = "Auto-detect",
        options: str = "",
        timeout: int = 200,
        enforce_timeout: bool = False,
        run_from_current_directory: bool = True,
    ) -> dict[str, Any]:
        valid, source, package, options, timeout, enforce_timeout, run_from_current_directory, error = self._validate_submission_inputs(
            sample_path=sample_path,
            package=package,
            options=options,
            timeout=timeout,
            enforce_timeout=enforce_timeout,
            run_from_current_directory=run_from_current_directory,
        )
        if not valid:
            return {"accepted": False, "error": error}

        with self._lock:
            if self._active_job_id:
                return {"accepted": False, "error": "Another analysis job is currently running"}

            job_id = uuid.uuid4().hex
            self._active_job_id = job_id
            self._jobs[job_id] = {
                "job_id": job_id,
                "state": "queued",
                "created_at": datetime.utcnow().isoformat(),
                "source_path": str(source),
                "analysis_dir": str(self.analysis_dir),
                "package": package,
                "options": options,
                "timeout": timeout,
                "enforce_timeout": enforce_timeout,
                "run_from_current_directory": run_from_current_directory,
                "analysis_id": self.default_analysis_id,
            }

        thread = threading.Thread(
            target=self._run_job,
            args=(job_id, source, package, options, timeout, enforce_timeout, run_from_current_directory),
            daemon=True,
        )
        thread.start()
        return {"accepted": True, "job_id": job_id, "state": "queued"}

    def _validate_submission_inputs(
        self,
        sample_path: Any,
        package: Any,
        options: Any,
        timeout: Any,
        enforce_timeout: Any,
        run_from_current_directory: Any,
    ) -> tuple[bool, Path | None, str, str, int, bool, bool, str]:
        if not isinstance(sample_path, str) or not sample_path.strip():
            return False, None, "Auto-detect", "", 200, False, True, "The file path is empty."

        source = Path(sample_path.strip())
        if not source.exists() or not source.is_file():
            return False, None, "Auto-detect", "", 200, False, True, f"The file {source} does not exist."

        if not isinstance(package, str) or not package.strip():
            return False, None, "Auto-detect", "", 200, False, True, "Package must be a non-empty string."
        package = package.strip()
        if package != "Auto-detect" and package not in self.available_packages:
            return (
                False,
                None,
                "Auto-detect",
                "",
                200,
                False,
                True,
                f"Unknown package '{package}'. Select a valid package from modules/packages or use Auto-detect.",
            )

        if options is None:
            options = ""
        if not isinstance(options, str):
            return False, None, "Auto-detect", "", 200, False, True, "Options must be a string."
        options = options.strip()
        if len(options) > MAX_OPTIONS_LENGTH:
            return (
                False,
                None,
                "Auto-detect",
                "",
                200,
                False,
                True,
                f"Options string is too long ({len(options)} > {MAX_OPTIONS_LENGTH}).",
            )

        if isinstance(timeout, bool):
            return False, None, "Auto-detect", "", 200, False, True, "Timeout must be an integer in seconds."
        try:
            timeout = int(timeout)
        except (TypeError, ValueError):
            return False, None, "Auto-detect", "", 200, False, True, "Timeout must be an integer in seconds."
        if timeout < MIN_TIMEOUT_SECONDS or timeout > MAX_TIMEOUT_SECONDS:
            return (
                False,
                None,
                "Auto-detect",
                "",
                200,
                False,
                True,
                f"Timeout must be between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS} seconds.",
            )

        if not isinstance(enforce_timeout, bool):
            return False, None, "Auto-detect", "", 200, False, True, "enforce_timeout must be true or false."
        if not isinstance(run_from_current_directory, bool):
            return False, None, "Auto-detect", "", 200, False, True, "run_from_current_directory must be true or false."

        return True, source, package, options, timeout, enforce_timeout, run_from_current_directory, ""

    def _run_job(
        self,
        job_id: str,
        source: Path,
        package: str,
        options: str,
        timeout: int,
        enforce_timeout: bool,
        run_from_current_directory: bool,
    ) -> None:
        analyzer = None
        resultserver = None
        staged_target = None
        try:
            self._set_job(job_id, state="running", started_at=datetime.utcnow().isoformat())
            os.chdir(CAPESOLO_ROOT)
            sys.path.append(str(CAPESOLO_ROOT))

            staging_dir = self.analysis_dir / MCP_STAGING_DIR
            staging_dir.mkdir(parents=True, exist_ok=True)

            sanitized_name = sanitize_filename(source.name)
            if not sanitized_name:
                sanitized_name = f"sample_{uuid.uuid4().hex}"
            staged_target = staging_dir / sanitized_name
            if staged_target.exists():
                staged_target = staging_dir / f"{staged_target.stem}_{uuid.uuid4().hex[:8]}{staged_target.suffix}"
            shutil.copy2(source, staged_target)

            target_copy = self.analysis_dir / f"s_{hash_file(hashlib.sha256, staged_target)}"
            shutil.copy2(staged_target, target_copy)

            package_name = package
            if package_name == "Auto-detect":
                package_name = _identify_package(staged_target)
                if not package_name:
                    raise RuntimeError("Package identification failed. Provide package explicitly.")

            conf = _build_analysis_conf(
                target_for_execution=staged_target,
                package=package_name,
                options=options,
                timeout=timeout,
                enforce_timeout=enforce_timeout,
                run_from_current_directory=run_from_current_directory,
            )
            ANALYSIS_CONF.write_text(conf)

            from CAPEsolo.analyzer import Analyzer

            resultserver = ResultServer("localhost", 9999, str(self.analysis_dir))
            analyzer = Analyzer()
            analyzer.prepare()
            run_result = analyzer.run()

            self._set_job(
                job_id,
                state="completed" if run_result else "failed",
                ended_at=datetime.utcnow().isoformat(),
                target_file=str(target_copy),
                execution_target=str(staged_target),
                package=package_name,
                run_result=bool(run_result),
            )
        except Exception as e:
            self._set_job(
                job_id,
                state="failed",
                ended_at=datetime.utcnow().isoformat(),
                error=str(e),
                traceback=traceback.format_exc(),
            )
            log.exception("Analysis job %s failed", job_id)
        finally:
            _cleanup_analyzer(analyzer, resultserver)

    def wait_for_completion(self, job_id: str, timeout: int = 0, poll_interval: float = 1.0) -> dict[str, Any]:
        start = datetime.utcnow().timestamp()
        while True:
            status = self.status(job_id)
            if not status.get("found"):
                return status
            if status.get("state") in {"completed", "failed"}:
                return status
            if timeout and (datetime.utcnow().timestamp() - start) > timeout:
                return {"found": True, "ready": False, "state": status.get("state"), "timeout": True}
            threading.Event().wait(poll_interval)

    def run_single(
        self,
        sample_path: str,
        package: str = "Auto-detect",
        options: str = "",
        timeout: int = 200,
        enforce_timeout: bool = False,
        run_from_current_directory: bool = True,
    ) -> dict[str, Any]:
        submitted = self.submit(
            sample_path=sample_path,
            package=package,
            options=options,
            timeout=timeout,
            enforce_timeout=enforce_timeout,
            run_from_current_directory=run_from_current_directory,
        )
        if not submitted.get("accepted"):
            return submitted
        job_id = submitted["job_id"]
        final_status = self.wait_for_completion(job_id, timeout=0)
        return {"accepted": True, "job_id": job_id, "status": final_status}

    def submit_password_zip(
        self,
        zip_path: str,
        zip_password: str = "infected",
        package: str = "Auto-detect",
        options: str = "",
        timeout: int = 200,
        enforce_timeout: bool = False,
        run_from_current_directory: bool = True,
        archive_member_path: str = "",
    ) -> dict[str, Any]:
        if not isinstance(zip_path, str) or not zip_path.strip():
            return {"accepted": False, "error": "zip_path must be a non-empty string."}
        if zip_password is None:
            zip_password = ""
        if not isinstance(zip_password, str):
            return {"accepted": False, "error": "zip_password must be a string."}
        zip_password = zip_password.strip() or "infected"
        if archive_member_path is None:
            archive_member_path = ""
        if not isinstance(archive_member_path, str):
            return {"accepted": False, "error": "archive_member_path must be a string."}

        source_zip = Path(zip_path.strip())
        if not source_zip.exists() or not source_zip.is_file():
            return {"accepted": False, "error": f"The ZIP file {source_zip} does not exist."}

        staging_dir = self.analysis_dir / MCP_STAGING_DIR
        try:
            extracted_sample = _extract_single_file_from_password_zip(
                zip_path=source_zip,
                zip_password=zip_password,
                extract_root=staging_dir,
                archive_member_path=archive_member_path,
            )
        except ValueError as exc:
            return {"accepted": False, "error": str(exc)}

        submitted = self.submit(
            sample_path=str(extracted_sample),
            package=package,
            options=options,
            timeout=timeout,
            enforce_timeout=enforce_timeout,
            run_from_current_directory=run_from_current_directory,
        )
        if submitted.get("accepted"):
            job_id = submitted.get("job_id")
            if job_id:
                self._set_job(
                    job_id,
                    source_zip_path=str(source_zip),
                    extracted_from_zip=True,
                    archive_member_path=archive_member_path.strip() or None,
                )
        return submitted

    def status(self, job_id: str) -> dict[str, Any]:
        valid, job_id, error = self._validate_job_id(job_id)
        if not valid:
            return {"found": False, "error": error}
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return {"found": False, "error": f"Job not found: {job_id}"}
            return {"found": True, **job}

    def cancel(self, job_id: str) -> dict[str, Any]:
        valid, job_id, error = self._validate_job_id(job_id)
        if not valid:
            return {"found": False, "error": error}
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return {"found": False, "error": f"Job not found: {job_id}"}
            if job.get("state") not in {"queued", "running"}:
                return {"found": True, "cancellable": False, "state": job.get("state")}
            if self._active_job_id != job_id:
                return {"found": True, "cancellable": False, "state": job.get("state")}
            analysis_id = int(job.get("analysis_id", self.default_analysis_id))

        kill_folder = _termination_folder_for_analysis_id(analysis_id)
        kill_folder.mkdir(exist_ok=True)
        self._set_job(job_id, cancel_requested=True, cancel_requested_at=datetime.utcnow().isoformat())
        return {"found": True, "cancellable": True, "state": "running", "termination_signal": str(kill_folder)}

    def _tail_file(self, path: Path, lines: int = 100) -> list[str]:
        if lines <= 0:
            return []
        with path.open("rb") as hfile:
            hfile.seek(0, os.SEEK_END)
            end = hfile.tell()
            block_size = 4096
            data = b""
            while end > 0 and data.count(b"\n") <= lines:
                read_size = min(block_size, end)
                end -= read_size
                hfile.seek(end)
                data = hfile.read(read_size) + data
            return data.decode("utf-8", errors="replace").splitlines()[-lines:]

    def get_job_log_tail(self, job_id: str, lines: int = 100) -> dict[str, Any]:
        valid, job_id, error = self._validate_job_id(job_id)
        if not valid:
            return {"found": False, "error": error}

        if isinstance(lines, bool):
            return {"found": False, "error": "lines must be an integer."}
        try:
            lines = int(lines)
        except (TypeError, ValueError):
            return {"found": False, "error": "lines must be an integer."}
        if lines < 1 or lines > 5000:
            return {"found": False, "error": "lines must be between 1 and 5000."}

        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return {"found": False, "error": f"Job not found: {job_id}"}
            analysis_dir = Path(job.get("analysis_dir", self.analysis_dir))

        log_path = analysis_dir / "analysis.log"
        if not log_path.exists():
            return {"found": True, "ready": False, "error": f"Log file not found: {log_path}"}
        tail = self._tail_file(log_path, lines=lines)
        return {"found": True, "ready": True, "path": str(log_path), "lines": tail}

    def list_payloads(self, job_id: str) -> dict[str, Any]:
        valid, job_id, error = self._validate_job_id(job_id)
        if not valid:
            return {"found": False, "error": error}
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return {"found": False, "error": f"Job not found: {job_id}"}
            state = job.get("state")
            analysis_dir = job.get("analysis_dir")

        if state != "completed":
            return {"found": True, "ready": False, "state": state}

        data = LoadFilesJson(analysis_dir)
        if "error" in data:
            return {"found": True, "ready": False, "error": data["error"]}

        payloads = []
        for key, value in data.items():
            if key.startswith("aux_"):
                continue
            path = Path(analysis_dir) / key
            payloads.append(
                {
                    "path": str(path),
                    "size": value.get("size"),
                    "type": value.get("type"),
                    "metadata": value.get("metadata", ""),
                }
            )
        return {"found": True, "ready": True, "payloads": payloads}

    def list_dropped_files(self, job_id: str) -> dict[str, Any]:
        valid, job_id, error = self._validate_job_id(job_id)
        if not valid:
            return {"found": False, "error": error}
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return {"found": False, "error": f"Job not found: {job_id}"}
            state = job.get("state")
            analysis_dir = Path(job.get("analysis_dir", self.analysis_dir))

        if state != "completed":
            return {"found": True, "ready": False, "state": state}

        dropped_dir = analysis_dir / "files"
        if not dropped_dir.exists():
            return {"found": True, "ready": True, "dropped_files": []}

        files = []
        for file_path in dropped_dir.rglob("*"):
            if file_path.is_file():
                files.append(
                    {
                        "path": str(file_path),
                        "relative_path": str(file_path.relative_to(dropped_dir)),
                        "size": file_path.stat().st_size,
                    }
                )
        return {"found": True, "ready": True, "dropped_files": files}

    def list_debug_logs(self, job_id: str) -> dict[str, Any]:
        valid, job_id, error = self._validate_job_id(job_id)
        if not valid:
            return {"found": False, "error": error}
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return {"found": False, "error": f"Job not found: {job_id}"}
            state = job.get("state")
            analysis_dir = Path(job.get("analysis_dir", self.analysis_dir))

        if state not in {"running", "completed", "failed"}:
            return {"found": True, "ready": False, "state": state}

        debug_dir = analysis_dir / "debugger"
        logs = []
        if debug_dir.exists():
            for log_path in sorted(debug_dir.glob("*.log")):
                if log_path.is_file():
                    logs.append({"path": str(log_path), "size": log_path.stat().st_size})
        analysis_log = analysis_dir / "analysis.log"
        if analysis_log.exists():
            logs.append({"path": str(analysis_log), "size": analysis_log.stat().st_size})
        return {"found": True, "ready": True, "debug_logs": logs}

    def get_results(self, job_id: str, include_strings: bool = True) -> dict[str, Any]:
        valid, job_id, error = self._validate_job_id(job_id)
        if not valid:
            return {"found": False, "error": error}
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return {"found": False, "error": f"Job not found: {job_id}"}
            state = job.get("state")
            target_file = job.get("target_file")
            analysis_dir = job.get("analysis_dir")

        if state != "completed":
            return {"found": True, "ready": False, "state": state}
        if not target_file:
            return {"found": True, "ready": False, "state": state, "error": "No target_file recorded for job"}

        results = GetResults(Path(target_file), analysis_dir, False)
        if not include_strings:
            if "target" in results:
                results["target"].pop("strings", None)
            for payload in results.get("payloads", []):
                for data in payload.values():
                    data.pop("strings", None)
        return {"found": True, "ready": True, "state": state, "results": results}

    def render_html_report(self, job_id: str) -> dict[str, Any]:
        valid, job_id, error = self._validate_job_id(job_id)
        if not valid:
            return {"found": False, "error": error}
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return {"found": False, "error": f"Job not found: {job_id}"}
            state = job.get("state")
            target_file = job.get("target_file")
            analysis_dir = job.get("analysis_dir")

        if state != "completed":
            return {"found": True, "ready": False, "state": state}
        if not target_file:
            return {"found": True, "ready": False, "state": state, "error": "No target_file recorded for job"}

        results = GetResults(Path(target_file), analysis_dir, False)
        report = ReportHTML()
        completed, msg = report.run(analysis_dir, str(CAPESOLO_ROOT), results)
        return {"found": True, "ready": True, "state": state, "completed": completed, "message": str(msg) if msg else ""}


manager = AnalysisJobManager()
mcp = FastMCP("capesolo") if FastMCP else None

if mcp:
    @mcp.tool()
    def capesolo_analyze_sample(
        sample_path: str,
        package: str = "Auto-detect",
        options: str = "",
        timeout: int = 200,
        enforce_timeout: bool = False,
        run_from_current_directory: bool = True,
    ) -> dict[str, Any]:
        return manager.submit(
            sample_path=sample_path,
            package=package,
            options=options,
            timeout=timeout,
            enforce_timeout=enforce_timeout,
            run_from_current_directory=run_from_current_directory,
        )


    @mcp.tool()
    def capesolo_analyze_password_zip(
        zip_path: str,
        zip_password: str = "infected",
        package: str = "Auto-detect",
        options: str = "",
        timeout: int = 200,
        enforce_timeout: bool = False,
        run_from_current_directory: bool = True,
        archive_member_path: str = "",
    ) -> dict[str, Any]:
        return manager.submit_password_zip(
            zip_path=zip_path,
            zip_password=zip_password,
            package=package,
            options=options,
            timeout=timeout,
            enforce_timeout=enforce_timeout,
            run_from_current_directory=run_from_current_directory,
            archive_member_path=archive_member_path,
        )


    @mcp.tool()
    def capesolo_get_job_status(job_id: str) -> dict[str, Any]:
        return manager.status(job_id)


    @mcp.tool()
    def capesolo_cancel_job(job_id: str) -> dict[str, Any]:
        return manager.cancel(job_id)


    @mcp.tool()
    def capesolo_get_results(job_id: str, include_strings: bool = True) -> dict[str, Any]:
        return manager.get_results(job_id, include_strings=include_strings)


    @mcp.tool()
    def capesolo_get_job_log_tail(job_id: str, lines: int = 100) -> dict[str, Any]:
        return manager.get_job_log_tail(job_id=job_id, lines=lines)


    @mcp.tool()
    def capesolo_render_html_report(job_id: str) -> dict[str, Any]:
        return manager.render_html_report(job_id)


    @mcp.tool()
    def capesolo_list_payloads(job_id: str) -> dict[str, Any]:
        return manager.list_payloads(job_id)


    @mcp.tool()
    def capesolo_list_dropped_files(job_id: str) -> dict[str, Any]:
        return manager.list_dropped_files(job_id)


    @mcp.tool()
    def capesolo_list_debug_logs(job_id: str) -> dict[str, Any]:
        return manager.list_debug_logs(job_id)


    @mcp.tool()
    def capesolo_update_yara() -> dict[str, Any]:
        updated = UpdateYara(CAPESOLO_ROOT)
        return {"updated": updated or {}}


def main() -> None:
    if not mcp:
        raise ImportError("MCP server requires the 'mcp' package. Install dependencies and retry.")
    mcp.run()


if __name__ == "__main__":
    main()
