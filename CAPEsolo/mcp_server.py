import argparse
import base64
import configparser
import copy
import hashlib
import hmac
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

from CAPEsolo.capelib.cmdconsts import (
    CMD_BREAKPOINT_LIST,
    CMD_CONTINUE,
    CMD_DELETE_BREAKPOINT,
    CMD_MEM_DUMP,
    CMD_MOD_FLAG,
    CMD_MODULE_LIST,
    CMD_NOP_INSTRUCTION,
    CMD_PATCH_BYTES,
    CMD_REG_UPDATE,
    CMD_RUN_UNTIL,
    CMD_SET_BREAKPOINT,
    CMD_SET_REGISTER,
    CMD_STACK_UPDATE,
    CMD_STEP_INTO,
    CMD_STEP_OUT,
    CMD_STEP_OVER,
    CMD_THREADS,
)
from CAPEsolo.capelib.config_paths import config_paths
from CAPEsolo.capelib.resultserver import ResultServer
from CAPEsolo.capelib.utils import sanitize_filename
from CAPEsolo.capelib.utils import LoadFilesJson
from CAPEsolo.classes.html_report import ReportHTML
from CAPEsolo.classes.json_report import GetResults, WriteJsonFile
from CAPEsolo.lib.common.hashing import hash_file
from CAPEsolo.utils.update_yara import UpdateYara

try:
    from mcp.server import MCPServer
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP as MCPServer
    except ImportError:
        MCPServer = None

log = logging.getLogger(__name__)

CAPESOLO_ROOT = Path(__file__).resolve().parent
ANALYSIS_CONF = CAPESOLO_ROOT / "analysis.conf"
MCP_STAGING_DIR = "mcp_staging"
DEFAULT_ANALYSIS_ID = 2
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 14400
MAX_OPTIONS_LENGTH = 8192
IDBG_TIMEOUT_SECONDS = 14400
DBG_DISASM_WINDOW = 8
DBG_STEP_COMMANDS = {
    "into": CMD_STEP_INTO,
    "over": CMD_STEP_OVER,
    "out": CMD_STEP_OUT,
}
DBG_FLAG_ACTIONS = (
    "ClearZeroFlag",
    "SetZeroFlag",
    "FlipZeroFlag",
    "ClearSignFlag",
    "SetSignFlag",
    "FlipSignFlag",
    "ClearCarryFlag",
    "SetCarryFlag",
    "FlipCarryFlag",
)
DBG_BREAKPOINT_SLOTS = ("next", "0", "1", "2", "3")
MCP_TRANSPORTS = ("stdio", "streamable-http")
DEFAULT_MCP_TRANSPORT = "stdio"
DEFAULT_MCP_HOST = "127.0.0.1"
DEFAULT_MCP_PORT = 8000
DEFAULT_MCP_PATH = "/mcp"
MCP_TOKEN_ENV = "CAPESOLO_MCP_TOKEN"
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
ANALYSIS_LOG_FORMAT = "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
MAX_REQUEST_BODY_SIZE = 32 * 1024 * 1024
MAX_UPLOAD_BYTES = 256 * 1024 * 1024
# Same expression as capelib/yaralib.py and classes/configs_panel.py; uploads must land
# where those loaders look.
DESKTOP_DIR = Path(os.path.expanduser("~")) / "Desktop"
CUSTOM_DIR = DESKTOP_DIR / "custom"
UPLOAD_DESTINATIONS = {"desktop": DESKTOP_DIR, "custom": CUSTOM_DIR}
CUSTOM_EXTENSIONS = (".yar", ".yara", ".py")
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
    config.read(config_paths())
    path = config.get("analysis_directory", "analysis", fallback=r"C:\Users\Public\CAPEsolo\analysis")
    return Path(path)


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _read_mcp_settings() -> dict[str, Any]:
    """Read the optional [mcp_server] section; fallbacks apply even when it is absent."""
    paths = config_paths()
    config = configparser.ConfigParser()
    read = config.read(paths)
    section = "mcp_server"
    try:
        port = config.getint(section, "port", fallback=DEFAULT_MCP_PORT)
    except ValueError:
        log.warning("Invalid [mcp_server] port in %s, using %s", read or paths, DEFAULT_MCP_PORT)
        port = DEFAULT_MCP_PORT

    return {
        "enabled": config.getboolean(section, "enabled", fallback=False),
        "transport": config.get(section, "transport", fallback=DEFAULT_MCP_TRANSPORT).strip().lower(),
        "host": config.get(section, "host", fallback=DEFAULT_MCP_HOST).strip(),
        "port": port,
        "path": config.get(section, "path", fallback=DEFAULT_MCP_PATH).strip(),
        "allowed_hosts": _split_csv(config.get(section, "allowed_hosts", fallback="")),
        "allowed_origins": _split_csv(config.get(section, "allowed_origins", fallback="")),
    }


def _read_default_analysis_id() -> int:
    config = configparser.ConfigParser()
    config.read(CAPESOLO_ROOT / "analysis_conf.default")
    try:
        return config.getint("analysis", "id", fallback=DEFAULT_ANALYSIS_ID)
    except Exception:
        return DEFAULT_ANALYSIS_ID


def _install_analysis_log_handler(analysis_dir: Path) -> tuple[Any, Any] | tuple[None, None]:
    """Write analysis.log for headless runs.

    In the GUI this handler is installed by LoggerWindow (classes/logger_window.py), so a
    headless or MCP run produced no analysis.log at all. Same level and format, so the file
    means the same thing however the analysis was started.
    """
    try:
        handler = logging.FileHandler(analysis_dir / "analysis.log", encoding="utf-8")
    except OSError:
        log.exception("Could not open analysis.log for writing in %s", analysis_dir)
        return None, None

    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(ANALYSIS_LOG_FORMAT))

    root = logging.getLogger()
    # A logger filters before its handlers, so root has to pass DEBUG through for the file
    # to receive it. Pin the existing handlers so console output keeps its current level.
    restore = [(root, root.level)] + [(h, h.level) for h in root.handlers]
    for existing in root.handlers:
        if existing.level == logging.NOTSET:
            existing.setLevel(root.level or logging.INFO)

    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    return handler, restore


def _remove_analysis_log_handler(handler: Any, restore: Any) -> None:
    if not handler:
        return

    root = logging.getLogger()
    root.removeHandler(handler)
    for target, level in restore or []:
        target.setLevel(level)
    handler.close()


def _import_debug_session():
    """Import the debugger session lazily; CAPEsolo.lib.core.pipe needs CAPESOLO_ROOT on sys.path."""
    if str(CAPESOLO_ROOT) not in sys.path:
        sys.path.append(str(CAPESOLO_ROOT))

    from CAPEsolo.capelib import debug_session

    return debug_session


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


def _option_keys(options: str) -> set[str]:
    """Option names from a comma-separated 'key=value' analyzer option string."""
    keys = set()
    for item in (options or "").split(","):
        name = item.split("=", 1)[0].strip().lower()
        if name:
            keys.add(name)
    return keys


def _check_undrivable_options(options: str, interactive_debug: bool) -> str:
    """Reject options that halt the analyzer with nothing able to release it.

    idbg puts the sample under the CAPEsolo debugger, but only the interactive_debug flag
    makes _run_job attach a DebuggerSession for the capesolo_dbg_* tools to drive. Passing
    the option alone leaves the sample stopped at its first breakpoint until the timeout,
    so the flag and the option are not allowed to disagree.
    """
    if "idbg" in _option_keys(options) and not interactive_debug:
        return (
            "idbg in options starts the debugger with nothing attached to drive it. "
            "Pass interactive_debug=true instead, which wires up the capesolo_dbg_* tools."
        )
    return ""


def _warn_unattended_options(options: str) -> None:
    """manual/interactive wait for a human to launch the sample.

    Not refused - an operator can still drive the guest desktop - but a caller that expects
    an unattended run would otherwise just see it stall until the timeout.
    """
    waiting = _option_keys(options) & {"manual", "interactive"}
    if waiting:
        log.warning(
            "Options %s wait for someone to launch the sample in the guest; an unattended "
            "run will stall until the timeout expires.",
            ", ".join(sorted(waiting)),
        )


def _cleanup_analyzer(analyzer: Any, resultserver: ResultServer | None) -> None:
    from CAPEsolo.analyzer import (
        INJECT_LIST,
        Files,
        disconnect_logger,
        disconnect_pipes,
        upload_files,
    )

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

    # The GUI reports these (start_panel.OnAnalyzerComplete); without them a headless run
    # that failed to hook its processes is indistinguishable from a clean one.
    for pid in INJECT_LIST:
        log.warning("Monitor injection attempted but failed for process %s", pid)

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
        self._debugger: Any = None
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
        interactive_debug: bool = False,
    ) -> dict[str, Any]:
        if not isinstance(interactive_debug, bool):
            return {"accepted": False, "error": "interactive_debug must be true or false."}

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

        conflict = _check_undrivable_options(options, interactive_debug)
        if conflict:
            return {"accepted": False, "error": conflict}
        _warn_unattended_options(options)

        if interactive_debug:
            options = f"{options},idbg=1" if options else "idbg=1"
            timeout = IDBG_TIMEOUT_SECONDS

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
                "interactive_debug": interactive_debug,
                "analysis_id": self.default_analysis_id,
            }

        thread = threading.Thread(
            target=self._run_job,
            args=(job_id, source, package, options, timeout, enforce_timeout, run_from_current_directory, interactive_debug),
            daemon=True,
        )
        thread.start()
        return {"accepted": True, "job_id": job_id, "state": "queued", "interactive_debug": interactive_debug}

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
        interactive_debug: bool = False,
    ) -> None:
        analyzer = None
        resultserver = None
        staged_target = None
        log_handler, log_restore = _install_analysis_log_handler(self.analysis_dir)
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

            if interactive_debug:
                self._debugger = _import_debug_session().DebuggerSession()
                self._debugger.launch()

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
            if self._debugger:
                self._debugger.shutdown()
                self._debugger = None

            _cleanup_analyzer(analyzer, resultserver)
            _remove_analysis_log_handler(log_handler, log_restore)

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
        # Fire-and-wait, used by `capesolo --headless-analyze`. There is no channel back to
        # a debugger client here, so interactive debugging is refused rather than exposed:
        # deliberately no interactive_debug parameter, and idbg in options is rejected.
        if "idbg" in _option_keys(options):
            return {
                "accepted": False,
                "error": (
                    "Interactive debugging is not available in headless mode - nothing can "
                    "drive the debugger, so the sample would stall at its first breakpoint. "
                    "Use the MCP server with interactive_debug=true instead."
                ),
            }

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
        interactive_debug: bool = False,
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
            interactive_debug=interactive_debug,
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

    @staticmethod
    def _strip_strings(results: dict[str, Any]) -> dict[str, Any]:
        stripped = copy.deepcopy(results)
        if "target" in stripped:
            stripped["target"].pop("strings", None)
        for payload in stripped.get("payloads", []):
            for data in payload.values():
                data.pop("strings", None)
        return stripped

    def _compute_results(self, job_id: str, include_strings: bool) -> Any:
        """Build the report once per job and reuse it.

        GetResults re-runs the full YARA scan and string extraction over the target and
        every payload, so asking for JSON and HTML used to pay that cost twice. The
        analysis directory no longer changes once a job completes, so the report cannot go
        stale and is safe to cache.
        """
        with self._lock:
            job = self._jobs.get(job_id)
            full = job.get("_results_full")
            lean = job.get("_results_nostrings")
            target_file = job.get("target_file")
            analysis_dir = job.get("analysis_dir")

        if full is not None:
            return full if include_strings else self._strip_strings(full)
        if not include_strings and lean is not None:
            return lean

        results = GetResults(
            Path(target_file), analysis_dir, False, includeStrings=include_strings
        )
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                job["_results_full" if include_strings else "_results_nostrings"] = results
        return results

    def get_results(
        self, job_id: str, include_strings: bool = True, write_file: bool = False
    ) -> dict[str, Any]:
        valid, job_id, error = self._validate_job_id(job_id)
        if not valid:
            return {"found": False, "error": error}
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return {"found": False, "error": f"Job not found: {job_id}"}
            state = job.get("state")
            target_file = job.get("target_file")

        if state != "completed":
            return {"found": True, "ready": False, "state": state}
        if not target_file:
            return {"found": True, "ready": False, "state": state, "error": "No target_file recorded for job"}

        results = self._compute_results(job_id, include_strings)
        payload = {"found": True, "ready": True, "state": state, "results": results}

        if write_file:
            # Same writer the GUI's JSON button uses, so the artifact lands in the same
            # place (~/Desktop/report.json) rather than somewhere headless-specific.
            written, err = WriteJsonFile(results)
            payload["written"] = bool(written)
            payload["report_path"] = str(Path(os.path.expanduser("~/Desktop")) / "report.json")
            if not written:
                payload["write_error"] = str(err)
        return payload

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

        # Shares the cache with get_results, so requesting both no longer runs YARA and
        # string extraction over every payload twice.
        results = self._compute_results(job_id, include_strings=True)
        report = ReportHTML()
        completed, msg = report.run(analysis_dir, str(CAPESOLO_ROOT), results)
        return {"found": True, "ready": True, "state": state, "completed": completed, "message": str(msg) if msg else ""}

    def _resolve_upload_path(self, filename: Any, destination: Any) -> tuple[Path | None, dict[str, Any] | None]:
        if not isinstance(destination, str) or destination.strip().lower() not in UPLOAD_DESTINATIONS:
            return None, {"ok": False, "error": f"destination must be one of {', '.join(UPLOAD_DESTINATIONS)}."}

        destination = destination.strip().lower()
        target_dir = UPLOAD_DESTINATIONS[destination]

        if not isinstance(filename, str) or not filename.strip():
            return None, {"ok": False, "error": "filename must be a non-empty string."}

        name = sanitize_filename(Path(filename.strip()).name).strip()
        if not name or name in (".", ".."):
            return None, {"ok": False, "error": f"filename is not usable after sanitizing: {filename}"}

        if destination == "custom" and not name.lower().endswith(CUSTOM_EXTENSIONS):
            return None, {
                "ok": False,
                "error": f"custom uploads must be one of {', '.join(CUSTOM_EXTENSIONS)}; got '{name}'.",
            }

        target_dir.mkdir(parents=True, exist_ok=True)
        path = (target_dir / name).resolve()
        if not path.is_relative_to(target_dir.resolve()):
            return None, {"ok": False, "error": f"filename escapes the {destination} directory: {filename}"}

        return path, None

    def upload_file(
        self,
        filename: str,
        data_base64: str,
        destination: str = "desktop",
        append: bool = False,
        sha256: str = "",
    ) -> dict[str, Any]:
        if not isinstance(append, bool):
            return {"ok": False, "error": "append must be true or false."}
        if not isinstance(data_base64, str):
            return {"ok": False, "error": "data_base64 must be a base64 string."}
        if sha256 is None:
            sha256 = ""
        if not isinstance(sha256, str):
            return {"ok": False, "error": "sha256 must be a hex string."}

        path, error = self._resolve_upload_path(filename, destination)
        if error:
            return error

        try:
            chunk = base64.b64decode(data_base64, validate=True)
        except ValueError:
            return {"ok": False, "error": "data_base64 is not valid base64."}

        existing = path.stat().st_size if append and path.exists() else 0
        if existing + len(chunk) > MAX_UPLOAD_BYTES:
            return {
                "ok": False,
                "error": f"upload would exceed {MAX_UPLOAD_BYTES} bytes (have {existing}, adding {len(chunk)}).",
            }

        try:
            with path.open("ab" if append else "wb") as out:
                out.write(chunk)
        except OSError as e:
            return {"ok": False, "error": f"Failed writing {path}: {e}"}

        digest = hash_file(hashlib.sha256, str(path))
        size = path.stat().st_size

        if sha256.strip() and sha256.strip().lower() != digest.lower():
            path.unlink(missing_ok=True)
            return {
                "ok": False,
                "error": f"sha256 mismatch: expected {sha256.strip().lower()}, got {digest.lower()}. Upload discarded.",
            }

        log.info("Uploaded %s bytes to %s (append=%s)", len(chunk), path, append)
        return {"ok": True, "path": str(path), "size": size, "sha256": digest, "destination": destination}

    def list_uploads(self) -> dict[str, Any]:
        listings: dict[str, Any] = {}
        for name, directory in UPLOAD_DESTINATIONS.items():
            entries = []
            if directory.exists():
                for item in sorted(directory.iterdir()):
                    if not item.is_file():
                        continue
                    entries.append(
                        {
                            "name": item.name,
                            "path": str(item),
                            "size": item.stat().st_size,
                            "sha256": hash_file(hashlib.sha256, str(item)),
                        }
                    )
            listings[name] = {"directory": str(directory), "exists": directory.exists(), "files": entries}
        return {"ok": True, **listings}

    @property
    def _dbg(self):
        return _import_debug_session()

    @staticmethod
    def _format_cip(session: Any) -> str | None:
        return f"{session.cip:#x}" if session.cip is not None else None

    def _require_debugger(self, require_break: bool = True) -> tuple[Any, dict[str, Any] | None]:
        session = self._debugger
        if not session:
            return None, {"ok": False, "error": "No interactive debug session is active."}
        if require_break and not session.connected:
            return None, {"ok": False, "error": "Debugger has not reported a break yet. Call capesolo_dbg_wait_break first."}
        return session, None

    def _validate_timeout(self, timeout_seconds: Any, default: float) -> tuple[float | None, dict[str, Any] | None]:
        if timeout_seconds is None:
            return default, None
        if isinstance(timeout_seconds, bool):
            return None, {"ok": False, "error": "timeout_seconds must be a number."}
        try:
            value = float(timeout_seconds)
        except (TypeError, ValueError):
            return None, {"ok": False, "error": "timeout_seconds must be a number."}
        if value < 1 or value > self._dbg.MAX_TIMEOUT:
            return None, {"ok": False, "error": f"timeout_seconds must be between 1 and {self._dbg.MAX_TIMEOUT}."}
        return value, None

    def _validate_count(self, value: Any, maximum: int, name: str) -> tuple[int | None, dict[str, Any] | None]:
        if isinstance(value, bool):
            return None, {"ok": False, "error": f"{name} must be an integer."}
        try:
            value = int(value)
        except (TypeError, ValueError):
            return None, {"ok": False, "error": f"{name} must be an integer."}
        if value < 1 or value > maximum:
            return None, {"ok": False, "error": f"{name} must be between 1 and {maximum}."}
        return value, None

    def _command(self, session: Any, command: str, data: str = "") -> tuple[str | None, dict[str, Any] | None]:
        payload = session.SendCommand(command, data, self._dbg.DEFAULT_COMMAND_TIMEOUT)
        if payload is None:
            return None, {"ok": False, "error": f"Debugger command {command} timed out."}
        if self._dbg.IsFailure(payload):
            return None, {"ok": False, "error": payload}
        return payload, None

    def _simple_command(self, command: str, data: str = "", key: str = "", parser: Any = None) -> dict[str, Any]:
        session, error = self._require_debugger()
        if error:
            return error

        payload, error = self._command(session, command, data)
        if error:
            return error

        result = {"ok": True, "payload": payload}
        if key and parser:
            result[key] = parser(payload)
        return result

    def debugger_status(self) -> dict[str, Any]:
        session = self._debugger
        if not session:
            return {"ok": True, "active": False}
        with self._lock:
            job_id = self._active_job_id
        return {
            "ok": True,
            "active": True,
            "connected": session.connected,
            "cip": self._format_cip(session),
            "bits": session.bits,
            "job_id": job_id,
        }

    def debugger_wait_break(self, timeout_seconds: Any = None) -> dict[str, Any]:
        session, error = self._require_debugger(require_break=False)
        if error:
            return error

        timeout, error = self._validate_timeout(timeout_seconds, self._dbg.DEFAULT_BREAK_TIMEOUT)
        if error:
            return error

        payload = session.WaitForBreak(timeout)
        if payload is None:
            return {"ok": True, "state": "running", "message": "No break reported within the timeout."}
        return {"ok": True, "state": "halted", "cip": self._format_cip(session), "payload": payload}

    def debugger_registers(self) -> dict[str, Any]:
        session, error = self._require_debugger()
        if error:
            return error
        return self._collect_registers(session)

    def _collect_registers(self, session: Any) -> dict[str, Any]:
        payload, error = self._command(session, CMD_REG_UPDATE)
        if error:
            return error

        if not session.bits:
            session.bits = 64 if "RAX" in payload else 32

        session.UpdateCip(payload)
        return {
            "ok": True,
            "bits": session.bits,
            "cip": self._format_cip(session),
            "registers": self._dbg.ParseRegisters(payload),
            "raw": payload,
        }

    def debugger_read_memory(self, address: Any, size: Any = 256) -> dict[str, Any]:
        session, error = self._require_debugger()
        if error:
            return error

        addr = self._dbg.ParseAddress(address)
        if addr is None:
            return {"ok": False, "error": f"Invalid address: {address}"}

        size, error = self._validate_count(size, self._dbg.MAX_MEM_READ, "size")
        if error:
            return error

        payload, error = self._command(session, CMD_MEM_DUMP, f"{addr:#x}|{size:#x}")
        if error:
            return error

        dumpAddr, data = self._dbg.ParseMemDump(payload)
        if dumpAddr is None:
            return {"ok": False, "error": f"Unexpected memory dump payload: {payload[:64]}"}
        if self._dbg.IsFailure(data):
            return {"ok": False, "error": data}

        return {"ok": True, "address": f"{dumpAddr:#x}", "size": len(data) // 2, "hex": data}

    def debugger_disassemble(self, address: Any = None, count: Any = 32) -> dict[str, Any]:
        session, error = self._require_debugger()
        if error:
            return error

        count, error = self._validate_count(count, self._dbg.MAX_INSTRUCTIONS, "count")
        if error:
            return error

        if address is None or address == "":
            if session.cip is None:
                return {"ok": False, "error": "No current instruction pointer is known; provide an address."}
            addr = session.cip
        else:
            addr = self._dbg.ParseAddress(address)
            if addr is None:
                return {"ok": False, "error": f"Invalid address: {address}"}

        if not session.bits:
            registers = self._collect_registers(session)
            if not registers.get("ok"):
                return registers

        size = min(count * self._dbg.MAX_INSTRUCTION_LEN, self._dbg.MAX_MEM_READ)
        memory = self.debugger_read_memory(f"{addr:#x}", size)
        if not memory.get("ok"):
            return memory

        try:
            raw = bytes.fromhex(memory["hex"])
        except ValueError:
            return {"ok": False, "error": "Memory dump was not valid hex."}

        return {
            "ok": True,
            "address": f"{addr:#x}",
            "bits": session.bits,
            "instructions": self._dbg.Disassemble(addr, raw, session.bits, count),
        }

    def debugger_execute(self, command: str, data: str = "", timeout_seconds: Any = None) -> dict[str, Any]:
        session, error = self._require_debugger()
        if error:
            return error

        timeout, error = self._validate_timeout(timeout_seconds, self._dbg.DEFAULT_BREAK_TIMEOUT)
        if error:
            return error

        payload = session.SendCommand(command, data, timeout)
        if payload is None or payload.startswith("TIMEOUT"):
            return {"ok": True, "state": "running", "message": "Target did not break within the timeout."}
        if self._dbg.IsFailure(payload):
            return {"ok": False, "error": payload}

        session.UpdateCip(payload)
        result = {"ok": True, "state": "halted", "cip": self._format_cip(session), "payload": payload}

        registers = self._collect_registers(session)
        if registers.get("ok"):
            result["bits"] = registers["bits"]
            result["cip"] = registers["cip"]
            result["registers"] = registers["registers"]

        disassembly = self.debugger_disassemble(count=DBG_DISASM_WINDOW)
        if disassembly.get("ok"):
            result["instructions"] = disassembly["instructions"]

        return result

    def debugger_step(self, mode: str = "into", timeout_seconds: Any = None) -> dict[str, Any]:
        if not isinstance(mode, str) or mode.strip().lower() not in DBG_STEP_COMMANDS:
            return {"ok": False, "error": f"mode must be one of {', '.join(DBG_STEP_COMMANDS)}."}
        return self.debugger_execute(DBG_STEP_COMMANDS[mode.strip().lower()], timeout_seconds=timeout_seconds)

    def debugger_continue(self, timeout_seconds: Any = None) -> dict[str, Any]:
        return self.debugger_execute(CMD_CONTINUE, timeout_seconds=timeout_seconds)

    def debugger_run_until(self, address: Any, timeout_seconds: Any = None) -> dict[str, Any]:
        addr = self._dbg.ParseAddress(address)
        if addr is None:
            return {"ok": False, "error": f"Invalid address: {address}"}
        return self.debugger_execute(CMD_RUN_UNTIL, f"{addr:#X}", timeout_seconds=timeout_seconds)

    def debugger_set_breakpoint(self, address: Any, slot: str = "next") -> dict[str, Any]:
        addr = self._dbg.ParseAddress(address)
        if addr is None:
            return {"ok": False, "error": f"Invalid address: {address}"}
        if not isinstance(slot, str) or slot.strip().lower() not in DBG_BREAKPOINT_SLOTS:
            return {"ok": False, "error": f"slot must be one of {', '.join(DBG_BREAKPOINT_SLOTS)}."}
        return self._simple_command(CMD_SET_BREAKPOINT, f"{slot.strip().lower()}|{addr:#X}")

    def debugger_delete_breakpoint(self, index: Any) -> dict[str, Any]:
        error = {"ok": False, "error": "index must be a debug register number between 0 and 3."}
        if isinstance(index, bool):
            return error
        try:
            index = int(index)
        except (TypeError, ValueError):
            return error
        if index < 0 or index > 3:
            return error
        return self._simple_command(CMD_DELETE_BREAKPOINT, str(index))

    def debugger_list_breakpoints(self) -> dict[str, Any]:
        return self._simple_command(CMD_BREAKPOINT_LIST, key="breakpoints", parser=self._dbg.ParseBreakpoints)

    def debugger_get_stack(self) -> dict[str, Any]:
        return self._simple_command(CMD_STACK_UPDATE, key="stack", parser=self._dbg.ParseStack)

    def debugger_list_modules(self) -> dict[str, Any]:
        return self._simple_command(CMD_MODULE_LIST, key="modules", parser=self._dbg.ParseModules)

    def debugger_list_threads(self) -> dict[str, Any]:
        return self._simple_command(CMD_THREADS, key="threads", parser=self._dbg.ParseThreads)

    def debugger_set_register(self, name: Any, value: Any) -> dict[str, Any]:
        if not isinstance(name, str) or not name.strip().isalnum():
            return {"ok": False, "error": "name must be a register name such as RAX or EIP."}

        register = name.strip().upper()
        if isinstance(value, bool):
            return {"ok": False, "error": "value must be an integer or hex string."}
        if isinstance(value, str):
            try:
                value = int(value.strip(), 0)
            except ValueError:
                return {"ok": False, "error": f"Invalid register value: {value}"}
        elif not isinstance(value, int):
            return {"ok": False, "error": "value must be an integer or hex string."}

        session, error = self._require_debugger()
        if error:
            return error

        payload, error = self._command(session, CMD_SET_REGISTER, f"{register}|{value:#X}")
        if error:
            return error

        session.UpdateCip(payload)
        return {"ok": True, "cip": self._format_cip(session), "registers": self._dbg.ParseRegisters(payload), "raw": payload}

    def debugger_set_cip(self, address: Any) -> dict[str, Any]:
        session, error = self._require_debugger()
        if error:
            return error

        addr = self._dbg.ParseAddress(address)
        if addr is None:
            return {"ok": False, "error": f"Invalid address: {address}"}

        if not session.bits:
            registers = self._collect_registers(session)
            if not registers.get("ok"):
                return registers

        return self.debugger_set_register("EIP" if session.bits == 32 else "RIP", addr)

    def debugger_modify_flag(self, action: Any) -> dict[str, Any]:
        if not isinstance(action, str) or action.strip() not in DBG_FLAG_ACTIONS:
            return {"ok": False, "error": f"action must be one of {', '.join(DBG_FLAG_ACTIONS)}."}

        session, error = self._require_debugger()
        if error:
            return error

        payload, error = self._command(session, CMD_MOD_FLAG, action.strip())
        if error:
            return error

        return {"ok": True, "registers": self._dbg.ParseRegisters(payload), "raw": payload}

    def debugger_patch_bytes(self, address: Any, hex_bytes: Any) -> dict[str, Any]:
        addr = self._dbg.ParseAddress(address)
        if addr is None:
            return {"ok": False, "error": f"Invalid address: {address}"}

        if not isinstance(hex_bytes, str):
            return {"ok": False, "error": "hex_bytes must be a hex string."}

        code = hex_bytes.strip().replace(" ", "")
        try:
            patch = bytes.fromhex(code)
        except ValueError:
            return {"ok": False, "error": f"hex_bytes is not valid hex: {hex_bytes}"}
        if not patch:
            return {"ok": False, "error": "hex_bytes must contain at least one byte."}

        return self._simple_command(CMD_PATCH_BYTES, f"{addr:#x}|{code.upper()}")

    def debugger_nop_instruction(self, address: Any) -> dict[str, Any]:
        addr = self._dbg.ParseAddress(address)
        if addr is None:
            return {"ok": False, "error": f"Invalid address: {address}"}
        return self._simple_command(CMD_NOP_INSTRUCTION, f"{addr:016X}")


manager = AnalysisJobManager()
mcp = MCPServer("capesolo") if MCPServer else None

if mcp:
    @mcp.tool()
    def capesolo_analyze_sample(
        sample_path: str,
        package: str = "Auto-detect",
        options: str = "",
        timeout: int = 200,
        enforce_timeout: bool = False,
        run_from_current_directory: bool = True,
        interactive_debug: bool = False,
    ) -> dict[str, Any]:
        """Submit a sample for detonation and return immediately with a job_id.

        Set interactive_debug to halt the sample under the CAPEsolo debugger; that forces
        idbg=1 into the options and a 4 hour timeout, and enables the capesolo_dbg_* tools.
        Pair it with breakpoint options such as "bp0=ep".
        """
        return manager.submit(
            sample_path=sample_path,
            package=package,
            options=options,
            timeout=timeout,
            enforce_timeout=enforce_timeout,
            run_from_current_directory=run_from_current_directory,
            interactive_debug=interactive_debug,
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
        interactive_debug: bool = False,
    ) -> dict[str, Any]:
        """Extract one file from a password-protected ZIP and submit it for detonation."""
        return manager.submit_password_zip(
            zip_path=zip_path,
            zip_password=zip_password,
            package=package,
            options=options,
            timeout=timeout,
            enforce_timeout=enforce_timeout,
            run_from_current_directory=run_from_current_directory,
            archive_member_path=archive_member_path,
            interactive_debug=interactive_debug,
        )


    @mcp.tool()
    def capesolo_get_job_status(job_id: str) -> dict[str, Any]:
        return manager.status(job_id)


    @mcp.tool()
    def capesolo_cancel_job(job_id: str) -> dict[str, Any]:
        return manager.cancel(job_id)


    @mcp.tool()
    def capesolo_get_results(
        job_id: str, include_strings: bool = True, write_file: bool = False
    ) -> dict[str, Any]:
        """Full analysis report: target, behavior, signatures, payloads, yara, configs.

        Computed once per job and cached, so calling this and capesolo_render_html_report
        does not rescan. include_strings=False skips string extraction rather than
        discarding it afterwards. write_file also saves the report the way the GUI's JSON
        button does.
        """
        return manager.get_results(
            job_id, include_strings=include_strings, write_file=write_file
        )


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


    @mcp.tool()
    def capesolo_upload_file(
        filename: str,
        data_base64: str,
        destination: str = "desktop",
        append: bool = False,
        sha256: str = "",
    ) -> dict[str, Any]:
        """Upload a file into the analysis VM and return its guest path.

        destination "desktop" (default) takes samples and accepts any extension.
        destination "custom" writes to Desktop/custom, where CAPEsolo loads custom YARA
        rules (.yar/.yara) and config extractors (.py, named after the YARA rule that hits);
        only those extensions are accepted there.

        For files larger than about 24 MB, split them: call once with append=False, then
        again with append=True for each remaining chunk. Pass sha256 on the final call to
        verify the assembled file; a mismatch discards it.

        Pass the returned path to capesolo_analyze_sample to detonate an uploaded sample.
        """
        return manager.upload_file(
            filename=filename,
            data_base64=data_base64,
            destination=destination,
            append=append,
            sha256=sha256,
        )


    @mcp.tool()
    def capesolo_list_uploads() -> dict[str, Any]:
        """List files on the VM Desktop and in Desktop/custom with sizes and SHA-256 hashes.

        Use it to confirm a chunked upload assembled correctly, or to see which custom YARA
        rules and extractors are currently installed.
        """
        return manager.list_uploads()


    @mcp.tool()
    def capesolo_dbg_status() -> dict[str, Any]:
        """Report whether an interactive debug session is active and where it is halted."""
        return manager.debugger_status()


    @mcp.tool()
    def capesolo_dbg_wait_break(timeout_seconds: float = 120) -> dict[str, Any]:
        """Wait for the target to halt at a breakpoint and return the break payload.

        Call this once after submitting with interactive_debug to catch the first break,
        and again after any tool that returns state "running".
        """
        return manager.debugger_wait_break(timeout_seconds)


    @mcp.tool()
    def capesolo_dbg_step(mode: str = "into", timeout_seconds: float = 120) -> dict[str, Any]:
        """Single-step the halted target. mode is one of into, over, out.

        Returns the new instruction pointer, registers and a short disassembly window.
        """
        return manager.debugger_step(mode, timeout_seconds)


    @mcp.tool()
    def capesolo_dbg_continue(timeout_seconds: float = 120) -> dict[str, Any]:
        """Resume the target until it hits the next breakpoint or the timeout expires."""
        return manager.debugger_continue(timeout_seconds)


    @mcp.tool()
    def capesolo_dbg_run_until(address: str, timeout_seconds: float = 120) -> dict[str, Any]:
        """Resume the target until it reaches address. Addresses are hex, 0x prefix optional."""
        return manager.debugger_run_until(address, timeout_seconds)


    @mcp.tool()
    def capesolo_dbg_get_registers() -> dict[str, Any]:
        """Read the register set of the halted target as both parsed values and raw text."""
        return manager.debugger_registers()


    @mcp.tool()
    def capesolo_dbg_get_stack() -> dict[str, Any]:
        """Read the stack window around the current stack pointer."""
        return manager.debugger_get_stack()


    @mcp.tool()
    def capesolo_dbg_read_memory(address: str, size: int = 256) -> dict[str, Any]:
        """Read up to 16384 bytes of target memory at address and return them as hex."""
        return manager.debugger_read_memory(address, size)


    @mcp.tool()
    def capesolo_dbg_disassemble(address: str = "", count: int = 32) -> dict[str, Any]:
        """Disassemble instructions at address, defaulting to the current instruction pointer."""
        return manager.debugger_disassemble(address, count)


    @mcp.tool()
    def capesolo_dbg_set_breakpoint(address: str, slot: str = "next") -> dict[str, Any]:
        """Set a hardware breakpoint at address. slot is next or a debug register 0-3."""
        return manager.debugger_set_breakpoint(address, slot)


    @mcp.tool()
    def capesolo_dbg_delete_breakpoint(index: int) -> dict[str, Any]:
        """Delete the hardware breakpoint held in debug register index (0-3)."""
        return manager.debugger_delete_breakpoint(index)


    @mcp.tool()
    def capesolo_dbg_list_breakpoints() -> dict[str, Any]:
        """List the hardware breakpoints currently set, with their debug register slots."""
        return manager.debugger_list_breakpoints()


    @mcp.tool()
    def capesolo_dbg_list_modules() -> dict[str, Any]:
        """List the modules loaded in the target with their base addresses, sizes and paths."""
        return manager.debugger_list_modules()


    @mcp.tool()
    def capesolo_dbg_list_threads() -> dict[str, Any]:
        """List the target threads with their start addresses; the current thread is flagged."""
        return manager.debugger_list_threads()


    @mcp.tool()
    def capesolo_dbg_set_register(name: str, value: str) -> dict[str, Any]:
        """Set a register such as RAX or EIP. value accepts decimal or 0x-prefixed hex."""
        return manager.debugger_set_register(name, value)


    @mcp.tool()
    def capesolo_dbg_set_cip(address: str) -> dict[str, Any]:
        """Move the instruction pointer to address, picking EIP or RIP by target bitness."""
        return manager.debugger_set_cip(address)


    @mcp.tool()
    def capesolo_dbg_modify_flag(action: str) -> dict[str, Any]:
        """Set, clear or flip a status flag.

        action is one of SetZeroFlag, ClearZeroFlag, FlipZeroFlag, SetSignFlag,
        ClearSignFlag, FlipSignFlag, SetCarryFlag, ClearCarryFlag, FlipCarryFlag.
        """
        return manager.debugger_modify_flag(action)


    @mcp.tool()
    def capesolo_dbg_patch_bytes(address: str, hex_bytes: str) -> dict[str, Any]:
        """Overwrite target memory at address with the given hex byte string."""
        return manager.debugger_patch_bytes(address, hex_bytes)


    @mcp.tool()
    def capesolo_dbg_nop_instruction(address: str) -> dict[str, Any]:
        """Replace the instruction at address with NOPs."""
        return manager.debugger_nop_instruction(address)


class BearerTokenMiddleware:
    """ASGI middleware requiring a shared bearer token on every request."""

    def __init__(self, app: Any, token: str):
        self.app = app
        self.expected = f"Bearer {token}".encode()

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        supplied = b""
        for name, value in scope.get("headers", []):
            if name.lower() == b"authorization":
                supplied = value
                break

        if not hmac.compare_digest(supplied, self.expected):
            log.warning("Rejected unauthenticated MCP request to %s", scope.get("path", ""))
            await send({"type": "http.response.start", "status": 401, "headers": [(b"content-type", b"text/plain")]})
            await send({"type": "http.response.body", "body": b"Unauthorized"})
            return

        await self.app(scope, receive, send)


def _run_streamable_http(host: str, port: int, path: str, allowed_hosts: list[str], allowed_origins: list[str]) -> None:
    import uvicorn
    from mcp.server.transport_security import TransportSecuritySettings

    token = os.environ.get(MCP_TOKEN_ENV, "").strip()
    if host not in LOOPBACK_HOSTS and not token:
        log.warning(
            "MCP server is bound to %s without %s set. Use a host-only VM network and "
            "never expose this port beyond it: these tools detonate samples and can read "
            "and patch process memory.",
            host,
            MCP_TOKEN_ENV,
        )

    if not allowed_hosts:
        if host == "0.0.0.0":
            log.warning(
                "Binding 0.0.0.0 without [mcp_server] allowed_hosts; the Host header cannot be "
                "derived, so requests will be rejected. Set allowed_hosts to the address clients use."
            )
        else:
            allowed_hosts = [f"{host}:{port}", f"{host}:*"]

    app = mcp.streamable_http_app(
        streamable_http_path=path,
        max_request_body_size=MAX_REQUEST_BODY_SIZE,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts,
            allowed_origins=allowed_origins,
        ),
        host=host,
    )
    if token:
        app = BearerTokenMiddleware(app, token)

    log.info("MCP server listening on http://%s:%s%s (auth: %s)", host, port, path, "bearer token" if token else "none")
    # log_config=None keeps uvicorn from installing its own colorizing formatter, which emits
    # raw ANSI escapes on consoles without VT processing. Its loggers then propagate to the
    # root handler and match the CAPEsolo log format.
    uvicorn.run(app, host=host, port=port, log_level="info", log_config=None)


def main() -> None:
    if not mcp:
        raise ImportError("MCP server requires the 'mcp' package. Install dependencies and retry.")

    settings = _read_mcp_settings()
    parser = argparse.ArgumentParser(description="CAPEsolo MCP server.")
    parser.add_argument(
        "--transport",
        choices=MCP_TRANSPORTS,
        default=settings["transport"],
        help="Transport to serve on (default: %(default)s)",
    )
    parser.add_argument("--host", default=settings["host"], help="Bind address for streamable-http (default: %(default)s)")
    parser.add_argument("--port", type=int, default=settings["port"], help="Bind port for streamable-http (default: %(default)s)")
    parser.add_argument("--path", default=settings["path"], help="HTTP path for streamable-http (default: %(default)s)")
    args = parser.parse_args()

    if not settings["enabled"]:
        msg = "MCP server is disabled. Set [mcp_server] enabled = true in cfg.ini to enable it."
        log.warning(msg)
        print(msg, file=sys.stderr)
        return

    if args.transport == "stdio":
        mcp.run()
        return

    _run_streamable_http(
        host=args.host,
        port=args.port,
        path=args.path,
        allowed_hosts=settings["allowed_hosts"],
        allowed_origins=settings["allowed_origins"],
    )


if __name__ == "__main__":
    main()
