import logging
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import OPT_ARGUMENTS

log = logging.getLogger(__name__)

# CONFIGURATION - allow non installed bun
# Grab a copy of Bun for Windows and store it in extras as bun.zip
BUN_ZIP_NAME = "bun.zip"
BUN_DIR_NAME = "bun"
BUN_EXE_NAME = "bun.exe"
INTERCEPTOR_NAME = "js_interceptor.js"


def resolve_extras_zip(zip_name):
    candidates = [
        os.path.abspath(os.path.join("extras", zip_name)),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "extras", zip_name)),
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return candidates[0]


def setup_bun_environment(bun_zip_path):
    """
    Attempts to unzip a portable Bun environment.
    Returns: (path_to_bun_exe, None) on success (None, error_message) on failure
    """
    try:
        user_profile = os.environ.get("USERPROFILE", "C:\\Users\\Admin")
        install_path = os.path.join(user_profile, "AppData", "Local", "app")
        bun_bin_path = os.path.join(install_path, BUN_DIR_NAME)

        if not os.path.exists(bun_zip_path):
            return None, f"Zip not found at {bun_zip_path}"

        with zipfile.ZipFile(bun_zip_path, "r") as z:
            file_list = z.namelist()
            bun_internal_path = next((f for f in file_list if f.lower().endswith(BUN_EXE_NAME)), None)
            if not bun_internal_path:
                return None, f"Archive does not contain {BUN_EXE_NAME}"

            bun_exe_path = os.path.normpath(os.path.join(bun_bin_path, bun_internal_path))
            if not os.path.exists(bun_exe_path):
                for member in z.infolist():
                    if member.filename.startswith("/") or ".." in member.filename:
                        return None, f"Aborting extraction. Zip contains potentially malicious path: {member.filename}"
                os.makedirs(bun_bin_path, exist_ok=True)
                log.info("Extracting Bun to %s...", bun_bin_path)
                z.extractall(bun_bin_path)

        if os.path.exists(bun_exe_path):
            bun_dir = os.path.dirname(bun_exe_path)
            current_path = os.environ.get("PATH", "")
            os.environ["PATH"] = f"{bun_dir};{current_path}"
            return bun_exe_path, None
        return None, f"Extraction finished but {BUN_EXE_NAME} not found on disk."

    except (zipfile.BadZipFile, OSError) as e:
        return None, f"Exception during Bun setup: {e}"


def _set_windows_env_var(name, value):
    # Set for current process immediately.
    os.environ[name] = value
    # Persist as a Windows user environment variable.
    try:
        subprocess.run(["setx", name, value], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception as e:
        log.debug("Failed to persist env var %s via setx: %s", name, e)


class Bun(Package):
    """Package for executing JavaScript files using Bun."""

    PATHS = [
        ("USERPROFILE", ".bun", "bin", "bun.exe"),
        ("ProgramFiles", "Bun", "bin", "bun.exe"),
        ("ProgramFiles(x86)", "Bun", "bin", "bun.exe"),
        ("SystemDrive", "bun", "bun.exe"),
    ]

    summary = "Executes a JS sample using Bun."
    description = "Uses bun.exe to execute JavaScript files."
    option_names = (OPT_ARGUMENTS,)

    def start(self, path):
        path = check_file_extension(path, ".js")
        args = self.options.get(OPT_ARGUMENTS, "")
        target_dir = os.path.dirname(path) or "."
        interceptor_path = os.path.join(target_dir, INTERCEPTOR_NAME)
        if os.path.exists(interceptor_path):
            preload_path = Path(interceptor_path).resolve().as_posix()
            _set_windows_env_var("BUN_OPTIONS", f"--preload {preload_path}")
        else:
            log.warning("Bun interceptor not found at %s. Running without preload.", interceptor_path)

        bun_args = ""
        if args:
            # Bun runtime flags must precede the script target.
            bun_args = f"{bun_args} {args}".strip()
        bun_args = f'{bun_args} "{path}"'.strip()

        binary = None
        bun_zip_path = resolve_extras_zip(BUN_ZIP_NAME)
        if os.path.exists(bun_zip_path):
            custom_bin, error = setup_bun_environment(bun_zip_path)
            if custom_bin:
                binary = custom_bin
                log.info("Using Custom Bun: %s", binary)
            else:
                log.error("Failed to setup Custom Bun: %s", error)

        if not binary:
            log.info("Falling back to system installed Bun")
            try:
                binary = self.get_path("bun.exe")
            except Exception:
                # PATH lookup for installations outside the hardcoded PATHS list.
                binary = shutil.which("bun.exe")

        if not binary:
            raise Exception("Bun executable not found in custom bundle OR system paths.")

        log.info(
            "Bun launch env: BUN_OPTIONS=%r interceptor_exists=%s interceptor_path=%s",
            os.environ.get("BUN_OPTIONS", ""),
            os.path.exists(interceptor_path),
            interceptor_path,
        )
        return self.execute(binary, bun_args, path)
