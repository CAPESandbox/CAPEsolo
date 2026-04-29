import logging
import os
import shutil
import zipfile

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import OPT_ARGUMENTS

log = logging.getLogger(__name__)

# CONFIGURATION - allow non installed deno
# Grab a copy of Deno for Windows and store it in extras as deno.zip
DENO_ZIP_NAME = "deno.zip"
DENO_DIR_NAME = "deno"
DENO_EXE_NAME = "deno.exe"
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


def setup_deno_environment(deno_zip_path):
    """
    Attempts to unzip a portable Deno environment.
    Returns: (path_to_deno_exe, None) on success (None, error_message) on failure
    """
    try:
        user_profile = os.environ.get("USERPROFILE", "C:\\Users\\Admin")
        install_path = os.path.join(user_profile, "AppData", "Local", "app")
        deno_bin_path = os.path.join(install_path, DENO_DIR_NAME)

        if not os.path.exists(deno_zip_path):
            return None, f"Zip not found at {deno_zip_path}"

        with zipfile.ZipFile(deno_zip_path, "r") as z:
            file_list = z.namelist()
            deno_internal_path = next((f for f in file_list if f.lower().endswith(DENO_EXE_NAME)), None)
            if not deno_internal_path:
                return None, f"Archive does not contain {DENO_EXE_NAME}"

            deno_exe_path = os.path.normpath(os.path.join(deno_bin_path, deno_internal_path))
            if not os.path.exists(deno_exe_path):
                for member in z.infolist():
                    if member.filename.startswith("/") or ".." in member.filename:
                        return None, f"Aborting extraction. Zip contains potentially malicious path: {member.filename}"
                os.makedirs(deno_bin_path, exist_ok=True)
                log.info("Extracting Deno to %s...", deno_bin_path)
                z.extractall(deno_bin_path)

        if os.path.exists(deno_exe_path):
            deno_dir = os.path.dirname(deno_exe_path)
            current_path = os.environ.get("PATH", "")
            os.environ["PATH"] = f"{deno_dir};{current_path}"
            return deno_exe_path, None
        return None, f"Extraction finished but {DENO_EXE_NAME} not found on disk."

    except (zipfile.BadZipFile, OSError) as e:
        return None, f"Exception during Deno setup: {e}"


class Deno(Package):
    """Package for executing JavaScript files using Deno."""

    PATHS = [
        ("USERPROFILE", ".deno", "bin", "deno.exe"),
        ("ProgramFiles", "Deno", "bin", "deno.exe"),
        ("ProgramFiles(x86)", "Deno", "bin", "deno.exe"),
        ("SystemDrive", "deno", "deno.exe"),
    ]

    summary = "Executes a JS sample using Deno."
    description = "Uses deno.exe to execute JavaScript files."
    option_names = (OPT_ARGUMENTS,)

    def start(self, path):
        path = check_file_extension(path, ".js")
        args = self.options.get(OPT_ARGUMENTS, "")
        target_dir = os.path.dirname(path) or "."
        interceptor_path = os.path.join(target_dir, INTERCEPTOR_NAME)

        deno_args = "run"
        if os.path.exists(interceptor_path):
            deno_args = f'{deno_args} --import-map="{interceptor_path}"'
        else:
            log.warning("Deno interceptor not found at %s. Running without import-map.", interceptor_path)

        if args:
            # Deno runtime flags must precede the script target.
            deno_args = f"{deno_args} {args}".strip()
        deno_args = f'{deno_args} "{path}"'.strip()

        binary = None
        deno_zip_path = resolve_extras_zip(DENO_ZIP_NAME)
        if os.path.exists(deno_zip_path):
            custom_bin, error = setup_deno_environment(deno_zip_path)
            if custom_bin:
                binary = custom_bin
                log.info("Using Custom Deno: %s", binary)
            else:
                log.error("Failed to setup Custom Deno: %s", error)

        if not binary:
            log.info("Falling back to system installed Deno")
            try:
                binary = self.get_path("deno.exe")
            except Exception:
                # PATH lookup for installations outside the hardcoded PATHS list.
                binary = shutil.which("deno.exe")

        if not binary:
            raise Exception("Deno executable not found in custom bundle OR system paths.")

        return self.execute(binary, deno_args, path)
