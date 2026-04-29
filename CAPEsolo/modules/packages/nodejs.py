import os
import zipfile
import logging
import shutil
import subprocess

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import OPT_ARGUMENTS

log = logging.getLogger(__name__)

# CONFIGURATION - allow non installed nodejs
# Best practice: Keep filenames in one place
# Grab a copy of https://nodejs.org/download/release/latest-v25.x/node-v25.2.1-win-x64.zip or another version of your interest
# Store it in extras as nodejs.zip
NODE_ZIP_NAME = "nodejs.zip"
NODE_DIR_NAME = "nodejs"
INTERCEPTOR_NAME = "js_interceptor.js"


def _set_windows_env_var(name, value):
    # Set for current process immediately.
    os.environ[name] = value
    # Persist as a Windows user environment variable.
    try:
        subprocess.run(["setx", name, value], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception as e:
        log.debug("Failed to persist env var %s via setx: %s", name, e)


def resolve_extras_zip(zip_name):
    candidates = [
        os.path.abspath(os.path.join("extras", zip_name)),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "extras", zip_name)),
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return candidates[0]


def setup_node_environment(node_zip_path):
    """
    Attempts to unzip a portable Node environment.
    Returns: (path_to_node_exe, None) on success (None, error_message) on failure
    """
    try:
        # Determine paths
        user_profile = os.environ.get("USERPROFILE", "C:\\Users\\Admin")
        install_path = os.path.join(user_profile, "AppData", "Local", "app")

        node_bin_path = os.path.join(install_path, NODE_DIR_NAME)

        if not os.path.exists(node_zip_path):
            return None, f"Zip not found at {node_zip_path}"

        # 1. Open Zip and Find node.exe BEFORE extracting
        with zipfile.ZipFile(node_zip_path, 'r') as z:
            # list of all files in zip
            file_list = z.namelist()

            # Find the internal path to node.exe
            # This works for both "node.exe" (root) and "node-v25.../node.exe" (subfolder)
            node_internal_path = next((f for f in file_list if f.lower().endswith("node.exe")), None)

            if not node_internal_path:
                return None, "Archive does not contain node.exe"

            extract_path = node_bin_path
            node_exe_path = os.path.normpath(os.path.join(extract_path, node_internal_path))
            if not os.path.exists(node_exe_path):
                # Security: Check for path traversal before extraction.
                for member in z.infolist():
                    if member.filename.startswith("/") or ".." in member.filename:
                        return None, f"Aborting extraction. Zip contains potentially malicious path: {member.filename}"

                os.makedirs(extract_path, exist_ok=True)
                log.info("Extracting to %s...", extract_path)
                z.extractall(extract_path)

        # 4. Final Verification and Env Setup
        if node_exe_path and os.path.exists(node_exe_path):
            # Add the folder containing node.exe to PATH
            node_dir = os.path.dirname(node_exe_path)
            current_path = os.environ.get("PATH", "")
            os.environ["PATH"] = f"{node_dir};{current_path}"

            return node_exe_path, None
        else:
            return None, "Extraction finished but node.exe not found on disk."

    except (zipfile.BadZipFile, OSError) as e:
        return None, f"Exception during Node setup: {str(e)}"


class NodeJS(Package):
    """Package for executing JavaScript files using NodeJS."""

    PATHS = [
        # Standard 64-bit Install (most common)
        # Default folder is usually lowercase "nodejs"
        ("ProgramFiles", "nodejs", "node.exe"),

        # 32-bit Node on 64-bit Windows
        ("ProgramFiles(x86)", "nodejs", "node.exe"),

        # Your specific custom paths (Case insensitive, so NodeJS works too)
        ("LOCALAPPDATA", "Programs", "NodeJS", "node.exe"),

        # Fallback for manual installs at root
        ("SystemDrive", "nodejs", "node.exe"),
    ]

    summary = "Executes a JS sample using NodeJS."
    description = "Uses node.exe to execute JavaScript files."
    option_names = (OPT_ARGUMENTS,)

    def start(self, path):
        path = check_file_extension(path, ".js")
        args = self.options.get(OPT_ARGUMENTS, "")
        target_dir = os.path.dirname(path) or "."
        interceptor_path = os.path.join(target_dir, INTERCEPTOR_NAME)

        if os.path.exists(interceptor_path):
            _set_windows_env_var("NODE_OPTIONS", f"--require ./{INTERCEPTOR_NAME}")
        else:
            _set_windows_env_var("NODE_OPTIONS", "")
            log.warning("Node interceptor not found at %s. Running without --require.", interceptor_path)

        node_args = ""
        if args:
            # Node runtime flags must precede the script target.
            node_args = f"{node_args} {args}".strip()
        node_args = f'{node_args} "{path}"'.strip()

        # 1. Try to set up Custom Node
        binary = None

        # Check if the zip exists before trying setup
        node_zip_path = resolve_extras_zip(NODE_ZIP_NAME)
        if os.path.exists(node_zip_path):
            custom_bin, error = setup_node_environment(node_zip_path)
            if custom_bin:
                binary = custom_bin
                log.info("Using Custom Node.js: %s", binary)
            else:
                log.error("Failed to setup Custom Node: %s", error)
                # Do NOT return here, fall through to system node

        # 2. Fallback to System Node if custom failed or zip missing
        if not binary:
            log.info("Falling back to system installed Node.js")
            try:
                binary = self.get_path("node.exe")
            except Exception:
                # PATH lookup for installations outside the hardcoded PATHS list.
                binary = shutil.which("node.exe")

        # 3. Execution
        if not binary:
            raise Exception("Node.js executable not found in custom bundle OR system paths.")

        return self.execute(binary, node_args, path)
