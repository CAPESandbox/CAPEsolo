# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import base64
import contextlib
import logging
import os
import platform
import random
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from ctypes import (
    POINTER,
    byref,
    c_buffer,
    c_int,
    c_ulong,
    c_void_p,
    create_string_buffer,
    sizeof,
    windll,
    ArgumentError,
)
from ctypes.wintypes import BOOL, DWORD, HANDLE
from pathlib import Path
from shutil import copy

from lib.common.defines import (
    CREATE_NEW_CONSOLE,
    CREATE_SUSPENDED,
    EVENT_MODIFY_STATE,
    GENERIC_READ,
    GENERIC_WRITE,
    KERNEL32,
    MAX_PATH,
    NTDLL,
    OPEN_EXISTING,
    PROCESS_ALL_ACCESS,
    PROCESS_BASIC_INFORMATION,
    PROCESS_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESSENTRY32,
    PSAPI,
    STARTUPINFO,
    STILL_ACTIVE,
    SYSTEM_INFO,
    TH32CS_SNAPPROCESS,
    THREAD_ALL_ACCESS,
)

from lib.common.constants import (
    CAPEMON32_NAME,
    CAPEMON64_NAME,
    LOADER32_NAME,
    LOADER64_NAME,
    LOGSERVER_PREFIX,
    PATHS,
    PIPE,
    SHUTDOWN_MUTEX,
    SIDELOADER32_NAME,
    SIDELOADER64_NAME,
    TERMINATE_EVENT,
    TTD32_NAME,
    TTD64_NAME,
)

from lib.common.constants import OPT_CURDIR, OPT_EXECUTIONDIR
from lib.common.errors import get_error_string
from lib.common.rand import random_string
from lib.common.results import upload_to_host
from lib.core.compound import create_custom_folders
from lib.core.config import Config
from lib.core.log import LogServer

# from lib.common.defines import STILL_ACTIVE

# CSIDL constants
CSIDL_WINDOWS = 0x0024
CSIDL_SYSTEM = 0x0025
CSIDL_SYSTEMX86 = 0x0029
CSIDL_PROGRAM_FILES = 0x0026
CSIDL_PROGRAM_FILESX86 = 0x002A

IOCTL_PID = 0x222008
IOCTL_CUCKOO_PATH = 0x22200C
PATH_KERNEL_DRIVER = "\\\\.\\DriverSSDT"

LOGSERVER_POOL = {}

log = logging.getLogger(__name__)

# Define function return types
KERNEL32.GetCurrentProcess.restype = HANDLE
KERNEL32.OpenProcess.restype = HANDLE
KERNEL32.OpenProcess.argtypes = [DWORD, BOOL, DWORD]
KERNEL32.OpenThread.restype = HANDLE
KERNEL32.OpenThread.argtypes = [DWORD, BOOL, DWORD]
KERNEL32.GetLastError.restype = DWORD


def is_os_64bit():
    return platform.machine().endswith("64")


def get_referrer_url(interest):
    """Get a Google referrer URL
    @return: URL to be added to the analysis config
    """

    if "://" not in interest:
        return ""

    escapedurl = urllib.parse.quote(interest, "")
    itemidx = random.randint(1, 30)
    vedstr = b"0CCEQfj" + base64.urlsafe_b64encode(random_string(random.randint(5, 8) * 3).encode())
    eistr = base64.urlsafe_b64encode(random_string(12).encode())
    usgstr = b"AFQj" + base64.urlsafe_b64encode(random_string(12).encode())
    return f"http://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd={itemidx}&ved={vedstr}&url={escapedurl}&ei={eistr}&usg={usgstr}"


def nt_path_to_dos_path_ansi(nt_path: str) -> str:
    drive_letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    nt_path_bytes = nt_path.encode("utf-8", errors="ignore")
    for letter in drive_letters:
        drive = f"{letter}:"
        target = create_string_buffer(1024)
        res = KERNEL32.QueryDosDeviceA(drive.encode("ascii"), target, 1024)
        if res != 0:
            device_path = target.value
            if nt_path_bytes.startswith(device_path):
                converted = nt_path_bytes.replace(device_path, drive.encode("ascii"), 1)
                return converted.decode("utf-8", errors="ignore")
    return nt_path


def NT_SUCCESS(val):
    return val >= 0


class Process:
    """Windows process."""

    process_num = 0
    # This adds 1 up to 30 times of 20 minutes to the startup
    # time of the process, therefore bypassing anti-vm checks
    # which check whether the VM has only been up for <10 minutes.
    startup_time = random.randint(1, 30) * 20 * 60 * 1000

    def __init__(
        self,
        options=None,
        config=None,
        pid=0,
        h_process=0,
        thread_id=0,
        h_thread=0,
        suspended=False,
    ):
        """@param pid: PID.
        @param h_process: process handle.
        @param thread_id: thread id.
        @param h_thread: thread handle.
        """
        if options is None:
            options = {}
        self.config = config
        self.options = options
        self.pid = pid
        self.h_process = HANDLE(h_process)
        self.thread_id = thread_id
        self.h_thread = HANDLE(h_thread)
        self.suspended = suspended
        self.system_info = SYSTEM_INFO()
        self.critical = False
        self.path = None

    def __del__(self):
        """Close open handles."""
        if hasattr(self, "h_process") and self.h_process != KERNEL32.GetCurrentProcess():
            KERNEL32.CloseHandle(self.h_process)
        if hasattr(self, "h_thread") and self.h_thread != 0:
            KERNEL32.CloseHandle(self.h_thread)

    def fill_system_info(self):
        """Get system information."""
        KERNEL32.GetSystemInfo(byref(self.system_info))

    def open(self):
        """Open a process and/or thread.
        @return: operation status.
        """
        ret = bool(self.pid or self.thread_id)
        if self.pid and not self.h_process:
            if self.pid == os.getpid():
                self.h_process = KERNEL32.GetCurrentProcess()
            else:
                self.h_process = KERNEL32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
                if not self.h_process:
                    self.h_process = KERNEL32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, self.pid)
            ret = True

        if self.thread_id and not self.h_thread:
            self.h_thread = KERNEL32.OpenThread(THREAD_ALL_ACCESS, False, self.thread_id)
            ret = True
        return ret

    def close(self):
        """Close any open handles.
        @return: operation status.
        """
        ret = bool(self.h_process or self.h_thread)

        if self.h_process:
            ret = NT_SUCCESS(KERNEL32.CloseHandle(self.h_process))
            self.h_process = None

        if self.h_thread:
            ret = NT_SUCCESS(KERNEL32.CloseHandle(self.h_thread))
            self.h_thread = None

        return ret

    def exit_code(self):
        """Get process exit code.
        @return: exit code value.
        """
        if not self.h_process:
            self.open()

        exit_code = c_ulong(0)
        KERNEL32.GetExitCodeProcess(self.h_process, byref(exit_code))

        return exit_code.value

    def get_filepath(self):
        """Get process image file path.
        @return: decoded file path.
        """
        if not self.h_process:
            self.open()

        pbi = create_string_buffer(1024)
        size = c_ulong()

        # Set return value to signed 32bit integer.
        NTDLL.NtQueryInformationProcess.restype = c_int

        ret = NTDLL.NtQueryInformationProcess(self.h_process, 27, byref(pbi), sizeof(pbi), byref(size))

        if NT_SUCCESS(ret) and size.value > 16:
            try:
                fbuf = pbi.raw[16 : size.value]
                return fbuf.decode("utf16", errors="ignore").rstrip("\x00")
            except Exception as e:
                log.info(e)

        return ""

    def get_folder_path(self, csidl):
        """Use SHGetFolderPathW to get the system folder path for a given CSIDL."""
        buf = create_string_buffer(MAX_PATH)
        windll.shell32.SHGetFolderPathA(None, csidl, None, 0, buf)
        return buf.value.decode("utf-8", errors="ignore")

    def get_image_name(self):
        """Get the image name; returns an empty string on error."""
        if not self.h_process:
            self.open()
        ret = ""
        image_name_buf = c_buffer(MAX_PATH)
        n = PSAPI.GetProcessImageFileNameA(self.h_process, image_name_buf, MAX_PATH)
        if not n:
            log.debug("Failed getting image name for pid %d", self.pid)
            return ret
        image_name = image_name_buf.value.decode()
        return image_name.split("\\")[-1]

    def is_alive(self):
        """Process is alive?
        @return: process status.
        """
        return self.exit_code() == STILL_ACTIVE

    def is_critical(self):
        """Determines if process is 'critical' or not, so we can prevent terminating it"""
        if not self.h_process:
            self.open()

        val = c_ulong(0)
        retlen = c_ulong(0)
        ret = NTDLL.NtQueryInformationProcess(self.h_process, 29, byref(val), sizeof(val), byref(retlen))
        if NT_SUCCESS(ret) and val.value:
            return True
        return False

    def get_parent_pid(self):
        """Get the Parent Process ID."""
        if not self.h_process:
            self.open()

        pbi = PROCESS_BASIC_INFORMATION()
        size = c_ulong()

        # Set return value to signed 32bit integer.
        NTDLL.NtQueryInformationProcess.restype = c_int
        NTDLL.NtQueryInformationProcess.argtypes = [
            HANDLE,
            c_int,
            c_void_p,
            c_ulong,
            POINTER(c_ulong),
        ]

        ret = NTDLL.NtQueryInformationProcess(self.h_process, 0, byref(pbi), sizeof(pbi), byref(size))

        if NT_SUCCESS(ret) and size.value == sizeof(pbi):
            return pbi.InheritedFromUniqueProcessId

        return None

    def detect_dll_sideloading(self, directory_path: str) -> bool:
        """Detect potential DLL sideloading in the provided directory."""
        try:
            directory = Path(directory_path)
            if not directory.is_dir():
                return False

            if (directory / "capemon.dll").exists():
                return False

            # Early exit if directory is a known system location
            try:
                system_dirs = {
                    Path(self.get_folder_path(CSIDL_WINDOWS)).resolve(),
                    Path(self.get_folder_path(CSIDL_SYSTEM)).resolve(),
                    Path(self.get_folder_path(CSIDL_SYSTEMX86)).resolve(),
                    Path(self.get_folder_path(CSIDL_PROGRAM_FILES)).resolve(),
                    Path(self.get_folder_path(CSIDL_PROGRAM_FILESX86)).resolve(),
                }
                if directory.resolve() in system_dirs:
                    return False
            except (OSError, ArgumentError, ValueError) as e:
                log.warning("detect_dll_sideloading: failed to retrieve system paths: %s", e)
                return False

            try:
                local_dlls = {f.name.lower() for f in directory.glob("*.dll") if f.is_file()}
                if not local_dlls:
                    return False
            except (OSError, PermissionError) as e:
                log.warning("detect_dll_sideloading: could not list DLLs in %s: %s", directory_path, e)
                return False

            # Build set of known system DLLs
            known_dlls = set()
            for sys_dir in system_dirs:
                try:
                    if sys_dir.exists():
                        known_dlls.update(f.name.lower() for f in sys_dir.glob("*.dll") if f.is_file())
                except (OSError, PermissionError) as e:
                    log.debug("detect_dll_sideloading: skipping system dir %s: %s", sys_dir, e)

            suspicious = local_dlls & known_dlls
            if suspicious:
                for dll in suspicious:
                    log.info("Potential dll side-loading detected in local directory: %s", dll)
            return bool(suspicious)

        except Exception as e:
            log.error("detect_dll_sideloading: unexpected error with path %s: %s", directory_path, e)
            return False

    def kernel_analyze(self):
        """zer0m0n kernel analysis"""
        log.info("Starting kernel analysis")
        log.info("Installing driver")
        if is_os_64bit():
            sys_file = os.path.join(Path.cwd(), "dll", "zer0m0n_x64.sys")
        else:
            sys_file = os.path.join(Path.cwd(), "dll", "zer0m0n.sys")
        exe_file = os.path.join(Path.cwd(), "dll", "logs_dispatcher.exe")
        if not os.path.isfile(sys_file) or not os.path.isfile(exe_file):
            log.warning(
                "No valid zer0m0n files to be used for process with pid %d, injection aborted",
                self.pid,
            )
            return False

        exe_name = service_name = driver_name = random_string(6)

        inf_data = (
            "[Version]\r\n"
            'Signature = "$Windows NT$"\r\n'
            'Class = "ActivityMonitor"\r\n'
            "ClassGuid = {{b86dff51-a31e-4bac-b3cf-e8cfe75c9fc2}}\r\n"
            "Provider = %Prov%\r\n"
            "DriverVer = 22/01/2014,1.0.0.0\r\n"
            "CatalogFile = %DriverName%.cat\r\n"
            "[DestinationDirs]\r\n"
            "DefaultDestDir = 12\r\n"
            "MiniFilter.DriverFiles = 12\r\n"
            "[DefaultInstall]\r\n"
            "OptionDesc = %ServiceDescription%\r\n"
            "CopyFiles = MiniFilter.DriverFiles\r\n"
            "[DefaultInstall.Services]\r\n"
            "AddService = %ServiceName%,,MiniFilter.Service\r\n"
            "[DefaultUninstall]\r\n"
            "DelFiles = MiniFilter.DriverFiles\r\n"
            "[DefaultUninstall.Services]\r\n"
            "DelService = %ServiceName%,0x200\r\n"
            "[MiniFilter.Service]\r\n"
            "DisplayName = %ServiceName%\r\n"
            "Description = %ServiceDescription%\r\n"
            "ServiceBinary = %12%\\%DriverName%.sys\r\n"
            'Dependencies = "FltMgr"\r\n'
            "ServiceType = 2\r\n"
            "StartType = 3\r\n"
            "ErrorControl = 1\r\n"
            'LoadOrderGroup = "FSFilter Activity Monitor"\r\n'
            "AddReg = MiniFilter.AddRegistry\r\n"
            "[MiniFilter.AddRegistry]\r\n"
            'HKR,,"DebugFlags",0x00010001 ,0x0\r\n'
            'HKR,"Instances","DefaultInstance",0x00000000,%DefaultInstance%\r\n'
            'HKR,"Instances\\"%Instance1.Name%,"Altitude",0x00000000,%Instance1.Altitude%\r\n'
            'HKR,"Instances\\"%Instance1.Name%,"Flags",0x00010001,%Instance1.Flags%\r\n'
            "[MiniFilter.DriverFiles]\r\n"
            "%DriverName%.sys\r\n"
            "[SourceDisksFiles]\r\n"
            f"{driver_name}.sys = 1,,\r\n"
            "[SourceDisksNames]\r\n"
            "1 = %DiskId1%,,,\r\n"
            "[Strings]\r\n"
            f'Prov = "{random_string(8)}"\r\n'
            f'ServiceDescription = "{random_string(12)}"\r\n'
            f'ServiceName = "{service_name}"\r\n'
            f'DriverName = "{driver_name}"\r\n'
            f'DiskId1 = "{service_name} Device Installation Disk"\r\n'
            f'DefaultInstance = "{service_name} Instance"\r\n'
            f'Instance1.Name = "{service_name} Instance"\r\n'
            'Instance1.Altitude = "370050"\r\n'
            "Instance1.Flags = 0x0"
        )

        new_inf = os.path.join(Path.cwd(), "dll", f"{service_name}.inf")
        new_sys = os.path.join(Path.cwd(), "dll", f"{driver_name}.sys")
        copy(sys_file, new_sys)
        new_exe = os.path.join(Path.cwd(), "dll", f"{exe_name}.exe")
        copy(exe_file, new_exe)
        log.info("[-] Driver name : %s", new_sys)
        log.info("[-] Inf name : %s", new_inf)
        log.info("[-] Application name : %s", new_exe)
        log.info("[-] Service : %s", service_name)

        _ = Path(new_inf).write_text(inf_data)
        os_is_64bit = is_os_64bit()
        if os_is_64bit:
            wow64 = c_ulong(0)
            KERNEL32.Wow64DisableWow64FsRedirection(byref(wow64))

        os.system(f'cmd /c "rundll32 setupapi.dll, InstallHinfSection DefaultInstall 132 {new_inf}"')
        os.system(f"net start {service_name}")

        si = STARTUPINFO()
        si.cb = sizeof(si)
        pi = PROCESS_INFORMATION()
        cr = CREATE_NEW_CONSOLE

        ldp = KERNEL32.CreateProcessW(
            new_exe,
            None,
            None,
            None,
            None,
            cr,
            None,
            os.getenv("TEMP"),
            byref(si),
            byref(pi),
        )
        if not ldp:
            if os_is_64bit:
                KERNEL32.Wow64RevertWow64FsRedirection(wow64)
            log.error("Failed starting %s.exe", exe_name)
            return False

        config_path = os.path.join(os.getenv("TEMP"), f"{self.pid}.ini")
        cfg = Config("analysis.conf")
        with open(config_path, "w") as config:
            config.write(f"host-ip={cfg.ip}\n")
            config.write(f"host-port={cfg.port}\n")
            config.write(f"pipe={PIPE}\n")

        log.info("Sending startup information")
        hFile = KERNEL32.CreateFileW(
            PATH_KERNEL_DRIVER,
            GENERIC_READ | GENERIC_WRITE,
            0,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        if os_is_64bit:
            KERNEL32.Wow64RevertWow64FsRedirection(wow64)
        if hFile:
            p = Process(pid=os.getpid())
            ppid = p.get_parent_pid()
            pid_vboxservice = 0
            pid_vboxtray = 0

            # get pid of VBoxService.exe and VBoxTray.exe
            proc_info = PROCESSENTRY32()
            proc_info.dwSize = sizeof(PROCESSENTRY32)

            snapshot = KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            flag = KERNEL32.Process32First(snapshot, byref(proc_info))
            while flag:
                if proc_info.sz_exeFile == "VBoxService.exe":
                    log.info("VBoxService.exe found!")
                    pid_vboxservice = proc_info.th32ProcessID
                elif proc_info.sz_exeFile == "VBoxTray.exe":
                    pid_vboxtray = proc_info.th32ProcessID
                    log.info("VBoxTray.exe found!")
                flag = KERNEL32.Process32Next(snapshot, byref(proc_info))
            bytes_returned = c_ulong(0)
            msg = f"{self.pid}_{ppid}_{os.getpid()}_{pi.dwProcessId}_{pid_vboxservice}_{pid_vboxtray}\0"
            KERNEL32.DeviceIoControl(hFile, IOCTL_PID, msg, len(msg), None, 0, byref(bytes_returned), None)
            msg = f"{Path.cwd()}\0"
            KERNEL32.DeviceIoControl(
                hFile,
                IOCTL_CUCKOO_PATH,
                msg,
                len(msg),
                None,
                0,
                byref(bytes_returned),
                None,
            )
        else:
            log.warning("Failed to access kernel driver")

        return True

    def execute(self, path, args=None, suspended=False, kernel_analysis=False):
        """Execute sample process.
        @param path: sample path.
        @param args: process args.
        @param suspended: is suspended.
        @return: operation status.
        """
        if not os.access(path, os.X_OK):
            log.error('Unable to access file at path "%s", execution aborted', path)
            return False

        startup_info = STARTUPINFO()
        startup_info.cb = sizeof(startup_info)
        # STARTF_USESHOWWINDOW
        startup_info.dwFlags = 1
        # SW_SHOWNORMAL
        startup_info.wShowWindow = 1
        process_info = PROCESS_INFORMATION()

        arguments = f'"{path}" '
        if args:
            arguments += args

        self.path = path

        creation_flags = CREATE_NEW_CONSOLE
        if suspended:
            self.suspended = True
            creation_flags += CREATE_SUSPENDED

        # Use the custom execution directory if provided, otherwise launch in the same location
        # where the sample resides (default %TEMP%)
        if OPT_EXECUTIONDIR in self.options.keys():
            execution_directory = self.options[OPT_EXECUTIONDIR]
        elif OPT_CURDIR in self.options.keys():
            execution_directory = self.options[OPT_CURDIR]
        else:
            execution_directory = os.getenv("TEMP")

        # Try to create the custom directories so that the execution path is deemed valid
        create_custom_folders(execution_directory)

        created = KERNEL32.CreateProcessW(
            path,
            arguments,
            None,
            None,
            None,
            creation_flags,
            None,
            execution_directory,
            byref(startup_info),
            byref(process_info),
        )

        if created:
            self.pid = process_info.dwProcessId
            self.h_process = process_info.hProcess
            self.thread_id = process_info.dwThreadId
            self.h_thread = process_info.hThread
            log.info(
                'Successfully executed process from path "%s" with arguments "%s" with pid %d',
                path,
                args or "",
                self.pid,
            )
            if kernel_analysis:
                return self.kernel_analyze()
            return True
        else:
            log.error(
                'Failed to execute process from path "%s" with arguments "%s" (Error: %s)',
                path,
                args,
                get_error_string(KERNEL32.GetLastError()),
            )
            return False

    def resume(self):
        """Resume a suspended thread.
        @return: operation status.
        """
        if not self.suspended:
            log.warning("The process with pid %d was not suspended at creation", self.pid)
            return False

        if not self.h_thread:
            return False

        KERNEL32.Sleep(2000)

        if KERNEL32.ResumeThread(self.h_thread) != -1:
            self.suspended = False
            log.info("Successfully resumed process with pid %d", self.pid)
            return True
        else:
            log.error("Failed to resume process with pid %d", self.pid)
            return False

    def ttd_stop(self):
        """Time Travel Debugging stop"""

        if not self.pid:
            return False

        if self.is_64bit():
            ttd_name = "bin\\TTD.exe"
            bit_str = "64-bit"
        else:
            ttd_name = "bin\\wow64\\TTD.exe"
            bit_str = "32-bit"

        try:
            result = subprocess.run(
                [
                    os.path.join(Path.cwd(), ttd_name),
                    "-accepteula",
                    "-stop",
                    str(self.pid),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=1,
            )
        except subprocess.TimeoutExpired as e:
            if e.stdout:
                log.info(" ".join(e.stdout.split()))
            if e.stderr:
                log.error(" ".join(e.stderr.split()))
        except Exception as e:
            log.error(
                "Exception attempting TTD stop for %s process with pid %d: %s",
                bit_str,
                self.pid,
                e,
            )

        if result.stdout:
            log.info(" ".join(result.stdout.split()))
        if result.stderr:
            log.error(" ".join(result.stderr.split()))

        log.info("Stopped TTD for %s process with pid %d", bit_str, self.pid)

        return True

    def set_terminate_event(self):
        """Sets the termination event for the process."""
        if self.h_process == 0:
            self.open()

        event_name = TERMINATE_EVENT + str(self.pid)
        self.terminate_event_handle = KERNEL32.OpenEventW(EVENT_MODIFY_STATE, False, event_name)
        if self.terminate_event_handle:
            # make sure process is aware of the termination
            KERNEL32.SetEvent(self.terminate_event_handle)
            log.info("Terminate event set for process %d", self.pid)
            KERNEL32.CloseHandle(self.terminate_event_handle)
        else:
            log.error("Failed to open terminate event for pid %d", self.pid)
            return

        # recreate event for monitor 'reply'
        self.terminate_event_handle = KERNEL32.CreateEventW(0, False, False, event_name)
        if not self.terminate_event_handle:
            log.error("Failed to create terminate-reply event for process %d", self.pid)
            return

        KERNEL32.WaitForSingleObject(self.terminate_event_handle, 5000)
        log.info("Termination confirmed for process %d", self.pid)
        KERNEL32.CloseHandle(self.terminate_event_handle)

        try:
            ttd = int(self.options.get("ttd", 0))
        except (ValueError, TypeError):
            ttd = 0

    def terminate(self):
        """Terminate process.
        @return: operation status.
        """
        if self.h_process == 0:
            self.open()

        if KERNEL32.TerminateProcess(self.h_process, 1):
            log.info("Successfully terminated process with pid %d", self.pid)
            return True
        else:
            log.error("Failed to terminate process with pid %d", self.pid)
            return False

    def is_64bit(self):
        """Determines if a process is 64bit.
        @return: True if 64bit, False if not
        """
        if self.h_process == 0:
            self.open()

        with contextlib.suppress(Exception):
            val = c_int(0)
            ret = KERNEL32.IsWow64Process(self.h_process, byref(val))
            if ret and not val.value and is_os_64bit():
                return True
        return False

    def write_monitor_config(self, interest=None, nosleepskip=False):

        config_path = os.path.join(Path.cwd(), "dll", f"{self.pid}.ini")
        log.info("Monitor config for process %s: %s", self.pid, config_path)

        # start the logserver for this monitored process
        logserver_path = f"{LOGSERVER_PREFIX}{self.pid}"
        if logserver_path not in LOGSERVER_POOL:
            LOGSERVER_POOL[logserver_path] = LogServer(self.config.ip, self.config.port, logserver_path)

        if "tlsdump" not in self.options:
            Process.process_num += 1
        firstproc = Process.process_num == 1

        with open(config_path, "w", encoding="utf-8") as config:
            config.write(f"host-ip={self.config.ip}\n")
            config.write(f"host-port={self.config.port}\n")
            config.write(f"pipe={PIPE}\n")
            config.write(f"logserver={logserver_path}\n")
            config.write(f"results={PATHS['root']}\n")
            config.write(f"analyzer={Path.cwd()}\n")
            config.write(f"pythonpath={os.path.dirname(sys.executable)}\n")
            config.write(f"first-process={1 if firstproc else 0}\n")
            config.write(f"startup-time={Process.startup_time}\n")
            config.write(f"file-of-interest={interest}\n")
            config.write(f"shutdown-mutex={SHUTDOWN_MUTEX}\n")
            config.write(f"terminate-event={TERMINATE_EVENT}{self.pid}\n")

            if nosleepskip or (
                "force-sleepskip" not in self.options and len(interest) > 2 and interest[:2] != "\\:" and Process.process_num <= 2
            ):
                config.write("force-sleepskip=0\n")

            if "norefer" not in self.options and "referrer" not in self.options:
                config.write(f"referrer={get_referrer_url(interest)}\n")

            server_options = [
                "dll",
                "dll_64",
                "loader",
                "loader_64",
                "route",
                "nohuman",
                "main_task_id",
                "function",
                "file",
                "free",
                "auto",
                "pre_script_args",
                "pre_script_timeout",
                "during_script_args",
                "ttd",
            ]

            for optname, option in self.options.items():
                if optname not in server_options:
                    config.write(f"{optname}={option}\n")
                    log.info("Option '%s' with value '%s' sent to monitor", optname, option)

    def inject(self, interest=None, nosleepskip=False):
        """Cuckoo DLL injection.
        @param interest: path to file of interest, handed to cuckoomon config
        @param nosleepskip: skip sleep or not
        """
        global LOGSERVER_POOL

        if not self.pid:
            return False

        thread_id = self.thread_id or 0
        if not self.is_alive():
            log.warning("The process with pid %d is not alive, injection aborted", self.pid)
            return False

        if self.is_64bit():
            ttd_name = TTD64_NAME
            bin_name = LOADER64_NAME
            dll = CAPEMON64_NAME
            bit_str = "64-bit"
            side_dll = SIDELOADER64_NAME
        else:
            ttd_name = TTD32_NAME
            bin_name = LOADER32_NAME
            dll = CAPEMON32_NAME
            bit_str = "32-bit"
            side_dll = SIDELOADER32_NAME

        bin_name = os.path.join(Path.cwd(), bin_name)
        dll = os.path.join(Path.cwd(), dll)

        if not os.path.exists(bin_name):
            log.warning(
                "Invalid loader path %s for injecting DLL in process with pid %d, injection aborted",
                bin_name,
                self.pid,
            )
            log.error(
                "Please ensure the %s loader is in analyzer/windows/bin in order to analyze %s binaries",
                bit_str,
                bit_str,
            )
            return False

        if not os.path.exists(dll):
            log.warning(
                "Invalid path %s for monitor DLL to be injected in process with pid %d, injection aborted",
                dll,
                self.pid,
            )
            return False

        ttd = int(self.options.get("ttd", 0))
        if ttd:
            self.options["no-iat"] = 1

        self.write_monitor_config(interest, nosleepskip)

        path = os.path.dirname(nt_path_to_dos_path_ansi(self.get_filepath()))

        if self.detect_dll_sideloading(path) and self.has_msimg32(path):
            self.deploy_version_proxy(path)
            return True

        if self.detect_dll_sideloading(path):
            try:
                copy(dll, os.path.join(path, "capemon.dll"))
                copy(side_dll, os.path.join(path, "version.dll"))
                copy(os.path.join(Path.cwd(), "dll", f"{self.pid}.ini"), os.path.join(path, "config.ini"))
            except OSError as e:
                log.error("Failed to copy DLL: %s", e)
                return False
            log.info(
                "%s DLL to sideload is %s, sideloader %s",
                bit_str,
                os.path.join(path, "capemon.dll"),
                os.path.join(path, "version.dll"),
            )
            return True

        log.info("%s DLL to inject is %s, loader %s", bit_str, dll, bin_name)

        try:
            ret = subprocess.run([bin_name, "inject", str(self.pid), str(thread_id), dll])

            if ret.returncode == 1:
                log.info("Injected into %s %s", bit_str, self)
            elif ret.returncode != 0:
                log.error(
                    "Unable to inject into %s process with pid %d, error: %d",
                    bit_str,
                    self.pid,
                    ret.returncode,
                )
        except Exception as e:
            log.error("Error running process: %s", e)
            return False

        if not ttd:
            return True

        try:
            subprocess.run(
                [
                    os.path.join(Path.cwd(), ttd_name),
                    "-accepteula",
                    "-out",
                    os.path.join(PATHS["TTD"], f"{self.pid}.run"),
                    "-attach",
                    str(self.pid),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=1,
            )
        except subprocess.TimeoutExpired as e:
            if e.stdout:
                log.info(" ".join(e.stdout.split()))
            if e.stderr:
                log.error(" ".join(e.stderr.split()))
        except Exception as e:
            log.error(
                "Exception attempting TTD injection into %s process with pid %d: %s",
                bit_str,
                self.pid,
                e,
            )

        return True

    def upload_memdump(self):
        """Upload process memory dump.
        @return: operation status.
        """
        if not self.pid:
            log.warning("No valid pid specified, memory dump cannot be uploaded")
            return False

        file_path = os.path.join(PATHS["memory"], f"{self.pid}.dmp")
        try:
            upload_to_host(file_path, os.path.join("memory", f"{self.pid}.dmp"), category="memory")
        except Exception as e:
            log.error(e, exc_info=True)
            log.error(os.path.join("memory", f"{self.pid}.dmp"))
            log.error(file_path)
        log.info("Memory dump of process %d uploaded", self.pid)

        return True

    def __str__(self):
        """Get a string representation of this process."""
        image_name = self.get_image_name() or "???"
        return f"<{self.__class__.__name__} {self.pid} {image_name}>"

    def has_msimg32(self, directory_path: str) -> bool:
        """Check if msimg32.dll exists in directory"""
        try:
            return any(f.name.lower() == "msimg32.dll" for f in Path(directory_path).glob("*") if f.is_file())
        except (OSError, PermissionError):
            return False

    def deploy_version_proxy(self, directory_path: str):
        """Deploy version.dll proxy loader"""
        if self.is_64bit():
            dll = CAPEMON64_NAME
            side_dll = SIDELOADER64_NAME
            bit_str = "64-bit"
        else:
            dll = CAPEMON32_NAME
            side_dll = SIDELOADER32_NAME
            bit_str = "32-bit"

        dll = os.path.join(Path.cwd(), dll)

        if not os.path.exists(dll):
            log.warning("invalid path %s for monitor DLL to be sideloaded in %s, sideloading aborted", dll, self)
            return

        try:
            copy(dll, os.path.join(directory_path, "capemon.dll"))
            copy(side_dll, os.path.join(directory_path, "version.dll"))
            copy(os.path.join(Path.cwd(), "dll", f"{self.pid}.ini"), os.path.join(directory_path, "config.ini"))
        except OSError as e:
            log.error("Failed to copy DLL: %s", e)
            return
        log.info(
            "%s DLL to sideload is %s, sideloader %s",
            bit_str,
            os.path.join(directory_path, "capemon.dll"),
            os.path.join(directory_path, "version.dll"),
        )
        return
