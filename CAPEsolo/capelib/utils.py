# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import errno
import html
import json
import logging
import os
import re
import string
import time
from io import StringIO
from pathlib import Path
from collections import deque

from markupsafe import Markup, escape

from . import utils_dicts, utils_pretty_print_funcs as pp_funcs
from .path_utils import path_is_dir, path_mkdir

log = logging.getLogger(__name__)
PRINTABLE_CHARACTERS = (
    string.ascii_letters + string.digits + string.punctuation + " \t\r\n"
)
FILENAME_CHARACTERS = (
    string.ascii_letters + string.digits + string.punctuation.replace("/", "") + " "
)

sanitize_len = 32
sanitize_to_len = 24

class Singleton(type):
    """Singleton.
    @see: http://stackoverflow.com/questions/6760685/creating-a-singleton-in-python
    """

    _instances = {}

    def __call__(self, *args, **kwargs):
        if self not in self._instances:
            self._instances[self] = super(Singleton, self).__call__(*args, **kwargs)
        return self._instances[self]


def bytes2str(convert):
    """Converts bytes to string
    @param convert: string as bytes.
    @return: string.
    """
    if isinstance(convert, bytes):
        try:
            convert = convert.decode()
        except UnicodeDecodeError:
            convert = "".join(chr(_) for _ in convert)

        return convert

    if isinstance(convert, bytearray):
        try:
            convert = convert.decode()
        except UnicodeDecodeError:
            convert = "".join(chr(_) for _ in convert)

        return convert

    items = []
    if isinstance(convert, dict):
        tmp_dict = {}
        items = convert.items()
        for k, v in items:
            if isinstance(v, bytes):
                try:
                    tmp_dict[k] = v.decode()
                except UnicodeDecodeError:
                    tmp_dict[k] = "".join(str(ord(_)) for _ in v)
            elif isinstance(v, str):
                tmp_dict[k] = v
        return tmp_dict
    elif isinstance(convert, list):
        converted_list = []
        items = enumerate(convert)
        for k, v in items:
            if isinstance(v, bytes):
                try:
                    converted_list.append(v.decode())
                except UnicodeDecodeError:
                    converted_list.append("".join(str(ord(_)) for _ in v))

        return converted_list

    return convert


def is_printable(s):
    """Test if a string is printable."""
    for c in s:
        if isinstance(c, int):
            c = chr(c)
        if c not in PRINTABLE_CHARACTERS:
            return False
    return True


def convert_char(c):
    """Escapes characters.
    @param c: dirty char.
    @return: sanitized char.
    """
    if isinstance(c, int):
        c = chr(c)
    return c if c in PRINTABLE_CHARACTERS else f"\\x{ord(c):02x}"


def pretty_print_retval(status, retval):
    """Creates pretty-printed versions of an API return value
    @return: pretty-printed version of the call's return value, or None if no conversion exists
    """
    if status:
        return None
    val = None
    try:
        val = int(retval, 16) & 0xFFFFFFFF
    except ValueError:
        return None
    return {
        0x00000103: "NO_MORE_ITEMS",
        0x00002AF9: "WSAHOST_NOT_FOUND",
        0x00002AFC: "WSANO_DATA",
        0x80000005: "BUFFER_OVERFLOW",
        0x80000006: "NO_MORE_FILES",
        0x8000000A: "HANDLES_CLOSED",
        0x8000001A: "NO_MORE_ENTRIES",
        0xC0000001: "UNSUCCESSFUL",
        0xC0000002: "NOT_IMPLEMENTED",
        0xC0000004: "INFO_LENGTH_MISMATCH",
        0xC0000005: "ACCESS_VIOLATION",
        0xC0000008: "INVALID_HANDLE",
        0xC000000B: "INVALID_CID",
        0xC000000D: "INVALID_PARAMETER",
        0xC000000F: "NO_SUCH_FILE",
        0xC0000011: "END_OF_FILE",
        0xC0000018: "CONFLICTING_ADDRESSES",
        0xC0000022: "ACCESS_DENIED",
        0xC0000023: "BUFFER_TOO_SMALL",
        0xC0000024: "OBJECT_TYPE_MISMATCH",
        0xC0000033: "OBJECT_NAME_INVALID",
        0xC0000034: "OBJECT_NAME_NOT_FOUND",
        0xC0000035: "OBJECT_NAME_COLLISION",
        0xC0000039: "OBJECT_PATH_INVALID",
        0xC000003A: "OBJECT_PATH_NOT_FOUND",
        0xC000003C: "DATA_OVERRUN",
        0xC0000043: "SHARING_VIOLATION",
        0xC0000045: "INVALID_PAGE_PROTECTION",
        0xC000007A: "PROCEDURE_NOT_FOUND",
        0xC00000AC: "PIPE_NOT_AVAILABLE",
        0xC00000BA: "FILE_IS_A_DIRECTORY",
        0xC000010A: "PROCESS_IS_TERMINATING",
        0xC0000121: "CANNOT_DELETE",
        0xC0000135: "DLL_NOT_FOUND",
        0xC0000139: "ENTRYPOINT_NOT_FOUND",
        0xC0000142: "DLL_INIT_FAILED",
        0xC000014B: "PIPE_BROKEN",
        0xC0000225: "NOT_FOUND",
    }.get(val)


def simple_pretty_print_convert(argval, enumdict):
    retnames = []
    leftover = argval
    for key, value in enumdict.items():
        if argval & value:
            leftover &= ~value
            retnames.append(key)

    if leftover:
        retnames.append(f"0x{leftover:08x}")

    return "|".join(retnames)


def arg_name_clscontext(arg_val):
    val = int(arg_val, 16)
    enumdict = utils_dicts.ClsContextDict()
    return simple_pretty_print_convert(val, enumdict)


def pretty_print_arg(category, api_name, arg_name, arg_val):
    """Creates pretty-printed versions of API arguments that convert raw values in common APIs to their named-enumeration forms
    @return: pretty-printed version of the argument value provided, or None if no conversion exists
    """
    if api_name == "NtCreateSection" and arg_name == "DesiredAccess":
        return pp_funcs.api_name_ntcreatesection_arg_name_desiredaccess(arg_val)
    elif api_name == "CreateToolhelp32Snapshot" and arg_name == "Flags":
        return pp_funcs.api_name_createtoolhelp32snapshot_arg_name_flags(arg_val)
    elif arg_name == "ClsContext":
        return arg_name_clscontext(arg_val)
    elif arg_name == "BlobType":
        return pp_funcs.blobtype(arg_val)
    elif arg_name == "Algid":
        return pp_funcs.algid(arg_val)
    elif api_name == "SHGetFolderPathW" and arg_name == "Folder":
        return pp_funcs.api_name_shgetfolderpathw_arg_name_folder(arg_val)
    elif arg_name == "HookIdentifier":
        return pp_funcs.hookidentifer(arg_val)
    elif arg_name == "InfoLevel":
        return pp_funcs.infolevel(arg_val)

    elif arg_name == "Disposition":
        return pp_funcs.disposition(arg_val)
    elif arg_name == "CreateDisposition":
        return pp_funcs.createdisposition(arg_val)
    elif arg_name == "ShareAccess":
        return pp_funcs.shareaccess(arg_val)
    elif arg_name == "SystemInformationClass":
        return pp_funcs.systeminformationclass(arg_val)
    elif category == "registry" and arg_name == "Type":
        return pp_funcs.category_registry_arg_name_type(arg_val)
    elif api_name in {"OpenSCManagerA", "OpenSCManagerW"} and arg_name == "DesiredAccess":
        return pp_funcs.api_name_opensc_arg_name_desiredaccess(arg_val)
    elif category == "services" and arg_name == "ControlCode":
        return pp_funcs.category_services_arg_name_controlcode(arg_val)
    elif category == "services" and arg_name == "ErrorControl":
        return pp_funcs.category_services_arg_name_errorcontrol(arg_val)
    elif category == "services" and arg_name == "StartType":
        return pp_funcs.category_services_arg_name_starttype(arg_val)
    elif category == "services" and arg_name == "ServiceType":
        return pp_funcs.category_services_arg_name_servicetype(arg_val)
    elif category == "services" and arg_name == "DesiredAccess":
        return pp_funcs.category_services_arg_name_desiredaccess(arg_val)
    elif category == "registry" and arg_name in {"Access", "DesiredAccess"}:
        return pp_funcs.category_registry_arg_name_access_desired_access(arg_val)
    elif arg_name == "IoControlCode":
        return pp_funcs.arg_name_iocontrolcode(arg_val)
    elif arg_name in {"Protection", "Win32Protect", "NewAccessProtection", "OldAccessProtection", "OldProtection"}:
        return pp_funcs.arg_name_protection_and_others(arg_val)
    elif (
        api_name in ("CreateProcessInternalW", "CreateProcessWithTokenW", "CreateProcessWithLogonW") and arg_name == "CreationFlags"
    ):
        return pp_funcs.api_name_in_creation(arg_val)
    elif api_name in {"MoveFileWithProgressW", "MoveFileWithProgressTransactedW"} and arg_name == "Flags":
        return pp_funcs.api_name_move_arg_name_flags(arg_val)
    elif arg_name == "FileAttributes":
        return pp_funcs.arg_name_fileattributes(arg_val)
    elif (
        api_name in {"NtCreateFile", "NtOpenFile", "NtCreateDirectoryObject", "NtOpenDirectoryObject"}
        and arg_name == "DesiredAccess"
    ):
        return pp_funcs.api_name_nt_arg_name_desiredaccess(arg_val)
    elif api_name == "NtOpenProcess" and arg_name == "DesiredAccess":
        return pp_funcs.api_name_ntopenprocess_arg_name_desiredaccess(arg_val)
    elif api_name == "NtOpenThread" and arg_name == "DesiredAccess":
        return pp_funcs.api_name_ntopenthread_arg_name_desiredaccess(arg_val)
    elif api_name == "CoInternetSetFeatureEnabled" and arg_name == "FeatureEntry":
        return pp_funcs.api_name_cointernet_arg_name_featureentry(arg_val)
    elif api_name == "CoInternetSetFeatureEnabled" and arg_name == "Flags":
        return pp_funcs.api_name_cointernet_arg_name_flags(arg_val)

    elif api_name == "InternetSetOptionA" and arg_name == "Option":
        return pp_funcs.api_name_internetsetoptiona_arg_name_option(arg_val)
    elif api_name in ("socket", "WSASocketA", "WSASocketW"):
        return pp_funcs.api_name_socket(arg_val, arg_name)
    elif arg_name == "FileInformationClass":
        return pp_funcs.arg_name_fileinformationclass(arg_val)
    elif arg_name == "ProcessInformationClass":
        return pp_funcs.arg_name_processinformationclass(arg_val)
    elif arg_name == "ThreadInformationClass":
        return pp_funcs.arg_name_threadinformationclass(arg_val)
    elif arg_name == "MemType":
        return pp_funcs.arg_name_memtype(arg_val)
    elif arg_name == "Show":
        return pp_funcs.arg_name_show(arg_val)
    elif arg_name == "Registry":
        return pp_funcs.arg_name_registry(arg_val)

    return None


def convert_to_printable(s: str, cache=None):
    """Convert char to printable.
    @param s: string.
    @param cache: an optional cache
    @return: sanitized string.
    """
    if isinstance(s, int):
        return str(s)

    if isinstance(s, bytes):
        return bytes2str(s)

    if is_printable(s):
        return s

    if cache is None:
        return "".join(convert_char(c) for c in s)
    elif s not in cache:
        cache[s] = "".join(convert_char(c) for c in s)
    return cache[s]


def create_folder(root=".", folder=None):
    """Create directory.
    @param root: root path.
    @param folder: folder name to be created.
    @raise CuckooOperationalError: if fails to create folder.
    """
    if folder is None:
        return
    folder_path = os.path.join(root, folder)
    if folder and not path_is_dir(folder_path):
        try:
            path_mkdir(folder_path, parent=True)
        except OSError as e:
            if e.errno != errno.EEXIST:
                log.error(f"Unable to create folder: {folder_path}")
        except Exception as e:
            print(e)


def logtime(dt):
    """Formats time like a logger does, for the csv output
       (e.g. "2013-01-25 13:21:44,590")
    @param dt: datetime object
    @return: time string
    """
    t = time.strftime("%Y-%m-%d %H:%M:%S", dt.timetuple())
    return f"{t},{dt.microsecond // 1000:03d}"


def is_sane_filename(s):
    """Test if a filename is sane."""
    for c in s:
        if isinstance(c, int):
            c = chr(c)
        if c not in FILENAME_CHARACTERS:
            return False
    return True


def convert_filename_char(c):
    """Escapes filename characters.
    @param c: dirty char.
    @return: sanitized char.
    """
    if isinstance(c, int):
        c = chr(c)
    return c if c in FILENAME_CHARACTERS else f"\\x{ord(c):02x}"


def sanitize_pathname(s: str):
    """Sanitize filename.
    @param s: string.
    @return: sanitized filename.
    """
    if is_sane_filename(s):
        return s

    return "".join(convert_filename_char(c) for c in s)


def open_exclusive(path, mode="xb"):
    """Open a file with O_EXCL, failing if it already exists
    [In Python 3, use open with x]"""
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    try:
        return os.fdopen(fd, mode)
    except OSError as e:
        log.error(e, "You might need to add whitelist folder in resultserver.py")
        os.close(fd)
        raise


def open_inclusive(path, mode="ab"):
    fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o644)
    try:
        return os.fdopen(fd, mode)
    except OSError as e:
        log.error(e, "You might need to add whitelist folder in resultserver.py")
        os.close(fd)
        raise


def default_converter(v):
    # Fix signed ints (bson is kind of limited there).
    # Need to account for subclasses since pymongo's bson module
    # uses 'bson.int64.Int64' clwhat ass for 64-bit values.
    if isinstance(v, int) or issubclass(type(v), int):
        return v & 0xFFFFFFFFFFFFFFFF if v & 0xFFFFFFFF00000000 else v & 0xFFFFFFFF
    return v


def JsonPathExists(analysisDir):
    filePath = Path(analysisDir) / "files.json"
    if filePath.exists():
        return True


def LoadFilesJson(analysisDir):
    filePath = Path(analysisDir) / "files.json"
    if filePath.exists():
        content = {}
        try:
            for line in open(filePath, "rb"):
                entry = json.loads(line)
                path = entry["path"]
                linePath = Path(analysisDir) / path
                size = linePath.stat().st_size
                content[path] = {
                    "pids": entry.get("pids"),
                    "ppids": entry.get("ppids"),
                    "filepath": entry.get("filepath", ""),
                    "metadata": entry.get("metadata", {}),
                    "category": entry.get("category", ""),
                    "size": size,
                }
            return content
        except Exception as e:
            return {"error": "Corrupt analysis/files.json"}
    else:
        return {"error": "No dump files"}


def sanitize_filename(x):
    """Kind of awful but necessary sanitizing of filenames to
    get rid of unicode problems."""
    while x.startswith(" "):
        x = x.lstrip()
    out = "".join(c if c in string.ascii_letters + string.digits + " _-." else "_" for c in x)

    """Prevent long filenames such as files named by hash
    as some malware checks for this."""
    if len(out) >= sanitize_len:
        out = truncate_filename(out)

    return out


def truncate_filename(x):
    truncated = None
    parts = x.rsplit(".", 1)
    if len(parts) > 1:
        # filename has extension
        extension = parts[1]
        name = parts[0][: (sanitize_to_len - (len(extension) + 1))]
        truncated = f"{name}.{extension}"
    elif len(parts) == 1:
        # no extension
        truncated = parts[0][:sanitize_to_len]

    return truncated


def extract_strings(
    filepath: str = False,
    nulltermonly: bool = False,
    data: bytes = False,
    dedup: bool = False,
    minchars: int = 0,
):
    """Extract strings from analyzed file.
    @return: list of printable strings.
    """
    if filepath:
        p = Path(filepath)
        if not p.exists():
            log.error("Sample file doesn't exist: %s", filepath)
            return
        try:
            data = p.read_bytes()
        except (IOError, OSError) as e:
            log.error("Error reading file: %s", e)
            return

    if not data:
        return

    endlimit = b"8192"
    if nulltermonly:
        apat = b"([\x20-\x7e]{" + str(minchars).encode() + b"," + endlimit + b"})\x00"
        upat = (
            b"((?:[\x20-\x7e][\x00]){"
            + str(minchars).encode()
            + b","
            + endlimit
            + b"})\x00\x00"
        )
    else:
        apat = b"[\x20-\x7e]{" + str(minchars).encode() + b"," + endlimit + b"}"
        upat = (
            b"(?:[\x20-\x7e][\x00]){" + str(minchars).encode() + b"," + endlimit + b"}"
        )

    strings = [bytes2str(string) for string in re.findall(apat, data)]
    strings.extend(str(ws.decode("utf-16le")) for ws in re.findall(upat, data))

    if dedup:
        strings = list(set(strings))

    return strings


def datefmt(value):
    try:
        value = str(value)
        if len(value) < 19:
            return value

        return (
            f"{value[2:6]}/{value[6:8]}/{value[8:10]} "
            f"{value[10:12]}:{value[12:14]}:{value[14:16]} "
            f"GMT{value[16:19]}"
        )
    except Exception:
        return value


def malware_config(obj, level=0):
    """
    Render malware config objects to HTML and return Markup so Jinja doesn't escape tags.

    - dict -> HTML table (recursive)
    - list -> HTML ul (recursive, 4 columns)
      - empty list -> empty string
      - single-item list -> unwrap and render item
    - other -> HTML-escaped string
    """
    buf = StringIO()

    def w(s):
        buf.write(s)

    def esc(x):
        return html.escape("" if x is None else str(x), quote=True)

    def render(value, lvl):
        if isinstance(value, dict):
            if not value:
                return
            w("<table class='table table-sm table-bordered' style='table-layout: fixed;'>")
            w("<tbody>")
            for k, v in value.items():
                w("<tr>")
                w("<th style='width: 25%; vertical-align: top; word-break: break-word;'>")
                w(esc(k))
                w("</th>")
                w("<td style='word-break: break-word;'>")
                render(v, lvl + 1)
                w("</td>")
                w("</tr>")
            w("</tbody>")
            w("</table>")
            return

        if isinstance(value, list):
            if not value:
                return
            if len(value) == 1:
                render(value[0], lvl)
                return

            w("<ul style='margin: 0; columns: 4;'>")
            for item in value:
                w("<li>")
                render(item, lvl + 1)
                w("</li>")
            w("</ul>")
            return

        w(esc(value))

    render(obj, level)
    html_out = buf.getvalue()
    buf.close()

    return Markup(html_out)


def dict2list(value):
    if isinstance(value, dict):
        return [value]
    return value


def getkey(mapping, value):
    if isinstance(mapping, dict):
        return mapping.get(value, "")
    return None


def parentfixup(value):
    if "file_size" in value:
        value["size"] = value["file_size"]
    if "name" not in value:
        value["name"] = value["sha256"]
    return value


def str2list(value):
    if isinstance(value, str):
        return [value]
    return value


def proctreetolist(tree):
    """
    Flatten a process tree into a list with special markers:
      {"startchildren": 1}
      {"endchildren": 1}
    """
    outlist = []
    if not tree:
        return outlist

    stack = deque(tree)

    while stack:
        node = stack.popleft()
        is_special = False

        if isinstance(node, dict) and ("startchildren" in node or "endchildren" in node):
            is_special = True
            outlist.append(node)
        else:
            newnode = {}

            pid = node.get("pid")
            name = node.get("name")
            module_path = node.get("module_path")

            newnode["pid"] = pid
            newnode["name"] = name

            if module_path:
                newnode["module_path"] = module_path

            environ = node.get("environ", {})
            cmdline = environ.get("CommandLine", "") or ""

            if cmdline:
                if cmdline.startswith('"') and cmdline.find('"', 1) == -1:
                    cmdline = cmdline[1:]

                try:
                    if module_path:
                        mp_lower = module_path.lower()

                        if cmdline.startswith('"'):
                            close_idx = cmdline[1:].index('"') + 1
                            argv0 = cmdline[: close_idx + 1].lower()
                            rest = cmdline[close_idx + 1 :].strip()
                            split_rest = rest.split()

                            if mp_lower in argv0:
                                cmdline = " ".join(split_rest).strip()
                            else:
                                cmdline = environ.get("CommandLine", "") or ""

                        else:
                            splitcmdline = cmdline.split()
                            if splitcmdline:
                                argv0 = splitcmdline[0].lower()
                                if mp_lower in argv0:
                                    cmdline = " ".join(splitcmdline[1:]).strip()
                                else:
                                    cmdline = environ.get("CommandLine", "") or ""

                    if len(cmdline) >= 215:
                        cmdline = f"{cmdline[:200]} ...(truncated)"

                    newnode["commandline"] = convert_to_printable(cmdline)

                except Exception as e:
                    print(f"Proctreetolist error: {e}")

            outlist.append(newnode)

        if is_special:
            continue

        children = node.get("children")
        if children:
            stack.appendleft({"endchildren": 1})
            stack.extendleft(reversed(children))
            stack.appendleft({"startchildren": 1})

    return outlist


malware_name_url_pattern = (
    '<a href="/analysis/search/detections:{name}">'
    '<span style="font-weight: bold;">{name}</span>'
    '</a>'
)


def get_detection_by_pid(dictionary, pid):
    """
    Return HTML links for malware detections associated with a PID.

    - dictionary: mapping of PID (as str) -> list of malware names
    - pid: process ID (int or str)

    Returns Markup or None.
    """
    if not dictionary:
        return None

    detections = dictionary.get(str(pid))
    if not detections:
        return None

    links = []
    for name in detections:
        safe_name = escape(name)
        links.append(
            malware_name_url_pattern.format(name=safe_name)
        )

    return Markup(" → ".join(links))
