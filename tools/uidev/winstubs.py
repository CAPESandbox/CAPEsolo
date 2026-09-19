"""Fake out the Windows-only / heavyweight imports so CAPEsolo's panels load under GTK.

The GUI modules pull in pywin32, bson, gevent's result server, sflock and friends at
import time. None of that is reachable from the Linux dev box and none of it is involved
in layout, so unresolvable third-party imports are answered with a permissive stub: any
attribute lookup returns another stub, and calling one returns a stub too.

Import this module and call install() before anything from CAPEsolo.
"""

import importlib.machinery
import os
import sys
import tempfile
import types
from pathlib import Path


class _StubMeta(type):
    """Metaclass so a stub attribute is usable as a base class, a callable and a value."""

    def __getattr__(cls, item):
        if item.startswith("__") and item.endswith("__"):
            raise AttributeError(item)
        return stub_class(f"{cls.__name__}.{item}")

    def __bool__(cls):
        return False

    def __iter__(cls):
        return iter(())


def stub_class(name):
    """A class that can be instantiated, called, subclassed or read from, endlessly.

    Attribute access has to hand back something subclassable, not another module: several
    CAPEsolo modules declare `class X(gevent.server.StreamServer)` at import time, and a
    module object in the bases list fails before any of the layout code is reached.
    """

    def __init__(self, *args, **kwargs):
        pass

    def __getattr__(self, item):
        if item.startswith("__") and item.endswith("__"):
            raise AttributeError(item)
        return stub_class(f"{name}.{item}")

    return _StubMeta(
        name,
        (object,),
        {
            "__init__": __init__,
            "__getattr__": __getattr__,
            "__call__": lambda self, *a, **k: stub_class(f"{name}()")(),
            "__bool__": lambda self: False,
            "__iter__": lambda self: iter(()),
            "__len__": lambda self: 0,
        },
    )


class _Stub(types.ModuleType):
    """A module whose every attribute is a stub class."""

    def __init__(self, name):
        super().__init__(name)
        self.__path__ = []
        self.__all__ = []

    def __getattr__(self, item):
        if item.startswith("__") and item.endswith("__"):
            raise AttributeError(item)
        child = stub_class(f"{self.__name__}.{item}")
        setattr(self, item, child)
        return child


class _StubLoader:
    def __init__(self, module):
        self._module = module

    def create_module(self, spec):
        return self._module

    def exec_module(self, module):
        return None


class _StubFinder:
    """Last-resort import hook: stub anything third-party that is not installed here.

    Appended to the end of sys.meta_path, so it only ever sees names every real finder has
    already declined. An explicit list of modules to fake did not scale - each one dragged
    in the next (pywin32 -> bson -> gevent -> ...) and the list had to be rediscovered by
    running the harness over and over. Nothing this fabricates can affect layout: a module
    that genuinely mattered would fail the moment a panel read a value out of it.
    """

    # Never stubbed: CAPEsolo itself and wx must fail loudly, otherwise a broken import
    # path in the harness silently screenshots an empty window. msvcrt likewise - the
    # stdlib's subprocess decides it is running on Windows by importing it successfully,
    # and then goes looking for the real _winapi.
    PROTECTED = ("CAPEsolo", "wx", "msvcrt")

    def find_spec(self, name, path=None, target=None):
        root = name.split(".")[0]
        if root in self.PROTECTED or root in sys.builtin_module_names:
            return None
        spec = importlib.machinery.ModuleSpec(name, _StubLoader(_Stub(name)))
        spec.submodule_search_locations = []
        return spec


def _preload(name):
    module = _Stub(name)
    sys.modules[name] = module
    return module


# Fixed, and outside the user's profile, on both platforms: the path itself is rendered.
HOME = "C:\\capesolo-uidev-home" if sys.platform == "win32" else "/tmp/capesolo-uidev-home"


def install(analysisDir):
    """Register the stub finder and point the config machinery at a throwaway directory."""
    # The Start tab shows a download directory derived from the home directory, which would
    # otherwise put the developer's real path into every screenshot - and make the visual
    # regression baseline differ on every machine. A fixed fake home keeps a render
    # byte-identical anywhere and keeps GTK off the developer's own configuration.
    home = Path(HOME)
    try:
        (home / "Desktop").mkdir(parents=True, exist_ok=True)
    except OSError:
        # A locked-down host may refuse the drive root. The render then carries this
        # machine's temp path, which is a visual-regression mismatch, not a failure.
        home = Path(tempfile.gettempdir()) / "capesolo-uidev-home"
        (home / "Desktop").mkdir(parents=True, exist_ok=True)
    os.environ["HOME"] = str(home)

    # The panels read cfg.ini through CAPEsolo.capelib.config_paths, which defaults to
    # %PUBLIC%. Point it at a temp copy so a screenshot run - which toggles the theme and
    # therefore writes the setting back - cannot touch the developer's real config.
    os.environ["CAPESOLO_CFG"] = str(Path(analysisDir) / "cfg.ini")
    os.environ.setdefault("PUBLIC", analysisDir)

    # The analyzer-side modules compute paths from the Windows environment at import time
    # (lib/common/constants.py builds ROOT from %SystemDrive%, and os.path.join raises on
    # the None that getenv returns off Windows). The values only have to be strings; nothing
    # in a screenshot run touches the filesystem through them.
    #
    # On Windows every one of these is already set and points at the real system, so only
    # the two that decide where a render's download path comes from are redirected -
    # overwriting SystemRoot or TEMP there would break subprocesses and the API itself.
    fabricated = (
        ("SystemDrive", analysisDir),
        ("SystemRoot", analysisDir),
        ("windir", analysisDir),
        ("TEMP", analysisDir),
        ("TMP", analysisDir),
        ("APPDATA", analysisDir),
        ("LOCALAPPDATA", analysisDir),
        ("USERPROFILE", str(home)),
        ("ProgramFiles", analysisDir),
        ("ProgramData", analysisDir),
        ("COMPUTERNAME", "HARNESS"),
        ("USERNAME", "analyst"),
    )
    if sys.platform == "win32":
        fabricated = (("USERPROFILE", str(home)), ("USERNAME", "analyst"))
    for name, value in fabricated:
        os.environ[name] = value


    # Stubbed even where a module of that name is installed. "yara" is the example that
    # forced this: the dev box has yara-python, the GitHub runner has a different package
    # of the same name whose module has no compile(), and main_frame.py builds a
    # YaraProcessor before the first panel exists - so the harness died on a machine
    # difference that has nothing to do with the UI. None of these libraries can affect
    # layout; a render must not depend on which one a host happens to have.
    #
    # UIDEV_FORCE_STUB extends the list, which is how a developer machine reproduces a bare
    # CI runner: there, nothing from pyproject is installed, so far more imports reach the
    # stub finder than they do here.
    forced = os.environ.get("UIDEV_FORCE_STUB", "")
    for name in ("yara", *(n.strip() for n in forced.split(",") if n.strip())):
        _preload(name)

    # sflock.identify() is called on the selected target to auto-pick a package. Given a
    # real function rather than letting the stub finder answer, so the dropdown lands on
    # "Auto-detect" - the state worth screenshotting - instead of on a stub's repr.
    sflock = _preload("sflock")
    _preload("sflock.abstracts").File = object
    ident = _preload("sflock.ident")
    ident.identify = lambda *a, **k: None
    sflock.abstracts = sys.modules["sflock.abstracts"]
    sflock.ident = ident

    if not any(isinstance(finder, _StubFinder) for finder in sys.meta_path):
        sys.meta_path.append(_StubFinder())

    _patch_ctypes()


def _patch_ctypes():
    """Add the Windows-only ctypes entry points, which are absent from the Linux build.

    classes/process_tools.py binds kernel32 at import time, outside any try/except, so
    without this the Start tab cannot be imported at all. The returned handle is a stub:
    the harness never calls into the API, it only needs the module to finish importing.
    """
    import ctypes

    if hasattr(ctypes, "WinDLL"):
        return

    ctypes.WinDLL = lambda *args, **kwargs: stub_class("WinDLL")()
    ctypes.OleDLL = ctypes.WinDLL
    ctypes.windll = stub_class("ctypes.windll")()
    ctypes.WinError = lambda *args, **kwargs: OSError("stubbed WinError")
    ctypes.get_last_error = lambda: 0
    ctypes.set_last_error = lambda value: 0
    # WINFUNCTYPE is CFUNCTYPE with the stdcall convention, which does not exist here.
    # The prototypes are only ever declared, never invoked, so the cdecl one will do.
    ctypes.WINFUNCTYPE = ctypes.CFUNCTYPE
    _install_wintypes(ctypes)


def _install_wintypes(ctypes):
    """Publish a ctypes.wintypes built from genuine ctypes primitives.

    Not left to the stub finder: process_tools declares ctypes.Structure subclasses whose
    _fields_ reference these names, and ctypes rejects a field type that has no storage
    info ("_type_ must have storage info"). The sizes are the Win32 ones, so the structures
    keep the same layout they would have on the target - which matters if a future harness
    target ever reads one back.
    """
    wintypes = types.ModuleType("ctypes.wintypes")
    wintypes.BYTE = ctypes.c_byte
    wintypes.WORD = ctypes.c_uint16
    wintypes.DWORD = ctypes.c_uint32
    wintypes.QWORD = ctypes.c_uint64
    wintypes.BOOL = ctypes.c_int
    wintypes.CHAR = ctypes.c_char
    wintypes.WCHAR = ctypes.c_wchar
    wintypes.LONG = ctypes.c_int32
    wintypes.ULONG = ctypes.c_uint32
    wintypes.LARGE_INTEGER = ctypes.c_int64
    wintypes.ULARGE_INTEGER = ctypes.c_uint64
    wintypes.LPVOID = ctypes.c_void_p
    wintypes.LPCVOID = ctypes.c_void_p
    wintypes.HANDLE = ctypes.c_void_p
    wintypes.HMODULE = ctypes.c_void_p
    wintypes.HWND = ctypes.c_void_p
    wintypes.LPSTR = ctypes.c_char_p
    wintypes.LPCSTR = ctypes.c_char_p
    wintypes.LPWSTR = ctypes.c_wchar_p
    wintypes.LPCWSTR = ctypes.c_wchar_p
    wintypes.UINT = ctypes.c_uint
    wintypes.INT = ctypes.c_int
    wintypes.ULONG_PTR = ctypes.c_size_t
    wintypes.LONG_PTR = ctypes.c_ssize_t
    wintypes.MAX_PATH = 260

    sys.modules["ctypes.wintypes"] = wintypes
    ctypes.wintypes = wintypes
