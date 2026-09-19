#!/usr/bin/env python3
"""Screenshot harness for CAPEsolo's wx UI.

Renders a target (a whole frame, a single panel, or the ui_kit gallery) off screen under
Xvfb and writes a PNG, so GUI work can be reviewed as pictures rather than as diffs.

    xvfb-run -a /usr/bin/python3 shoot.py start --theme dark -o /tmp/start.png

Targets are registered in TARGETS at the bottom. Rendering happens on GTK, so the
remaining *native* controls (combo popups, grid scrollbars) will not look exactly as they
do on wxMSW; everything drawn by ui_kit will.
"""

import argparse
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent

sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO))
# The analyzer-side modules import each other as bare `lib.common...`, not
# `CAPEsolo.lib.common...` (see the note at the top of classes/process_tools.py), so the
# package directory has to be importable as a root as well. cli.py does the same thing.
sys.path.insert(0, str(REPO / "CAPEsolo"))

import winstubs  # noqa: E402

# MainFrame reads version.txt by relative path, so the harness has to run from the same
# working directory the app does.
os.chdir(REPO / "CAPEsolo")

WORKDIR = Path(tempfile.mkdtemp(prefix="capesolo-shoot-"))
(WORKDIR / "analysis").mkdir(parents=True, exist_ok=True)
winstubs.install(str(WORKDIR))

# Force the X11 backend, before wx pulls GTK in.
#
# On a Wayland desktop GTK ignores the DISPLAY that xvfb-run sets and connects to the
# compositor instead, so `xvfb-run -a shoot.py` quietly renders on the developer's real
# session: their GTK theme, their fonts, their monitor work area capping the window size -
# and nothing like CI, where there is no compositor. That difference hid a hang for a whole
# CI run. Everything here must be reproducible, so the session is never used. GTK only
# exists on the Unix build; on Windows wx talks to the Win32 API and neither variable means
# anything.
if sys.platform != "win32":
    os.environ.pop("WAYLAND_DISPLAY", None)
    os.environ["GDK_BACKEND"] = "x11"

import wx  # noqa: E402


def _flush(app, cycles=6):
    """Let GTK finish laying out and painting before the bitmap is grabbed.

    A single Yield is not enough: sizers settle on one idle pass and the paint handlers
    run on the next, so an early grab catches a half-drawn window.
    """
    for _ in range(cycles):
        app.Yield()
        wx.MilliSleep(40)


def grab(window, path):
    """Write *window*'s client area to *path* as a PNG."""
    width, height = window.GetClientSize()
    bitmap = wx.Bitmap(width, height)
    memory = wx.MemoryDC(bitmap)
    # Blit from the window's own DC rather than the screen: this way the grab is unaffected
    # by anything else Xvfb happens to have mapped, and works even if the WM never mapped
    # the window at the position we asked for.
    memory.Blit(0, 0, width, height, wx.ClientDC(window), 0, 0)
    memory.SelectObject(wx.NullBitmap)
    bitmap.ConvertToImage().SaveFile(str(path), wx.BITMAP_TYPE_PNG)
    return width, height


def build_frame(app, size):
    frame = wx.Frame(None, title="CAPEsolo harness", size=size)
    return frame


# --- targets ---------------------------------------------------------------


def target_start(app, size):
    """The real Start tab, inside a stand-in for MainFrame's notebook."""
    from CAPEsolo.classes.theme import apply_theme
    from CAPEsolo.classes.start_panel import StartPanel

    frame = build_frame(app, size)
    # StartPanel reads these off its parent (normally the FlatNotebook MainFrame builds).
    holder = wx.Panel(frame)
    holder.analysisDir = str(WORKDIR / "analysis")
    holder.capesoloRoot = str(REPO / "CAPEsolo")
    holder.targetFile = None
    holder.results = {}
    holder.configHits = []

    panel = StartPanel(holder)
    sizer = wx.BoxSizer(wx.VERTICAL)
    sizer.Add(panel, 1, wx.EXPAND)
    holder.SetSizer(sizer)

    outer = wx.BoxSizer(wx.VERTICAL)
    outer.Add(holder, 1, wx.EXPAND)
    frame.SetSizer(outer)
    apply_theme(frame)
    return frame


def target_frame(app, size):
    """The whole MainFrame, tabs and all."""
    from CAPEsolo.classes.main_frame import MainFrame

    frame = MainFrame(rootDir=str(REPO / "CAPEsolo"), parent=None, size=size)
    return frame


def target_gallery(app, size):
    """Every ui_kit primitive in every state, the tight loop for Phase 2."""
    from gallery import GalleryFrame

    return GalleryFrame(size)


# Result panels, by the name used on the command line. Each is (module, class).
PANELS = {
    "behavior": ("behavior_panel", "BehaviorPanel"),
    "configs": ("configs_panel", "ConfigsPanel"),
    "debugger": ("debugger_panel", "DebuggerPanel"),
    "js": ("js_console_panel", "JsConsolePanel"),
    "network": ("network_panel", "NetworkPanel"),
    "payloads": ("payloads_panel", "PayloadsPanel"),
    "signatures": ("signatures_panel", "SignaturesPanel"),
    "strings": ("strings_panel", "StringsPanel"),
    "target": ("target_info", "TargetInfoPanel"),
    "yara": ("yara_panel", "YaraPanel"),
}


def make_panel_target(module, classname):
    """A target that renders one result panel inside a stand-in for the notebook page."""

    def target(app, size):
        import importlib

        from CAPEsolo.classes.theme import apply_theme

        panelClass = getattr(
            importlib.import_module(f"CAPEsolo.classes.{module}"), classname
        )

        frame = build_frame(app, size)
        # The panels read shared analysis state off their parent, which is normally the
        # notebook MainFrame builds.
        holder = wx.Panel(frame)
        holder.analysisDir = str(WORKDIR / "analysis")
        holder.capesoloRoot = str(REPO / "CAPEsolo")
        holder.targetFile = None
        holder.results = {}
        holder.configHits = []
        holder.yara = None

        panel = panelClass(holder)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(panel, 1, wx.EXPAND)
        holder.SetSizer(sizer)

        outer = wx.BoxSizer(wx.VERTICAL)
        outer.Add(holder, 1, wx.EXPAND)
        frame.SetSizer(outer)
        apply_theme(frame)
        return frame

    return target


TARGETS = {
    "start": target_start,
    "frame": target_frame,
    "gallery": target_gallery,
}
TARGETS.update(
    {name: make_panel_target(*spec) for name, spec in PANELS.items()}
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", choices=sorted(TARGETS))
    parser.add_argument("--theme", choices=("dark", "light"), default="dark")
    parser.add_argument("--size", default="1180x800")
    parser.add_argument("-o", "--out", default="/tmp/capesolo.png")
    args = parser.parse_args()

    width, height = (int(v) for v in args.size.lower().split("x"))
    app = wx.App()

    # Set before any panel is built: the tokens are read at widget-construction time.
    from CAPEsolo.classes import theme

    theme._init()
    theme.set_theme(args.theme)

    frame = TARGETS[args.target](app, wx.Size(width, height))
    frame.Show()
    frame.SetSize(wx.Size(width, height))
    frame.Layout()
    _flush(app)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    got = grab(frame, out)
    print(f"{out} {got[0]}x{got[1]}")

    frame.Destroy()
    app.Yield()


if __name__ == "__main__":
    main()
