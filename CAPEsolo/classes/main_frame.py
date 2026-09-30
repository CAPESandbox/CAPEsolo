import configparser
import logging
import os
import threading
from contextlib import suppress
from pathlib import Path

import wx

from CAPEsolo.capelib.config_paths import config_paths
from CAPEsolo.capelib.path_utils import path_mkdir

from . import ui_kit as ui
from .behavior_panel import BehaviorPanel
from .configs_panel import ConfigsPanel
from .debugger_panel import DebuggerPanel
from .js_console_panel import JsConsolePanel
from .network_panel import NetworkPanel
from .payloads_panel import PayloadsPanel
from .process_yara import ProcessYara
from .signatures_panel import SignaturesPanel
from .start_panel import StartPanel
from .status_bar import AnalysisStatusBar
from .strings_panel import StringsPanel
from .target_info import TargetInfoPanel
from .theme import SP_XS, BG_MAIN, ToggleTheme, apply_theme, dip, is_dark
from .theme import _init as _init_theme
from .yara_panel import YaraPanel

log = logging.getLogger(__name__)


class ConfigObject:
    def __init__(self, section_data):
        for key, value in section_data.items():
            setattr(self, key, value)


class ConfigReader:
    def __init__(self, config_file):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        self._create_section_objects()

    def _create_section_objects(self):
        for section in self.config.sections():
            section_data = {
                key: self._to_boolean(value)
                for key, value in self.config.items(section)
            }
            setattr(self, section, ConfigObject(section_data))

    def _to_boolean(self, value):
        if isinstance(value, str):
            if value.lower() == "false":
                return False
            elif value.lower() == "true":
                return True
        return value


class MainFrame(wx.Frame):
    def __init__(self, rootDir=None, *args, **kwargs):
        self.capesoloRoot = rootDir
        # Popped before super(): wx.Frame does not accept it. Set by cli.CapesoloApp when a
        # restore.zip was extracted this launch, so InitUi can announce it in the status bar.
        restored = kwargs.pop("restored", False)
        self.version = Path("version.txt").read_text()
        kwargs["title"] = f"Capesolo - v{self.version}"
        super().__init__(*args, **kwargs)
        self.SetAppIcon()
        self.GetConfig()
        self.CreateAnalysisDirectory()
        self.InitUi()
        if restored:
            self.statusBar.SetMessage("Restored analysis from restore.zip")
        self.Bind(wx.EVT_CLOSE, self.OnClose)

    def InitUi(self):
        _init_theme()
        self.panel = wx.Panel(self)
        # A plain page-holder plus our own drawn tab strip, rather than FlatNotebook: its
        # boxed tabs are the most dated element on screen and it exposes only four colours,
        # none of which reach the tab borders. Simplebook keeps the AddPage/GetPage API and
        # stays the pages' parent, so the panels that read analysisDir and friends off
        # GetParent() are unaffected.
        # Set before any page exists: StartPanel reads it when it builds its action bar.
        self.processing = False
        self.notebook = wx.Simplebook(self.panel)
        self.notebook.analysisDir = self.analysisDir
        self.notebook.results = {}
        self.notebook.yara = ProcessYara(self.analysisDir)
        self.notebook.configHits = []
        self.notebook.targetFile = None
        self.notebook.capesoloRoot = self.capesoloRoot
        self.startTab = StartPanel(self.notebook)
        self.notebook.AddPage(self.startTab, "Start")
        self._BuildResultPages()
        self.notebook.SetSelection(0)
        # Simplebook is a wxBookCtrl, so it reports page changes as a book event rather
        # than the notebook-specific one FlatNotebook sent.
        self.notebook.Bind(wx.EVT_BOOKCTRL_PAGE_CHANGED, self.OnNotebookPageChanged)

        self.tabBar = ui.TabBar(self.panel, self.notebook)

        # Layout. Vertical so the tab strip and the status bar can dock above and below the
        # pages.
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self.tabBar, 0, wx.EXPAND)
        sizer.Add(self.notebook, 1, wx.EXPAND)

        # The status bar paints itself through its own EVT_PAINT and is double buffered, so
        # the theme toggle sits beside it rather than as a child of it.
        bottom = wx.BoxSizer(wx.HORIZONTAL)
        self.statusBar = AnalysisStatusBar(self.panel)
        # Ghost buttons: these sit on the status strip and should read as chrome, not as
        # actions competing with Launch and Kill on the page above.
        self.extendTimeoutBtn = ui.Button(
            self.panel,
            label="Extend",
            variant=ui.GHOST,
            tooltip="Add time to the running analysis timeout.",
        )
        self.extendTimeoutBtn.Disable()
        self.extendTimeoutBtn.Bind(wx.EVT_BUTTON, self.startTab.OnExtendTimeout)
        self.settingsButton = ui.Button(
            self.panel,
            label="Settings",
            variant=ui.GHOST,
            glyph=ui.SETTINGS,
            tooltip="Edit CAPEsolo settings (cfg.ini)",
        )
        self.settingsButton.Bind(wx.EVT_BUTTON, self.OnSettings)
        self.themeButton = ui.Button(
            self.panel,
            label=self.ThemeLabel(),
            variant=ui.GHOST,
            tooltip="Switch between the light and dark palettes",
        )
        self.themeButton.Bind(wx.EVT_BUTTON, self.OnToggleTheme)
        gap = dip(self.panel, SP_XS)
        bottom.Add(self.statusBar, 1, wx.EXPAND)
        bottom.Add(self.extendTimeoutBtn, 0, wx.ALIGN_CENTER_VERTICAL | wx.LEFT, gap)
        bottom.Add(self.settingsButton, 0, wx.ALIGN_CENTER_VERTICAL | wx.LEFT, gap)
        bottom.Add(self.themeButton, 0, wx.ALIGN_CENTER_VERTICAL | wx.LEFT | wx.RIGHT, gap)
        sizer.Add(bottom, 0, wx.EXPAND)

        self.panel.SetSizer(sizer)
        # SetSizer() does not apply the layout itself. Without this, self.panel keeps
        # whatever size it had before the sizer was attached - typically the tiny
        # placeholder size children get before their first paint - and every child
        # (tabBar, notebook, statusBar) stays collapsed to its unlaid-out minimum until
        # something later resizes the frame to a genuinely different size. cli.py's
        # startup width correction reads startTab.GetClientSize() right after Show(),
        # which depends on this having already run.
        self.panel.Layout()
        self.SetBackgroundColour(BG_MAIN)
        self.panel.SetBackgroundColour(BG_MAIN)
        apply_theme(self)
        # apply_theme paints every wx.Panel in card colours; the frame's root panel is the
        # page background behind the tab strip, not a card.
        self.panel.SetBackgroundColour(BG_MAIN)

    def _BuildResultPages(self):
        """Every page after Start. Shared by InitUi and ResetResults so the two cannot drift."""
        self.infoTab = TargetInfoPanel(self.notebook)
        self.notebook.AddPage(self.infoTab, "Info")
        self.behaviorTab = BehaviorPanel(self.notebook)
        self.notebook.AddPage(self.behaviorTab, "Behavior")
        self.signaturesTab = SignaturesPanel(self.notebook)
        self.notebook.AddPage(self.signaturesTab, "Signatures")
        self.payloadsTab = PayloadsPanel(self.notebook)
        self.notebook.AddPage(self.payloadsTab, "Payloads")
        self.yaraTab = YaraPanel(self.notebook)
        self.notebook.AddPage(self.yaraTab, "Yara")
        self.configsTab = ConfigsPanel(self.notebook)
        self.notebook.AddPage(self.configsTab, "Configs")
        self.stringsTab = StringsPanel(self.notebook)
        self.notebook.AddPage(self.stringsTab, "Strings")
        self.debuggerTab = DebuggerPanel(self.notebook)
        self.notebook.AddPage(self.debuggerTab, "Debugger")
        self.jsConsoleTab = JsConsolePanel(self.notebook)
        self.notebook.AddPage(self.jsConsoleTab, "JS Log")
        self.networkTab = NetworkPanel(self.notebook)
        self.notebook.AddPage(self.networkTab, "Network")

    def ResetResults(self):
        """Replace every result page, and the state they share, with fresh ones.

        Nothing cleared the completion flags, grids or shared results before, so a second
        Launch (or a static pass followed by a dynamic one) mixed the two analyses and skipped
        the tabs already marked processed. Rebuilding the pages rather than resetting each
        in place means no panel needs a Reset() kept in step with its own state. The new
        shared objects exist before the pages do, since each panel copies its references
        (results, configHits, yara) at construction.
        """
        self.Freeze()
        try:
            # ChangeSelection, not SetSelection: no page-changed event for a page about to go.
            self.notebook.ChangeSelection(0)
            while self.notebook.GetPageCount() > 1:
                self.notebook.DeletePage(1)
            self.notebook.results = {}
            self.notebook.configHits = []
            self.notebook.yara = ProcessYara(self.analysisDir)
            self._BuildResultPages()
            for index in range(1, self.notebook.GetPageCount()):
                apply_theme(self.notebook.GetPage(index))
            self.startTab._reportCache = None
        finally:
            self.Thaw()
        self.tabBar.Refresh()
        self.panel.Layout()

    def ThemeLabel(self):
        return "Theme: Dark" if is_dark() else "Theme: Light"

    def OnToggleTheme(self, event):
        self.RefreshTheme()

    def OnSettings(self, event):
        from .settings_dialog import SettingsDialog

        dlg = SettingsDialog(self)
        dlg.ShowModal()
        dlg.Destroy()

    def RefreshTheme(self):
        """Switch palette and restyle everything already on screen."""
        ToggleTheme()
        apply_theme(self)
        # apply_theme walks wx.Panels as cards; this one is the page background. It runs
        # after the walk already refreshed self.panel with the (wrong, card) colour, so it
        # needs its own repaint to actually show BG_MAIN.
        self.panel.SetBackgroundColour(BG_MAIN)
        self.panel.Refresh()

        # apply_theme re-sets widget colours and the grids' defaults, but not a GridCellAttr
        # already attached to a row: SetBackgroundColour copied the colour in when the attr
        # was built, so mutating the token afterwards never reaches it. Every panel that
        # shades rows already owns the method that rebuilds them, so reuse it rather than
        # teaching this loop about each panel's grid.
        for index in range(self.notebook.GetPageCount()):
            shade = getattr(self.notebook.GetPage(index), "ApplyAlternateRowShading", None)
            if shade is None:
                continue

            # One page failing to restyle must not abort the switch half way through.
            with suppress(Exception):
                shade()

        self.themeButton.SetLabel(self.ThemeLabel())
        # apply_theme() now refreshes every widget it visits (tabBar and statusBar
        # included) on its way down, so no per-widget repaint is needed here.
        self.Layout()
        self.Refresh()

    def RunSteps(self, steps, onDone=None):
        """Run processing on a worker thread so the window stays responsive.

        *steps* is an iterable of (label, compute, render), consumed on the worker - so a
        generator can decide a later step from what an earlier one produced, as the
        auto-process chain does. compute() does the work and must not touch wx; render(result)
        updates the widgets on the GUI thread, and the worker waits for it, so every step still
        sees what the previous ones published, in the same order as when all of it ran on the
        GUI thread. Either may be None. A step that raises is logged and the rest still run;
        onDone(failed) then gets the labels that failed.

        One job at a time, because the steps share notebook.results and the pages: while one
        runs this returns False and does nothing.
        """
        if self.processing:
            self.statusBar.SetMessage("Busy - wait for the current processing to finish")
            return False
        self.SetProcessing(True)
        threading.Thread(target=self._RunSteps, args=(steps, onDone), daemon=True).start()
        return True

    def _RunSteps(self, steps, onDone):
        failed = []
        try:
            for label, compute, render in steps:
                wx.CallAfter(self._SetStatus, f"Processing {label}...")
                try:
                    result = compute() if compute else None
                    if render:
                        ui.on_gui(render, result)
                except Exception:
                    log.exception("Processing %s failed", label)
                    failed.append(label)
        except Exception:
            # The step generator itself raised: nothing after it can be planned.
            log.exception("Processing failed")
            failed.append("processing")
        wx.CallAfter(self._StepsDone, failed, onDone)

    def _SetStatus(self, message):
        if self:
            self.statusBar.SetMessage(message)

    def _StepsDone(self, failed, onDone):
        if not self:
            return
        self.SetProcessing(False)
        if onDone:
            onDone(failed)
        elif failed:
            self.statusBar.SetMessage(f"Processing failed: {', '.join(failed)} (see log)")
        else:
            self.statusBar.SetMessage("Processing complete")

    def SetProcessing(self, processing):
        self.processing = processing
        self.startTab.UpdateAnalysisControls()
        if not processing:
            # Page changes skip their loads and button updates while a job runs; catch the
            # page on screen up once the job's onDone has had its turn (it may start another).
            wx.CallAfter(self._RefreshCurrentPage)

    def _RefreshCurrentPage(self):
        if self and not self.processing:
            self.RefreshPage(self.notebook.GetCurrentPage())

    def OnNotebookPageChanged(self, event):
        # A running job fills the pages itself; loading one here as well would do it twice.
        if not self.processing:
            self.RefreshPage(self.notebook.GetPage(event.GetSelection()))
        event.Skip()

    def RefreshPage(self, selectedPage):
        if selectedPage == self.behaviorTab or selectedPage == self.signaturesTab:
            selectedPage.UpdateGenerateButtonState()
        elif selectedPage == self.infoTab:
            selectedPage.LoadAndDisplayContent()
        elif selectedPage == self.payloadsTab:
            selectedPage.PayloadsReady()
        elif selectedPage == self.yaraTab:
            selectedPage.UpdateYaraButtonState()
        elif selectedPage == self.configsTab:
            selectedPage.UpdateConfigsButtonState()
        elif selectedPage == self.stringsTab:
            selectedPage.PopulateFileDropdown()
        elif selectedPage == self.debuggerTab:
            selectedPage.PopulateLogFileDropdown()
        elif selectedPage == self.jsConsoleTab or selectedPage == self.networkTab:
            selectedPage.UpdateProcessButtonState()

    def CreateAnalysisDirectory(self):
        with suppress(FileExistsError):
            path_mkdir(self.analysisDir)

    def GetConfig(self):
        g_config = ConfigReader(config_paths())
        analysisDir = g_config.analysis_directory.analysis
        if analysisDir:
            self.analysisDir = analysisDir

    def SetAppIcon(self):
        """Set the window icon from the multi-size .ico.

        SetIcons with a bundle rather than SetIcon with one image: Windows asks for 16px for
        the title bar and 32px for Alt-Tab and the taskbar, and a bundle lets it take the
        frame rendered at that size instead of shrinking one bitmap on the fly. The previous
        icon was a single 39x45 PNG, which is neither of the sizes actually requested.
        """
        iconPath = os.path.join(self.capesoloRoot, "capesolo.ico")
        self.SetIcons(wx.IconBundle(iconPath, wx.BITMAP_TYPE_ICO))

    def OnClose(self, event):
        # Kill the download broker so its held key password does not outlive the app.
        stop = getattr(self.startTab, "_StopDownloadBroker", None)
        if stop:
            try:
                stop()
            except Exception:
                pass
        self.Destroy()
