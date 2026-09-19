import configparser
import os
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
        self.notebook = wx.Simplebook(self.panel)
        self.notebook.analysisDir = self.analysisDir
        self.notebook.results = {}
        self.notebook.yara = ProcessYara(self.analysisDir)
        self.notebook.configHits = []
        self.notebook.targetFile = None
        self.notebook.capesoloRoot = self.capesoloRoot
        self.startTab = StartPanel(self.notebook)
        self.notebook.AddPage(self.startTab, "Start")
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

    def OnNotebookPageChanged(self, event):
        newSelection = event.GetSelection()
        selectedPage = self.notebook.GetPage(newSelection)
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

        event.Skip()

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
