import configparser
import os
from contextlib import suppress
from pathlib import Path

import wx

from .behavior_panel import BehaviorPanel
from .configs_panel import ConfigsPanel
from .debugger_panel import DebuggerPanel
from .js_console_panel import JsConsolePanel
from .network_panel import NetworkPanel
from .payloads_panel import PayloadsPanel
from .process_yara import ProcessYara
from .start_panel import StartPanel
from .status_bar import AnalysisStatusBar
from .strings_panel import StringsPanel
from .target_info import TargetInfoPanel
from .yara_panel import YaraPanel
from .signatures_panel import SignaturesPanel
from .theme import BG_MAIN, FONT_UI, ToggleTheme, _init as _init_theme, apply_theme, is_dark
from CAPEsolo.capelib.config_paths import config_paths
from CAPEsolo.capelib.path_utils import path_mkdir


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
        self.version = Path("version.txt").read_text()
        kwargs["title"] = f"Capesolo - v{self.version}"
        super(MainFrame, self).__init__(*args, **kwargs)
        self.SetAppIcon()
        self.GetConfig()
        self.CreateAnalysisDirectory()
        self.InitUi()
        self.Bind(wx.EVT_CLOSE, self.OnClose)

    def InitUi(self):
        _init_theme()
        self.panel = wx.Panel(self)
        import wx.lib.agw.flatnotebook as fnb
        self.notebook = fnb.FlatNotebook(
            self.panel,
            wx.ID_ANY,
            style=fnb.FNB_NO_X_BUTTON | fnb.FNB_NODRAG | fnb.FNB_NO_NAV_BUTTONS | fnb.FNB_TABS_BORDER_SIMPLE
        )
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
        self.notebook.Bind(wx.EVT_NOTEBOOK_PAGE_CHANGED, self.OnNotebookPageChanged)

        # Layout. Vertical so the status bar can dock beneath the notebook; with a single
        # proportion-1 EXPAND child this lays out identically to the previous default.
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self.notebook, 1, wx.EXPAND)

        # The status bar paints itself through its own EVT_PAINT and is double buffered, so
        # the theme toggle sits beside it rather than as a child of it.
        bottom = wx.BoxSizer(wx.HORIZONTAL)
        self.statusBar = AnalysisStatusBar(self.panel)
        self.settingsButton = wx.Button(self.panel, label="Settings", style=wx.BU_EXACTFIT)
        self.settingsButton.SetToolTip("Edit CAPEsolo settings (cfg.ini)")
        self.settingsButton.Bind(wx.EVT_BUTTON, self.OnSettings)
        self.themeButton = wx.Button(self.panel, label=self.ThemeLabel(), style=wx.BU_EXACTFIT)
        self.themeButton.SetToolTip("Switch between the light and dark palettes")
        self.themeButton.Bind(wx.EVT_BUTTON, self.OnToggleTheme)
        bottom.Add(self.statusBar, 1, wx.EXPAND)
        bottom.Add(self.settingsButton, 0, wx.ALIGN_CENTER_VERTICAL | wx.LEFT, 6)
        bottom.Add(self.themeButton, 0, wx.ALIGN_CENTER_VERTICAL | wx.LEFT | wx.RIGHT, 6)
        sizer.Add(bottom, 0, wx.EXPAND)

        self.panel.SetSizer(sizer)
        self.SetBackgroundColour(BG_MAIN)
        self.panel.SetBackgroundColour(BG_MAIN)
        apply_theme(self)
        self.StyleThemeButton()

    def ThemeLabel(self):
        return "Theme: Dark" if is_dark() else "Theme: Light"

    def StyleThemeButton(self):
        """Shrink the toggle a point below the rest of the UI.

        Built from FONT_UI's properties rather than by mutating the font the button reports:
        that object is the shared FONT_UI token, so changing it in place would shrink every
        control in the app. Has to run after each apply_theme, which resets buttons to FONT_UI.
        """
        self.themeButton.SetFont(
            wx.Font(
                max(6, FONT_UI.GetPointSize() - 1),
                FONT_UI.GetFamily(),
                FONT_UI.GetStyle(),
                FONT_UI.GetWeight(),
                faceName=FONT_UI.GetFaceName(),
            )
        )
        self.themeButton.SetMinSize(wx.DefaultSize)
        self.themeButton.Fit()

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
        self.StyleThemeButton()
        # Reads TIMER_WARN at paint time, so a repaint is all it needs.
        self.statusBar.Refresh()
        self.Layout()
        self.Refresh()

    def OnNotebookPageChanged(self, event):
        newSelection = event.GetSelection()
        selectedPage = self.notebook.GetPage(newSelection)
        if selectedPage == self.behaviorTab:
            selectedPage.UpdateGenerateButtonState()
        elif selectedPage == self.signaturesTab:
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
        elif selectedPage == self.jsConsoleTab:
            selectedPage.UpdateProcessButtonState()
        elif selectedPage == self.networkTab:
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
        icon = wx.Icon()
        iconPath = os.path.join(self.capesoloRoot, "cape_logo.png")
        icon.LoadFile(iconPath, wx.BITMAP_TYPE_PNG)
        self.SetIcon(icon)

    def OnClose(self, event):
        # Kill the download broker so its held key password does not outlive the app.
        stop = getattr(self.startTab, "_StopDownloadBroker", None)
        if stop:
            try:
                stop()
            except Exception:
                pass
        self.Destroy()
