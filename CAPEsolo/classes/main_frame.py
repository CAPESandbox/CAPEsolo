import configparser
import os
from contextlib import suppress
from pathlib import Path

import wx

from .behavior_panel import BehaviorPanel
from .configs_panel import ConfigsPanel
from .debugger_panel import DebuggerPanel
from .payloads_panel import PayloadsPanel
from .process_yara import ProcessYara
from .start_panel import StartPanel
from .strings_panel import StringsPanel
from .target_info import TargetInfoPanel
from .yara_panel import YaraPanel
from .signatures_panel import SignaturesPanel
from .theme import BG_MAIN, _init as _init_theme, apply_theme
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
        self.logger_window = None
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
        self.notebook.Bind(wx.EVT_NOTEBOOK_PAGE_CHANGED, self.OnNotebookPageChanged)

        # Layout
        sizer = wx.BoxSizer()
        sizer.Add(self.notebook, 1, wx.EXPAND)

        self.panel.SetSizer(sizer)
        self.SetBackgroundColour(BG_MAIN)
        self.panel.SetBackgroundColour(BG_MAIN)
        apply_theme(self)

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

        event.Skip()

    def CreateAnalysisDirectory(self):
        with suppress(FileExistsError):
            path_mkdir(self.analysisDir)

    def GetConfig(self):
        configFile = os.path.join(self.capesoloRoot, "cfg.ini")
        g_config = ConfigReader(configFile)
        analysisDir = g_config.analysis_directory.analysis
        if analysisDir:
            self.analysisDir = analysisDir

    def SetAppIcon(self):
        icon = wx.Icon()
        iconPath = os.path.join(self.capesoloRoot, "cape_logo.png")
        icon.LoadFile(iconPath, wx.BITMAP_TYPE_PNG)
        self.SetIcon(icon)

    def OnClose(self, event):
        self.Destroy()
