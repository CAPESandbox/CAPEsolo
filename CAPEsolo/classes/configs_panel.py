import importlib
import importlib.util
import os
from contextlib import suppress
from pathlib import Path

import wx

from .theme import FONT_CODE, apply_theme


def PrintResults(cfg):
    content = ""
    if isinstance(cfg, list):
        for key, value in cfg[0].items():
            if isinstance(value, map):
                value = list(value)
            content += f"\t{key}: {value}\n"
    elif isinstance(cfg, dict):
        for key, value in cfg.items():
            if isinstance(value, map):
                value = list(value)
            content += f"\t{key}: {value}\n"
    return content


def Extract(configHits, analysisDir, jsonResults=False):
    content = ""
    configs = []
    CAPE_PARSERS = ("core", "community")
    customParsers = os.path.join(os.path.expanduser("~"), "Desktop", "custom")

    for hit in configHits:
        decoderModule = ""
        hitPath = list(hit.keys())[0]
        hitName = hit.get(hitPath, "")
        modPath = os.path.join(customParsers, f"{hitName}.py")

        for parser in CAPE_PARSERS:
            try:
                decoderModule = importlib.import_module(f"cape_parsers.CAPE.{parser}.{hitName}", __package__)
            except (ImportError, IndexError, AttributeError):
                continue
            except SyntaxError as e:
                print(f"CAPE parser: Fix your code in {parser}/{hitName} - {e}")
            except Exception as e:
                print(f"CAPE parser: Fix your code in {parser}/{hitName} - {e}")

        if not decoderModule:
            try:
                spec = importlib.util.spec_from_file_location(hitName, modPath)
                decoderModule = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(decoderModule)
            except (FileNotFoundError, ImportError, AttributeError):
                continue
            except SyntaxError as e:
                print(f"CAPE parser: Fix your code in {modPath} - {e}")
            except Exception as e:
                print(f"CAPE parser: Fix your code in {modPath} - {e}")

        if decoderModule:
            cfg = ""
            if analysisDir not in hitPath:
                hitPath = Path(analysisDir) / hitPath
            filedata = Path(hitPath).read_bytes()
            with suppress(Exception):
                if hasattr(decoderModule, "extract_config"):
                    cfg = decoderModule.extract_config(filedata)
                else:
                    cfg = decoderModule.config(filedata)
            if cfg:
                if jsonResults:
                    configs.append({hitPath: cfg})

                content += f"\u2022 {hitPath}:\n\tFamily: {hitName}\n"
                content += PrintResults(cfg)
        else:
            content += f"\n{hitPath}: No parser for {hitName}"

    if jsonResults:
        return configs

    return content


class ConfigsPanel(wx.Panel):
    def __init__(self, parent):
        super(ConfigsPanel, self).__init__(parent)
        self.configHits = parent.configHits
        self.analysisDir = parent.analysisDir
        self.capesoloRoot = parent.capesoloRoot
        self.InitUI()

    def InitUI(self):
        vbox = wx.BoxSizer(wx.VERTICAL)

        vbox.AddSpacer(10)
        self.configsButton = wx.Button(self, label="Extract Configs")
        self.configsButton.Bind(wx.EVT_BUTTON, self.ExtractConfigs)
        self.configsButton.Disable()
        vbox.Add(self.configsButton, proportion=0, border=5)
        self.resultsWindow = wx.TextCtrl(
            self, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.EXPAND, size=wx.Size(-1, 100)
        )
        self.resultsWindow.SetFont(FONT_CODE)
        vbox.Add(self.resultsWindow, proportion=1, flag=wx.EXPAND | wx.ALL, border=10)
        content = "Extract after Yara Processing."
        self.resultsWindow.SetValue(content)
        self.SetSizer(vbox)
        apply_theme(self)

    def ExtractConfigs(self, event):
        self.resultsWindow.SetValue("")
        content = Extract(self.configHits, self.analysisDir)
        self.resultsWindow.SetValue(content)

    def UpdateConfigsButtonState(self):
        if self.configHits:
            self.configsButton.Enable()
        else:
            self.configsButton.Disable()
