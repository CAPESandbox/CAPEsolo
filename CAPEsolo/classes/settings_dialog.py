"""GUI editor for CAPEsolo's cfg.ini settings.

Reads the effective (merged) config to show current values, and writes changes to the USER
cfg.ini only (user_config_path()) so the packaged defaults are never modified — mirroring
theme._write_theme_name. Most settings take effect on restart; the theme applies live.
"""

import configparser
import os
from contextlib import suppress

import wx
import wx.lib.scrolledpanel as scrolled

from CAPEsolo.capelib.config_paths import config_paths, user_config_path
from .theme import apply_theme, is_dark

# Each row: (section, key, label, kind, choices, default).
# kind: bool | choice | dir | text | int | float. Encrypted key blobs are opaque text: the
# panel only pastes/clears them (encryption happens off-VM via tools/encrypt_api_key.py).
SETTINGS_SCHEMA = [
    ("Analysis", [
        ("analysis_directory", "analysis", "Analysis directory", "dir", None, r"C:\Users\Public\CAPEsolo\analysis"),
    ]),
    ("Appearance", [
        ("gui", "theme", "Theme", "choice", ["dark", "light"], "dark"),
    ]),
    ("Downloads", [
        ("download", "enabled", "Enable downloads", "bool", None, "false"),
        ("download", "directory", "Download directory (blank = Desktop)", "dir", None, ""),
        ("virustotal", "api_key_enc", "VirusTotal key (encrypted blob)", "text", None, ""),
        ("malwarebazaar", "api_key_enc", "MalwareBazaar key (encrypted blob)", "text", None, ""),
    ]),
    ("MCP server", [
        ("mcp_server", "enabled", "Enable MCP server", "bool", None, "false"),
        ("mcp_server", "transport", "Transport", "choice", ["stdio", "streamable-http"], "stdio"),
        ("mcp_server", "host", "Host", "text", None, "127.0.0.1"),
        ("mcp_server", "port", "Port", "int", None, "8000"),
        ("mcp_server", "path", "Path", "text", None, "/mcp"),
        ("mcp_server", "allowed_hosts", "Allowed hosts (comma-separated)", "text", None, ""),
        ("mcp_server", "allowed_origins", "Allowed origins (comma-separated)", "text", None, ""),
    ]),
    ("Result server", [
        ("resultserver", "pool_size", "Pool size (0 = unlimited)", "int", None, "0"),
        ("resultserver", "idle_timeout", "Idle timeout seconds (0 = never)", "int", None, "0"),
        ("resultserver", "upload_max_size", "Upload max size (bytes)", "int", None, "2000000000"),
        ("resultserver", "drain_timeout", "Drain timeout seconds", "float", None, "10.0"),
    ]),
]

_TRUE = ("1", "true", "yes", "on")


class SettingsDialog(wx.Dialog):
    def __init__(self, parent):
        super().__init__(parent, title="Settings", style=wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER)
        self.parent = parent
        self._widgets = {}  # (section, key) -> (widget, kind)

        config = self._read_effective()

        outer = wx.BoxSizer(wx.VERTICAL)
        panel = scrolled.ScrolledPanel(self, style=wx.TAB_TRAVERSAL)
        vbox = wx.BoxSizer(wx.VERTICAL)

        for groupLabel, items in SETTINGS_SCHEMA:
            box = wx.StaticBoxSizer(wx.VERTICAL, panel, groupLabel)
            boxParent = box.GetStaticBox()
            grid = wx.FlexGridSizer(rows=0, cols=2, hgap=8, vgap=8)
            grid.AddGrowableCol(1, 1)
            for section, key, label, kind, choices, default in items:
                current = config.get(section, key, fallback=default)
                grid.Add(wx.StaticText(boxParent, label=f"{label}:"), flag=wx.ALIGN_CENTER_VERTICAL)
                self._add_value_widget(grid, boxParent, section, key, kind, choices, current)
            box.Add(grid, proportion=1, flag=wx.EXPAND | wx.ALL, border=6)
            vbox.Add(box, flag=wx.EXPAND | wx.ALL, border=8)

        panel.SetSizer(vbox)
        panel.SetupScrolling(scroll_x=False, scroll_y=True)
        outer.Add(panel, proportion=1, flag=wx.EXPAND | wx.ALL, border=6)

        btnRow = wx.BoxSizer(wx.HORIZONTAL)
        saveBtn = wx.Button(self, wx.ID_OK, "Save")
        saveBtn.SetDefault()
        btnRow.AddStretchSpacer(1)
        btnRow.Add(saveBtn, flag=wx.RIGHT, border=8)
        btnRow.Add(wx.Button(self, wx.ID_CANCEL, "Cancel"))
        outer.Add(btnRow, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=10)

        self.SetSizer(outer)
        apply_theme(self)
        self.SetSize(wx.Size(560, 660))
        self.Bind(wx.EVT_BUTTON, self.OnSave, id=wx.ID_OK)

    def _read_effective(self):
        config = configparser.ConfigParser()
        with suppress(configparser.Error, OSError):
            config.read([str(p) for p in config_paths()])
        return config

    def _add_value_widget(self, grid, parent, section, key, kind, choices, current):
        if kind == "bool":
            w = wx.CheckBox(parent)
            w.SetValue(str(current).strip().lower() in _TRUE)
            grid.Add(w, flag=wx.ALIGN_CENTER_VERTICAL)
            self._widgets[(section, key)] = (w, kind)
            return
        if kind == "choice":
            w = wx.Choice(parent, choices=choices)
            cur = str(current).strip().lower()
            w.SetSelection(choices.index(cur) if cur in choices else 0)
            grid.Add(w, flag=wx.EXPAND)
            self._widgets[(section, key)] = (w, kind)
            return
        if kind == "dir":
            cell = wx.BoxSizer(wx.HORIZONTAL)
            tc = wx.TextCtrl(parent, value=str(current))
            browse = wx.Button(parent, label="Browse...")
            browse.Bind(wx.EVT_BUTTON, lambda e, ctrl=tc: self._OnBrowseDir(ctrl))
            cell.Add(tc, proportion=1, flag=wx.EXPAND | wx.RIGHT, border=5)
            cell.Add(browse, proportion=0)
            grid.Add(cell, flag=wx.EXPAND)
            self._widgets[(section, key)] = (tc, kind)
            return
        # text, int, float
        w = wx.TextCtrl(parent, value=str(current))
        grid.Add(w, flag=wx.EXPAND)
        self._widgets[(section, key)] = (w, kind)

    def _OnBrowseDir(self, ctrl):
        current = ctrl.GetValue().strip()
        defaultPath = current if os.path.isdir(current) else ""
        with wx.DirDialog(self, "Choose directory", defaultPath=defaultPath) as dlg:
            if dlg.ShowModal() == wx.ID_OK:
                ctrl.SetValue(dlg.GetPath())

    def OnSave(self, event):
        collected = []
        for _, items in SETTINGS_SCHEMA:
            for section, key, label, kind, choices, default in items:
                widget, _ = self._widgets[(section, key)]
                if kind == "bool":
                    val = "true" if widget.GetValue() else "false"
                elif kind == "choice":
                    val = widget.GetStringSelection()
                else:
                    val = widget.GetValue().strip()
                    if val and kind == "int" and not self._is_int(val):
                        return self._invalid(label, "an integer")
                    if val and kind == "float" and not self._is_float(val):
                        return self._invalid(label, "a number")
                collected.append((section, key, kind, val))

        path = user_config_path()
        config = configparser.ConfigParser()
        with suppress(configparser.Error, OSError):
            config.read(str(path))
        for section, key, kind, val in collected:
            if not config.has_section(section):
                config.add_section(section)
            if val == "" and kind in ("text", "dir"):
                config.remove_option(section, key)
            else:
                config.set(section, key, val)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w") as fh:
                config.write(fh)
        except OSError as e:
            wx.MessageBox(f"Could not save settings to {path}:\n{e}", "Error", wx.OK | wx.ICON_ERROR)
            return

        # Theme applies live; RefreshTheme toggles, so only call it when the value flipped.
        newTheme = dict(((s, k), v) for s, k, _, v in collected).get(("gui", "theme"), "dark")
        currentMode = "dark" if is_dark() else "light"
        if newTheme != currentMode and hasattr(self.parent, "RefreshTheme"):
            self.parent.RefreshTheme()

        wx.MessageBox(
            f"Settings saved to:\n{path}\n\nThe theme applies now. Other changes (analysis "
            "directory, MCP/result server, download enable) take effect after restarting CAPEsolo.",
            "Settings saved",
            wx.OK | wx.ICON_INFORMATION,
        )
        self.EndModal(wx.ID_OK)

    def _invalid(self, label, what):
        wx.MessageBox(f"{label} must be {what}.", "Invalid setting", wx.OK | wx.ICON_ERROR)

    @staticmethod
    def _is_int(value):
        try:
            int(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_float(value):
        try:
            float(value)
            return True
        except ValueError:
            return False
