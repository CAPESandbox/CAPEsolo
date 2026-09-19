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

from . import ui_kit as ui
from .theme import BG_MAIN, FONT_CODE, SP_SM, SP_XS, apply_theme, dip, is_dark

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
    ("VirusTotal lookups", [
        # Plaintext free community key for the GUI's own post-launch VT lookups/uploads (Payloads/Info
        # buttons); replaces the throttled built-in public key. Not used for downloads. Blank = public key.
        ("virustotal", "community_key", "Community API key (post-launch lookups, plaintext)", "text", None, ""),
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


class SettingsDialog(ui.Dialog):
    def __init__(self, parent):
        super().__init__(
            parent, "Settings", style=wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER
        )
        self.parent = parent
        self._widgets = {}  # (section, key) -> (widget, kind)

        config = self._read_effective()

        outer = wx.BoxSizer(wx.VERTICAL)
        panel = scrolled.ScrolledPanel(self, style=wx.TAB_TRAVERSAL)
        panel.SetBackgroundColour(BG_MAIN)
        vbox = wx.BoxSizer(wx.VERTICAL)

        for groupLabel, items in SETTINGS_SCHEMA:
            card = ui.Card(panel, title=groupLabel)
            grid = wx.FlexGridSizer(rows=0, cols=2, hgap=8, vgap=8)
            grid.AddGrowableCol(1, 1)
            for section, key, label, kind, choices, default in items:
                current = config.get(section, key, fallback=default)
                grid.Add(
                    wx.StaticText(card, label=f"{label}:"), flag=wx.ALIGN_CENTER_VERTICAL
                )
                self._add_value_widget(grid, card, section, key, kind, choices, current)
            card.body.Add(grid, proportion=1, flag=wx.EXPAND)
            if groupLabel == "MCP server":
                helpBtn = ui.Button(card, label="Command line...")
                helpBtn.Bind(wx.EVT_BUTTON, self.OnMcpHelp)
                card.body.Add(helpBtn, flag=wx.TOP, border=dip(self, SP_XS))
            vbox.Add(card, flag=wx.EXPAND | wx.ALL, border=dip(self, SP_SM))

        panel.SetSizer(vbox)
        panel.SetupScrolling(scroll_x=False, scroll_y=True)
        outer.Add(panel, proportion=1, flag=wx.EXPAND | wx.ALL, border=dip(self, SP_XS))

        btnRow = wx.BoxSizer(wx.HORIZONTAL)
        saveBtn = ui.Button(self, wx.ID_OK, "Save", variant=ui.PRIMARY)
        btnRow.AddStretchSpacer(1)
        btnRow.Add(saveBtn, flag=wx.RIGHT, border=dip(self, SP_SM))
        btnRow.Add(ui.Button(self, wx.ID_CANCEL, "Cancel"))
        outer.Add(btnRow, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=dip(self, SP_SM))

        self.SetSizer(outer)
        apply_theme(self)
        # apply_theme paints every wx.Panel BG_CARD, which would make the scroll area the
        # same colour as the cards sitting on it.
        panel.SetBackgroundColour(BG_MAIN)
        self.SetSize(wx.Size(560, 660))
        self.Bind(wx.EVT_BUTTON, self.OnSave, id=wx.ID_OK)
        self.Bind(wx.EVT_BUTTON, self.OnCancel, id=wx.ID_CANCEL)

    def OnCancel(self, event):
        self.EndModal(wx.ID_CANCEL)

    def _read_effective(self):
        config = configparser.ConfigParser()
        with suppress(configparser.Error, OSError):
            config.read([str(p) for p in config_paths()])
        return config

    def _add_value_widget(self, grid, parent, section, key, kind, choices, current):
        if kind == "bool":
            w = ui.Check(parent)
            w.SetValue(str(current).strip().lower() in _TRUE)
            grid.Add(w, flag=wx.ALIGN_CENTER_VERTICAL)
            self._widgets[(section, key)] = (w, kind)
            return
        if kind == "choice":
            w = ui.Picker(parent, choices=choices)
            cur = str(current).strip().lower()
            w.SetSelection(choices.index(cur) if cur in choices else 0)
            grid.Add(w, flag=wx.EXPAND)
            self._widgets[(section, key)] = (w, kind)
            return
        if kind == "dir":
            cell = wx.BoxSizer(wx.HORIZONTAL)
            field = ui.Field(parent, value=str(current))
            tc = field.ctrl
            browse = ui.Button(parent, label="Browse...", glyph=ui.FOLDER)
            browse.Bind(wx.EVT_BUTTON, lambda e, ctrl=tc: self._OnBrowseDir(ctrl))
            cell.Add(field, proportion=1, flag=wx.EXPAND | wx.RIGHT, border=dip(self, SP_XS))
            cell.Add(browse, proportion=0)
            grid.Add(cell, flag=wx.EXPAND)
            # The TextCtrl, not the wrapper: OnSave reads GetValue off whatever is stored.
            self._widgets[(section, key)] = (tc, kind)
            return
        # text, int, float
        field = ui.Field(parent, value=str(current))
        grid.Add(field, flag=wx.EXPAND)
        self._widgets[(section, key)] = (field.ctrl, kind)

    def _OnBrowseDir(self, ctrl):
        current = ctrl.GetValue().strip()
        defaultPath = current if os.path.isdir(current) else ""
        with wx.DirDialog(self, "Choose directory", defaultPath=defaultPath) as dlg:
            if dlg.ShowModal() == wx.ID_OK:
                ctrl.SetValue(dlg.GetPath())

    def OnMcpHelp(self, event):
        """Show how to start the server, since CAPEsolo itself never does."""
        def widget(key):
            return self._widgets[("mcp_server", key)][0]

        transport = widget("transport").GetStringSelection()
        host = widget("host").GetValue().strip() or "127.0.0.1"
        port = widget("port").GetValue().strip() or "8000"
        path = widget("path").GetValue().strip() or "/mcp"
        if transport == "stdio":
            effect = "stdio opens no port - the MCP client launches the server itself."
        else:
            effect = f"Clients connect to http://{host}:{port}{path}"

        text = (
            "CAPEsolo does not start the MCP server. Save these settings, then run it\n"
            "yourself from a command prompt in this VM:\n"
            "\n"
            "    CAPEsolo-mcp\n"
            "\n"
            "It reads the settings above, so no flags are needed. Equivalent:\n"
            "\n"
            "    python -m CAPEsolo.mcp_server\n"
            "\n"
            "Flag syntax, overriding the saved values for one run:\n"
            "\n"
            "    CAPEsolo-mcp --transport streamable-http\n"
            f"        --host {host} --port {port} --path {path}\n"
            "\n"
            "Require a bearer token on every HTTP request (set it before starting):\n"
            "\n"
            "    set CAPESOLO_MCP_TOKEN=some-long-random-value\n"
            "\n"
            f"Current transport is {transport}. {effect}\n"
            "\n"
            "The server refuses to start unless 'Enable MCP server' is checked. Full guide:\n"
            "github.com/CAPESandbox/CAPEsolo - mcp_server.md"
        )

        dlg = ui.Dialog(
            self,
            "Starting the MCP server",
            style=wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER,
        )
        dlg.SetEscapeId(wx.ID_OK)
        sizer = wx.BoxSizer(wx.VERTICAL)
        ctrl = wx.TextCtrl(dlg, value=text, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.HSCROLL)
        ctrl.SetFont(FONT_CODE)
        sizer.Add(ctrl, proportion=1, flag=wx.EXPAND | wx.ALL, border=dip(self, SP_SM))
        close = ui.Button(dlg, wx.ID_OK, "Close", variant=ui.PRIMARY)
        close.Bind(wx.EVT_BUTTON, lambda event: dlg.EndModal(wx.ID_OK))
        sizer.Add(close, flag=wx.ALIGN_RIGHT | wx.RIGHT | wx.BOTTOM, border=dip(self, SP_SM))
        dlg.SetSizer(sizer)
        apply_theme(dlg)
        dlg.SetSize(wx.Size(700, 520))
        dlg.ShowModal()
        dlg.Destroy()

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
            ui.message(f"Could not save settings to {path}:\n{e}", "Error", wx.OK | wx.ICON_ERROR)
            return

        # Theme applies live; RefreshTheme toggles, so only call it when the value flipped.
        newTheme = dict(((s, k), v) for s, k, _, v in collected).get(("gui", "theme"), "dark")
        currentMode = "dark" if is_dark() else "light"
        if newTheme != currentMode and hasattr(self.parent, "RefreshTheme"):
            self.parent.RefreshTheme()

        ui.message(
            f"Settings saved to:\n{path}\n\nThe theme applies now. Analysis directory, result "
            "server and download enable take effect after restarting CAPEsolo.\n\nMCP settings "
            "apply to the separate CAPEsolo-mcp process, which CAPEsolo does not start - "
            "restarting CAPEsolo will not open the port. See \"Command line...\" under MCP server.",
            "Settings saved",
            wx.OK | wx.ICON_INFORMATION,
        )
        self.EndModal(wx.ID_OK)

    def _invalid(self, label, what):
        ui.message(f"{label} must be {what}.", "Invalid setting", wx.OK | wx.ICON_ERROR)

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
