#!/usr/bin/env python3
"""Standalone triage viewer for a CAPEsolo JSON report (report.json).

Self-contained: standard library only (tkinter/ttk + json), so it runs on any host with Python,
no CAPEsolo install and no pip dependencies. tkinter ships with the standard Windows/macOS Python;
on Linux install python3-tk.

Presents a triage report - Overview verdict, Signatures, Processes, Network, Payloads, IOCs -
plus a global search and a Raw JSON tree. Built for large reports: the file is read in chunks with
a progress bar, the Raw JSON tree loads lazily, and the detail panes are bounded.

Usage:
    python report_viewer.py [path\\to\\report.json | path\\to\\bundle.zip] [--theme dark|light]

With no argument it defaults to ~/Desktop/report.json (where CAPEsolo writes it).

A results bundle (Zip Results in CAPEsolo) opens directly: the report is read out of the zip in
place, so a full bundle's payload bytes are never written to the machine doing the triage. The
Capture tab reports what the analysis stored and what it lost.

The palette follows the OS setting on Windows and is dark elsewhere; the top-bar button flips it
for the session, and --theme forces one. Colours mirror CAPEsolo/classes/theme.py, which stays
the source of truth for them.
"""

import csv
import gc
import json
import os
import sys
import threading
import tkinter as tk
import zipfile
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

VALUE_PREVIEW_LEN = 200
MAX_CHILDREN = 2000
FULL_DUMP_LIMIT = 5000
MAX_SCALAR = 200_000
READ_CHUNK = 8 * 1024 * 1024
MAX_INDEX = 300_000          # cap on global-search index entries
MAX_STRINGS = 100_000        # cap on strings pulled into the search index
DETAIL_STRINGS = 2000        # cap on strings shown in a payload detail pane
PLAINTEXT_BLOCK = 8000       # cap on a decrypted request/response block shown in Network
CALLS_CAP = 5000             # cap on per-process API calls shown in the Processes tab
TABLE_ROW_CAP = 5000         # cap on rows pushed into a plain table (js events, enhanced, imports)
DARK, LIGHT = "dark", "light"

# Palette mirrored from CAPEsolo/classes/theme.py (_PALETTES) so a bundle opened on the host
# looks like the app it came from. The values are duplicated by necessity - this file must run
# on a machine with no CAPEsolo install - so theme.py stays the source of truth: change it there
# first, then copy.
PALETTES = {
    DARK: {
        "BG_MAIN": "#181c24",
        "BG_CARD": "#212631",
        "BG_INPUT": "#0f1115",
        "BG_SURFACE": "#272d3a",
        "BG_HOVER": "#2c3444",
        "BG_SELECT": "#1e4066",
        "FG_SELECT": "#c9d1d9",
        "FG_PRIMARY": "#c9d1d9",
        "FG_SECONDARY": "#8b949e",
        "FG_DISABLED": "#6e7681",
        "BORDER_SUBTLE": "#2c3340",
        "BORDER_STRONG": "#677081",
        "ACCENT": "#58a6ff",
        "GRID_ROW_ALT": "#191e28",
    },
    LIGHT: {
        "BG_MAIN": "#eceff4",
        "BG_CARD": "#f6f8fa",
        "BG_INPUT": "#ffffff",
        "BG_SURFACE": "#ffffff",
        "BG_HOVER": "#eaeef2",
        "BG_SELECT": "#cce8ff",
        "FG_SELECT": "#24292f",
        "FG_PRIMARY": "#24292f",
        "FG_SECONDARY": "#57606a",
        "FG_DISABLED": "#838c96",
        "BORDER_SUBTLE": "#d8dee4",
        "BORDER_STRONG": "#88919a",
        "ACCENT": "#0969da",
        "GRID_ROW_ALT": "#f6f8fa",
    },
}

# Row tints for API-call categories, from theme.py's _BEHAVIOR_PALETTES. Unmapped categories
# get no tint. "com" and "windows" have no wx counterpart and are derived to match.
CALL_CATEGORY_PALETTES = {
    DARK: {
        "filesystem": "#503214", "registry": "#501414", "process": "#142850",
        "threading": "#192850", "services": "#281450", "device": "#321e28",
        "network": "#143c14", "socket": "#143c14", "synchronization": "#3c1446",
        "browser": "#143714", "crypto": "#373714", "system": "#3c3714",
        "hooking": "#323232", "misc": "#282828", "com": "#143c46", "windows": "#3c2814",
    },
    LIGHT: {
        "filesystem": "#ffedd5", "registry": "#fee2e2", "process": "#dbeafe",
        "threading": "#e0e7ff", "services": "#ede9fe", "device": "#fde8f1",
        "network": "#dcfce7", "socket": "#dcfce7", "synchronization": "#fae8ff",
        "browser": "#e2fce7", "crypto": "#fef9c3", "system": "#fef3c7",
        "hooking": "#f3f4f6", "misc": "#f9fafb", "com": "#d6f0f5", "windows": "#f0e2d0",
    },
}

# Treeview row tags that carry meaning rather than category: severity, and the artifact that
# was not stored whole.
ROW_TAGS = {
    DARK: {
        "sev_high": {"background": "#5c1d1d", "foreground": "#ffb4b4"},
        "sev_med": {"background": "#5e3f08", "foreground": "#f0d9a8"},
        "partial": {"background": "#5c1d1d", "foreground": "#ffb4b4"},
    },
    LIGHT: {
        "sev_high": {"background": "#ffdddd", "foreground": "#7a1414"},
        "sev_med": {"background": "#fff0d0", "foreground": "#7a5514"},
        "partial": {"background": "#ffe2e2", "foreground": "#7a1414"},
    },
}

# Text-pane tags. Applied to every detail pane on a theme change - a tag only paints the ranges
# that use it, so the union is harmless and keeps the colours in one place.
TEXT_TAGS = {
    DARK: {
        "h": {"font": ("Consolas", 11, "bold"), "foreground": "#58a6ff"},
        "sev_high": {"foreground": "#ff7b72"},
        "sev_med": {"foreground": "#d29922"},
        "warn": {"foreground": "#ff7b72"},
        "ok": {"foreground": "#3fb950"},
    },
    LIGHT: {
        "h": {"font": ("Consolas", 11, "bold"), "foreground": "#0969da"},
        "sev_high": {"foreground": "#c0392b"},
        "sev_med": {"foreground": "#c07a1f"},
        "warn": {"foreground": "#c0392b"},
        "ok": {"foreground": "#1e7a3c"},
    },
}
# Every group behavior.Summary.run() returns, in its order, so nothing it collects is dropped.
SUMMARY_GROUPS = (
    "files", "read_files", "write_files", "delete_files", "keys", "read_keys",
    "write_keys", "delete_keys", "executed_commands", "resolved_apis", "mutexes",
    "created_services", "started_services",
)
# js_log events the JS Log tab's HTTP and DNS rows already pair up; everything else
# (console, warning, init, eval, tcp_*, socket_*, module_intercept*) stays an Event row.
JS_PAIRED_EVENTS = {
    "dns_query", "dns_result", "dns_error",
    "http_request", "http_response", "http_error", "http_request_body",
}
DEFAULT_REPORT = os.path.join(os.path.expanduser("~"), "Desktop", "report.json")


def _mono_family():
    """Pick an installed fixed-width face.

    Tk falls back to a proportional font for a family it does not have, without erroring, so
    hardcoding "Consolas" renders every detail pane proportionally on Linux and macOS. Needs a
    Tk root to exist, so it is resolved at construction rather than at import.
    """
    try:
        installed = {name.lower() for name in tkfont.families()}
    except tk.TclError:
        return "TkFixedFont"
    for family in ("Consolas", "Menlo", "DejaVu Sans Mono", "Liberation Mono", "Courier New"):
        if family.lower() in installed:
            return family
    # Tk guarantees this one is fixed-width on every platform.
    return tkfont.nametofont("TkFixedFont").actual("family")


def _detect_theme():
    """Follow the OS setting where it can be read; dark elsewhere.

    Windows records it per-user in the registry; winreg is stdlib, so this keeps the viewer
    dependency-free. Anything else (or a locked-down registry) falls back to dark, which is
    what CAPEsolo itself defaults to.
    """
    if sys.platform != "win32":
        return DARK
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        ) as key:
            return LIGHT if winreg.QueryValueEx(key, "AppsUseLightTheme")[0] else DARK
    except Exception:  # noqa: BLE001 - never let theme detection stop the viewer opening
        return DARK


def _set_titlebar(window, dark):
    """Darken the OS-drawn title bar on Windows 10 1809+ / 11. No-op everywhere else."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        window.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
        value = ctypes.c_int(1 if dark else 0)
        # 20 is DWMWA_USE_IMMERSIVE_DARK_MODE; 19 was the pre-20H1 attribute number.
        for attribute in (20, 19):
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, attribute, ctypes.byref(value), ctypes.sizeof(value)
            ) == 0:
                break
    except Exception:  # noqa: BLE001 - cosmetic only
        return


def _preview(value):
    if isinstance(value, dict):
        return f"{{{len(value)}}}"
    if isinstance(value, list):
        return f"[{len(value)}]"
    text = " ".join(str(value).split())
    return text if len(text) <= VALUE_PREVIEW_LEN else text[:VALUE_PREVIEW_LEN] + "…"


def _bounded_count(value, limit):
    stack = [value]
    n = 0
    while stack:
        v = stack.pop()
        n += 1
        if n > limit:
            return n
        if isinstance(v, dict):
            stack.extend(v.values())
        elif isinstance(v, list):
            stack.extend(v)
    return n


def _severity_tag(sev):
    try:
        sev = int(sev)
    except (TypeError, ValueError):
        sev = 1
    if sev >= 3:
        return "sev_high"
    if sev == 2:
        return "sev_med"
    return "sev_low"


class ReportViewer:
    def __init__(self, root, path=None, theme=None, ai_config=None):
        self.root = root
        self.path = None
        self.report = {}
        self.raw_data = {}      # raw-tree item id -> value
        self.raw_lazy = set()
        self._prog = None
        self.search_index = []  # list of (category, value, tab_key)
        self.tab_frames = {}    # tab_key -> frame (for search jump)
        # Widgets the ttk Style cannot reach: tk.Text panes and the per-row tag colours of
        # every Treeview have to be recoloured by hand when the theme changes.
        self._texts = []
        self._trees = []
        self.style = ttk.Style(root)
        self.mono = _mono_family()
        self.mode = theme or _detect_theme()
        # AI analysis: optional, lazily constructed, and inert until the analyst consents.
        self.ai_config = ai_config or AIConfig()
        self.engine = None
        self.ai_panes = {}
        self._ai_busy = False
        self._ai_cancel = threading.Event()

        root.title("CAPEsolo Report Viewer")
        root.geometry("1150x720")

        self._build_menu()
        self._build_topbar()
        self._build_tabs()
        self._apply_theme(self.mode)

        initial = path if (path and os.path.isfile(path)) else DEFAULT_REPORT
        if os.path.isfile(initial):
            self.load(initial)

    # ------------------------------------------------------------------ theme
    def _apply_theme(self, mode):
        """Repaint everything. ttk widgets follow the Style; the rest is done by hand."""
        self.mode = mode
        palette = PALETTES[mode]
        self._style_ttk(palette)
        self.root.configure(bg=palette["BG_MAIN"])
        for text in self._texts:
            text.configure(
                bg=palette["BG_INPUT"], fg=palette["FG_PRIMARY"],
                insertbackground=palette["FG_PRIMARY"],
                selectbackground=palette["BG_SELECT"], selectforeground=palette["FG_SELECT"],
                highlightthickness=0, borderwidth=0,
            )
            for tag, options in TEXT_TAGS[mode].items():
                if "font" in options:
                    options = dict(options, font=(self.mono,) + tuple(options["font"][1:]))
                text.tag_configure(tag, **options)
        for tree in self._trees:
            for category, color in CALL_CATEGORY_PALETTES[mode].items():
                tree.tag_configure(category, background=color, foreground=palette["FG_PRIMARY"])
            for tag, options in ROW_TAGS[mode].items():
                tree.tag_configure(tag, **options)
        if hasattr(self, "theme_btn"):
            self.theme_btn.config(text="Light" if mode == DARK else "Dark")
        _set_titlebar(self.root, mode == DARK)

    def _style_ttk(self, palette):
        """clam is the only stock ttk theme that honours these colours on Windows - the
        native vista/xpnative themes draw from the OS visual style and ignore them."""
        style = self.style
        style.theme_use("clam")
        bg, card, fg = palette["BG_MAIN"], palette["BG_CARD"], palette["FG_PRIMARY"]
        inputbg, border = palette["BG_INPUT"], palette["BORDER_SUBTLE"]
        style.configure(".", background=bg, foreground=fg, fieldbackground=inputbg,
                        bordercolor=border, darkcolor=card, lightcolor=card,
                        troughcolor=palette["BG_INPUT"], focuscolor=palette["ACCENT"],
                        insertcolor=fg)
        style.configure("TFrame", background=bg)
        style.configure("TLabel", background=bg, foreground=fg)
        style.configure("TPanedwindow", background=bg)
        style.configure("Sash", sashthickness=6, gripcount=0, background=palette["BORDER_SUBTLE"])
        style.configure("TButton", background=palette["BG_SURFACE"], foreground=fg,
                        bordercolor=palette["BORDER_STRONG"], focusthickness=1, padding=4)
        style.map("TButton",
                  background=[("pressed", palette["BG_HOVER"]), ("active", palette["BG_HOVER"])],
                  foreground=[("disabled", palette["FG_DISABLED"])])
        style.configure("TEntry", fieldbackground=inputbg, foreground=fg,
                        bordercolor=palette["BORDER_STRONG"], insertcolor=fg)
        style.configure("TCombobox", fieldbackground=inputbg, foreground=fg,
                        background=palette["BG_SURFACE"], arrowcolor=fg,
                        bordercolor=palette["BORDER_STRONG"])
        style.map("TCombobox", fieldbackground=[("readonly", inputbg)],
                  foreground=[("disabled", palette["FG_DISABLED"])])
        # The dropdown list is a classic tk Listbox inside the combobox, reachable only
        # through the option database.
        self.root.option_add("*TCombobox*Listbox.background", inputbg)
        self.root.option_add("*TCombobox*Listbox.foreground", fg)
        self.root.option_add("*TCombobox*Listbox.selectBackground", palette["BG_SELECT"])
        self.root.option_add("*TCombobox*Listbox.selectForeground", palette["FG_SELECT"])
        style.configure("TNotebook", background=bg, bordercolor=border)
        style.configure("TNotebook.Tab", background=card, foreground=palette["FG_SECONDARY"],
                        bordercolor=border, padding=(10, 4))
        style.map("TNotebook.Tab",
                  background=[("selected", palette["BG_SURFACE"])],
                  foreground=[("selected", fg)])
        style.configure("Treeview", background=inputbg, fieldbackground=inputbg, foreground=fg,
                        bordercolor=border, rowheight=20)
        style.map("Treeview", background=[("selected", palette["BG_SELECT"])],
                  foreground=[("selected", palette["FG_SELECT"])])
        style.configure("Treeview.Heading", background=palette["BG_SURFACE"], foreground=fg,
                        bordercolor=border, relief="flat")
        style.map("Treeview.Heading", background=[("active", palette["BG_HOVER"])])
        style.configure("TScrollbar", background=palette["BG_SURFACE"],
                        troughcolor=bg, bordercolor=border, arrowcolor=fg)
        style.map("TScrollbar", background=[("active", palette["BG_HOVER"])])
        style.configure("TProgressbar", background=palette["ACCENT"], troughcolor=inputbg,
                        bordercolor=border)

    def _toggle_theme(self):
        self._apply_theme(LIGHT if self.mode == DARK else DARK)

    # ------------------------------------------------------------------ UI scaffold
    def _build_menu(self):
        menubar = tk.Menu(self.root)
        m = tk.Menu(menubar, tearoff=0)
        m.add_command(label="Open...", command=self.on_open, accelerator="Ctrl+O")
        m.add_command(label="Reload", command=self.on_reload, accelerator="Ctrl+R")
        m.add_separator()
        m.add_command(label="Exit", command=self.root.destroy)
        menubar.add_cascade(label="File", menu=m)
        self.root.config(menu=menubar)
        self.root.bind_all("<Control-o>", lambda e: self.on_open())
        self.root.bind_all("<Control-r>", lambda e: self.on_reload())

    def _build_topbar(self):
        bar = ttk.Frame(self.root)
        bar.pack(fill=tk.X, padx=6, pady=4)
        ttk.Label(bar, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        entry = ttk.Entry(bar, textvariable=self.search_var, width=40)
        entry.pack(side=tk.LEFT, padx=4)
        entry.bind("<Return>", lambda e: self.on_search())
        ttk.Button(bar, text="Find", command=self.on_search).pack(side=tk.LEFT)
        # In the top bar rather than the menu: the Windows menubar is OS-drawn and stays
        # light whatever the palette, so the control that switches themes should not live
        # in the one strip that cannot follow them.
        ttk.Button(bar, text="Analyze tab", command=self._analyze_current_tab).pack(
            side=tk.LEFT, padx=(8, 0))
        self.theme_btn = ttk.Button(bar, text="Light", width=7, command=self._toggle_theme)
        self.theme_btn.pack(side=tk.RIGHT, padx=(6, 0))
        self.path_label = ttk.Label(bar, text="")
        self.path_label.pack(side=tk.RIGHT)

    def _build_tabs(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        self._build_overview_tab()
        self._build_ai_tab()
        self._build_capture_tab()
        self._build_signatures_tab()
        self._build_processes_tab()
        self._build_behavior_tab()
        self._build_network_tab()
        self._build_jslog_tab()
        self._build_payloads_tab()
        self._build_configs_tab()
        self._build_yara_tab()
        self._build_static_tab()
        self._build_iocs_tab()
        self._build_raw_tab()

    def _table(self, parent, columns, widths=None):
        frame = ttk.Frame(parent)
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        widths = widths or {}
        for c in columns:
            tree.heading(c, text=c)
            tree.column(c, width=widths.get(c, 140), anchor="w")
        ys = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=ys.set)
        tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self._trees.append(tree)
        return frame, tree

    def _detail_text(self, parent):
        frame = ttk.Frame(parent)
        text = tk.Text(frame, wrap=tk.NONE, font=(self.mono, 10), state=tk.DISABLED, height=10)
        self._texts.append(text)
        ys = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text.yview)
        xs = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=text.xview)
        text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        text.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        return frame, text

    @staticmethod
    def _set_text(widget, text):
        widget.config(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert("1.0", text)
        widget.config(state=tk.DISABLED)

    @staticmethod
    def _detail_value(value):
        """Full value for a detail pane - unlike _preview, which is for a table cell."""
        if isinstance(value, (dict, list)):
            return json.dumps(value, indent=2, ensure_ascii=False, default=str)
        return str(value)

    @staticmethod
    def _more_row(tree, remaining):
        """Say how many rows a cap hid, rather than truncating in silence."""
        if remaining > 0:
            columns = tree.cget("columns")
            tree.insert("", "end", values=("…", f"{remaining} more not shown - see the Raw JSON tab")
                        + ("",) * (len(columns) - 2))

    def _add_tab(self, frame, label, key):
        self.notebook.add(frame, text=label)
        self.tab_frames[key] = frame

    # ------------------------------------------------------------------ tab widgets
    def _build_overview_tab(self):
        # Tag colours (h / sev_high / sev_med / warn / ok) come from TEXT_TAGS via
        # _apply_theme, so every pane follows a theme switch without knowing about it.
        frame, self.overview = self._detail_text(self.notebook)
        self._add_tab(frame, "Overview", "Overview")

    def _build_capture_tab(self):
        frame, self.capture = self._detail_text(self.notebook)
        self._add_tab(frame, "Capture", "Capture")

    def _build_signatures_tab(self):
        pane = ttk.PanedWindow(self.notebook, orient=tk.VERTICAL)
        tframe, self.sig_tree = self._table(pane, ("Sev", "Name", "Categories"),
                                            {"Sev": 45, "Name": 260, "Categories": 220})
        self.sig_tree.bind("<<TreeviewSelect>>", self._on_sig_select)
        dframe, self.sig_detail = self._detail_text(pane)
        pane.add(tframe, weight=2)
        pane.add(dframe, weight=1)
        self._add_tab(pane, "Signatures", "Signatures")

    def _build_processes_tab(self):
        pane = ttk.PanedWindow(self.notebook, orient=tk.HORIZONTAL)
        tframe = ttk.Frame(pane)
        self.proc_tree = ttk.Treeview(tframe, show="tree")
        ys = ttk.Scrollbar(tframe, orient=tk.VERTICAL, command=self.proc_tree.yview)
        self.proc_tree.configure(yscrollcommand=ys.set)
        self.proc_tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        tframe.rowconfigure(0, weight=1)
        tframe.columnconfigure(0, weight=1)
        self.proc_tree.bind("<<TreeviewSelect>>", self._on_proc_select)
        self._proc_pid = {}
        # Right side: process metadata over a per-process API-call table (like the Behavior tab).
        rpane = ttk.PanedWindow(pane, orient=tk.VERTICAL)
        dframe, self.proc_detail = self._detail_text(rpane)
        callsFrame = ttk.Frame(rpane)
        bar = ttk.Frame(callsFrame)
        bar.pack(fill=tk.X, padx=2, pady=2)
        ttk.Label(bar, text="Category:").pack(side=tk.LEFT)
        self.call_cat = ttk.Combobox(bar, state="readonly", width=16, values=["all"])
        self.call_cat.set("all")
        self.call_cat.pack(side=tk.LEFT, padx=(2, 8))
        self.call_cat.bind("<<ComboboxSelected>>", lambda e: self._apply_call_filters())
        ttk.Label(bar, text="TID:").pack(side=tk.LEFT)
        self.call_tid = ttk.Entry(bar, width=8)
        self.call_tid.pack(side=tk.LEFT, padx=(2, 8))
        self.call_tid.bind("<Return>", lambda e: self._apply_call_filters())
        ttk.Label(bar, text="API:").pack(side=tk.LEFT)
        self.call_api = ttk.Entry(bar, width=20)
        self.call_api.pack(side=tk.LEFT, padx=(2, 8))
        self.call_api.bind("<Return>", lambda e: self._apply_call_filters())
        ttk.Button(bar, text="Clear", command=self._clear_call_filters).pack(side=tk.LEFT)
        self.call_status = ttk.Label(bar, text="")
        self.call_status.pack(side=tk.RIGHT)
        cframe, self.proc_calls = self._table(
            callsFrame,
            ("Time", "TID", "Caller", "Parent caller", "API", "Arguments", "Status", "Return", "Repeated"),
            {"Time": 150, "TID": 60, "Caller": 110, "Parent caller": 110, "API": 160,
             "Arguments": 300, "Status": 60, "Return": 90, "Repeated": 70},
        )
        cframe.pack(fill=tk.BOTH, expand=True)
        self._proc_calls_all = []
        rpane.add(dframe, weight=1)
        rpane.add(callsFrame, weight=3)
        pane.add(tframe, weight=2)
        pane.add(rpane, weight=5)
        self._add_tab(pane, "Processes", "Processes")

    def _build_behavior_tab(self):
        outer = ttk.Frame(self.notebook)
        inner = ttk.Notebook(outer)
        inner.pack(fill=tk.BOTH, expand=True)
        frame, self.beh_summary = self._table(inner, ("Type", "Value"), {"Type": 150, "Value": 760})
        inner.add(frame, text="Summary")
        frame, self.beh_anomaly = self._table(
            inner, ("Process", "PID", "Category", "Function", "Message"),
            {"Process": 160, "PID": 60, "Category": 120, "Function": 170, "Message": 420},
        )
        inner.add(frame, text="Anomalies")
        # A captured buffer is the whole pre-encryption plaintext, so it needs a detail pane
        # rather than a cell.
        pane = ttk.PanedWindow(inner, orient=tk.VERTICAL)
        tframe, self.beh_bufs = self._table(
            pane, ("Process", "PID", "API", "Size", "Key"),
            {"Process": 170, "PID": 60, "API": 170, "Size": 80, "Key": 260},
        )
        self.beh_bufs.bind("<<TreeviewSelect>>", self._on_buf_select)
        self._buf_rows = {}
        dframe, self.beh_buf_detail = self._detail_text(pane)
        pane.add(tframe, weight=2)
        pane.add(dframe, weight=3)
        inner.add(pane, text="Encrypted buffers")
        frame, self.beh_enhanced = self._table(
            inner, ("Time", "Event", "Object", "Data"),
            {"Time": 150, "Event": 100, "Object": 100, "Data": 620},
        )
        inner.add(frame, text="Enhanced")
        self._add_tab(outer, "Behavior", "Behavior")

    def _build_network_tab(self):
        outer = ttk.Frame(self.notebook)
        self.net_sources = ttk.Label(outer, text="")
        self.net_sources.pack(fill=tk.X, padx=4, pady=2)
        self.net_notebook = ttk.Notebook(outer)
        self.net_notebook.pack(fill=tk.BOTH, expand=True)
        self.net_tables = {}

        def add_table(name, cols):
            frame, tree = self._table(self.net_notebook, cols, {c: 220 for c in cols})
            self.net_tables[name] = tree
            self.net_notebook.add(frame, text=name)

        add_table("DNS", ("request", "type", "answers"))
        # HTTP entries carry the request text ("data", folded in from the decrypted streams)
        # plus body/version/user-agent, none of which fit a flat row, so this sub-tab is a
        # table over a detail pane like Plaintext below.
        hpane = ttk.PanedWindow(self.net_notebook, orient=tk.VERTICAL)
        tframe, self.net_http_tree = self._table(
            hpane, ("method", "host", "port", "uri", "count"),
            {"method": 70, "host": 200, "port": 60, "uri": 360, "count": 60},
        )
        self.net_http_tree.bind("<<TreeviewSelect>>", self._on_net_http_select)
        self._net_http_rows = {}
        dframe, self.net_http_detail = self._detail_text(hpane)
        hpane.add(tframe, weight=2)
        hpane.add(dframe, weight=2)
        self.net_notebook.add(hpane, text="HTTP")
        add_table("Hosts", ("ip",))
        add_table("Domains", ("domain", "ip"))
        add_table("Flows", ("proto", "src", "sport", "dst", "dport", "time"))
        # Decrypted/reassembled streams need a detail pane for their request and response,
        # unlike the flat tables above, so this sub-tab is a table over a detail text pane.
        pane = ttk.PanedWindow(self.net_notebook, orient=tk.VERTICAL)
        tframe, self.net_plain_tree = self._table(
            pane, ("proto", "method", "host", "uri", "status"),
            {"proto": 70, "method": 70, "host": 200, "uri": 300, "status": 60},
        )
        self.net_plain_tree.bind("<<TreeviewSelect>>", self._on_net_plain_select)
        self._net_plain_rows = {}
        dframe, self.net_plain_detail = self._detail_text(pane)
        pane.add(tframe, weight=2)
        pane.add(dframe, weight=3)
        self.net_notebook.add(pane, text="Plaintext")
        self._add_tab(outer, "Network", "Network")

    def _build_jslog_tab(self):
        outer = ttk.Frame(self.notebook)
        self.js_header = ttk.Label(outer, text="")
        self.js_header.pack(fill=tk.X, padx=4, pady=2)
        inner = ttk.Notebook(outer)
        inner.pack(fill=tk.BOTH, expand=True)
        # Activity uses the same row model as the GUI's JS Console tab (kind/ts/src/dst/info
        # over a detail pane), minus the stream reassembly that needs the analysis directory.
        actFrame = ttk.Frame(inner)
        bar = ttk.Frame(actFrame)
        bar.pack(fill=tk.X, padx=2, pady=2)
        ttk.Label(bar, text="Kind:").pack(side=tk.LEFT)
        self.js_kind = ttk.Combobox(bar, state="readonly", width=14, values=["all"])
        self.js_kind.set("all")
        self.js_kind.pack(side=tk.LEFT, padx=(2, 8))
        self.js_kind.bind("<<ComboboxSelected>>", lambda e: self._fill_js_rows())
        self.js_status = ttk.Label(bar, text="")
        self.js_status.pack(side=tk.RIGHT)
        pane = ttk.PanedWindow(actFrame, orient=tk.VERTICAL)
        pane.pack(fill=tk.BOTH, expand=True)
        tframe, self.js_tree = self._table(
            pane, ("Time", "Kind", "Source", "Destination", "Info"),
            {"Time": 150, "Kind": 90, "Source": 110, "Destination": 260, "Info": 420},
        )
        self.js_tree.bind("<<TreeviewSelect>>", self._on_js_select)
        self._js_rows = {}
        self._js_all = []
        dframe, self.js_detail = self._detail_text(pane)
        pane.add(tframe, weight=2)
        pane.add(dframe, weight=3)
        inner.add(actFrame, text="Activity")
        frame, self.js_buffers = self._table(
            inner, ("Stream", "SHA256", "Bytes"),
            {"Stream": 240, "SHA256": 470, "Bytes": 90},
        )
        inner.add(frame, text="Buffers")
        frame, self.js_raw = self._detail_text(inner)
        inner.add(frame, text="Raw log")
        self._add_tab(outer, "JS Log", "JS Log")

    def _build_payloads_tab(self):
        pane = ttk.PanedWindow(self.notebook, orient=tk.VERTICAL)
        tframe, self.pay_tree = self._table(
            pane, ("Name", "Type", "Size", "SHA256", "PID", "State"),
            {"Name": 220, "Type": 200, "Size": 90, "SHA256": 300, "PID": 60, "State": 90},
        )
        self.pay_tree.bind("<<TreeviewSelect>>", self._on_pay_select)
        self._pay_rows = {}
        dframe, self.pay_detail = self._detail_text(pane)
        pane.add(tframe, weight=2)
        pane.add(dframe, weight=1)
        self._add_tab(pane, "Payloads", "Payloads")

    def _build_configs_tab(self):
        pane = ttk.PanedWindow(self.notebook, orient=tk.VERTICAL)
        tframe, self.cfg_tree = self._table(
            pane, ("File", "Field", "Value"),
            {"File": 240, "Field": 180, "Value": 620},
        )
        self.cfg_tree.bind("<<TreeviewSelect>>", self._on_cfg_select)
        self._cfg_rows = {}
        dframe, self.cfg_detail = self._detail_text(pane)
        pane.add(tframe, weight=2)
        pane.add(dframe, weight=1)
        self._add_tab(pane, "Configs", "Configs")

    def _build_yara_tab(self):
        pane = ttk.PanedWindow(self.notebook, orient=tk.VERTICAL)
        tframe, self.yara_tree = self._table(
            pane, ("File", "Rule", "CAPE name", "Strings", "Description"),
            {"File": 260, "Rule": 200, "CAPE name": 120, "Strings": 70, "Description": 420},
        )
        self.yara_tree.bind("<<TreeviewSelect>>", self._on_yara_select)
        self._yara_rows = {}
        dframe, self.yara_detail = self._detail_text(pane)
        pane.add(tframe, weight=2)
        pane.add(dframe, weight=2)
        self._add_tab(pane, "Yara", "Yara")

    def _build_static_tab(self):
        outer = ttk.Frame(self.notebook)
        inner = ttk.Notebook(outer)
        inner.pack(fill=tk.BOTH, expand=True)
        frame, self.static_info = self._detail_text(inner)
        inner.add(frame, text="File")
        frame, self.pe_sections = self._table(
            inner, ("Name", "Raw address", "Virtual address", "Virtual size", "Size of data",
                    "Entropy", "Characteristics"),
            {"Name": 110, "Raw address": 110, "Virtual address": 120, "Virtual size": 110,
             "Size of data": 110, "Entropy": 70, "Characteristics": 320},
        )
        inner.add(frame, text="Sections")
        frame, self.pe_imports = self._table(
            inner, ("DLL", "Address", "Symbol"),
            {"DLL": 220, "Address": 120, "Symbol": 420},
        )
        inner.add(frame, text="Imports")
        frame, self.pe_exports = self._table(
            inner, ("Address", "Ordinal", "Name"),
            {"Address": 120, "Ordinal": 80, "Name": 460},
        )
        inner.add(frame, text="Exports")
        frame, self.pe_resources = self._table(
            inner, ("Name", "Offset", "Size", "Language", "Sublanguage", "Entropy"),
            {"Name": 160, "Offset": 110, "Size": 100, "Language": 150, "Sublanguage": 220,
             "Entropy": 70},
        )
        inner.add(frame, text="Resources")
        frame, self.static_strings = self._detail_text(inner)
        inner.add(frame, text="Strings")
        self._add_tab(outer, "Static", "Static")

    def _build_iocs_tab(self):
        frame = ttk.Frame(self.notebook)
        bar = ttk.Frame(frame)
        bar.pack(fill=tk.X)
        ttk.Button(bar, text="Copy all", command=self._copy_iocs).pack(side=tk.LEFT, padx=2, pady=2)
        ttk.Button(bar, text="Export CSV", command=lambda: self._export_iocs("csv")).pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="Export text", command=lambda: self._export_iocs("txt")).pack(side=tk.LEFT, padx=2)
        tframe, self.ioc_tree = self._table(frame, ("Type", "Value"), {"Type": 160, "Value": 700})
        tframe.pack(fill=tk.BOTH, expand=True)
        self._add_tab(frame, "IOCs", "IOCs")

    def _build_raw_tab(self):
        pane = ttk.PanedWindow(self.notebook, orient=tk.HORIZONTAL)
        tframe = ttk.Frame(pane)
        self.raw_tree = ttk.Treeview(tframe, columns=("value",), show="tree headings")
        self.raw_tree.heading("#0", text="Key")
        self.raw_tree.heading("value", text="Value")
        self.raw_tree.column("#0", width=300, stretch=False)
        self.raw_tree.column("value", width=360)
        ys = ttk.Scrollbar(tframe, orient=tk.VERTICAL, command=self.raw_tree.yview)
        self.raw_tree.configure(yscrollcommand=ys.set)
        self.raw_tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        tframe.rowconfigure(0, weight=1)
        tframe.columnconfigure(0, weight=1)
        self.raw_tree.bind("<<TreeviewSelect>>", self._on_raw_select)
        self.raw_tree.bind("<<TreeviewOpen>>", self._on_raw_expand)
        dframe, self.raw_detail = self._detail_text(pane)
        pane.add(tframe, weight=3)
        pane.add(dframe, weight=4)
        self._add_tab(pane, "Raw JSON", "Raw JSON")

    # ------------------------------------------------------------------ loading
    def load(self, path):
        if not os.path.isfile(path):
            messagebox.showerror("Report Viewer", f"File not found:\n{path}")
            return
        win = tk.Toplevel(self.root)
        win.title("Loading")
        win.transient(self.root)
        win.resizable(False, False)
        win.configure(bg=PALETTES[self.mode]["BG_MAIN"])
        _set_titlebar(win, self.mode == DARK)
        ttk.Label(win, text=f"Loading {os.path.basename(path)}\n(a large report may pause while parsing)",
                  justify="center").pack(padx=24, pady=(16, 8))
        bar = ttk.Progressbar(win, mode="determinate", maximum=100, length=380)
        bar.pack(padx=24, pady=(0, 6))
        status = ttk.Label(win, text="")
        status.pack(padx=24, pady=(0, 8))
        shared = {"read": 0, "size": max(1, os.path.getsize(path)), "cancel": False}
        ttk.Button(win, text="Cancel", command=lambda: shared.__setitem__("cancel", True)).pack(pady=(0, 14))
        win.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - win.winfo_width()) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - win.winfo_height()) // 2
        win.geometry(f"+{max(0, x)}+{max(0, y)}")
        win.grab_set()
        self._prog = (win, bar, status)
        threading.Thread(target=self._load_worker, args=(path, shared), daemon=True).start()
        self.root.after(80, lambda: self._poll_load(path, shared))

    def _load_worker(self, path, shared):
        try:
            # A CAPEsolo results bundle is a zip with report.json at its root; reading it in
            # place means payload bytes in a full bundle are never written to this machine.
            if zipfile.is_zipfile(path):
                buf, capture = self._read_bundle(path, shared)
            else:
                buf, capture = self._read_plain(path, shared), None
            if buf is None:  # cancelled
                shared["error"] = "cancelled"
                return
            shared["phase"] = "parsing"
            gc.disable()
            try:
                data = json.loads(buf)
            finally:
                gc.enable()
            _merge_capture(data, capture)
            shared["data"] = data
        except Exception as e:  # noqa: BLE001
            shared["error"] = e

    @staticmethod
    def _read_plain(path, shared):
        buf = bytearray()
        with open(path, "rb") as f:
            while True:
                if shared["cancel"]:
                    return None
                chunk = f.read(READ_CHUNK)
                if not chunk:
                    break
                buf += chunk
                shared["read"] = len(buf)
        return buf

    @staticmethod
    def _read_bundle(path, shared):
        """Read report.json - and capture.json, if present - out of a bundle zip."""
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            member = _bundle_member(names, "report.json")
            if member is None:
                listing = ", ".join(sorted(names)[:20]) or "nothing"
                raise ValueError(
                    "This zip contains no report.json, so there is no report to show.\n\n"
                    f"It contains: {listing}\n\n"
                    "Generate a report in CAPEsolo (JSON Report), then zip the results again."
                )
            # Progress against the uncompressed member, not the archive.
            shared["size"] = max(1, archive.getinfo(member).file_size)
            buf = bytearray()
            with archive.open(member) as fd:
                while True:
                    if shared["cancel"]:
                        return None, None
                    chunk = fd.read(READ_CHUNK)
                    if not chunk:
                        break
                    buf += chunk
                    shared["read"] = len(buf)

            capture = None
            captureMember = _bundle_member(names, "capture.json")
            if captureMember:
                try:
                    capture = json.loads(archive.read(captureMember))
                except ValueError:
                    capture = None
            return buf, capture

    def _poll_load(self, path, shared):
        win, bar, status = self._prog
        if "data" in shared or "error" in shared:
            err = shared.get("error")
            if err is not None:
                win.grab_release()
                win.destroy()
                self._prog = None
                if err != "cancelled":
                    messagebox.showerror("Report Viewer", f"Could not read report:\n{path}\n\n{err}")
                return
            # Building the tables can take seconds on a huge report; keep the dialog up so the UI
            # does not silently freeze (the very thing the progress bar exists to avoid).
            bar["value"] = 100
            status.config(text="Building views…")
            win.update_idletasks()
            self.path = path
            self.root.title(f"CAPEsolo Report Viewer - {path}")
            self.path_label.config(text=path)
            self._on_loaded(shared["data"])
            win.grab_release()
            win.destroy()
            self._prog = None
            return
        if shared.get("phase") == "parsing":
            bar["value"] = 100
            status.config(text="Parsing JSON…")
        else:
            read, size = shared["read"], shared["size"]
            bar["value"] = read * 100 / size
            status.config(text=f"Reading… {read // (1024 * 1024)} / {size // (1024 * 1024)} MB")
        self.root.after(80, lambda: self._poll_load(path, shared))

    def _on_loaded(self, report):
        self.report = report if isinstance(report, dict) else {"report": report}
        self.engine = None
        for pane in self.ai_panes.values():
            pane["tree"].delete(*pane["tree"].get_children())
            pane["rows"] = {}
            pane["status"].config(text="not run")
            self._set_text(pane["detail"], "")
        if hasattr(self, "ai_status"):
            self.ai_status.config(text="")
        if hasattr(self, "ask_text"):
            self._clear_ask()
        self._build_raw(report)
        self._build_overview()
        self._build_capture()
        self._build_signatures()
        self._build_processes()
        self._build_behavior()
        self._build_network()
        self._build_jslog()
        self._build_payloads()
        self._build_configs()
        self._build_yara()
        self._build_static()
        self._build_iocs()
        self._build_index()

    # ------------------------------------------------------------------ Overview
    def _build_overview(self):
        r = self.report
        target = r.get("target") or {}
        beh = r.get("behavior") or {}
        net = r.get("network") or {}
        self.overview.config(state=tk.NORMAL)
        self.overview.delete("1.0", tk.END)

        def head(t):
            self.overview.insert(tk.END, t + "\n", "h")

        def line(t):
            self.overview.insert(tk.END, t + "\n")

        verdict = self._ai_overview_lines()
        if verdict:
            head("AI verdict")
            for entry in verdict:
                line(entry)
            line("")

        head("File")
        for k in ("name", "type", "size", "md5", "sha1", "sha256"):
            if target.get(k) not in (None, ""):
                line(f"  {k}: {target.get(k)}")

        head("\nDetections")
        det = r.get("detections") or []
        line("  " + (", ".join(map(str, det)) if det else "none"))

        sigs = sorted(r.get("signatures") or [], key=lambda s: s.get("severity") or 0, reverse=True)
        head("\nTop signatures")
        if not sigs:
            line("  none")
        for s in sigs[:10]:
            self.overview.insert(tk.END, f"  [{s.get('severity', 1)}] ", _severity_tag(s.get("severity", 1)))
            line(f"{s.get('name', '')} - {s.get('description', '')}")

        configs = r.get("configs") or []
        if configs:
            head("\nConfig highlights")
            for entry in configs:
                for path, cfg in (entry.items() if isinstance(entry, dict) else []):
                    line(f"  {os.path.basename(str(path))}:")
                    for k, v in list(_pairs(cfg))[:12]:
                        line(f"    {k}: {_preview(v)}")

        head("\nCounts")
        line(f"  processes: {len(beh.get('processes') or [])}")
        line(f"  network hosts: {len(net.get('hosts') or [])}  domains: {len(net.get('domains') or [])}"
             f"  http: {len(net.get('http') or [])}")
        line(f"  payloads: {len(r.get('payloads') or [])}")
        line(f"  yara hits: {len(r.get('yara') or [])}"
             f"  (target: {len(target.get('yara') or [])})")
        line(f"  anomalies: {len(beh.get('anomaly') or [])}"
             f"  encrypted buffers: {len(beh.get('encryptedbuffers') or [])}")
        js = r.get("js_log") or {}
        line(f"  js events: {js.get('parsed_lines', 0) if js.get('exists') else 'no js log'}")

        # Say up front whether the rest of this report is the whole picture.
        capture = r.get("capture") or {}
        warnings = capture.get("warnings") or []
        head("\nCapture")
        if not capture:
            line("  no capture manifest in this report")
        elif warnings:
            for warning in warnings:
                self.overview.insert(tk.END, "  ! ", "sev_high")
                line(warning)
            line("  (see the Capture tab)")
        else:
            line("  nothing reported lost")
        self.overview.config(state=tk.DISABLED)

    # ------------------------------------------------------------------ Signatures
    def _build_signatures(self):
        self.sig_tree.delete(*self.sig_tree.get_children())
        self._sig_rows = {}
        sigs = sorted(self.report.get("signatures") or [], key=lambda s: s.get("severity") or 0, reverse=True)
        for s in sigs:
            cats = ", ".join(s.get("categories") or [])
            item = self.sig_tree.insert("", "end",
                                        values=(s.get("severity", 1), s.get("name", ""), cats),
                                        tags=(_severity_tag(s.get("severity", 1)),))
            self._sig_rows[item] = s
        self._set_text(self.sig_detail, "")

    def _on_sig_select(self, event):
        sel = self.sig_tree.selection()
        if not sel:
            return
        s = self._sig_rows.get(sel[0], {})
        lines = [s.get("name", ""), "", s.get("description", "")]
        meta = [f"{k}: {s.get(k)}" for k in ("severity", "weight", "confidence", "alert")
                if s.get(k) not in (None, "")]
        if meta:
            lines += ["", "  ".join(meta)]
        if s.get("families"):
            lines += ["", "families: " + ", ".join(map(str, s["families"]))]
        if s.get("references"):
            lines += ["", "references:"] + [f"  {ref}" for ref in s["references"]]
        # A signature's evidence is data + new_data (signatures.py does the same union):
        # non-evented signatures append plain {label: value} dicts to data, evented ones fill
        # new_data with per-process marks. Showing only new_data left most signatures bare.
        data = s.get("data") or []
        if data:
            lines += ["", "data:"]
            for d in data:
                if isinstance(d, dict):
                    lines += [f"  {k}: {self._detail_value(v)}" for k, v in d.items()]
                else:
                    lines.append(f"  {self._detail_value(d)}")
        evid = s.get("new_data") or []
        if evid:
            lines += ["", "evidence:"]
            for e in evid:
                proc = e.get("process") or {}
                who = f"{proc.get('process_name', '?')} ({proc.get('process_id', '?')})" if proc else "-"
                lines.append(f"  {who}")
                for sign in e.get("signs") or []:
                    lines.append(f"    {sign.get('type', '')}: {sign.get('value', '')}")
        self._set_text(self.sig_detail, "\n".join(lines))

    # ------------------------------------------------------------------ Processes
    def _build_processes(self):
        self.proc_tree.delete(*self.proc_tree.get_children())
        self.proc_calls.delete(*self.proc_calls.get_children())
        self._proc_node = {}
        self._tree_pids = set()
        # Reset the call filters too, otherwise the category list and the status line still
        # describe the previously loaded report until a process is selected.
        self._proc_calls_all = []
        self.call_cat.config(values=["all"])
        self.call_cat.set("all")
        self.call_status.config(text="")
        beh = self.report.get("behavior") or {}
        # calls / environ / first_seen / threads live on behavior.processes, keyed by pid; the
        # tree comes from processtree. Map pid -> process to join them on selection.
        self._proc_by_pid = {p.get("process_id"): p for p in (beh.get("processes") or [])}
        for node in beh.get("processtree") or []:
            self._add_proc(node, "")
        # processtree is only fed from API calls (behavior.ProcessTree.event_apicall), so a
        # process that logged none - or every process, if ProcessTree raised and the key is
        # missing - is absent from it while behavior.processes still carries it. Add those as
        # roots so no process in the report is invisible here.
        for pid, proc in self._proc_by_pid.items():
            if pid in self._tree_pids:
                continue
            self._add_proc(
                {
                    "name": proc.get("process_name"),
                    "pid": pid,
                    "parent_id": proc.get("parent_id"),
                    "module_path": proc.get("module_path"),
                    "threads": proc.get("threads"),
                },
                "",
            )
        if not self.proc_tree.get_children(""):
            self.proc_tree.insert("", "end", text="(no process tree)")
        self._set_text(self.proc_detail, "")

    def _add_proc(self, node, parent):
        label = f"{node.get('name', '?')} ({node.get('pid', '?')})"
        item = self.proc_tree.insert(parent, "end", text=label, open=True)
        self._proc_node[item] = node
        self._tree_pids.add(node.get("pid"))
        for child in node.get("children") or []:
            self._add_proc(child, item)

    @staticmethod
    def _call_arguments(call):
        args = call.get("arguments") or []
        # Flat single-line form for a Treeview row (behavior_panel.GetArguments wraps at 64 chars
        # for a multi-line grid cell, which is wrong here).
        return "; ".join(f"{a.get('name', '')}={a.get('value', '')}" for a in args if isinstance(a, dict))

    def _fill_proc_calls(self, calls):
        self.proc_calls.delete(*self.proc_calls.get_children())

        def cell(value):
            return _preview(str(value).replace("\x00", ""))

        for call in calls[:CALLS_CAP]:
            status = "Success" if call.get("status") else "Failure"
            ret = call.get("pretty_return") or call.get("return", "")
            cat = call.get("category")
            tags = (cat,) if cat in CALL_CATEGORY_PALETTES[self.mode] else ()
            self.proc_calls.insert("", "end", tags=tags, values=(
                cell(call.get("timestamp", "")), cell(call.get("thread_id", "")),
                cell(call.get("caller", "")), cell(call.get("parentcaller", "")),
                cell(call.get("api", "")),
                cell(self._call_arguments(call)), cell(status), cell(ret),
                # Consecutive identical calls are collapsed by the parser with a counter, so
                # without this column the grid understates how often an API was called.
                cell(call.get("repeated", 0)),
            ))

    def _clear_call_filters(self):
        self.call_cat.set("all")
        self.call_tid.delete(0, tk.END)
        self.call_api.delete(0, tk.END)
        self._apply_call_filters()

    def _apply_call_filters(self):
        # Deviates from the Behavior tab on purpose: filters COMBINE (AND) rather than being
        # mutually exclusive, and TID/API are case-insensitive substring matches rather than
        # exact - friendlier for triage. str()-normalize since report data is external.
        cat = self.call_cat.get()
        tid = self.call_tid.get().strip().lower()
        api = self.call_api.get().strip().lower()
        matched = []
        for call in self._proc_calls_all:
            if cat and cat != "all" and call.get("category") != cat:
                continue
            if tid and tid not in str(call.get("thread_id", "")).lower():
                continue
            if api and api not in str(call.get("api", "")).lower():
                continue
            matched.append(call)
        self._fill_proc_calls(matched)
        shown = min(len(matched), CALLS_CAP)
        self.call_status.config(
            text=f"displaying {shown} of {len(matched)} matched ({len(self._proc_calls_all)} total)"
        )

    def _on_proc_select(self, event):
        sel = self.proc_tree.selection()
        if not sel:
            return
        node = self._proc_node.get(sel[0])
        if not node:
            self._set_text(self.proc_detail, "")
            return
        lines = []
        for k in ("name", "pid", "parent_id", "module_path"):
            if node.get(k) not in (None, ""):
                lines.append(f"{k}: {node.get(k)}")
        # Join to behavior.processes for the richer fields and the per-process calls. As of the
        # json_report accretion fix these calls are this process's own; a pre-fix report.json
        # still has every process carrying the identical accreted list.
        proc = self._proc_by_pid.get(node.get("pid"))
        if proc:
            cmdline = (proc.get("environ") or {}).get("CommandLine")
            if cmdline:
                lines.append(f"command line: {cmdline}")
            if proc.get("first_seen") not in (None, ""):
                lines.append(f"first_seen: {proc.get('first_seen')}")
            lines.append(f"threads: {len(proc.get('threads') or node.get('threads') or [])}")
            self._proc_calls_all = proc.get("calls") or []
        else:
            lines.append(f"threads: {len(node.get('threads') or [])}")
            lines.append("calls: (no matching process record in report.json)")
            self._proc_calls_all = []
        self._set_text(self.proc_detail, "\n".join(lines))
        # Category options come from the categories actually present in this process's calls.
        cats = sorted({c.get("category") for c in self._proc_calls_all if c.get("category")})
        self.call_cat.config(values=["all"] + cats)
        if self.call_cat.get() not in (["all"] + cats):
            self.call_cat.set("all")
        self._apply_call_filters()

    # ------------------------------------------------------------------ Capture
    def _build_capture(self):
        """What the analysis managed to store, and what it lost.

        Without this the viewer cannot tell a quiet analysis from a lossy one: a payload that
        was skipped for size, truncated at upload_max_size or never stored simply is not in
        the report, and every other tab renders as if that were the whole picture.
        """
        cap = self.report.get("capture") or {}
        self.capture.config(state=tk.NORMAL)
        self.capture.delete("1.0", tk.END)

        def head(t):
            self.capture.insert(tk.END, t + "\n", "h")

        def line(t, tag=None):
            self.capture.insert(tk.END, t + "\n", tag or ())

        if not cap:
            line("No capture manifest in this report.")
            line("")
            line("Reports written before capture accounting existed have none. Re-run the JSON")
            line("Report button in CAPEsolo to produce one, or check capture.json in the")
            line("analysis directory.")
            self.capture.config(state=tk.DISABLED)
            return

        warnings = cap.get("warnings") or []
        head("Verdict")
        if warnings:
            for warning in warnings:
                line(f"  ! {warning}", "warn")
        else:
            line("  Nothing was reported lost - every listed artifact is present and whole.", "ok")
        if cap.get("bundle"):
            line(f"  bundle: {cap['bundle']}"
                 + ("  (payload bytes deliberately left in the guest)"
                    if cap["bundle"] == "report" else ""))
        if cap.get("generated"):
            line(f"  generated: {cap['generated']}")

        transfers = cap.get("transfers") or {}
        if transfers:
            head("\nTransfers")
            line(f"  complete: {transfers.get('complete', 0)}"
                 f"   incomplete: {transfers.get('incomplete', 0)}"
                 f"   truncated: {transfers.get('truncated', 0)}")

        files = cap.get("files") or {}
        if files:
            head("\nFiles")
            line(f"  listed in files.json: {files.get('listed', 0)}"
                 f"   present on disk: {files.get('present', 0)}")
            if files.get("unreadable_lines"):
                line(f"  unreadable files.json lines: {files['unreadable_lines']}", "warn")
            for label, key in (("missing", "missing"), ("incomplete", "incomplete"),
                               ("truncated", "truncated")):
                entries = files.get(key) or []
                if entries:
                    line(f"  {label} ({len(entries)}):", "warn")
                    for name in entries[:MAX_CHILDREN]:
                        line(f"    {name}")
                    if len(entries) > MAX_CHILDREN:
                        line(f"    … {len(entries) - MAX_CHILDREN} more")

        skipped = cap.get("skipped") or []
        if skipped:
            head("\nNever uploaded")
            for entry in skipped[:MAX_CHILDREN]:
                size = f" ({entry['size']} bytes)" if entry.get("size") else ""
                line(f"  [{entry.get('reason', '?')}] {entry.get('path', '')}{size}", "warn")

        artifacts = cap.get("artifacts") or {}
        if artifacts:
            head("\nArtifacts present")
            for name, value in artifacts.items():
                line(f"  {name}: {value}")

        limits = cap.get("limits") or {}
        if limits:
            head("\nLimits in force")
            for key, value in limits.items():
                line(f"  {key}: {_preview(value)}")
        self.capture.config(state=tk.DISABLED)

    # ------------------------------------------------------------------ Behavior
    def _build_behavior(self):
        beh = self.report.get("behavior") or {}
        for tree in (self.beh_summary, self.beh_anomaly, self.beh_bufs, self.beh_enhanced):
            tree.delete(*tree.get_children())
        self._buf_rows = {}
        summary = beh.get("summary") or {}
        # resolved_apis alone runs to tens of thousands of entries on a real run, so this
        # table is capped like the others; values go in whole, as the IOC tab does.
        shown = 0
        total = sum(len(summary.get(group) or []) for group in SUMMARY_GROUPS)
        for group in SUMMARY_GROUPS:
            for value in summary.get(group) or []:
                if shown >= TABLE_ROW_CAP:
                    break
                self.beh_summary.insert("", "end", values=(group, value))
                shown += 1
        self._more_row(self.beh_summary, total - shown)
        for a in beh.get("anomaly") or []:
            self.beh_anomaly.insert("", "end", values=(
                a.get("name", ""), a.get("pid", ""), a.get("category", ""),
                a.get("funcname", ""), _preview(a.get("message", ""))))
        for b in beh.get("encryptedbuffers") or []:
            item = self.beh_bufs.insert("", "end", values=(
                b.get("process_name", ""), b.get("pid", ""), b.get("api_call", ""),
                b.get("buffer_size", ""), _preview(b.get("crypt_key", ""))))
            self._buf_rows[item] = b
        self._set_text(self.beh_buf_detail, "")
        enhanced = beh.get("enhanced") or []
        for e in enhanced[:TABLE_ROW_CAP]:
            data = e.get("data") or {}
            self.beh_enhanced.insert("", "end", values=(
                e.get("timestamp", ""), e.get("event", ""), e.get("object", ""),
                _preview("; ".join(f"{k}={v}" for k, v in data.items()))))
        self._more_row(self.beh_enhanced, len(enhanced) - TABLE_ROW_CAP)

    def _on_buf_select(self, event):
        sel = self.beh_bufs.selection()
        if not sel:
            return
        b = self._buf_rows.get(sel[0])
        if b is None:
            return
        header = [
            ("Process", f"{b.get('process_name', '')} ({b.get('pid', '')})"),
            ("API", b.get("api_call", "")),
            ("Size", b.get("buffer_size", "")),
            ("Key", b.get("crypt_key", "")),
        ]
        sections = ["\n".join(f"{k + ':':<14}{v}" for k, v in header if v not in (None, ""))]
        block = self._net_block("buffer", b.get("buffer"))
        if block:
            sections.append(block)
        self._set_text(self.beh_buf_detail, "\n\n".join(sections))

    # ------------------------------------------------------------------ Network
    def _build_network(self):
        net = self.report.get("network") or {}
        sources = net.get("sources")
        self.net_sources.config(text=f"sources: {sources}" if sources else "")
        for tree in self.net_tables.values():
            tree.delete(*tree.get_children())
        for q in net.get("dns") or []:
            ans = ", ".join(a.get("data", "") if isinstance(a, dict) else str(a)
                            for a in (q.get("answers") or []))
            self.net_tables["DNS"].insert("", "end", values=(q.get("request", ""), q.get("type", ""), ans))
        self.net_http_tree.delete(*self.net_http_tree.get_children())
        self._net_http_rows = {}
        for h in net.get("http") or []:
            item = self.net_http_tree.insert("", "end", values=(
                h.get("method", ""), h.get("host", ""), h.get("port", ""),
                h.get("uri", ""), h.get("count", "")))
            self._net_http_rows[item] = h
        self._set_text(self.net_http_detail, "")
        for h in net.get("hosts") or []:
            self.net_tables["Hosts"].insert("", "end", values=(h.get("ip", ""),))
        for d in net.get("domains") or []:
            self.net_tables["Domains"].insert("", "end", values=(d.get("domain", ""), d.get("ip", "")))
        for proto in ("tcp", "udp"):
            for f in net.get(proto) or []:
                self.net_tables["Flows"].insert("", "end", values=(
                    proto, f.get("src", ""), f.get("sport", ""),
                    f.get("dst", ""), f.get("dport", ""), f.get("time", "")))
        self._build_plaintext(net)

    def _build_plaintext(self, net):
        # http_ex/https_ex/smtp_ex carry the decrypted plaintext; each row holds its whole
        # entry so the detail pane can show request/response and the on-disk body digests.
        self.net_plain_tree.delete(*self.net_plain_tree.get_children())
        self._net_plain_rows = {}
        for key in ("http_ex", "https_ex"):
            for e in net.get(key) or []:
                item = self.net_plain_tree.insert("", "end", values=(
                    e.get("protocol", ""), e.get("method", ""),
                    e.get("host") or e.get("dst", ""), e.get("uri", ""), e.get("status", "")))
                self._net_plain_rows[item] = ("http", e)
        for e in net.get("smtp_ex") or []:
            r = e.get("req") or {}
            to = r.get("mail_to")
            if isinstance(to, (list, tuple)):
                to = ", ".join(str(x) for x in to)
            item = self.net_plain_tree.insert("", "end", values=(
                "smtp", "", r.get("hostname", ""), to or "", ""))
            self._net_plain_rows[item] = ("smtp", e)
        self._set_text(self.net_plain_detail, self._decrypted_status(net))

    @staticmethod
    def _decrypted_status(net):
        # The report carries why decryption produced little or nothing (missing dependency,
        # no secrets, truncated capture); say so rather than showing an empty pane.
        dec = net.get("decrypted") or {}
        has = any(net.get(k) for k in ("http_ex", "https_ex", "smtp_ex"))
        if not dec:
            return ("Select a stream to view its request and response." if has
                    else "No decrypted streams. (No capture was processed, or decryption did not run.)")
        if dec.get("error"):
            return f"Decryption unavailable: {dec['error']}"
        c = dec.get("counts") or {}
        line = (f"{c.get('https_ex', 0)} decrypted, {c.get('http_ex', 0)} cleartext, "
                f"{c.get('smtp_ex', 0)} smtp stream(s) from {dec.get('secrets', 0)} TLS secret(s).")
        if has:
            return line + "\n\nSelect a stream to view its request and response."
        return line + ("\nNo streams could be reassembled - the capture may lack TLS secrets "
                       "or be truncated to a fixed frame size.")

    @staticmethod
    def _net_block(title, text):
        if not text:
            return ""
        # tkinter's Text terminates on a NUL, so strip them the way the Network tab does.
        text = str(text).replace("\x00", "")
        if len(text) > PLAINTEXT_BLOCK:
            text = text[:PLAINTEXT_BLOCK] + f"\n... [truncated, {len(text)} chars total; full body on disk] ..."
        return f"--- {title} ---\n{text}"

    @staticmethod
    def _net_body(title, digests):
        if not digests:
            return ""
        lines = [f"--- {title} ---",
                 f"sha256 {digests.get('sha256', '')}  ({digests.get('size', 0)} bytes)"]
        if digests.get("path"):
            lines.append(f"saved to {digests['path']}")
        lines.extend(digests.get("preview") or ())
        return "\n".join(lines)

    def _http_detail(self, e):
        header = [
            ("Protocol", e.get("protocol", "")),
            ("Method", e.get("method", "")),
            ("Host", e.get("host") or e.get("dst", "")),
            ("URI", e.get("uri", "")),
            ("Status", e.get("status") or "no response"),
            ("Source", f"{e.get('src', '')}:{e.get('sport', '')}"),
            ("Destination", f"{e.get('dst', '')}:{e.get('dport', '')}"),
        ]
        sections = ["\n".join(f"{k + ':':<14}{v}" for k, v in header)]
        for block in (
            self._net_block("request", e.get("request")),
            self._net_block("response", e.get("response")),
            self._net_body("request body", e.get("req")),
            self._net_body("response body", e.get("resp")),
        ):
            if block:
                sections.append(block)
        return "\n\n".join(sections)

    def _smtp_detail(self, e):
        r = e.get("req") or {}
        to = r.get("mail_to")
        if isinstance(to, (list, tuple)):
            to = ", ".join(str(x) for x in to)
        header = [
            ("Protocol", "smtp"),
            ("Hostname", r.get("hostname", "")),
            ("Mail from", r.get("mail_from", "")),
            ("Mail to", to or ""),
            ("Source", f"{e.get('src', '')}:{e.get('sport', '')}"),
            ("Destination", f"{e.get('dst', '')}:{e.get('dport', '')}"),
        ]
        sections = ["\n".join(f"{k + ':':<14}{v}" for k, v in header)]
        headers = r.get("headers") or {}
        if headers:
            sections.append("--- headers ---\n" + "\n".join(f"    {n}: {v}" for n, v in headers.items()))
        block = self._net_block("message", r.get("mail_body"))
        if block:
            sections.append(block)
        banner = (e.get("resp") or {}).get("banner")
        if banner:
            sections.append(f"--- server banner ---\n{banner}")
        return "\n\n".join(sections)

    def _on_net_http_select(self, event):
        sel = self.net_http_tree.selection()
        if not sel:
            return
        h = self._net_http_rows.get(sel[0])
        if h is None:
            return
        header = [
            ("Method", h.get("method", "")),
            ("Host", h.get("host", "")),
            ("Port", h.get("port", "")),
            ("URI", h.get("uri", "")),
            ("Path", h.get("path", "")),
            ("Version", h.get("version", "")),
            ("User-agent", h.get("user-agent", "")),
            ("Count", h.get("count", "")),
        ]
        sections = ["\n".join(f"{k + ':':<14}{v}" for k, v in header)]
        for block in (self._net_block("request", h.get("data")),
                      self._net_block("body", h.get("body"))):
            if block:
                sections.append(block)
        self._set_text(self.net_http_detail, "\n\n".join(sections))

    def _on_net_plain_select(self, event):
        sel = self.net_plain_tree.selection()
        if not sel:
            return
        kind, entry = self._net_plain_rows.get(sel[0], (None, None))
        if entry is None:
            return
        text = self._smtp_detail(entry) if kind == "smtp" else self._http_detail(entry)
        self._set_text(self.net_plain_detail, text)

    # ------------------------------------------------------------------ JS log
    @staticmethod
    def _js_body(body):
        # The interceptor logs a body as {text, truncated}, never a bare string, but older
        # logs carry the string form.
        if isinstance(body, dict):
            return body.get("text") or ""
        return "" if body is None else str(body)

    @staticmethod
    def _js_headers(headers):
        if not isinstance(headers, dict):
            return ""
        return "\n".join(f"{k}: {v}" for k, v in headers.items())

    def _js_http_rows(self, js):
        # Pair each http_request with its http_response / http_error by request_id and fold in
        # the separately emitted http_request_body, the way js_console_panel does.
        reqs = {r.get("request_id"): r for r in js.get("http_requests") or []}
        bodies = {ev.get("request_id"): self._js_body(ev.get("body"))
                  for ev in js.get("events") or [] if ev.get("event") == "http_request_body"}
        rows = []
        seen = set()
        for resp in js.get("http_responses") or []:
            rid = resp.get("request_id")
            seen.add(rid)
            rows.append(self._js_http_row(reqs.get(rid), resp, None, bodies.get(rid)))
        for err in js.get("http_errors") or []:
            rid = err.get("request_id")
            seen.add(rid)
            rows.append(self._js_http_row(reqs.get(rid), None, err, bodies.get(rid)))
        for rid, req in reqs.items():
            if rid not in seen:
                rows.append(self._js_http_row(req, None, None, bodies.get(rid)))
        return rows

    def _js_http_row(self, req, resp, err, reqBody):
        req = req or {}
        method = req.get("method", "")
        url = req.get("url", "")
        status = f"{resp.get('status', '')} {resp.get('status_text', '')}".strip() if resp else ""
        error = err.get("error", "") if err else ""
        sections = [f"{method} {url}  [{req.get('transport', '')}]".strip()]
        if req.get("headers"):
            sections.append("--- request headers ---\n" + self._js_headers(req["headers"]))
        if reqBody:
            sections.append(self._net_block("request body", reqBody))
        if resp:
            sections.append(f"HTTP {status}")
            if resp.get("headers"):
                sections.append("--- response headers ---\n" + self._js_headers(resp["headers"]))
            respBody = self._js_body(resp.get("body"))
            if respBody:
                sections.append(self._net_block("response body", respBody))
        if error:
            sections.append("Error: " + error)
        return {
            "kind": "HTTP",
            "ts": (resp or err or req).get("ts", ""),
            "src": req.get("transport", ""),
            "dst": url,
            "info": " ".join(p for p in (method, url, status, error) if p),
            "detail": "\n\n".join(s for s in sections if s),
        }

    @staticmethod
    def _js_dns_rows(js):
        # One row per lookup, dns_query / dns_result / dns_error paired by request_id.
        lookups = {}
        order = 0
        for ev in js.get("events") or []:
            name = ev.get("event")
            if name not in ("dns_query", "dns_result", "dns_error"):
                continue
            rid = ev.get("request_id")
            if rid is None:
                rid = f"noid:{order}"
            entry = lookups.setdefault(rid, {"host": "", "query_type": "", "answers": None,
                                             "error": "", "ts": ev.get("ts") or "", "order": order})
            order += 1
            if ev.get("host"):
                entry["host"] = ev["host"]
            if ev.get("query_type"):
                entry["query_type"] = ev["query_type"]
            if name == "dns_result":
                entry["answers"] = ev.get("result")
            elif name == "dns_error":
                entry["error"] = ev.get("error", "")

        rows = []
        for entry in sorted(lookups.values(), key=lambda e: e["order"]):
            answers = entry["answers"]
            if isinstance(answers, dict):
                answers = answers.get("text", "")
            answers = "" if answers is None else str(answers)
            fields = [("Query type", entry["query_type"]), ("Host", entry["host"]),
                      ("Answers", answers), ("Error", entry["error"])]
            rows.append({
                "kind": "DNS",
                "ts": entry["ts"],
                "src": "",
                "dst": entry["host"],
                "info": " ".join(p for p in (entry["query_type"], entry["host"], answers,
                                             entry["error"]) if p),
                "detail": "\n".join(f"{k + ':':<14}{v}" for k, v in fields if v),
            })
        return rows

    def _js_event_rows(self, js):
        rows = []
        for ev in js.get("events") or []:
            if ev.get("event") in JS_PAIRED_EVENTS:
                continue
            if ev.get("event") == "console":
                info = f"{ev.get('level', '')} {ev.get('message', '')}".strip()
            else:
                info = " ".join(f"{k}: {v}" for k, v in ev.items()
                                if k not in ("ts", "event", "source") and v not in (None, ""))
            rows.append({
                "kind": "Event",
                "ts": ev.get("ts", ""),
                "src": ev.get("source", ""),
                "dst": str(ev.get("event", "")),
                "info": info,
                "detail": json.dumps(ev, indent=2, ensure_ascii=False, default=str),
            })
        return rows

    def _build_jslog(self):
        js = self.report.get("js_log") or {}
        if js.get("exists"):
            self.js_header.config(text=(
                f"{js.get('path', '')}   lines: {js.get('total_lines', 0)}   "
                f"events: {js.get('parsed_lines', 0)}   malformed: {js.get('malformed_lines', 0)}"
                + ("   [log truncated]" if js.get("truncated") else "")))
        else:
            self.js_header.config(text="No JS console log in this analysis.")
        self._js_all = self._js_http_rows(js) + self._js_dns_rows(js) + self._js_event_rows(js)
        kinds = sorted({r["kind"] for r in self._js_all})
        self.js_kind.config(values=["all"] + kinds)
        self.js_kind.set("all")
        self._fill_js_rows()
        self.js_buffers.delete(*self.js_buffers.get_children())
        for b in js.get("buffers") or []:
            self.js_buffers.insert("", "end", values=(
                b.get("stream", ""), b.get("sha256", ""), b.get("bytes", "")))
        self._set_text(self.js_raw, (js.get("log") or "").replace("\x00", ""))

    def _fill_js_rows(self):
        self.js_tree.delete(*self.js_tree.get_children())
        self._js_rows = {}
        kind = self.js_kind.get()
        rows = [r for r in self._js_all if kind in ("", "all") or r["kind"] == kind]
        for row in rows[:TABLE_ROW_CAP]:
            item = self.js_tree.insert("", "end", values=(
                _preview(row["ts"]), row["kind"], _preview(row["src"]),
                _preview(row["dst"]), _preview(row["info"])))
            self._js_rows[item] = row
        self.js_status.config(
            text=f"displaying {min(len(rows), TABLE_ROW_CAP)} of {len(rows)} "
                 f"({len(self._js_all)} total)")
        self._set_text(self.js_detail, "")

    def _on_js_select(self, event):
        sel = self.js_tree.selection()
        if not sel:
            return
        row = self._js_rows.get(sel[0])
        if row is None:
            return
        self._set_text(self.js_detail, (row["detail"] or "").replace("\x00", ""))

    # ------------------------------------------------------------------ Payloads
    def _build_payloads(self):
        self.pay_tree.delete(*self.pay_tree.get_children())
        self._pay_rows = {}
        for entry in self.report.get("payloads") or []:
            if not isinstance(entry, dict):
                continue
            for path, data in entry.items():
                data = data or {}
                state = ", ".join(f for f in ("incomplete", "truncated") if data.get(f))
                item = self.pay_tree.insert("", "end", tags=("partial",) if state else (), values=(
                    data.get("name", os.path.basename(str(path))),
                    data.get("cape_type", ""),
                    data.get("size", ""),
                    data.get("sha256", ""),
                    data.get("pid", ""),
                    state,
                ))
                self._pay_rows[item] = (path, data)
        self._set_text(self.pay_detail, "")

    def _on_pay_select(self, event):
        sel = self.pay_tree.selection()
        if not sel:
            return
        path, data = self._pay_rows.get(sel[0], ("", {}))
        lines = [f"path: {path}"]
        for k in ("name", "cape_type", "cape_type_string", "type", "size", "md5", "sha1",
                  "sha256", "sha512", "crc32", "rh_hash", "tlsh", "guest_paths",
                  "process_name", "process_path", "pid", "module_path", "virtual_address",
                  "target_path", "target_process", "target_pid"):
            if data.get(k) not in (None, ""):
                lines.append(f"{k}: {data.get(k)}")
        yara = data.get("yara") or []
        if yara:
            lines += ["", "yara: " + ", ".join(h.get("name", "") for h in yara)]
        strings = data.get("strings") or []
        if strings:
            lines += ["", f"strings ({len(strings)}):"]
            lines += [f"  {s}" for s in strings[:DETAIL_STRINGS]]
            if len(strings) > DETAIL_STRINGS:
                lines.append(f"  … {len(strings) - DETAIL_STRINGS} more")
        self._set_text(self.pay_detail, "\n".join(lines))

    # ------------------------------------------------------------------ Configs
    def _build_configs(self):
        # Overview only prints the first 12 fields of each config and the IOC tab only keeps
        # scalar values, so without this tab a large or nested config is Raw-JSON-only. Rows
        # mirror the GUI's Configs grid (configs_panel): file / field / value over a detail
        # pane that expands whatever the cell had to collapse.
        self.cfg_tree.delete(*self.cfg_tree.get_children())
        self._cfg_rows = {}
        for entry in self.report.get("configs") or []:
            for path, cfg in (entry.items() if isinstance(entry, dict) else []):
                name = os.path.basename(str(path))
                for key, value in _pairs(cfg):
                    item = self.cfg_tree.insert("", "end", values=(name, key, _preview(value)))
                    self._cfg_rows[item] = (path, key, value)
        self._set_text(self.cfg_detail, "")

    def _on_cfg_select(self, event):
        sel = self.cfg_tree.selection()
        if not sel:
            return
        path, key, value = self._cfg_rows.get(sel[0], ("", "", ""))
        self._set_text(self.cfg_detail,
                       f"file: {path}\nfield: {key}\n\n{self._detail_value(value)}")

    # ------------------------------------------------------------------ Yara
    def _yara_hits(self):
        """Every hit, from the report's own section or reconstructed for older reports.

        report.json gained a top-level "yara" section (json_report.YaraHits); before that,
        hits only existed attached to the target and to individual payloads, and hits on
        parser-dumped files were dropped entirely. Fall back so an old report still shows
        what it does have.
        """
        hits = self.report.get("yara")
        if hits:
            return hits

        recovered = []
        target = self.report.get("target") or {}
        for hit in target.get("yara") or []:
            recovered.append({"file": target.get("name", "target"), "rule": hit.get("name", ""),
                              "capename": "", "meta": hit.get("meta") or {},
                              "description": (hit.get("meta") or {}).get("description", ""),
                              "strings": hit.get("strings") or [],
                              "addresses": hit.get("addresses") or {}})
        for entry in self.report.get("payloads") or []:
            for path, data in (entry.items() if isinstance(entry, dict) else []):
                for hit in (data or {}).get("yara") or []:
                    recovered.append({"file": os.path.basename(str(path)),
                                      "rule": hit.get("name", ""), "capename": "",
                                      "meta": hit.get("meta") or {},
                                      "description": (hit.get("meta") or {}).get("description", ""),
                                      "strings": hit.get("strings") or [],
                                      "addresses": hit.get("addresses") or {}})
        return recovered

    def _build_yara(self):
        self.yara_tree.delete(*self.yara_tree.get_children())
        self._yara_rows = {}
        for hit in self._yara_hits():
            item = self.yara_tree.insert("", "end", values=(
                _preview(hit.get("file", "")), hit.get("rule", ""), hit.get("capename", ""),
                len(hit.get("strings") or []), _preview(hit.get("description", ""))))
            self._yara_rows[item] = hit
        count = len(self._yara_rows)
        files = len({h.get("file") for h in self._yara_rows.values()})
        self._set_text(self.yara_detail,
                       f"{count} hit(s) across {files} file(s). Select one for its metadata, "
                       "matched strings and offsets."
                       if count else "No yara hits in this report.")

    def _on_yara_select(self, event):
        selection = self.yara_tree.selection()
        if not selection:
            return
        hit = self._yara_rows.get(selection[0])
        if not hit:
            return
        lines = [f"file: {hit.get('file', '')}", f"rule: {hit.get('rule', '')}"]
        if hit.get("capename"):
            lines.append(f"CAPE name: {hit['capename']}")
        meta = hit.get("meta") or {}
        if meta:
            lines += ["", "meta:"] + [f"  {k}: {_preview(v)}" for k, v in meta.items()]
        strings = hit.get("strings") or []
        if strings:
            lines += ["", f"matched strings ({len(strings)}):"]
            lines += [f"  {s}" for s in strings[:DETAIL_STRINGS]]
            if len(strings) > DETAIL_STRINGS:
                lines.append(f"  … {len(strings) - DETAIL_STRINGS} more")
        addresses = hit.get("addresses") or {}
        if addresses:
            lines += ["", "offsets:"] + [f"  {k}: {v}" for k, v in addresses.items()]
        self._set_text(self.yara_detail, "\n".join(lines))

    # ------------------------------------------------------------------ Static / PE
    def _build_static(self):
        target = self.report.get("target") or {}
        pe = target.get("pe") or {}
        lines = []
        for k in ("name", "path", "type", "category", "size", "crc32", "md5", "sha1", "sha256",
                  "sha512", "rh_hash", "sha3_384", "tlsh"):
            if target.get(k) not in (None, ""):
                lines.append(f"{k}: {target.get(k)}")
        guest = target.get("guest_paths")
        if guest:
            lines.append(f"guest_paths: {_preview(guest)}")

        yara = target.get("yara") or []
        lines += ["", f"yara ({len(yara)}):" if yara else "yara: none"]
        for hit in yara:
            lines.append(f"  {hit.get('name', '')}  {_preview((hit.get('meta') or {}).get('description', ''))}")

        if pe:
            lines += ["", "PE:"]
            for k in ("imagebase", "entrypoint", "ep_bytes", "reported_checksum",
                      "actual_checksum", "osversion", "pdbpath", "imphash", "timestamp",
                      "exported_dll_name", "imported_dll_count"):
                if pe.get(k) not in (None, ""):
                    lines.append(f"  {k}: {pe.get(k)}")
            overlay = pe.get("overlay")
            if overlay:
                lines.append(f"  overlay: offset {overlay.get('offset', '')} size {overlay.get('size', '')}")
            for entry in pe.get("versioninfo") or []:
                lines.append(f"  versioninfo {entry.get('name', '')}: {_preview(entry.get('value', ''))}")
            for signer in pe.get("digital_signers") or []:
                lines.append("  signer: " + "; ".join(f"{k}={v}" for k, v in signer.items()))
            for entry in pe.get("dirents") or []:
                if entry.get("size") not in (None, "", "0x00000000"):
                    lines.append(f"  dirent {entry.get('name', '')}: "
                                 f"{entry.get('virtual_address', '')} size {entry.get('size', '')}")
        else:
            lines += ["", "PE: none (target is not a PE image, or pefile is unavailable)"]
        self._set_text(self.static_info, "\n".join(lines))

        for tree in (self.pe_sections, self.pe_imports, self.pe_exports, self.pe_resources):
            tree.delete(*tree.get_children())
        for s in pe.get("sections") or []:
            self.pe_sections.insert("", "end", values=(
                s.get("name", ""), s.get("raw_address", ""), s.get("virtual_address", ""),
                s.get("virtual_size", ""), s.get("size_of_data", ""), s.get("entropy", ""),
                _preview(s.get("characteristics", ""))))
        # imports is a dict of dll -> {"dll": name, "imports": [{address, name}]}.
        rows = 0
        total = sum(len(e.get("imports") or []) for e in (pe.get("imports") or {}).values())
        for entry in (pe.get("imports") or {}).values():
            for symbol in entry.get("imports") or []:
                if rows >= TABLE_ROW_CAP:
                    break
                self.pe_imports.insert("", "end", values=(
                    entry.get("dll", ""), symbol.get("address", ""), symbol.get("name", "")))
                rows += 1
        self._more_row(self.pe_imports, total - rows)
        for e in pe.get("exports") or []:
            self.pe_exports.insert("", "end", values=(
                e.get("address", ""), e.get("ordinal", ""), e.get("name", "")))
        for r in pe.get("resources") or []:
            self.pe_resources.insert("", "end", values=(
                r.get("name", ""), r.get("offset", ""), r.get("size", ""),
                r.get("language", ""), r.get("sublanguage", ""), r.get("entropy", "")))

        strings = target.get("strings") or []
        if strings:
            text = [f"strings ({len(strings)}):"] + list(strings[:DETAIL_STRINGS])
            if len(strings) > DETAIL_STRINGS:
                text.append(f"… {len(strings) - DETAIL_STRINGS} more (drill into target.strings "
                            "in the Raw JSON tab)")
        else:
            text = ["No strings in this report (the report was built with strings disabled)."]
        self._set_text(self.static_strings, "\n".join(text))

    # ------------------------------------------------------------------ IOCs
    def _aggregate_iocs(self):
        r = self.report
        beh = r.get("behavior") or {}
        summary = beh.get("summary") or {}
        net = r.get("network") or {}
        out = []  # (type, value)
        seen = set()

        def add(kind, value):
            value = str(value)
            key = (kind, value)
            if value and key not in seen:
                seen.add(key)
                out.append((kind, value))

        for v in summary.get("mutexes") or []:
            add("Mutex", v)
        for group in ("keys", "read_keys", "write_keys", "delete_keys"):
            for v in summary.get(group) or []:
                add("RegKey", v)
        for group in ("files", "read_files", "write_files", "delete_files"):
            for v in summary.get(group) or []:
                add("File", v)
        for group in ("created_services", "started_services"):
            for v in summary.get(group) or []:
                add("Service", v)
        for v in summary.get("executed_commands") or []:
            add("Command", v)
        for h in net.get("hosts") or []:
            add("Host", h.get("ip", ""))
        for d in net.get("domains") or []:
            add("Domain", d.get("domain", ""))
        for h in net.get("http") or []:
            add("URL", h.get("uri", ""))
        for entry in r.get("configs") or []:
            for _p, cfg in (entry.items() if isinstance(entry, dict) else []):
                for k, v in _pairs(cfg):
                    # config field values are commonly lists (e.g. C2/URLs); flatten them so the
                    # indicators are not silently dropped.
                    for item in (v if isinstance(v, list) else [v]):
                        if isinstance(item, (str, int)) and str(item):
                            add(f"Config:{k}", item)
        for fam in r.get("detections") or []:
            add("Family", fam)
        out.sort(key=lambda kv: kv[0])  # group by type (stable: keeps insertion order within a type)
        return out

    def _build_iocs(self):
        self.ioc_tree.delete(*self.ioc_tree.get_children())
        self._iocs = self._aggregate_iocs()
        for kind, value in self._iocs:
            self.ioc_tree.insert("", "end", values=(kind, value))

    def _ioc_text(self):
        return "\n".join(f"{k}\t{v}" for k, v in getattr(self, "_iocs", []))

    def _copy_iocs(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self._ioc_text())

    def _export_iocs(self, fmt):
        if not getattr(self, "_iocs", None):
            return
        path = filedialog.asksaveasfilename(defaultextension=f".{fmt}",
                                            filetypes=[(fmt.upper(), f"*.{fmt}"), ("All files", "*.*")],
                                            initialfile=f"iocs.{fmt}")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8", newline="") as f:
                if fmt == "csv":
                    w = csv.writer(f)
                    w.writerow(["type", "value"])
                    w.writerows(self._iocs)
                else:
                    f.write(self._ioc_text())
        except OSError as e:
            messagebox.showerror("Report Viewer", f"Could not write {path}:\n{e}")

    # ------------------------------------------------------------------ global search
    def _build_index(self):
        r = self.report
        idx = []

        def add(cat, value, tab):
            if value and len(idx) < MAX_INDEX:
                idx.append((cat, str(value), tab))

        for s in r.get("signatures") or []:
            add("signature", f"{s.get('name', '')} {s.get('description', '')}", "Signatures")
            for e in s.get("new_data") or []:
                for sign in e.get("signs") or []:
                    add("signature", sign.get("value", ""), "Signatures")
        net = r.get("network") or {}
        for h in net.get("hosts") or []:
            add("network", h.get("ip", ""), "Network")
        for d in net.get("domains") or []:
            add("network", d.get("domain", ""), "Network")
        for h in net.get("http") or []:
            add("network", h.get("uri", ""), "Network")
        for q in net.get("dns") or []:
            add("network", q.get("request", ""), "Network")
        for entry in r.get("payloads") or []:
            for _p, data in (entry.items() if isinstance(entry, dict) else []):
                data = data or {}
                add("payload", f"{data.get('name', '')} {data.get('cape_type', '')} {data.get('sha256', '')}", "Payloads")
                for s in (data.get("strings") or [])[:5000]:
                    add("string", s, "Payloads")
        beh = r.get("behavior") or {}
        summary = beh.get("summary") or {}
        for group in SUMMARY_GROUPS:
            for value in summary.get(group) or []:
                add("behavior", value, "Behavior")
        for a in beh.get("anomaly") or []:
            add("anomaly", f"{a.get('funcname', '')} {a.get('message', '')}", "Behavior")
        for b in beh.get("encryptedbuffers") or []:
            add("buffer", b.get("buffer", ""), "Behavior")
        for row in getattr(self, "_js_all", []):
            add("js", row["info"], "JS Log")
        for entry in r.get("configs") or []:
            for _p, cfg in (entry.items() if isinstance(entry, dict) else []):
                for key, value in _pairs(cfg):
                    add("config", f"{key} {value}", "Configs")
        for _kind, value in getattr(self, "_iocs", []):
            add("ioc", value, "IOCs")
        for s in ((r.get("target") or {}).get("strings") or [])[:MAX_STRINGS]:
            add("string", s, "Static")
        self.search_index = idx

    def on_search(self):
        term = self.search_var.get().strip().lower()
        if not term:
            return
        matches = [(c, v, t) for (c, v, t) in self.search_index if term in v.lower()]
        self._show_search_results(term, matches)

    def _show_search_results(self, term, matches):
        win = tk.Toplevel(self.root)
        win.title(f"Search: {term} ({len(matches)})")
        win.geometry("700x400")
        win.configure(bg=PALETTES[self.mode]["BG_MAIN"])
        _set_titlebar(win, self.mode == DARK)
        frame, tree = self._table(win, ("Category", "Match", "Tab"),
                                  {"Category": 100, "Match": 460, "Tab": 100})
        frame.pack(fill=tk.BOTH, expand=True)
        for c, v, t in matches[:5000]:
            tree.insert("", "end", values=(c, v if len(v) <= 300 else v[:300] + "…", t))
        tree.bind("<Double-1>",
                  lambda e: self._jump(tree.item(tree.focus(), "values")[2] if tree.focus() else None, win))

    def _jump(self, tab_key, win):
        frame = self.tab_frames.get(tab_key)
        if frame is not None:
            self.notebook.select(frame)
        if win is not None:
            win.destroy()

    # ------------------------------------------------------------------ Raw JSON (lazy)
    def _build_raw(self, report):
        self.raw_tree.delete(*self.raw_tree.get_children())
        self.raw_data.clear()
        self.raw_lazy.clear()
        self._set_text(self.raw_detail, "")
        if isinstance(report, dict):
            self._raw_children("", report)
        else:
            self._raw_add("", "report", report)
        for item in self.raw_tree.get_children(""):
            self._raw_expand(item)
            self.raw_tree.item(item, open=True)

    def _raw_add(self, parent, key, value):
        item = self.raw_tree.insert(parent, "end", text=str(key), values=(_preview(value),))
        self.raw_data[item] = value
        if (isinstance(value, dict) and value) or (isinstance(value, list) and value):
            self.raw_tree.insert(item, "end", text="")
            self.raw_lazy.add(item)
        return item

    def _raw_children(self, item, value):
        entries = value.items() if isinstance(value, dict) else enumerate(value)
        total = len(value)
        for i, (k, v) in enumerate(entries):
            if i >= MAX_CHILDREN:
                self.raw_tree.insert(item, "end", text=f"… {total - i} more", values=("(truncated)",))
                break
            self._raw_add(item, k, v)

    def _raw_expand(self, item):
        if item not in self.raw_lazy:
            return
        self.raw_lazy.discard(item)
        self.raw_tree.delete(*self.raw_tree.get_children(item))
        self._raw_children(item, self.raw_data[item])

    def _on_raw_expand(self, event):
        self._raw_expand(self.raw_tree.focus())

    def _on_raw_select(self, event):
        sel = self.raw_tree.selection()
        if not sel:
            return
        self._set_text(self.raw_detail, self._render_detail(self.raw_data.get(sel[0])))

    def _render_detail(self, value):
        if isinstance(value, (dict, list)):
            if _bounded_count(value, FULL_DUMP_LIMIT) <= FULL_DUMP_LIMIT:
                return json.dumps(value, indent=2, ensure_ascii=False, default=str)
            kind = "dict" if isinstance(value, dict) else "list"
            lines = [f"{kind} with {len(value)} entries (too large to dump - drill into the tree):", ""]
            entries = value.items() if isinstance(value, dict) else enumerate(value)
            for i, (k, v) in enumerate(entries):
                if i >= MAX_CHILDREN:
                    lines.append(f"… {len(value) - i} more")
                    break
                lines.append(f"{k}: {_preview(v)}")
            return "\n".join(lines)
        text = str(value)
        if len(text) > MAX_SCALAR:
            text = text[:MAX_SCALAR] + f"\n\n… (truncated; {len(text)} chars total)"
        return text

    # ------------------------------------------------------------------ AI analysis UI
    def _build_ai_tab(self):
        outer = ttk.Frame(self.notebook)
        bar = ttk.Frame(outer)
        bar.pack(fill=tk.X, padx=4, pady=4)
        ttk.Button(bar, text="Analyze all", command=self._run_all_agents).pack(side=tk.LEFT)
        ttk.Button(bar, text="Settings", command=self._ai_settings).pack(side=tk.LEFT, padx=6)
        ttk.Button(bar, text="Cancel", command=self._cancel_ai).pack(side=tk.LEFT)
        self.ai_status = ttk.Label(bar, text="")
        self.ai_status.pack(side=tk.RIGHT)
        inner = ttk.Notebook(outer)
        inner.pack(fill=tk.BOTH, expand=True)
        self.ai_notebook = inner

        for tab, _focus in AGENTS:
            pane = ttk.PanedWindow(inner, orient=tk.VERTICAL)
            head = ttk.Frame(pane)
            row = ttk.Frame(head)
            row.pack(fill=tk.X, padx=2, pady=2)
            button = ttk.Button(row, text=f"Analyze {tab}",
                                command=lambda t=tab: self._run_agent(t))
            button.pack(side=tk.LEFT)
            status = ttk.Label(row, text="not run")
            status.pack(side=tk.RIGHT)
            tframe, tree = self._table(head, ("Severity", "Finding"),
                                       {"Severity": 90, "Finding": 820})
            tframe.pack(fill=tk.BOTH, expand=True)
            tree.bind("<<TreeviewSelect>>", lambda e, t=tab: self._on_finding_select(t))
            dframe, detail = self._detail_text(pane)
            pane.add(head, weight=2)
            pane.add(dframe, weight=3)
            inner.add(pane, text=tab)
            self.ai_panes[tab] = {"tree": tree, "detail": detail, "status": status,
                                  "button": button, "rows": {}}

        # Ask: the same engine, with a tool that can reach past the digest into the report.
        askFrame = ttk.Frame(inner)
        askBar = ttk.Frame(askFrame)
        askBar.pack(fill=tk.X, padx=2, pady=2)
        ttk.Label(askBar, text="Question:").pack(side=tk.LEFT)
        self.ask_entry = ttk.Entry(askBar)
        self.ask_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        self.ask_entry.bind("<Return>", lambda e: self._ask())
        ttk.Button(askBar, text="Ask", command=self._ask).pack(side=tk.LEFT)
        ttk.Button(askBar, text="Clear", command=self._clear_ask).pack(side=tk.LEFT, padx=4)
        aframe, self.ask_text = self._detail_text(askFrame)
        aframe.pack(fill=tk.BOTH, expand=True)
        inner.add(askFrame, text="Ask")
        self._ask_history = []
        self._add_tab(outer, "AI", "AI")

    # -- plumbing ----------------------------------------------------------------------
    def _ensure_engine(self):
        """Build the engine on first use, after the analyst has agreed to the egress."""
        if not self.report:
            raise AIUnavailable("Load a report first.")
        if not self._ai_consent():
            return None
        if self.engine is None:
            self.engine = AnalysisEngine(self.report, self.ai_config)
        return self.engine

    def _ai_consent(self):
        """Say plainly what leaves the machine, once per session."""
        if self.ai_config.consented:
            return True
        agreed = messagebox.askokcancel(
            "Send report data to the Anthropic API?",
            "AI analysis sends parts of this report - file names and hashes, signature text, "
            "process and registry activity, network endpoints, config fields and payload "
            "strings - to the Anthropic API.\n\n"
            "Payload bytes and the sample itself are never sent.\n\n"
            "Nothing is sent until you press OK, and every other tab works without this.",
        )
        self.ai_config.consented = bool(agreed)
        return self.ai_config.consented

    def _ai_settings(self):
        """Session-only settings: nothing here is written to disk."""
        win = tk.Toplevel(self.root)
        win.title("AI settings")
        win.transient(self.root)
        win.configure(bg=PALETTES[self.mode]["BG_MAIN"])
        _set_titlebar(win, self.mode == DARK)
        frame = ttk.Frame(win)
        frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)
        ttk.Label(frame, text="Kept for this session only - never written to disk.").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        entries = {}
        for row, (label, value, hide) in enumerate((
            ("API key", self.ai_config.api_key, True),
            ("Model", self.ai_config.model, False),
            ("Effort", self.ai_config.effort, False),
        ), start=1):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=2)
            entry = ttk.Entry(frame, width=46, show="*" if hide else "")
            entry.insert(0, value or "")
            entry.grid(row=row, column=1, sticky="ew", padx=6, pady=2)
            entries[label] = entry
        source = "environment" if os.environ.get("ANTHROPIC_API_KEY") else "not set"
        ttk.Label(frame, text=f"ANTHROPIC_API_KEY: {source}").grid(
            row=4, column=0, columnspan=2, sticky="w", pady=(8, 0))

        def save():
            self.ai_config.api_key = entries["API key"].get().strip()
            self.ai_config.model = entries["Model"].get().strip() or DEFAULT_MODEL
            self.ai_config.effort = entries["Effort"].get().strip() or DEFAULT_EFFORT
            # The engine caches a client built from the old settings.
            self.engine = None
            win.destroy()

        buttons = ttk.Frame(frame)
        buttons.grid(row=5, column=0, columnspan=2, sticky="e", pady=(10, 0))
        ttk.Button(buttons, text="Save", command=save).pack(side=tk.LEFT, padx=4)
        ttk.Button(buttons, text="Cancel", command=win.destroy).pack(side=tk.LEFT)
        frame.columnconfigure(1, weight=1)

    def _ai_busy_set(self, busy, message=""):
        self._ai_busy = busy
        self.ai_status.config(text=message)
        for pane in self.ai_panes.values():
            pane["button"].config(state=tk.DISABLED if busy else tk.NORMAL)

    def _cancel_ai(self):
        if self._ai_busy:
            self._ai_cancel.set()
            # An HTTP request already in flight cannot be pulled back; say so rather than
            # implying the current agent stopped.
            self.ai_status.config(text="cancelling after the current agent…")

    def _ai_thread(self, work, done):
        """Run an engine call off the UI thread, deliver the result back on it."""
        def runner():
            try:
                result = work()
                self.root.after(0, lambda: done(result, None))
            except Exception as e:  # noqa: BLE001 - surfaced in the pane, never swallowed
                self.root.after(0, lambda e=e: done(None, e))

        threading.Thread(target=runner, daemon=True).start()

    # -- running the agents ------------------------------------------------------------
    def _run_agent(self, tab):
        if self._ai_busy:
            return
        try:
            engine = self._ensure_engine()
        except AIUnavailable as e:
            self._set_text(self.ai_panes[tab]["detail"], str(e))
            return
        if engine is None:
            return
        self._ai_cancel = threading.Event()
        self._ai_busy_set(True, f"running {tab}…")
        self.ai_panes[tab]["status"].config(text="running…")

        def done(result, error):
            self._ai_busy_set(False, self._spend_text())
            if error is not None:
                self.ai_panes[tab]["status"].config(text="failed")
                self._set_text(self.ai_panes[tab]["detail"], str(error))
                return
            self._render_findings(tab, result)

        self._ai_thread(lambda: engine.analyze(tab), done)

    def _run_all_agents(self):
        if self._ai_busy:
            return
        try:
            engine = self._ensure_engine()
        except AIUnavailable as e:
            messagebox.showerror("AI analysis", str(e))
            return
        if engine is None:
            return
        try:
            estimate = engine.estimate()
        except AIUnavailable as e:
            messagebox.showerror("AI analysis", str(e))
            return
        except Exception as e:  # noqa: BLE001 - a failed estimate must not block the run
            estimate = None
            log_line = str(e)
            self.ai_status.config(text=f"could not estimate cost: {log_line}")
        if estimate and not messagebox.askokcancel(
            "Run all agents?",
            f"{estimate['agents']} specialists plus a synthesis pass, on "
            f"{self.ai_config.model}.\n\n"
            f"Input: ~{estimate['input_tokens']:,} tokens\n"
            f"Output: ~{estimate['output_tokens']:,} tokens (estimated)\n"
            f"Cost: ~${estimate['dollars']:.2f}\n\n"
            "The case digest is cached, so the later agents re-read it at about a tenth of "
            "that input price - the real cost is usually lower.",
        ):
            return

        self._ai_cancel = threading.Event()
        self._ai_busy_set(True, "starting…")

        def progress(step, total, tab):
            self.root.after(0, lambda: self.ai_status.config(
                text=f"{step}/{total} {tab}…"))

        def done(result, error):
            self._ai_busy_set(False, self._spend_text())
            if error is not None:
                messagebox.showerror("AI analysis", str(error))
                return
            for tab in AGENT_KEYS:
                if tab in engine.results:
                    self._render_findings(tab, engine.results[tab])
            if result is None:
                self.ai_status.config(text="cancelled - " + self._spend_text())
                return
            self._build_overview()          # verdict card now has something to show
            self.notebook.select(self.tab_frames["Overview"])

        self._ai_thread(
            lambda: engine.analyze_all(progress=progress, cancelled=self._ai_cancel.is_set),
            done)

    def _analyze_current_tab(self):
        """Top-bar shortcut: run the specialist for whichever tab is open."""
        try:
            current = self.notebook.tab(self.notebook.select(), "text")
        except tk.TclError:
            return
        if current not in self.ai_panes:
            messagebox.showinfo(
                "AI analysis",
                f"No specialist for the {current} tab.\n\n"
                "Open one of: " + ", ".join(AGENT_KEYS))
            return
        self.notebook.select(self.tab_frames["AI"])
        self.ai_notebook.select(list(self.ai_panes).index(current))
        self._run_agent(current)

    def _spend_text(self):
        if self.engine is None or not self.engine.usage["calls"]:
            return ""
        usage = self.engine.usage
        return (f"{usage['calls']} calls  in {usage['input']:,} "
                f"(cached {usage['cache_read']:,})  out {usage['output']:,}  "
                f"~${self.engine.spend():.2f}")

    # -- rendering ---------------------------------------------------------------------
    def _render_findings(self, tab, result):
        pane = self.ai_panes[tab]
        pane["tree"].delete(*pane["tree"].get_children())
        pane["rows"] = {}
        result = result or {}

        if "refusal" in result:
            pane["status"].config(text="declined")
            self._set_text(pane["detail"],
                           f"The model declined this request (category: {result['refusal']}).\n\n"
                           f"{result.get('explanation', '')}\n\n"
                           "Malware evidence can trip the safety classifier. The request already "
                           "carries a server-side fallback, so this means the fallback declined "
                           "too. Try a narrower question on the Ask tab.")
            return
        if "error" in result:
            pane["status"].config(text="failed")
            self._set_text(pane["detail"], str(result["error"]))
            return

        findings = result.get("findings") or []
        for finding in findings:
            severity = str(finding.get("severity", "info"))
            tags = ("sev_high",) if severity in ("critical", "high") else (
                ("sev_med",) if severity == "medium" else ())
            item = pane["tree"].insert("", "end", tags=tags,
                                       values=(severity, _preview(finding.get("title", ""))))
            pane["rows"][item] = finding
        pane["status"].config(
            text=f"{len(findings)} finding(s), confidence {result.get('confidence', '?')}")

        lines = [result.get("verdict", ""), ""]
        if result.get("iocs"):
            lines += ["indicators:"] + [f"  {ioc}" for ioc in result["iocs"]] + [""]
        if result.get("gaps"):
            lines += ["gaps:"] + [f"  {gap}" for gap in result["gaps"]] + [""]
        lines.append("Select a finding for its evidence.")
        self._set_text(pane["detail"], "\n".join(lines))

    def _on_finding_select(self, tab):
        pane = self.ai_panes[tab]
        selection = pane["tree"].selection()
        if not selection:
            return
        finding = pane["rows"].get(selection[0])
        if not finding:
            return
        lines = [finding.get("title", ""), f"severity: {finding.get('severity', '')}", "",
                 finding.get("rationale", ""), "", "evidence:"]
        lines += [f"  {item}" for item in finding.get("evidence") or []]
        self._set_text(pane["detail"], "\n".join(lines))

    def _ai_overview_lines(self):
        """The verdict card, folded into the Overview tab when a synthesis exists."""
        synthesis = getattr(self.engine, "synthesis", None) if self.engine else None
        if not synthesis or "verdict" not in synthesis:
            return []
        lines = [
            "",
            f"  {synthesis['verdict']}",
            (f"  family: {synthesis.get('family', 'unknown')}   "
             f"confidence: {synthesis.get('confidence', '?')}"),
        ]
        for label, key in (("certain", "certain"), ("inferred", "inferred"),
                           ("next steps", "next_steps")):
            for entry in synthesis.get(key) or []:
                lines.append(f"  [{label}] {entry}")
        return lines

    # -- Ask ---------------------------------------------------------------------------
    def _ask(self):
        question = self.ask_entry.get().strip()
        if not question or self._ai_busy:
            return
        try:
            engine = self._ensure_engine()
        except AIUnavailable as e:
            self._append_ask(f"\n{e}\n")
            return
        if engine is None:
            return
        self.ask_entry.delete(0, tk.END)
        self._append_ask(f"\n> {question}\n\n")
        self._ai_cancel = threading.Event()
        self._ai_busy_set(True, "asking…")

        def done(result, error):
            self._ai_busy_set(False, self._spend_text())
            if error is not None:
                self._append_ask(f"[error] {error}\n")
                return
            answer, history = result
            self._ask_history = history
            self._append_ask(answer + "\n")

        self._ai_thread(lambda: engine.ask(question, self._ask_history), done)

    def _append_ask(self, text):
        self.ask_text.config(state=tk.NORMAL)
        self.ask_text.insert(tk.END, text)
        self.ask_text.see(tk.END)
        self.ask_text.config(state=tk.DISABLED)

    def _clear_ask(self):
        self._ask_history = []
        self._set_text(self.ask_text, "")

    # ------------------------------------------------------------------ menu actions
    def on_open(self):
        initial = os.path.dirname(self.path) if self.path else os.path.dirname(DEFAULT_REPORT)
        path = filedialog.askopenfilename(
            title="Open CAPEsolo report", initialdir=initial, initialfile="report.json",
            filetypes=[("Report or bundle", "*.json *.zip"), ("JSON report", "*.json"),
                       ("Results bundle", "*.zip"), ("All files", "*.*")])
        if path:
            self.load(path)

    def on_reload(self):
        if self.path:
            self.load(self.path)


# ============================================================================ AI analysis
# Optional by design: the viewer runs on bare stdlib, and these features light up only when
# the anthropic SDK is installed. Without it every pane shows an install hint and the rest of
# the viewer is untouched.

DEFAULT_MODEL = "claude-opus-5"
DEFAULT_EFFORT = "high"
ANALYSIS_MAX_TOKENS = 16000
CHAT_MAX_TOKENS = 64000
# Malware triage content can trip the cyber safety classifier. The server-side fallback re-runs
# a declined request on a fallback model inside the same call, so a refusal degrades to a
# second opinion rather than an empty pane.
FALLBACK_BETA = "server-side-fallback-2026-07-01"
# List prices, $ per million tokens (input, output), for the pre-run estimate only.
MODEL_PRICES = {
    "claude-opus-5": (5.0, 25.0),
    "claude-fable-5-1": (10.0, 50.0),
    "claude-sonnet-5": (2.0, 10.0),
    "claude-haiku-4-5": (1.0, 5.0),
}

# How much of each section a slice may carry. A report is routinely hundreds of MB; the model
# gets a selection, and every cap that bites is declared to it (and to the analyst) rather than
# silently dropping evidence.
CAPS = {
    "signatures": 40, "processes": 40, "calls": 150, "network": 60, "payloads": 40,
    "strings": 60, "events": 120, "iocs": 250, "config_fields": 80, "summary": 60,
    "imports": 60, "sections": 30, "buffers": 20, "yara": 60,
}

SYSTEM_PROMPT = """You are a senior malware analyst triaging a CAPEsolo sandbox report.

You are given a case digest and one section of evidence. Both are SELECTIONS from a much larger
report: any "omitted" field tells you what was left out, and you must reason within that limit -
say what the evidence supports, say plainly when it does not support a conclusion, and never
invent an artifact that is not in the data you were given.

Ground every finding in specific evidence from the input (an API call, a signature name, a host,
a config field, a string). Prefer "insufficient evidence" over a confident guess. Note when the
capture manifest shows the analysis lost data that would have changed your answer."""

# One specialist per evidence tab. The key matches the viewer's tab key so the top-bar button
# can analyse whatever tab the analyst is looking at.
AGENTS = (
    ("Signatures", (
        "Which signature matches are load-bearing and which are noise, what they collectively "
        "imply about family and capability, and which are contradicted by other evidence.")),
    ("Processes", (
        "The execution chain as a narrative: what spawned what, which processes are injected or "
        "hollowed, and which API activity is anomalous for the process it came from.")),
    ("Behavior", (
        "Host-based TTPs: persistence, defence evasion, privilege use, service and registry "
        "manipulation, and what the encrypted buffers reveal.")),
    ("Network", (
        "Command-and-control assessment: which endpoints are real C2 versus noise or telemetry, "
        "beaconing shape, and the intent of any decrypted request.")),
    ("JS Log", (
        "Script-stage behaviour: fetch/XHR activity, dropped buffers, eval chains, and what the "
        "script was trying to retrieve or execute.")),
    ("Payloads", (
        "What each dumped artifact is, the unpacking chain between them, and which payload is "
        "the real final stage.")),
    ("Configs", (
        "What each extracted configuration field means operationally, and what the campaign and "
        "infrastructure look like from it.")),
    ("Yara", (
        "Which rules are meaningful versus generic shelf rules, what the CAPE names imply "
        "about family, and whether the hits agree with the signatures and extracted configs.")),
    ("Static", (
        "Static indicators from the PE: packing, signing, suspicious imports, resources, and "
        "section anomalies.")),
    ("IOCs", (
        "Which indicators are actually actionable for detection or blocking, with a confidence "
        "for each, and which are environment noise that would cause false positives.")),
    ("Capture", (
        "Whether the evidence is complete enough to trust a verdict, and which specific "
        "conclusions are weakened by what the analysis failed to collect.")),
)
AGENT_KEYS = tuple(key for key, _focus in AGENTS)

FINDINGS_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "description": "One or two sentences: what this evidence shows."},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                    "evidence": {"type": "array", "items": {"type": "string"},
                                 "description": "Verbatim artifacts from the input supporting this."},
                    "rationale": {"type": "string"},
                },
                "required": ["title", "severity", "evidence", "rationale"],
                "additionalProperties": False,
            },
        },
        "iocs": {"type": "array", "items": {"type": "string"}},
        "gaps": {"type": "array", "items": {"type": "string"},
                 "description": "What you could not determine, and what evidence would settle it."},
    },
    "required": ["verdict", "confidence", "findings", "iocs", "gaps"],
    "additionalProperties": False,
}

SYNTHESIS_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string"},
        "family": {"type": "string", "description": "Best-supported family, or 'unknown'."},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "certain": {"type": "array", "items": {"type": "string"},
                    "description": "Conclusions the evidence directly supports."},
        "inferred": {"type": "array", "items": {"type": "string"},
                     "description": "Conclusions that are inference, with the leap named."},
        "next_steps": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["verdict", "family", "confidence", "certain", "inferred", "next_steps"],
    "additionalProperties": False,
}


def load_anthropic():
    """Import the SDK on demand. Returns the module, or None when it is not installed."""
    try:
        import anthropic

        return anthropic
    except ImportError:
        return None


class AIConfig:
    """Resolution order: explicit argument, then a session override, then the environment.

    Nothing is written to disk - the viewer is opened on whatever host is triaging a malware
    bundle, and an API key should not be left behind on it.
    """

    def __init__(self, api_key=None, model=None, effort=None):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model or os.environ.get("ANTHROPIC_MODEL", "") or DEFAULT_MODEL
        self.effort = effort or DEFAULT_EFFORT
        self.consented = False

    @property
    def ready(self):
        return bool(self.api_key)

    def price(self):
        return MODEL_PRICES.get(self.model, MODEL_PRICES[DEFAULT_MODEL])


# ---------------------------------------------------------------------------- the digest
def _cap(items, limit, label, omitted):
    """Take the first *limit* items, recording what that left behind."""
    items = list(items or ())
    if len(items) > limit:
        omitted[label] = f"showing {limit} of {len(items)}"
        return items[:limit]
    return items


def _trim(value, length=400):
    text = " ".join(str(value).split())
    return text if len(text) <= length else text[:length] + "…"


def case_digest(report):
    """The shared context every agent sees, and the cached prefix of every request."""
    target = report.get("target") or {}
    behavior = report.get("behavior") or {}
    network = report.get("network") or {}
    capture = report.get("capture") or {}
    omitted = {}

    signatures = sorted(report.get("signatures") or [],
                        key=lambda s: s.get("severity") or 0, reverse=True)
    processes = behavior.get("processes") or []
    payloads = []
    for entry in report.get("payloads") or []:
        for path, data in (entry.items() if isinstance(entry, dict) else []):
            data = data or {}
            payloads.append({"name": data.get("name") or os.path.basename(str(path)),
                             "type": data.get("cape_type") or data.get("type", ""),
                             "size": data.get("size", ""), "pid": data.get("pid", "")})

    return {
        "target": {k: target.get(k) for k in ("name", "type", "size", "md5", "sha256")
                   if target.get(k) not in (None, "")},
        "detections": report.get("detections") or [],
        "top_signatures": [{"name": s.get("name"), "severity": s.get("severity"),
                            "description": _trim(s.get("description", ""), 200)}
                           for s in _cap(signatures, 15, "top_signatures", omitted)],
        "processes": [{"pid": p.get("process_id"), "name": p.get("process_name"),
                       "parent": p.get("parent_id"), "calls": len(p.get("calls") or [])}
                      for p in _cap(processes, 20, "processes", omitted)],
        "network": {
            "hosts": [h.get("ip") for h in _cap(network.get("hosts"), 20, "hosts", omitted)],
            "domains": [d.get("domain") for d in _cap(network.get("domains"), 20, "domains", omitted)],
            "http": [f"{h.get('method', '')} {h.get('host', '')}{h.get('uri', '')}"
                     for h in _cap(network.get("http"), 20, "http", omitted)],
        },
        "payloads": _cap(payloads, 20, "payloads", omitted),
        "config_families": [os.path.basename(str(path)) for entry in report.get("configs") or []
                            for path in (entry.keys() if isinstance(entry, dict) else [])],
        "yara_rules": sorted({f"{h.get('rule', '')}"
                              + (f" [{h['capename']}]" if h.get("capename") else "")
                              for h in _cap(report.get("yara"), 25, "yara_rules", omitted)}),
        # The model is told what the analysis itself failed to collect, so it can caveat a
        # verdict built on partial evidence instead of treating absence as absence of activity.
        "capture": {"warnings": capture.get("warnings") or [],
                    "transfers": capture.get("transfers") or {}},
        "omitted": omitted,
    }


def tab_slice(report, tab):
    """The evidence for one agent, capped, with what was dropped declared alongside it."""
    behavior = report.get("behavior") or {}
    network = report.get("network") or {}
    target = report.get("target") or {}
    omitted = {}
    data = {}

    if tab == "Signatures":
        data["signatures"] = [
            {"name": s.get("name"), "severity": s.get("severity"),
             "description": s.get("description"), "categories": s.get("categories"),
             "families": s.get("families"),
             "evidence": [_trim(d, 300) for d in (s.get("data") or [])][:10],
             "marks": [{"process": (m.get("process") or {}).get("process_name"),
                        "signs": [f"{x.get('type')}={_trim(x.get('value'), 200)}"
                                  for x in (m.get("signs") or [])][:5]}
                       for m in (s.get("new_data") or [])][:5]}
            for s in _cap(report.get("signatures"), CAPS["signatures"], "signatures", omitted)
        ]
    elif tab == "Processes":
        data["processtree"] = behavior.get("processtree") or []
        procs = []
        for process in _cap(behavior.get("processes"), CAPS["processes"], "processes", omitted):
            calls = process.get("calls") or []
            categories = {}
            for call in calls:
                categories[call.get("category") or "?"] = categories.get(call.get("category") or "?", 0) + 1
            sample_omitted = {}
            procs.append({
                "pid": process.get("process_id"), "name": process.get("process_name"),
                "parent": process.get("parent_id"),
                "command_line": (process.get("environ") or {}).get("CommandLine", ""),
                "call_count": len(calls), "call_categories": categories,
                "sampled_calls": [
                    {"api": c.get("api"), "category": c.get("category"),
                     "status": c.get("status"),
                     "args": _trim("; ".join(f"{a.get('name')}={a.get('value')}"
                                             for a in (c.get("arguments") or [])
                                             if isinstance(a, dict)), 300)}
                    for c in _cap(calls, CAPS["calls"], "calls", sample_omitted)],
            })
            if sample_omitted:
                procs[-1]["omitted"] = sample_omitted
        data["processes"] = procs
    elif tab == "Behavior":
        summary = behavior.get("summary") or {}
        data["summary"] = {group: _cap(values, CAPS["summary"], f"summary.{group}", omitted)
                           for group, values in summary.items() if values}
        data["anomalies"] = behavior.get("anomaly") or []
        data["encrypted_buffers"] = [
            {"process": b.get("process_name"), "api": b.get("api_call"),
             "buffer": _trim(b.get("buffer"), 600)}
            for b in _cap(behavior.get("encryptedbuffers"), CAPS["buffers"], "buffers", omitted)]
        data["enhanced"] = _cap(behavior.get("enhanced"), CAPS["events"], "enhanced", omitted)
    elif tab == "Network":
        data["sources"] = network.get("sources")
        data["dns"] = _cap(network.get("dns"), CAPS["network"], "dns", omitted)
        data["http"] = [{k: v for k, v in h.items() if k != "body"}
                        for h in _cap(network.get("http"), CAPS["network"], "http", omitted)]
        data["hosts"] = _cap(network.get("hosts"), CAPS["network"], "hosts", omitted)
        data["domains"] = _cap(network.get("domains"), CAPS["network"], "domains", omitted)
        data["flows"] = _cap((network.get("tcp") or []) + (network.get("udp") or []),
                             CAPS["network"], "flows", omitted)
        data["decrypted"] = [
            {"host": e.get("host"), "method": e.get("method"), "uri": e.get("uri"),
             "status": e.get("status"), "request": _trim(e.get("request"), 800),
             "response": _trim(e.get("response"), 800)}
            for e in _cap((network.get("http_ex") or []) + (network.get("https_ex") or []),
                          20, "decrypted", omitted)]
    elif tab == "JS Log":
        js = report.get("js_log") or {}
        data["exists"] = js.get("exists")
        data["counters"] = {k: js.get(k) for k in ("total_lines", "parsed_lines", "malformed_lines")}
        data["events"] = [{k: _trim(v, 300) for k, v in event.items()}
                          for event in _cap(js.get("events"), CAPS["events"], "events", omitted)]
        data["buffers"] = js.get("buffers") or []
    elif tab == "Payloads":
        entries = []
        for entry in report.get("payloads") or []:
            for path, payload in (entry.items() if isinstance(entry, dict) else []):
                payload = payload or {}
                entries.append({
                    "name": payload.get("name") or os.path.basename(str(path)),
                    "cape_type": payload.get("cape_type"), "type": payload.get("type"),
                    "size": payload.get("size"), "sha256": payload.get("sha256"),
                    "pid": payload.get("pid"), "process": payload.get("process_name"),
                    "target_process": payload.get("target_process"),
                    "incomplete": payload.get("incomplete"), "truncated": payload.get("truncated"),
                    "yara": [h.get("name") for h in (payload.get("yara") or [])],
                    "strings": (payload.get("strings") or [])[-CAPS["strings"]:],
                })
        data["payloads"] = _cap(entries, CAPS["payloads"], "payloads", omitted)
    elif tab == "Configs":
        configs = []
        for entry in report.get("configs") or []:
            for path, cfg in (entry.items() if isinstance(entry, dict) else []):
                fields = dict(_cap(list(_pairs(cfg)), CAPS["config_fields"], "config_fields", omitted))
                configs.append({"file": os.path.basename(str(path)), "fields": fields})
        data["configs"] = configs
        data["detections"] = report.get("detections") or []
    elif tab == "Yara":
        data["hits"] = [
            {"file": hit.get("file"), "rule": hit.get("rule"),
             "capename": hit.get("capename"), "description": hit.get("description"),
             "meta": hit.get("meta"),
             "matched_strings": (hit.get("strings") or [])[:20],
             "offsets": len(hit.get("addresses") or {})}
            for hit in _cap(report.get("yara"), CAPS["yara"], "yara", omitted)]
        data["detections"] = report.get("detections") or []
        data["config_families"] = [os.path.basename(str(path))
                                   for entry in report.get("configs") or []
                                   for path in (entry.keys() if isinstance(entry, dict) else [])]
    elif tab == "Static":
        pe = target.get("pe") or {}
        data["file"] = {k: target.get(k) for k in
                        ("name", "type", "size", "md5", "sha256", "tlsh") if target.get(k)}
        data["yara"] = [{"name": h.get("name"),
                         "description": (h.get("meta") or {}).get("description")}
                        for h in (target.get("yara") or [])]
        data["pe"] = {k: pe.get(k) for k in
                      ("imagebase", "entrypoint", "imphash", "timestamp", "pdbpath",
                       "reported_checksum", "actual_checksum", "digital_signers", "versioninfo",
                       "overlay", "exported_dll_name") if pe.get(k)}
        data["sections"] = _cap(pe.get("sections"), CAPS["sections"], "sections", omitted)
        imports = [f"{entry.get('dll')}!{symbol.get('name')}"
                   for entry in (pe.get("imports") or {}).values()
                   for symbol in (entry.get("imports") or [])]
        data["imports"] = _cap(imports, CAPS["imports"], "imports", omitted)
    elif tab == "IOCs":
        summary = behavior.get("summary") or {}
        data["indicators"] = {
            group: _cap(values, 40, f"iocs.{group}", omitted)
            for group, values in summary.items() if values
        }
        data["hosts"] = [h.get("ip") for h in (network.get("hosts") or [])][:CAPS["iocs"]]
        data["domains"] = [d.get("domain") for d in (network.get("domains") or [])][:CAPS["iocs"]]
        data["detections"] = report.get("detections") or []
    elif tab == "Capture":
        data["capture"] = report.get("capture") or {}
        data["payload_flags"] = [
            {"name": (payload or {}).get("name"), "incomplete": (payload or {}).get("incomplete"),
             "truncated": (payload or {}).get("truncated")}
            for entry in report.get("payloads") or []
            for payload in (entry.values() if isinstance(entry, dict) else [])
            if (payload or {}).get("incomplete") or (payload or {}).get("truncated")]

    if omitted:
        data["omitted"] = omitted
    return data


# ---------------------------------------------------------------------------- the engine
class AIUnavailable(Exception):
    """Raised when the SDK or a key is missing - always shown, never swallowed."""


class AnalysisEngine:
    """One engine behind all three surfaces (tabs, Ask pane, CLI), so an answer does not
    depend on where it was asked from.

    The client is injectable: the tests drive a stub and never reach the network.
    """

    def __init__(self, report, config=None, client=None):
        self.report = report or {}
        self.config = config or AIConfig()
        self.digest = case_digest(self.report)
        self.results = {}       # tab -> parsed findings, or {"error"/"refusal": ...}
        self.synthesis = None
        self.usage = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0, "calls": 0}
        self._client = client
        self._sdk = None

    # -- client ------------------------------------------------------------------------
    def client(self):
        if self._client is not None:
            return self._client
        self._sdk = load_anthropic()
        if self._sdk is None:
            raise AIUnavailable(
                "The anthropic SDK is not installed.\n\n"
                "    pip install anthropic\n\n"
                "Every other tab works without it."
            )
        if not self.config.api_key:
            raise AIUnavailable(
                "No API key. Set ANTHROPIC_API_KEY in the environment, pass --api-key, or "
                "enter one in Settings (it is kept for this session only)."
            )
        self._client = self._sdk.Anthropic(api_key=self.config.api_key)
        return self._client

    @property
    def available(self):
        return load_anthropic() is not None and self.config.ready

    # -- request building --------------------------------------------------------------
    def _context(self, body):
        """The cached case digest, then this request's own evidence.

        The digest block carries the cache breakpoint and the system prompt is identical for
        every agent, so the whole prefix is shared: the second and later agents re-read the
        case at cache rates instead of paying for it again.
        """
        return [
            {"type": "text",
             "text": "CASE DIGEST\n" + json.dumps(self.digest, indent=2, default=str),
             "cache_control": {"type": "ephemeral"}},
            {"type": "text", "text": body},
        ]

    def _record(self, response):
        usage = getattr(response, "usage", None)
        if usage is None:
            return
        self.usage["calls"] += 1
        self.usage["input"] += getattr(usage, "input_tokens", 0) or 0
        self.usage["output"] += getattr(usage, "output_tokens", 0) or 0
        self.usage["cache_read"] += getattr(usage, "cache_read_input_tokens", 0) or 0
        self.usage["cache_write"] += getattr(usage, "cache_creation_input_tokens", 0) or 0

    @staticmethod
    def _refusal(response):
        """Check before reading content: a declined request returns 200 with no answer."""
        if getattr(response, "stop_reason", None) != "refusal":
            return None
        details = getattr(response, "stop_details", None)
        category = getattr(details, "category", None) or "unspecified"
        explanation = getattr(details, "explanation", None) or ""
        return {"refusal": category, "explanation": explanation}

    @staticmethod
    def _text(response):
        for block in getattr(response, "content", None) or []:
            if getattr(block, "type", None) == "text":
                return block.text
        return ""

    def _structured(self, body, schema, instruction):
        """One agent call: structured JSON out, refusal handled, usage recorded."""
        response = self.client().beta.messages.create(
            model=self.config.model,
            max_tokens=ANALYSIS_MAX_TOKENS,
            thinking={"type": "adaptive"},
            output_config={"effort": self.config.effort,
                           "format": {"type": "json_schema", "schema": schema}},
            # A cyber-category decline is a live possibility on malware evidence; the
            # server-side fallback answers from another model in the same call.
            betas=[FALLBACK_BETA],
            fallbacks="default",
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": self._context(body + "\n\n" + instruction)}],
        )
        self._record(response)
        refused = self._refusal(response)
        if refused:
            return refused
        try:
            return json.loads(self._text(response))
        except ValueError as e:
            return {"error": f"Model returned unparsable JSON: {e}"}

    # -- the agents --------------------------------------------------------------------
    def analyze(self, tab):
        """Run one tab's specialist. Returns the parsed findings and stores them."""
        focus = dict(AGENTS).get(tab)
        if focus is None:
            raise ValueError(f"No agent for tab {tab!r}")
        evidence = tab_slice(self.report, tab)
        body = f"EVIDENCE - {tab}\n" + json.dumps(evidence, indent=2, default=str)
        instruction = (
            f"You are the {tab} specialist. Focus on: {focus}\n"
            "Report only what this evidence supports. If a cap in an 'omitted' field means you "
            "cannot answer something, say so in gaps rather than guessing."
        )
        result = self._structured(body, FINDINGS_SCHEMA, instruction)
        self.results[tab] = result
        return result

    def synthesize(self):
        """Lead-analyst pass over the specialists' findings, not over the raw report."""
        if not self.results:
            raise ValueError("Nothing to synthesise - run the tab agents first")
        body = "SPECIALIST FINDINGS\n" + json.dumps(
            {tab: result for tab, result in self.results.items()}, indent=2, default=str)
        instruction = (
            "You are the lead analyst. Reconcile the specialists' findings into one verdict. "
            "Name the family only if the evidence supports it. Separate what the evidence "
            "directly shows from what you are inferring, and name the leap in each inference. "
            "Where specialists disagree, say which you believe and why."
        )
        self.synthesis = self._structured(body, SYNTHESIS_SCHEMA, instruction)
        return self.synthesis

    def analyze_all(self, tabs=None, progress=None, cancelled=None):
        """Run each specialist then synthesise, reporting progress and honouring cancel."""
        tabs = tabs or AGENT_KEYS
        for index, tab in enumerate(tabs, 1):
            if cancelled is not None and cancelled():
                return None
            if progress:
                progress(index, len(tabs) + 1, tab)
            try:
                self.analyze(tab)
            except AIUnavailable:
                raise
            except Exception as e:  # noqa: BLE001 - one dead agent must not sink the run
                self.results[tab] = {"error": str(e)}
        if cancelled is not None and cancelled():
            return None
        if progress:
            progress(len(tabs) + 1, len(tabs) + 1, "Overview")
        return self.synthesize()

    # -- interactive -------------------------------------------------------------------
    def ask(self, question, history=None):
        """Answer a question, with a tool that can fetch what the digest left out.

        This is the one place a tool loop earns its keep: the digest is a selection, and
        without a way back to the full report the model would have to guess about anything
        capped out of it.
        """
        sdk = load_anthropic()
        if sdk is None and self._client is None:
            raise AIUnavailable("The anthropic SDK is not installed.\n\n    pip install anthropic")
        report = self.report

        def report_query(path: str, limit: int = 20) -> str:
            """Read a slice of the full analysis report that the digest may have omitted.

            Args:
                path: Dotted path into report.json, e.g. "behavior.summary.mutexes",
                    "network.dns", "signatures", "behavior.processes.0.calls".
                limit: Maximum number of list entries to return.
            """
            node = report
            for part in [p for p in str(path).split(".") if p]:
                if isinstance(node, dict):
                    node = node.get(part)
                elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
                    node = node[int(part)]
                else:
                    return f"No such path: {path}"
                if node is None:
                    return f"No such path: {path}"
            if isinstance(node, list):
                total = len(node)
                node = node[:max(1, min(int(limit), 200))]
                return json.dumps({"total": total, "returned": len(node), "items": node},
                                  indent=2, default=str)[:20000]
            return json.dumps(node, indent=2, default=str)[:20000]

        # The SDK's decorator builds the tool schema from the signature and docstring above.
        # With an injected client and no SDK (the tests) the bare function stands in - it is
        # recorded, never sent.
        decorate = getattr(sdk, "beta_tool", None)
        tools = [decorate(report_query) if decorate else report_query]
        messages = list(history or [])
        messages.append({"role": "user", "content": self._context(f"QUESTION\n{question}")})
        runner = self.client().beta.messages.tool_runner(
            model=self.config.model,
            max_tokens=ANALYSIS_MAX_TOKENS,
            thinking={"type": "adaptive"},
            output_config={"effort": self.config.effort},
            betas=[FALLBACK_BETA],
            fallbacks="default",
            system=SYSTEM_PROMPT,
            tools=tools,
            messages=messages,
        )
        response = runner.until_done()
        self._record(response)
        refused = self._refusal(response)
        if refused:
            return (f"[declined: {refused['refusal']}] {refused['explanation']}".strip(),
                    messages)
        answer = self._text(response)
        messages.append({"role": "assistant", "content": answer})
        return answer, messages

    # -- cost --------------------------------------------------------------------------
    def estimate(self, tabs=None):
        """Count tokens for the planned run and price it, before anything is spent."""
        tabs = tabs or AGENT_KEYS
        total_input = 0
        for tab in tabs:
            body = f"EVIDENCE - {tab}\n" + json.dumps(tab_slice(self.report, tab),
                                                      indent=2, default=str)
            counted = self.client().messages.count_tokens(
                model=self.config.model,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": self._context(body)}],
            )
            total_input += getattr(counted, "input_tokens", 0) or 0
        # Output is unknown before the fact; assume each agent fills a third of its budget.
        est_output = len(tabs) * (ANALYSIS_MAX_TOKENS // 3)
        in_price, out_price = self.config.price()
        return {
            "agents": len(tabs),
            "input_tokens": total_input,
            "output_tokens": est_output,
            "dollars": total_input / 1e6 * in_price + est_output / 1e6 * out_price,
        }

    def spend(self):
        """What has actually been spent so far, from the responses' own usage."""
        in_price, out_price = self.config.price()
        return (self.usage["input"] / 1e6 * in_price
                + self.usage["cache_read"] / 1e6 * in_price * 0.1
                + self.usage["output"] / 1e6 * out_price)


def _merge_capture(data, capture):
    """Fold a bundle's capture.json into the report it sits beside.

    The report's own manifest wins, but only capture.json knows which kind of bundle this is:
    the report was written into the analysis directory before any archive existed, so it can
    never carry that stamp.
    """
    if not capture or not isinstance(data, dict):
        return data
    existing = data.get("capture")
    if not existing:
        data["capture"] = capture
    elif capture.get("bundle") and not existing.get("bundle"):
        existing["bundle"] = capture["bundle"]
    return data


def read_report(path):
    """Load a report or bundle outside the GUI, for the headless CLI paths."""
    shared = {"read": 0, "size": 1, "cancel": False}
    if zipfile.is_zipfile(path):
        buf, capture = ReportViewer._read_bundle(path, shared)
    else:
        buf, capture = ReportViewer._read_plain(path, shared), None
    return _merge_capture(json.loads(buf), capture)


def _bundle_member(names, target):
    """Find *target* at the zip root, or anywhere in it if the bundle was nested."""
    if target in names:
        return target
    for name in names:
        if name.rsplit("/", 1)[-1] == target:
            return name
    return None


def _pairs(cfg):
    """Yield (key, value) pairs from a config that may be a dict or a list of dicts."""
    if isinstance(cfg, dict):
        yield from cfg.items()
    elif isinstance(cfg, list):
        for element in cfg:
            if isinstance(element, dict):
                yield from element.items()


USAGE = """CAPEsolo report viewer

    python report_viewer.py [report.json | bundle.zip] [options]

    --theme dark|light   force a palette (default: follow the OS on Windows)
    --model ID           Claude model (default: $ANTHROPIC_MODEL or claude-opus-5)
    --api-key KEY        API key (default: $ANTHROPIC_API_KEY)
    --effort LEVEL       low|medium|high|xhigh|max (default: high)
    --ask "QUESTION"     answer one question about the report and exit
    --chat               interactive question loop in the terminal
    --analyze [TAB|all]  run the AI specialists headless and print their findings
    --yes                skip the "this sends data to the API" confirmation
"""

EGRESS_NOTICE = """AI analysis sends parts of this report - file names and hashes, signature
text, process and registry activity, network endpoints, config fields and payload strings - to
the Anthropic API. Payload bytes and the sample itself are never sent."""


def _take_option(args, name, default=None):
    """Pull "--name value" out of the argument list, returning the value."""
    if name not in args:
        return default
    index = args.index(name)
    value = args[index + 1] if index + 1 < len(args) and not args[index + 1].startswith("--") else ""
    del args[index:index + (2 if value else 1)]
    return value or default


def _confirm_egress(assume_yes):
    if assume_yes:
        return True
    print(EGRESS_NOTICE)
    try:
        return input("\nContinue? [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


def _print_findings(tab, result):
    print(f"\n=== {tab} " + "=" * max(0, 68 - len(tab)))
    if "refusal" in result:
        print(f"declined ({result['refusal']}): {result.get('explanation', '')}")
        return
    if "error" in result:
        print(f"error: {result['error']}")
        return
    print(f"{result.get('verdict', '')}   [confidence: {result.get('confidence', '?')}]")
    for finding in result.get("findings") or []:
        print(f"\n  [{finding.get('severity', '?')}] {finding.get('title', '')}")
        print(f"      {finding.get('rationale', '')}")
        for item in finding.get("evidence") or []:
            print(f"      - {item}")
    if result.get("iocs"):
        print("\n  indicators: " + ", ".join(result["iocs"]))
    if result.get("gaps"):
        print("  gaps:")
        for gap in result["gaps"]:
            print(f"    - {gap}")


def run_cli(path, config, mode, question, assume_yes):
    """Headless surfaces: --ask, --chat and --analyze. Never opens a window."""
    if not path or not os.path.isfile(path):
        print(f"No report to read: {path or '(none given)'}")
        return 2
    if load_anthropic() is None:
        print("The anthropic SDK is not installed.\n\n    pip install anthropic")
        return 3
    if not config.ready:
        print("No API key. Set ANTHROPIC_API_KEY or pass --api-key.")
        return 3
    if not _confirm_egress(assume_yes):
        print("Cancelled - nothing was sent.")
        return 1

    engine = AnalysisEngine(read_report(path), config)
    try:
        if mode == "ask":
            answer, _history = engine.ask(question)
            print("\n" + answer)
        elif mode == "chat":
            print("Ask about this report. Ctrl-C or 'exit' to quit.\n")
            history = []
            while True:
                try:
                    line = input("> ").strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    break
                if line.lower() in ("exit", "quit"):
                    break
                if not line:
                    continue
                answer, history = engine.ask(line, history)
                print("\n" + answer + "\n")
        else:
            tabs = AGENT_KEYS if question in ("", "all", None) else (question,)
            unknown = [tab for tab in tabs if tab not in AGENT_KEYS]
            if unknown:
                print(f"No specialist for {unknown[0]!r}. Choose from: {', '.join(AGENT_KEYS)}")
                return 2
            for tab in tabs:
                _print_findings(tab, engine.analyze(tab))
            if len(tabs) > 1:
                synthesis = engine.synthesize()
                print("\n=== Overview " + "=" * 57)
                if "verdict" in synthesis:
                    print(f"{synthesis['verdict']}\n")
                    print(f"family: {synthesis.get('family')}   "
                          f"confidence: {synthesis.get('confidence')}")
                    for label in ("certain", "inferred", "next_steps"):
                        for entry in synthesis.get(label) or []:
                            print(f"  [{label}] {entry}")
                else:
                    print(synthesis)
    except AIUnavailable as e:
        print(str(e))
        return 3
    except KeyboardInterrupt:
        print("\ninterrupted")
    finally:
        if engine.usage["calls"]:
            usage = engine.usage
            print(f"\n{usage['calls']} call(s)  in {usage['input']:,} "
                  f"(cached {usage['cache_read']:,})  out {usage['output']:,}  "
                  f"~${engine.spend():.2f}")
    return 0


def main():
    args = sys.argv[1:]
    if "--help" in args or "-h" in args:
        print(USAGE)
        return 0

    theme = _take_option(args, "--theme")
    if theme is not None and theme not in (DARK, LIGHT):
        print(f"--theme takes {DARK} or {LIGHT}")
        return 2
    config = AIConfig(api_key=_take_option(args, "--api-key"),
                      model=_take_option(args, "--model"),
                      effort=_take_option(args, "--effort"))
    assume_yes = "--yes" in args
    if assume_yes:
        args.remove("--yes")
    question = _take_option(args, "--ask")
    mode = "ask" if question is not None else None
    if "--chat" in args:
        args.remove("--chat")
        mode = "chat"
    if "--analyze" in args:
        question = _take_option(args, "--analyze", "all")
        mode = "analyze"
    path = args[0] if args else (DEFAULT_REPORT if mode else None)

    if mode:
        return run_cli(path, config, mode, question, assume_yes)

    root = tk.Tk()
    ReportViewer(root, path, theme=theme, ai_config=config)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
