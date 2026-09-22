#!/usr/bin/env python3
"""Standalone triage viewer for a CAPEsolo JSON report (report.json).

Self-contained: standard library only (tkinter/ttk + json), so it runs on any host with Python,
no CAPEsolo install and no pip dependencies. tkinter ships with the standard Windows/macOS Python;
on Linux install python3-tk.

Presents a triage report - Overview verdict, Signatures, Processes, Network, Payloads, IOCs -
plus a global search and a Raw JSON tree. Built for large reports: the file is read in chunks with
a progress bar, the Raw JSON tree loads lazily, and the detail panes are bounded.

Usage:
    python report_viewer.py [path\\to\\report.json]

With no argument it defaults to ~/Desktop/report.json (where CAPEsolo writes it).
"""

import csv
import gc
import json
import os
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

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
# Light-theme row tints for API-call categories (report_viewer uses the light ttk theme, so the
# wx app's dark BEHAVIOR_CATEGORY_COLORS are not reused). Unmapped categories get no tint.
CALL_CATEGORY_COLORS = {
    "filesystem": "#ffe8cc",
    "registry": "#ffd6d6",
    "process": "#dbe6ff",
    "threading": "#cfe8ff",
    "services": "#e8d9ff",
    "device": "#f3d9e8",
    "network": "#d9f5d9",
    "socket": "#d9f5e2",
    "synchronization": "#ecd9ff",
    "browser": "#d9f5ea",
    "crypto": "#f5f0c2",
    "system": "#f7f1cf",
    "hooking": "#e4e4e4",
    "misc": "#eeeeee",
    "com": "#d6f0f5",
    "windows": "#f0e2d0",
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
    def __init__(self, root, path=None):
        self.root = root
        self.path = None
        self.report = {}
        self.raw_data = {}      # raw-tree item id -> value
        self.raw_lazy = set()
        self._prog = None
        self.search_index = []  # list of (category, value, tab_key)
        self.tab_frames = {}    # tab_key -> frame (for search jump)

        root.title("CAPEsolo Report Viewer")
        root.geometry("1150x720")

        self._build_menu()
        self._build_topbar()
        self._build_tabs()

        initial = path if (path and os.path.isfile(path)) else DEFAULT_REPORT
        if os.path.isfile(initial):
            self.load(initial)

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
        self.path_label = ttk.Label(bar, text="")
        self.path_label.pack(side=tk.RIGHT)

    def _build_tabs(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        self._build_overview_tab()
        self._build_signatures_tab()
        self._build_processes_tab()
        self._build_behavior_tab()
        self._build_network_tab()
        self._build_jslog_tab()
        self._build_payloads_tab()
        self._build_configs_tab()
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
        return frame, tree

    def _detail_text(self, parent):
        frame = ttk.Frame(parent)
        text = tk.Text(frame, wrap=tk.NONE, font=("Consolas", 10), state=tk.DISABLED, height=10)
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
        frame, self.overview = self._detail_text(self.notebook)
        for tag, color in (("h", None), ("sev_high", "#c0392b"), ("sev_med", "#c07a1f")):
            if color:
                self.overview.tag_config(tag, foreground=color)
        self.overview.tag_config("h", font=("Consolas", 11, "bold"))
        self._add_tab(frame, "Overview", "Overview")

    def _build_signatures_tab(self):
        pane = ttk.PanedWindow(self.notebook, orient=tk.VERTICAL)
        tframe, self.sig_tree = self._table(pane, ("Sev", "Name", "Categories"),
                                            {"Sev": 45, "Name": 260, "Categories": 220})
        self.sig_tree.tag_configure("sev_high", background="#ffdddd", foreground="#7a1414")
        self.sig_tree.tag_configure("sev_med", background="#fff0d0", foreground="#7a5514")
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
        for cat, color in CALL_CATEGORY_COLORS.items():
            self.proc_calls.tag_configure(cat, background=color)
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
            pane, ("Name", "Type", "Size", "SHA256", "PID"),
            {"Name": 220, "Type": 200, "Size": 90, "SHA256": 320, "PID": 60},
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
            buf = bytearray()
            with open(path, "rb") as f:
                while True:
                    if shared["cancel"]:
                        shared["error"] = "cancelled"
                        return
                    chunk = f.read(READ_CHUNK)
                    if not chunk:
                        break
                    buf += chunk
                    shared["read"] = len(buf)
            shared["phase"] = "parsing"
            gc.disable()
            try:
                shared["data"] = json.loads(buf)
            finally:
                gc.enable()
        except Exception as e:  # noqa: BLE001
            shared["error"] = e

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
        self._build_raw(report)
        self._build_overview()
        self._build_signatures()
        self._build_processes()
        self._build_behavior()
        self._build_network()
        self._build_jslog()
        self._build_payloads()
        self._build_configs()
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
        line(f"  yara (target): {len((target.get('yara') or []))}")
        line(f"  anomalies: {len(beh.get('anomaly') or [])}"
             f"  encrypted buffers: {len(beh.get('encryptedbuffers') or [])}")
        js = r.get("js_log") or {}
        line(f"  js events: {js.get('parsed_lines', 0) if js.get('exists') else 'no js log'}")
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
            tags = (cat,) if cat in CALL_CATEGORY_COLORS else ()
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
                item = self.pay_tree.insert("", "end", values=(
                    data.get("name", os.path.basename(str(path))),
                    data.get("cape_type", ""),
                    data.get("size", ""),
                    data.get("sha256", ""),
                    data.get("pid", ""),
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

    # ------------------------------------------------------------------ menu actions
    def on_open(self):
        initial = os.path.dirname(self.path) if self.path else os.path.dirname(DEFAULT_REPORT)
        path = filedialog.askopenfilename(title="Open CAPEsolo report", initialdir=initial,
                                          initialfile="report.json",
                                          filetypes=[("JSON report", "*.json"), ("All files", "*.*")])
        if path:
            self.load(path)

    def on_reload(self):
        if self.path:
            self.load(self.path)


def _pairs(cfg):
    """Yield (key, value) pairs from a config that may be a dict or a list of dicts."""
    if isinstance(cfg, dict):
        yield from cfg.items()
    elif isinstance(cfg, list):
        for element in cfg:
            if isinstance(element, dict):
                yield from element.items()


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else None
    root = tk.Tk()
    ReportViewer(root, path)
    root.mainloop()


if __name__ == "__main__":
    main()
