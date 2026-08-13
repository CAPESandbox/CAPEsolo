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
        self._build_network_tab()
        self._build_payloads_tab()
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
        dframe, self.proc_detail = self._detail_text(pane)
        pane.add(tframe, weight=2)
        pane.add(dframe, weight=3)
        self._add_tab(pane, "Processes", "Processes")

    def _build_network_tab(self):
        outer = ttk.Frame(self.notebook)
        self.net_sources = ttk.Label(outer, text="")
        self.net_sources.pack(fill=tk.X, padx=4, pady=2)
        self.net_notebook = ttk.Notebook(outer)
        self.net_notebook.pack(fill=tk.BOTH, expand=True)
        self.net_tables = {}
        specs = [
            ("DNS", ("request", "type", "answers")),
            ("HTTP", ("method", "host", "port", "uri")),
            ("Hosts", ("ip",)),
            ("Domains", ("domain", "ip")),
            ("Flows", ("proto", "src", "dst", "dport")),
        ]
        for name, cols in specs:
            frame, tree = self._table(self.net_notebook, cols, {c: 220 for c in cols})
            self.net_tables[name] = tree
            self.net_notebook.add(frame, text=name)
        self._add_tab(outer, "Network", "Network")

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
        self._build_network()
        self._build_payloads()
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
        if s.get("families"):
            lines += ["", "families: " + ", ".join(map(str, s["families"]))]
        if s.get("references"):
            lines += ["", "references:"] + [f"  {ref}" for ref in s["references"]]
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
        self._proc_node = {}
        beh = self.report.get("behavior") or {}
        roots = beh.get("processtree") or []
        if not roots:
            self.proc_tree.insert("", "end", text="(no process tree)")
        for node in roots:
            self._add_proc(node, "")
        self._set_text(self.proc_detail, "")

    def _add_proc(self, node, parent):
        label = f"{node.get('name', '?')} ({node.get('pid', '?')})"
        item = self.proc_tree.insert(parent, "end", text=label, open=True)
        self._proc_node[item] = node
        for child in node.get("children") or []:
            self._add_proc(child, item)

    def _on_proc_select(self, event):
        sel = self.proc_tree.selection()
        if not sel:
            return
        # The processtree node carries the metadata directly (name/pid/parent_id/module_path/
        # threads); don't touch behavior.processes[].calls (cumulatively accreted, unreliable).
        node = self._proc_node.get(sel[0])
        if not node:
            self._set_text(self.proc_detail, "")
            return
        lines = []
        for k in ("name", "pid", "parent_id", "module_path"):
            if node.get(k) not in (None, ""):
                lines.append(f"{k}: {node.get(k)}")
        lines.append(f"threads: {len(node.get('threads') or [])}")
        self._set_text(self.proc_detail, "\n".join(lines))

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
        for h in net.get("http") or []:
            self.net_tables["HTTP"].insert("", "end",
                                           values=(h.get("method", ""), h.get("host", ""), h.get("port", ""), h.get("uri", "")))
        for h in net.get("hosts") or []:
            self.net_tables["Hosts"].insert("", "end", values=(h.get("ip", ""),))
        for d in net.get("domains") or []:
            self.net_tables["Domains"].insert("", "end", values=(d.get("domain", ""), d.get("ip", "")))
        for proto in ("tcp", "udp"):
            for f in net.get(proto) or []:
                self.net_tables["Flows"].insert("", "end",
                                                values=(proto, f.get("src", ""), f.get("dst", ""), f.get("dport", "")))

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
        for k in ("name", "cape_type", "type", "size", "md5", "sha1", "sha256",
                  "process_name", "pid", "module_path", "target_process", "target_pid"):
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
        for group in ("files", "write_files", "delete_files"):
            for v in summary.get(group) or []:
                add("File", v)
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
        for _kind, value in getattr(self, "_iocs", []):
            add("ioc", value, "IOCs")
        for s in ((r.get("target") or {}).get("strings") or [])[:MAX_STRINGS]:
            add("string", s, "Raw JSON")
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
