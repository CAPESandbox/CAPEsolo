#!/usr/bin/env python3
"""Standalone viewer for a CAPEsolo JSON report (report.json).

Self-contained: uses only the Python standard library (tkinter/ttk + json), so it runs on any
host with Python and no CAPEsolo install and no pip dependencies. tkinter ships with the standard
Windows/macOS Python; on Linux install python3-tk.

Built for large reports (multi-hundred-MB / GB):
  * the file is read in chunks on a worker thread with a real progress bar (disk read is the
    big time cost and, being I/O, keeps the UI responsive);
  * the tree is populated lazily - only a node's immediate children are created when it is
    expanded - so a huge report never builds millions of widgets up front;
  * the detail pane renders a bounded view, so selecting a huge node never freezes.
The one unavoidable pause is json.loads itself (the CPython JSON parser holds the GIL); the
progress dialog labels that phase. A GB report also needs several GB of RAM to hold the parsed
object - that is inherent to stdlib json.

Usage:
    python report_viewer.py [path\\to\\report.json]

With no argument it defaults to ~/Desktop/report.json (where CAPEsolo writes it).
"""

import gc
import json
import os
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

VALUE_PREVIEW_LEN = 200      # chars shown in the tree's Value column
MAX_CHILDREN = 2000          # max child nodes materialized per expand (rest summarized)
FULL_DUMP_LIMIT = 5000       # node budget under which the detail pane pretty-dumps fully
MAX_SCALAR = 200_000         # chars of a scalar shown in the detail pane
READ_CHUNK = 8 * 1024 * 1024
DEFAULT_REPORT = os.path.join(os.path.expanduser("~"), "Desktop", "report.json")


def _preview(value):
    """Short one-line preview for the tree's Value column / shallow detail."""
    if isinstance(value, dict):
        return f"{{{len(value)}}}"
    if isinstance(value, list):
        return f"[{len(value)}]"
    text = " ".join(str(value).split())
    return text if len(text) <= VALUE_PREVIEW_LEN else text[:VALUE_PREVIEW_LEN] + "…"


def _bounded_count(value, limit):
    """Total nested node count, capped: returns >limit as soon as the budget is exceeded."""
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


class ReportViewer:
    def __init__(self, root, path=None):
        self.root = root
        self.path = None
        self.data = {}       # tree item id -> full Python value (Treeview can't hold objects)
        self.lazy = set()    # tree item ids whose children are not yet materialized
        self._prog = None

        root.title("CAPEsolo Report Viewer")
        root.geometry("1000x650")

        self._build_menu()
        self._build_widgets()

        initial = path if (path and os.path.isfile(path)) else DEFAULT_REPORT
        if os.path.isfile(initial):
            self.load(initial)

    # -- UI ----------------------------------------------------------------------
    def _build_menu(self):
        menubar = tk.Menu(self.root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Open...", command=self.on_open, accelerator="Ctrl+O")
        filemenu.add_command(label="Reload", command=self.on_reload, accelerator="Ctrl+R")
        filemenu.add_command(label="Collapse all", command=self._collapse_all)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.root.destroy)
        menubar.add_cascade(label="File", menu=filemenu)
        self.root.config(menu=menubar)
        self.root.bind_all("<Control-o>", lambda e: self.on_open())
        self.root.bind_all("<Control-r>", lambda e: self.on_reload())

    def _build_widgets(self):
        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(paned)
        self.tree = ttk.Treeview(left, columns=("value",), show="tree headings")
        self.tree.heading("#0", text="Key")
        self.tree.heading("value", text="Value")
        self.tree.column("#0", width=320, stretch=False)
        self.tree.column("value", width=360)
        yscroll = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.bind("<<TreeviewOpen>>", self.on_expand)
        paned.add(left, weight=3)

        right = ttk.Frame(paned)
        self.detail = tk.Text(right, wrap=tk.NONE, font=("Consolas", 10), state=tk.DISABLED)
        dyscroll = ttk.Scrollbar(right, orient=tk.VERTICAL, command=self.detail.yview)
        dxscroll = ttk.Scrollbar(right, orient=tk.HORIZONTAL, command=self.detail.xview)
        self.detail.configure(yscrollcommand=dyscroll.set, xscrollcommand=dxscroll.set)
        self.detail.grid(row=0, column=0, sticky="nsew")
        dyscroll.grid(row=0, column=1, sticky="ns")
        dxscroll.grid(row=1, column=0, sticky="ew")
        right.rowconfigure(0, weight=1)
        right.columnconfigure(0, weight=1)
        paned.add(right, weight=4)

    # -- loading (chunked read on a worker thread + progress) --------------------
    def load(self, path):
        if not os.path.isfile(path):
            messagebox.showerror("Report Viewer", f"File not found:\n{path}")
            return
        win = tk.Toplevel(self.root)
        win.title("Loading")
        win.transient(self.root)
        win.resizable(False, False)
        ttk.Label(
            win,
            text=f"Loading {os.path.basename(path)}\n(a large report may pause while parsing)",
            justify="center",
        ).pack(padx=24, pady=(16, 8))
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
            gc.disable()  # millions of objects: skip GC churn during the parse
            try:
                shared["data"] = json.loads(buf)  # json.loads accepts bytes/bytearray
            finally:
                gc.enable()
        except Exception as e:  # noqa: BLE001 - report any failure to the user
            shared["error"] = e

    def _poll_load(self, path, shared):
        win, bar, status = self._prog
        if "data" in shared or "error" in shared:
            win.grab_release()
            win.destroy()
            self._prog = None
            err = shared.get("error")
            if err is not None:
                if err != "cancelled":
                    messagebox.showerror("Report Viewer", f"Could not read report:\n{path}\n\n{err}")
                return
            self.path = path
            self.root.title(f"CAPEsolo Report Viewer - {path}")
            self._populate(shared["data"])
            return

        if shared.get("phase") == "parsing":
            bar["value"] = 100
            status.config(text="Parsing JSON…")
        else:
            read, size = shared["read"], shared["size"]
            bar["value"] = read * 100 / size
            status.config(text=f"Reading… {read // (1024 * 1024)} / {size // (1024 * 1024)} MB")
        self.root.after(80, lambda: self._poll_load(path, shared))

    # -- lazy tree ---------------------------------------------------------------
    def _populate(self, report):
        self.tree.delete(*self.tree.get_children())
        self.data.clear()
        self.lazy.clear()
        self._set_detail("")

        if isinstance(report, dict):
            self._populate_children("", report)
        else:
            self._add("", "report", report)

        # Pre-expand the top level (one level) for an immediate overview.
        for item in self.tree.get_children(""):
            self._expand(item)
            self.tree.item(item, open=True)

    def _add(self, parent, key, value):
        item = self.tree.insert(parent, "end", text=str(key), values=(_preview(value),))
        self.data[item] = value
        if (isinstance(value, dict) and value) or (isinstance(value, list) and value):
            self.tree.insert(item, "end", text="")  # placeholder so the expander arrow shows
            self.lazy.add(item)
        return item

    def _populate_children(self, item, value):
        entries = value.items() if isinstance(value, dict) else enumerate(value)
        total = len(value)
        for i, (k, v) in enumerate(entries):
            if i >= MAX_CHILDREN:
                self.tree.insert(item, "end", text=f"… {total - i} more", values=("(truncated)",))
                break
            self._add(item, k, v)

    def _expand(self, item):
        if item not in self.lazy:
            return
        self.lazy.discard(item)
        self.tree.delete(*self.tree.get_children(item))  # remove the placeholder
        self._populate_children(item, self.data[item])

    def on_expand(self, event):
        self._expand(self.tree.focus())

    def _collapse_all(self):
        def walk(item):
            self.tree.item(item, open=False)
            for child in self.tree.get_children(item):
                walk(child)

        for item in self.tree.get_children(""):
            walk(item)

    # -- detail pane (bounded) ---------------------------------------------------
    def on_select(self, event):
        selection = self.tree.selection()
        if not selection:
            return
        self._set_detail(self._render_detail(self.data.get(selection[0])))

    def _render_detail(self, value):
        if isinstance(value, (dict, list)):
            if _bounded_count(value, FULL_DUMP_LIMIT) <= FULL_DUMP_LIMIT:
                return json.dumps(value, indent=2, ensure_ascii=False, default=str)
            kind = "dict" if isinstance(value, dict) else "list"
            lines = [f"{kind} with {len(value)} entries (too large to dump — drill into the tree):", ""]
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

    def _set_detail(self, text):
        self.detail.config(state=tk.NORMAL)
        self.detail.delete("1.0", tk.END)
        self.detail.insert("1.0", text)
        self.detail.config(state=tk.DISABLED)

    # -- menu actions ------------------------------------------------------------
    def on_open(self):
        initial = os.path.dirname(self.path) if self.path else os.path.dirname(DEFAULT_REPORT)
        path = filedialog.askopenfilename(
            title="Open CAPEsolo report",
            initialdir=initial,
            initialfile="report.json",
            filetypes=[("JSON report", "*.json"), ("All files", "*.*")],
        )
        if path:
            self.load(path)

    def on_reload(self):
        if self.path:
            self.load(self.path)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else None
    root = tk.Tk()
    ReportViewer(root, path)
    root.mainloop()


if __name__ == "__main__":
    main()
