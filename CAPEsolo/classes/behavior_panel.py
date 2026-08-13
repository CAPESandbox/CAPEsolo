import textwrap
from pathlib import Path

import wx
import wx.grid as gridlib

from CAPEsolo.capelib.behavior import BehaviorAnalysis
from CAPEsolo.capelib.utils import convert_to_printable

from .custom_grid import CopyableGrid
from .key_event import KeyEventHandlerMixin
from .theme import FONT_CODE, GRID_ROW_ALT, apply_theme, BEHAVIOR_CATEGORY_COLORS

BACKGNDCLR = BEHAVIOR_CATEGORY_COLORS

CATEGORY_ROW_CAP = 5000       # cap on rows shown in a behavior-category grid
CATEGORY_DETAIL_CAP = 8000    # cap on chars shown in the category detail pane


class Options:
    def __init__(self):
        self.analysis_call_limit = None
        self.ram_boost = None


class BehaviorPanel(wx.Panel, KeyEventHandlerMixin):
    def __init__(self, parent):
        super(BehaviorPanel, self).__init__(parent)
        self.analysisDir = parent.analysisDir
        self.results = parent.results
        self.BindKeyEvents()
        self.behaviorComplete = False
        self.mycalls = []
        self.filter = ""
        self.category = "all"
        self.numcalls = 0
        self.current_page = 1
        self.items_per_page = 100
        self.InitUI()

    def InitUI(self):
        vbox = wx.BoxSizer(wx.VERTICAL)

        vbox.AddSpacer(10)
        self.behaviorButton = wx.Button(self, label="Generate Behavior Results")
        self.behaviorButton.Bind(wx.EVT_BUTTON, self.GenerateBehavior)
        self.behaviorButton.Disable()
        vbox.Add(self.behaviorButton, proportion=0, border=5)

        self.categoryPane = wx.CollapsiblePane(self, label="Behavior Categories")
        self.categoryPane.Bind(
            wx.EVT_COLLAPSIBLEPANE_CHANGED, self.OnCategoryPaneChanged
        )
        vbox.Add(
            self.categoryPane, 0, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=5
        )
        catPane = self.categoryPane.GetPane()
        catBox = wx.BoxSizer(wx.VERTICAL)
        self.categoryDropdown = wx.ComboBox(catPane, style=wx.CB_READONLY)
        self.categoryDropdown.Bind(wx.EVT_COMBOBOX, self.OnCatView)
        catBox.Add(self.categoryDropdown, 0, flag=wx.EXPAND | wx.ALL, border=5)
        # Columns are set per category at render time; a selected row's full record shows in
        # the detail pane below (long registry content / decrypted buffers do not fit a cell).
        self.categoryGrid = CopyableGrid(catPane, 0, 0)
        self.categoryGrid.SetRowLabelSize(0)
        self.categoryGrid.EnableEditing(False)
        self.categoryGrid.SetMinSize((-1, 250))
        self.categoryGrid.Bind(gridlib.EVT_GRID_SELECT_CELL, self.OnCategoryRowSelect)
        catBox.Add(self.categoryGrid, 1, flag=wx.EXPAND | wx.ALL, border=5)
        self.categoryDetail = wx.TextCtrl(
            catPane, style=wx.TE_MULTILINE | wx.TE_READONLY
        )
        self.categoryDetail.SetMinSize((-1, 120))
        self.categoryDetail.SetValue("Select a category to view its data.")
        catBox.Add(self.categoryDetail, 0, flag=wx.EXPAND | wx.ALL, border=5)
        catPane.SetSizer(catBox)
        # Full source record per grid row, parallel to the rows, for the detail pane.
        self._categoryRows = []

        self.procTreePane = wx.CollapsiblePane(self, label="Process Tree")
        self.procTreePane.Bind(
            wx.EVT_COLLAPSIBLEPANE_CHANGED, self.OnProcTreePaneChanged
        )
        vbox.Add(
            self.procTreePane, 0, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=5
        )
        treePane = self.procTreePane.GetPane()
        treeBox = wx.BoxSizer(wx.VERTICAL)
        self.procTree = wx.TreeCtrl(
            treePane,
            style=wx.TR_DEFAULT_STYLE
            | wx.TR_HIDE_ROOT
            | wx.TR_HAS_BUTTONS
            | wx.TR_LINES_AT_ROOT,
        )
        self.procTree.SetMinSize((-1, 200))
        self.procTree.Bind(wx.EVT_TREE_SEL_CHANGED, self.OnProcTreeSelect)
        self.procTree.Bind(wx.EVT_TREE_ITEM_GETTOOLTIP, self.OnProcTreeTooltip)
        treeBox.Add(self.procTree, 1, flag=wx.EXPAND | wx.ALL, border=5)
        treePane.SetSizer(treeBox)

        self.resultsWindow = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY)
        vbox.Add(
            self.resultsWindow,
            proportion=1,
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=5,
        )
        vbox.Add(wx.StaticText(self, label="Calls:"), flag=wx.LEFT | wx.TOP, border=5)

        collapsePane = wx.CollapsiblePane(self, label="API Categories")
        collapsePane.Bind(wx.EVT_COLLAPSIBLEPANE_CHANGED, self.OnPaneChanged)
        vbox.Add(collapsePane, 0, wx.ALL | wx.EXPAND, 5)

        pane = collapsePane.GetPane()
        paneBox = wx.BoxSizer(wx.VERTICAL)

        panehBox1 = wx.BoxSizer(wx.HORIZONTAL)

        self.tid = wx.TextCtrl(pane, size=wx.Size(100, -1), style=wx.TE_PROCESS_ENTER)
        self.tidButton = wx.Button(pane, label="Filter Thread ID")
        self.tidButton.Bind(wx.EVT_BUTTON, self.OnTidFilterButtonClick)

        self.api = wx.TextCtrl(pane, style=wx.TE_PROCESS_ENTER)
        self.apiFilterButton = wx.Button(pane, label="Filter API")
        self.apiFilterButton.Bind(wx.EVT_BUTTON, self.OnApiFilterButtonClick)

        panehBox1.Add(self.tid, flag=wx.ALL, border=5)
        panehBox1.Add(self.tidButton, flag=wx.ALL, border=5)
        self.tidButton.Disable()

        panehBox1.Add(self.api, proportion=1, flag=wx.EXPAND | wx.ALL, border=5)
        panehBox1.Add(self.apiFilterButton, flag=wx.ALL, border=5)
        self.apiFilterButton.Disable()

        panehBox2 = wx.WrapSizer(wx.HORIZONTAL)

        apiButtonFont = FONT_CODE

        for key, rgbColor in BACKGNDCLR.items():
            apiButton = wx.Button(pane, label=key)
            apiButton.SetBackgroundColour(wx.Colour(rgbColor))
            apiButton.SetFont(apiButtonFont)
            apiButton.Bind(wx.EVT_BUTTON, self.OnApiCategoryClick)
            panehBox2.Add(apiButton, 0, wx.ALL, 5)

        paneBox.Add(panehBox1, flag=wx.EXPAND | wx.ALL, border=5)
        paneBox.Add(panehBox2, flag=wx.EXPAND | wx.ALL, border=5)

        pane.SetSizer(paneBox)
        paneBox.Layout()

        self.grid = CopyableGrid(self, 0, 8)
        columnLabels = [
            "Time",
            "TID",
            "Caller",
            "API",
            "Arguments",
            "Status",
            "Return",
            "Repeated",
        ]
        for i, label in enumerate(columnLabels):
            self.grid.SetColLabelValue(i, label)
            self.grid.SetColLabelAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)

        for col in range(self.grid.GetNumberCols()):
            attr = gridlib.GridCellAttr()
            attr.SetAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)
            self.grid.SetColAttr(col, attr)

        argsAttr = gridlib.GridCellAttr()
        argsAttr.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE)
        self.grid.SetColAttr(4, argsAttr)
        self.grid.SetRowLabelSize(0)
        self.grid.EnableEditing(False)

        self.grid.Hide()
        vbox.Add(
            self.grid,
            proportion=1,
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=5,
        )

        self.pagination_sizer = wx.BoxSizer(wx.HORIZONTAL)

        self.first_page_button = wx.Button(self, label="<<")
        self.first_page_button.Bind(wx.EVT_BUTTON, self.OnFirstPage)
        self.first_page_button.Disable()
        self.pagination_sizer.Add(self.first_page_button, 0, wx.ALL, 5)

        self.prev_button = wx.Button(self, label="Previous")
        self.prev_button.Bind(wx.EVT_BUTTON, self.OnPrevPage)
        self.prev_button.Disable()
        self.pagination_sizer.Add(self.prev_button, 0, wx.ALL, 5)

        self.page_label = wx.StaticText(self, label="Page 1 of 1")
        self.pagination_sizer.Add(self.page_label, 0, wx.ALL | wx.CENTER, 5)

        self.page_input = wx.TextCtrl(
            self, value="1", size=wx.Size(50, -1), style=wx.TE_PROCESS_ENTER
        )
        self.page_input.Bind(wx.EVT_TEXT_ENTER, self.OnGoToPage)
        self.pagination_sizer.Add(self.page_input, 0, wx.ALL, 5)

        self.go_button = wx.Button(self, label="Go")
        self.go_button.Bind(wx.EVT_BUTTON, self.OnGoToPage)
        self.pagination_sizer.Add(self.go_button, 0, wx.ALL, 5)

        self.next_button = wx.Button(self, label="Next")
        self.next_button.Bind(wx.EVT_BUTTON, self.OnNextPage)
        self.next_button.Disable()
        self.pagination_sizer.Add(self.next_button, 0, wx.ALL, 5)

        self.last_page_button = wx.Button(self, label=">>")
        self.last_page_button.Bind(wx.EVT_BUTTON, self.OnLastPage)
        self.last_page_button.Disable()
        self.pagination_sizer.Add(self.last_page_button, 0, wx.ALL, 5)

        self.items_per_page_choices = [25, 50, 100, 500, 1000, 10000]
        self.items_per_page_dropdown = wx.ComboBox(
            self, value=str(self.items_per_page), choices=[str(c) for c in self.items_per_page_choices], style=wx.CB_READONLY
        )
        self.items_per_page_dropdown.Bind(wx.EVT_COMBOBOX, self.OnItemsPerPageChange)
        self.pagination_sizer.Add(
            wx.StaticText(self, label="Calls per page:"), 0, wx.ALL | wx.CENTER, 5
        )
        self.pagination_sizer.Add(self.items_per_page_dropdown, 0, wx.ALL, 5)

        self.max_button = wx.Button(self, label="Max")
        self.max_button.Bind(wx.EVT_BUTTON, self.OnMax)
        self.pagination_sizer.Add(self.max_button, 0, wx.ALL, 5)

        vbox.Add(self.pagination_sizer, 0, wx.CENTER | wx.BOTTOM, 5)
        self.pagination_sizer.Hide(True)

        self.SetSizer(vbox)
        vbox.Fit(self)
        # CollapsiblePanes start collapsed. Show the Process Tree by default and keep Behavior
        # Categories collapsed; the two form an accordion. Set both states explicitly -
        # programmatic Collapse() does not fire EVT_COLLAPSIBLEPANE_CHANGED.
        self.categoryPane.Collapse(True)
        self.procTreePane.Collapse(False)
        self.Layout()
        apply_theme(self)

    def OnMax(self, event):
        self.items_per_page = self.numcalls
        self.current_page = 1
        self.AddTableData()

    def OnTidFilterButtonClick(self, event):
        self.filterKey = "thread_id"
        self.filter = self.tid.GetValue()
        self.AddTableData()

    def OnApiFilterButtonClick(self, event):
        self.filterKey = "api"
        self.filter = self.api.GetValue()
        self.AddTableData()

    def OnPaneChanged(self, event):
        self.Layout()

    def OnApiCategoryClick(self, event):
        button = event.GetEventObject()
        self.category = button.GetLabel()
        self.AddTableData()

    def UpdateGenerateButtonState(self):
        logsDir = Path(self.analysisDir) / "logs"
        if logsDir.exists() and any(logsDir.iterdir()) and not self.behaviorComplete:
            self.behaviorButton.Enable()
        else:
            self.behaviorButton.Disable()

    def GenerateBehavior(self, event):
        # A busy cursor rather than a PD_APP_MODAL wx.ProgressDialog. The dialog had no
        # try/finally, so a failure in behavior.run() left an app-modal window on screen
        # that could never be dismissed. It also only ever reported 0% and 100%, so no
        # real progress information is lost. Matches PayloadsPanel.PayloadsReady.
        with wx.BusyCursor():
            options = Options()
            options.analysis_call_limit = 0
            options.ram_boost = True
            behavior = BehaviorAnalysis()
            behavior.set_path(self.analysisDir)
            behavior.set_options(options)
            self.results["behavior"] = behavior.run()
            self.LoadResultCategories()
            self.BuildProcessTree()
            self.behaviorButton.Disable()

        self.tidButton.Enable()
        self.apiFilterButton.Enable()
        self.behaviorComplete = True

    def BuildProcessTree(self):
        # Guard the selection handler: DeleteAllItems fires EVT_TREE_SEL_CHANGED with an
        # invalid item on MSW, which would otherwise run mid-rebuild.
        self._buildingTree = True
        try:
            self.procTree.DeleteAllItems()
            root = self.procTree.AddRoot("Processes")
            tree = self.results.get("behavior", {}).get("processtree", [])
            self._AddProcNodes(root, tree)
        finally:
            self._buildingTree = False
        # Select the first top-level process so the details and call grid populate on load,
        # the way the pre-selected "processtree" category used to fill the panel. Drive the
        # display directly rather than via the selection event: appending the first item can
        # auto-select it on MSW, so an explicit SelectItem may not fire EVT_TREE_SEL_CHANGED.
        firstChild, _ = self.procTree.GetFirstChild(self.procTree.GetRootItem())
        if firstChild.IsOk():
            self.procTree.SelectItem(firstChild)
            node = self.procTree.GetItemData(firstChild)
            if node:
                self._ShowProcNode(node)

    def _AddProcNodes(self, parentItem, nodes):
        for node in nodes or []:
            item = self.procTree.AppendItem(
                parentItem, f'{node.get("name")} ({node.get("pid")})'
            )
            self.procTree.SetItemData(item, node)
            self._AddProcNodes(item, node.get("children", []))
            # Only real nodes are expanded; expanding the hidden root raises on wx.
            self.procTree.Expand(item)

    def OnProcTreePaneChanged(self, event):
        # Accordion: expanding the Process Tree collapses Behavior Categories. Programmatic
        # Collapse() fires no event, and the IsExpanded() guard makes this recursion-proof.
        if self.procTreePane.IsExpanded():
            self.categoryPane.Collapse(True)
        self.Layout()

    def OnCategoryPaneChanged(self, event):
        if self.categoryPane.IsExpanded():
            self.procTreePane.Collapse(True)
        self.Layout()

    def OnProcTreeTooltip(self, event):
        node = self.procTree.GetItemData(event.GetItem())
        if not node:
            return
        modulepath = node.get("module_path", "") or ""
        cmdline = node.get("environ", {}).get("CommandLine", "")
        if cmdline:
            cmdline = self.GetCmdLine(cmdline, modulepath)
        if modulepath and cmdline:
            event.SetToolTip(f"{modulepath}\n{cmdline}")
        elif modulepath or cmdline:
            event.SetToolTip(modulepath or cmdline)

    def OnProcTreeSelect(self, event):
        if getattr(self, "_buildingTree", False):
            return
        item = event.GetItem()
        if not item.IsOk():
            return
        node = self.procTree.GetItemData(item)
        if node:
            self._ShowProcNode(node)

    def _ShowProcNode(self, node):
        proc = self.GetProcBehavior(node.get("pid"))
        if proc is None:
            # A process seen only in the tree (e.g. a parent with no logged calls): show what
            # the node carries and leave the call grid empty.
            proc = {
                "process_id": node.get("pid"),
                "process_name": node.get("name"),
                "parent_id": node.get("parent_id"),
                "module_path": node.get("module_path"),
                "calls": [],
            }
        self.Display(proc, "process")

    def LoadResultCategories(self):
        categories = self.results.get("behavior", {}).keys()
        self.categoryDropdown.Append("<Select category>")
        self.categoryDropdown.SetSelection(0)
        # "processtree" now has its own tree widget; "processes" is the raw per-process list.
        for category in categories:
            if category not in ("processes", "processtree"):
                self.categoryDropdown.Append(category)

    def OnCatView(self, event):
        selectedCategory = self.categoryDropdown.GetValue()
        # LoadResultCategories inserts "<Select category>"; comparing against the process
        # placeholder meant this guard never fired and the placeholder was looked up as if
        # it were a real category, silently displaying "No results".
        if not selectedCategory or selectedCategory == "<Select category>":
            wx.MessageBox(
                "Please select a category dropdown.",
                "No Category Selected",
                wx.OK | wx.ICON_WARNING,
            )
            return
        results = self.GetCatBehavior(selectedCategory)
        # Category output has its own grid + detail pane, decoupled from process details.
        self.BuildCategoryView(selectedCategory, results)
        self.Layout()

    def GetCatBehavior(self, category):
        results = self.results.get("behavior", {}).get(category) or "No results"
        return results

    @staticmethod
    def _CategoryCell(value):
        # Collapse whitespace and strip NULs (a raw NUL silently truncates a native grid cell,
        # like network_panel does), and clamp the cell; the full value is in the detail pane.
        if value is None:
            return ""
        return " ".join(str(value).split()).replace("\x00", "")[:512]

    def _CategoryRows(self, category, data):
        """Return (columns, rows, records) for a category, or (None, [], []) for a text dump.

        columns: list of (label, width); rows: list of pre-cleaned cell lists; records: the full
        source object per row, for the detail pane.
        """
        cell = self._CategoryCell
        if category == "summary" and isinstance(data, dict):
            cols = [("Type", 160), ("Value", 820)]
            rows, records = [], []
            for key, items in data.items():
                for item in items or []:
                    rows.append([cell(key), cell(item)])
                    records.append({key: item})
            return cols, rows, records
        if category == "enhanced" and isinstance(data, list):
            cols = [("Time", 170), ("Event", 90), ("Object", 100), ("Details", 700)]
            rows, records = [], []
            for e in data:
                d = e.get("data") or {}
                details = "; ".join(f"{k}={v}" for k, v in d.items() if v is not None)
                rows.append(
                    [cell(e.get("timestamp")), cell(e.get("event")), cell(e.get("object")), cell(details)]
                )
                records.append(e)
            return cols, rows, records
        if category == "encryptedbuffers" and isinstance(data, list):
            cols = [("Process", 160), ("PID", 60), ("API", 150), ("Info", 90), ("Buffer", 600)]
            rows, records = [], []
            for e in data:
                info = e.get("buffer_size") or e.get("crypt_key") or ""
                rows.append(
                    [cell(e.get("process_name")), cell(e.get("pid")), cell(e.get("api_call")),
                     cell(info), cell(e.get("buffer"))]
                )
                records.append(e)
            return cols, rows, records
        if category == "anomaly" and isinstance(data, list):
            cols = [("Process", 160), ("PID", 60), ("Category", 120), ("Function", 160), ("Message", 500)]
            rows, records = [], []
            for e in data:
                rows.append(
                    [cell(e.get("name")), cell(e.get("pid")), cell(e.get("category")),
                     cell(e.get("funcname")), cell(e.get("message"))]
                )
                records.append(e)
            return cols, rows, records
        # Generic fallbacks for any future category.
        if isinstance(data, dict):
            cols = [("Type", 160), ("Value", 820)]
            rows, records = [], []
            for key, val in data.items():
                for item in (val if isinstance(val, list) else [val]):
                    rows.append([cell(key), cell(item)])
                    records.append({key: item})
            return cols, rows, records
        if isinstance(data, list) and data and isinstance(data[0], dict):
            keys = list(data[0].keys())
            cols = [(k, 200) for k in keys]
            rows, records = [], []
            for e in data:
                rows.append([cell(e.get(k)) for k in keys])
                records.append(e)
            return cols, rows, records
        return None, [], []

    def _ResetCategoryGrid(self, columns):
        grid = self.categoryGrid
        if grid.GetNumberRows() > 0:
            grid.DeleteRows(0, grid.GetNumberRows())
        cur = grid.GetNumberCols()
        need = len(columns)
        if need > cur:
            grid.AppendCols(need - cur)
        elif need < cur:
            grid.DeleteCols(need, cur - need)
        for col, (label, width) in enumerate(columns):
            grid.SetColLabelValue(col, label)
            grid.SetColSize(col, width)

    def _ShadeCategoryGrid(self):
        for row in range(self.categoryGrid.GetNumberRows()):
            if row % 2 == 0:
                attr = gridlib.GridCellAttr()
                attr.SetBackgroundColour(GRID_ROW_ALT)
                self.categoryGrid.SetRowAttr(row, attr)
        self.categoryGrid.ForceRefresh()

    def _SetCategoryDetail(self, text):
        text = str(text).replace("\x00", "")
        if len(text) > CATEGORY_DETAIL_CAP:
            text = text[:CATEGORY_DETAIL_CAP] + f"\n... [truncated, {len(text)} chars total] ..."
        self.categoryDetail.SetValue(text)

    def BuildCategoryView(self, category, data):
        # Cleared first so a stale record cannot be read if a select event fires mid-rebuild.
        self._categoryRows = []
        columns, rows, records = self._CategoryRows(category, data)
        if columns is None:
            self._ResetCategoryGrid([])
            self._SetCategoryDetail(self.ViewData(data))
            return
        self._ResetCategoryGrid(columns)
        total = len(rows)
        rows = rows[:CATEGORY_ROW_CAP]
        records = records[:CATEGORY_ROW_CAP]
        if rows:
            self.categoryGrid.AppendRows(len(rows))
            for r, row in enumerate(rows):
                for c, value in enumerate(row):
                    self.categoryGrid.SetCellValue(r, c, value)
        self._categoryRows = records
        self._ShadeCategoryGrid()
        if not total:
            self._SetCategoryDetail("No entries for this category.")
        elif total > CATEGORY_ROW_CAP:
            self._SetCategoryDetail(
                f"Showing first {CATEGORY_ROW_CAP} of {total} entries. Select a row for details."
            )
        else:
            self._SetCategoryDetail("Select a row for details.")

    def OnCategoryRowSelect(self, event):
        row = event.GetRow()
        if 0 <= row < len(self._categoryRows):
            self._SetCategoryDetail(self.ViewData(self._categoryRows[row]))
        event.Skip()

    def GetProcBehavior(self, pid):
        for proc in self.results.get("behavior", {}).get("processes", []):
            if pid == proc.get("process_id"):
                return proc
        return None

    def ViewData(self, data, indent=0, depthLimit=10):
        lines = []
        prefix = " " * indent

        if depthLimit <= 0:
            lines.append(f"{prefix}...")
            return "\n".join(lines)

        if isinstance(data, dict):
            for key, value in data.items():
                lines.append(f"{prefix}{key}:")
                lines.extend(
                    self.ViewData(value, indent + 4, depthLimit - 1).splitlines()
                )
        elif isinstance(data, list):
            for item in data:
                lines.extend(
                    self.ViewData(item, indent + 4, depthLimit - 1).splitlines()
                )
        elif isinstance(data, bytes):
            try:
                decoded = data.decode("utf-8")
                lines.append(f"{prefix}Binary String: '{decoded}'")
            except UnicodeDecodeError:
                lines.append(f"{prefix}Binary String: <binary data>")
        else:
            lines.append(f"{prefix}{data}")

        return "\n".join(lines)

    def GetArguments(self, data):
        args = []
        argsdata = data.get("arguments", [])
        for arg in argsdata:
            raw = arg.get("value")
            if isinstance(raw, str):
                if len(raw) > 64:
                    raw = "\n".join(
                        textwrap.wrap(
                            raw,
                            width=64,
                            break_long_words=True,
                            replace_whitespace=False,
                        )
                    )
            args.append(f' {arg.get("name")}: {raw}')
        return args

    def Display(self, data, dataType):
        if dataType == "process":
            height = 5 * self.resultsWindow.GetCharHeight()
            self.resultsWindow.SetSizeHints(-1, -1, -1, height)
            self.resultsWindow.SetMinSize((1, height))
            self.pagination_sizer.Show(True)
            self.grid.Show()
            self.Layout()
            self.ViewProcess(data)
            self.ApplyAlternateRowShading()

    def GetCmdLine(self, cmdline, modulepath):
        if cmdline.startswith('"') and '"' in cmdline[1:]:
            splitcmdline = cmdline[cmdline[1:].index('"') + 2 :].split()
            argv0 = cmdline[: cmdline[1:].index('"') + 1].lower()
            if modulepath.lower() in argv0:
                cmdline = " ".join(splitcmdline).strip()
        elif cmdline:
            splitcmdline = cmdline.split()
            if splitcmdline:
                argv0 = splitcmdline[0].lower()
                if modulepath.lower() in argv0:
                    cmdline = " ".join(splitcmdline[1:]).strip()
        if len(cmdline) >= 200 + 15:
            cmdline = cmdline[:200] + " ...(truncated)"

        return convert_to_printable(cmdline)

    def ViewProcess(self, data):
        output = [
            f'Process Id: {data.get("process_id")}',
            f'Process Name: {data.get("process_name")}',
            f'Parent Id: {data.get("parent_id")}',
            f'Module Path: {data.get("module_path")}',
        ]
        self.resultsWindow.SetValue("\n".join(output))
        mycalls = []
        try:
            for call in data.get("calls", []):
                mycalls.append(call)
        except Exception:
            return

        self.mycalls = mycalls
        self.current_page = 1
        self.AddTableData()

    def ClearGrid(self):
        self.grid.ClearGrid()
        rows = self.grid.GetNumberRows()
        if rows > 0:
            self.grid.DeleteRows(0, rows)

    def AddTableData(self):
        if self.filter:
            mycalls = self.GetCallsFilter()
        else:
            mycalls = self.GetCalls()

        self.numcalls = len(mycalls)
        self.UpdatePaginationControls()
        self.ClearGrid()

        start_index = (self.current_page - 1) * self.items_per_page
        end_index = start_index + self.items_per_page
        paginated_calls = mycalls[start_index:end_index]

        for i, call in enumerate(paginated_calls):
            category = call.get("category", "none")
            self.grid.AppendRows(1)
            self.grid.SetCellValue(i, 0, call.get("timestamp", ""))
            self.grid.SetCellValue(i, 1, str(call.get("thread_id", "")))

            caller = f'{call.get("parentcaller", "")}\n{call.get("caller", "")}'
            self.grid.SetCellValue(i, 2, caller)

            apiName = call.get("api", "")
            self.grid.SetCellValue(i, 3, apiName)

            args = self.GetArguments(call)
            arguments = "\n".join(args)
            self.grid.SetCellValue(i, 4, arguments)

            status = "Success" if call.get("status", "") else "Failure"
            self.grid.SetCellValue(i, 5, status)

            returnVal = str(call.get("return", ""))
            if call.get("pretty_return", ""):
                returnVal = call.get("pretty_return")

            self.grid.SetCellValue(i, 6, returnVal)
            self.grid.SetCellValue(i, 7, str(call.get("repeated", "")))

            color = wx.Colour(BACKGNDCLR.get(category, (255, 255, 255)))
            self.ApplyBackgroundColor(i, color)

        self.grid.AutoSizeColumns()
        self.grid.AutoSizeRows()

    def ApplyBackgroundColor(self, row, color):
        for col in range(self.grid.GetNumberCols()):
            self.grid.SetCellBackgroundColour(row, col, color)
        self.grid.ForceRefresh()

    def ApplyAlternateRowShading(self):
        numRows = self.grid.GetNumberRows()

        for row in range(numRows):
            if row % 2 == 0:
                attr = gridlib.GridCellAttr()
                attr.SetBackgroundColour(GRID_ROW_ALT)
                self.grid.SetRowAttr(row, attr)
        self.grid.ForceRefresh()

    def GetCalls(self):
        if self.category == "all":
            return self.mycalls
        return [
            d for d in self.mycalls if "category" in d and d["category"] == self.category
        ]

    def GetCallsFilter(self):
        key = self.filterKey
        return [d for d in self.mycalls if key in d and d[key].lower() == self.filter.lower()]

    def UpdatePaginationControls(self):
        total_pages = (self.numcalls + self.items_per_page - 1) // self.items_per_page
        self.page_label.SetLabel(f"Page {self.current_page} of {total_pages}")
        self.first_page_button.Enable(self.current_page > 1)
        self.prev_button.Enable(self.current_page > 1)
        self.next_button.Enable(self.current_page < total_pages)
        self.last_page_button.Enable(self.current_page < total_pages)
        self.page_input.SetValue(str(self.current_page))

        self.Layout()

    def OnPrevPage(self, event):
        if self.current_page > 1:
            self.current_page -= 1
            self.AddTableData()

    def OnNextPage(self, event):
        total_pages = (self.numcalls + self.items_per_page - 1) // self.items_per_page
        if self.current_page < total_pages:
            self.current_page += 1
            self.AddTableData()

    def OnItemsPerPageChange(self, event):
        new_value = int(self.items_per_page_dropdown.GetValue())
        if new_value in self.items_per_page_choices:
            self.items_per_page = new_value
            self.current_page = 1
            self.AddTableData()

    def OnFirstPage(self, event):
        self.current_page = 1
        self.AddTableData()

    def OnLastPage(self, event):
        total_pages = (self.numcalls + self.items_per_page - 1) // self.items_per_page
        self.current_page = total_pages
        self.AddTableData()

    def OnGoToPage(self, event):
        total_pages = (self.numcalls + self.items_per_page - 1) // self.items_per_page
        try:
            page_num = int(self.page_input.GetValue())
            if 1 <= page_num <= total_pages:
                self.current_page = page_num
                self.AddTableData()
            else:
                wx.MessageBox(
                    f"Page number must be between 1 and {total_pages}.",
                    "Invalid Page Number",
                    wx.OK | wx.ICON_ERROR,
                )
        except ValueError:
            wx.MessageBox(
                "Please enter a valid integer page number.",
                "Invalid Input",
                wx.OK | wx.ICON_ERROR
            )
