import textwrap
from pathlib import Path

import wx
import wx.grid as gridlib

from .custom_grid import CopyableGrid
from .key_event import KeyEventHandlerMixin
from CAPEsolo.capelib.behavior import BehaviorAnalysis
from CAPEsolo.capelib.utils import convert_to_printable


BACKGNDCLR = {
    "filesystem": (255, 227, 197),
    "registry": (255, 197, 197),
    "process": (197, 224, 255),
    "threading": (211, 224, 255),
    "services": (204, 197, 255),
    "device": (211, 197, 204),
    "network": (211, 255, 197),
    "socket": (211, 255, 197),
    "synchronization": (249, 197, 255),
    "browser": (223, 255, 223),
    "crypto": (240, 242, 197),
    "system": (255, 252, 197),
    "hooking": (240, 240, 240),
    "misc": (200, 200, 200),
    "all": (255, 255, 255),
}


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
        self.InitUI()

    def InitUI(self):
        vbox = wx.BoxSizer(wx.VERTICAL)

        vbox.AddSpacer(10)
        self.behaviorButton = wx.Button(self, label="Generate Behavior Results")
        self.behaviorButton.Bind(wx.EVT_BUTTON, self.GenerateBehavior)
        self.behaviorButton.Disable()
        vbox.Add(self.behaviorButton, proportion=0, border=5)

        self.hbox = wx.BoxSizer(wx.HORIZONTAL)
        self.categoryDropdown = wx.ComboBox(self, style=wx.CB_READONLY)
        self.hbox.Add(
            self.categoryDropdown, proportion=1, flag=wx.EXPAND | wx.RIGHT, border=5
        )
        self.categoryDropdown.Bind(wx.EVT_COMBOBOX, self.OnCatView)
        vbox.Add(
            wx.StaticText(self, label="Categories:"), flag=wx.LEFT | wx.TOP, border=5
        )
        vbox.Add(self.hbox, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=5)
        self.hbox2 = wx.BoxSizer(wx.HORIZONTAL)
        self.processDropdown = wx.ComboBox(self, style=wx.CB_READONLY)
        self.hbox2.Add(
            self.processDropdown, proportion=1, flag=wx.EXPAND | wx.RIGHT, border=5
        )
        self.processDropdown.Bind(wx.EVT_COMBOBOX, self.OnProcView)
        vbox.Add(
            wx.StaticText(self, label="Processes:"), flag=wx.LEFT | wx.TOP, border=5
        )
        vbox.Add(self.hbox2, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=5)

        self.resultsWindow = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY)
        vbox.Add(
            self.resultsWindow,
            proportion=1,
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=5,
        )
        vbox.Add(wx.StaticText(self, label="Calls:"), flag=wx.LEFT | wx.TOP, border=5)

        collapsePane = wx.CollapsiblePane(self, label="API Categories")
        collapsePane.Bind(wx.EVT_COLLAPSIBLEPANE_CHANGED, self.onPaneChanged)
        vbox.Add(collapsePane, 0, wx.ALL | wx.EXPAND, 5)

        pane = collapsePane.GetPane()
        paneBox = wx.BoxSizer(wx.VERTICAL)

        panehBox1 = wx.BoxSizer(wx.HORIZONTAL)

        self.tid = wx.TextCtrl(pane, size=(100, -1), style=wx.TE_PROCESS_ENTER)
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

        apiButtonFont = wx.Font(
            8, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL
        )

        for key, rgbColor in BACKGNDCLR.items():
            apiButton = wx.Button(pane, label=key)
            apiButton.SetBackgroundColour(wx.Colour(rgbColor))
            apiButton.SetFont(apiButtonFont)
            apiButton.Bind(wx.EVT_BUTTON, self.onApiCategoryClick)
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

        self.grid.SetColAttr(4, attr.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE))
        self.grid.SetColAttr(8, attr.SetAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE))
        self.grid.SetRowLabelSize(0)
        self.grid.EnableEditing(False)

        self.grid.Hide()
        vbox.Add(
            self.grid,
            proportion=1,
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=5,
        )

        self.SetSizer(vbox)
        vbox.Fit(self)

    def OnTidFilterButtonClick(self, event):
        self.filterKey = "thread_id"
        self.AddTableData(filter=self.tid.GetValue())

    def OnApiFilterButtonClick(self, event):
        self.filterKey = "api"
        self.AddTableData(filter=self.api.GetValue())

    def onPaneChanged(self, event):
        self.Layout()

    def onApiCategoryClick(self, event):
        button = event.GetEventObject()
        category = button.GetLabel()
        self.AddTableData(category)

    def UpdateGenerateButtonState(self):
        logsDir = Path(self.analysisDir) / "logs"
        if logsDir.exists() and any(logsDir.iterdir()) and not self.behaviorComplete:
            self.behaviorButton.Enable()
        else:
            self.behaviorButton.Disable()

    def GenerateBehavior(self, event):
        options = Options()
        options.analysis_call_limit = 0
        options.ram_boost = True
        behavior = BehaviorAnalysis()
        behavior.set_path(self.analysisDir)
        behavior.set_options(options)
        self.results["behavior"] = behavior.run()
        self.LoadResultCategories()
        self.LoadResultProcesses()
        self.behaviorButton.Disable()
        self.tidButton.Enable()
        self.apiFilterButton.Enable()
        self.behaviorComplete = True

    def LoadResultProcesses(self):
        processes = self.results.get("behavior", {}).get("processes", [])
        self.processDropdown.Append("<Select process>")
        self.processDropdown.SetSelection(0)
        for process in processes:
            proc = (
                f'{process.get("process_id", "")}:{process.get("process_name", None)}'
            )
            self.processDropdown.Append(proc)

    def LoadResultCategories(self):
        categories = self.results.get("behavior", {}).keys()
        self.categoryDropdown.Append("<Select category>")
        self.categoryDropdown.SetSelection(0)
        for category in categories:
            if "processes" not in category:
                self.categoryDropdown.Append(category)

    def OnCatView(self, event):
        selectedCategory = self.categoryDropdown.GetValue()
        if not selectedCategory or selectedCategory == "<Select process>":
            wx.MessageBox(
                "Please select a category dropdown.",
                "No Category Selected",
                wx.OK | wx.ICON_WARNING,
            )
            return
        results = self.GetCatBehavior(selectedCategory)
        self.Display(results, selectedCategory)
        if isinstance(self.GetParent(), wx.Frame):
            self.GetParent().Fit()
            self.GetParent().Layout()

    def OnProcView(self, event):
        selectedProcess = self.processDropdown.GetValue()
        if not selectedProcess or selectedProcess == "<Select process>":
            wx.MessageBox(
                "Please select a process dropdown.",
                "No Process Selected",
                wx.OK | wx.ICON_WARNING,
            )
            return
        results = self.GetProcBehavior(selectedProcess)
        self.Display(results, "process")

    def GetCatBehavior(self, category):
        results = self.results.get("behavior", {}).get(category) or "No results"
        return results

    def GetProcBehavior(self, process):
        pid = process.split(":")[0]
        for proc in self.results.get("behavior", {}).get("processes", []):
            if int(pid) == proc.get("process_id"):
                return proc

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
            self.grid.Show()
            self.Layout()
            self.ViewProcess(data)
            self.ApplyAlternateRowShading()
        elif dataType == "processtree":
            height = 15 * self.resultsWindow.GetCharHeight()
            self.resultsWindow.SetSizeHints(-1, -1, -1, height)
            self.ViewProcessTree(data)
        else:
            height = 15 * self.resultsWindow.GetCharHeight()
            self.resultsWindow.SetSizeHints(-1, -1, -1, height)
            self.resultsWindow.SetValue(self.ViewData(data))

    def GetCmdLine(self, cmdline, modulepath):
        if cmdline.startswith('"'):
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

    def PrintProcessTree(self, processes, indent=0):
        processInfo = ""
        for process in processes:
            modulepath = process.get("module_path", "")
            cmdline = process.get("environ", {}).get("CommandLine", "")
            if cmdline:
                cmdline = self.GetCmdLine(cmdline, modulepath)
            processInfo += f'{" " * indent}\u2022 {process.get("name")} {process.get("pid")} {cmdline}\n'
            for child in process.get("children", []):
                processInfo += self.PrintProcessTree([child], indent + 4)

        return processInfo

    def ViewProcessTree(self, data):
        output = self.PrintProcessTree(data)
        self.resultsWindow.SetValue(output)

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
            for _, call in enumerate(data.get("calls", [])):
                mycalls.append(call)
        except Exception:
            return

        self.mycalls = mycalls

        self.AddTableData()

    def ClearGrid(self):
        self.grid.ClearGrid()
        rows = self.grid.GetNumberRows()
        if rows > 0:
            self.grid.DeleteRows(0, rows)

    def AddTableData(self, category="all", filter=""):
        if filter:
            mycalls = self.GetCallsFilter(filter)
        else:
            mycalls = self.GetCalls(category)
        self.ClearGrid()

        for i, call in enumerate(mycalls):
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
        lightGrey = wx.Colour(240, 240, 240)

        for row in range(numRows):
            if row % 2 == 0:
                attr = gridlib.GridCellAttr()
                attr.SetBackgroundColour(lightGrey)
                self.grid.SetRowAttr(row, attr)
        self.grid.ForceRefresh()

    def GetCalls(self, category):
        if category == "all":
            return self.mycalls
        return [
            d for d in self.mycalls if "category" in d and d["category"] == category
        ]

    def GetCallsFilter(self, value):
        key = self.filterKey
        return [d for d in self.mycalls if key in d and d[key].lower() == value.lower()]
