import json

import wx
import wx.grid as gridlib

from CAPEsolo.capelib.js_log import GetJsLogPath, JsLog
from CAPEsolo.capelib.js_streams import AssembleConversations, AssembleDns, DropExtractedFiles

from CAPEsolo.capelib.path_utils import path_exists

from . import ui_kit as ui
from .custom_grid import CopyableGrid
from .key_event import KeyEventHandlerMixin
from .theme import FONT_CODE, GRID_ROW_ALT, SP_XS, apply_theme, dip

ALL = "<All>"
# Order the kind filter offers; a kind only appears when it has rows.
KIND_ORDER = ("Conversation", "HTTP", "DNS", "Event")
# Events the network views (Conversation/HTTP/DNS rows) already cover; everything else stays an Event row.
NETWORK_EVENTS = {
    "tcp_connect", "tcp_endpoints", "tcp_send", "tcp_receive", "tcp_error",
    "dns_query", "dns_result", "dns_error",
    "http_request", "http_response", "http_error", "http_request_body",
}
BODY_TEXT_CAP = 64 * 1024
INFO_COL_MAX = 520
ADDR_COL_MAX = 240


class JsConsolePanel(wx.Panel, KeyEventHandlerMixin):
    def __init__(self, parent):
        super().__init__(parent)
        self.analysisDir = parent.analysisDir
        self.results = parent.results
        self.BindKeyEvents()
        self.jsLogComplete = False
        self.allRows = []
        self.pageRows = []
        self.category = ALL
        self.numevents = 0
        self.current_page = 1
        self.items_per_page = 100
        self.InitUI()

    def InitUI(self):
        vbox = wx.BoxSizer(wx.VERTICAL)

        vbox.AddSpacer(10)
        self.jsLogButton = ui.Button(self, label="Process JS Log", variant=ui.PRIMARY)
        self.jsLogButton.Bind(wx.EVT_BUTTON, self.ProcessJsLog)
        self.jsLogButton.Disable()
        vbox.Add(self.jsLogButton, proportion=0, flag=wx.ALL, border=dip(self, SP_XS))

        self.categoryDropdown = ui.Picker(self)
        self.categoryDropdown.Bind(wx.EVT_COMBOBOX, self.OnCatView)
        vbox.Add(wx.StaticText(self, label="Show:"), flag=wx.LEFT | wx.TOP, border=dip(self, SP_XS))
        vbox.Add(
            self.categoryDropdown,
            proportion=0,
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=dip(self, SP_XS),
        )

        # Grid over detail pane, matching the Network tab's convention.
        self.splitter = wx.SplitterWindow(self, style=wx.SP_LIVE_UPDATE | wx.SP_3DSASH)
        self.splitter.SetSashGravity(0.6)
        self.splitter.SetMinimumPaneSize(80)

        self.grid = CopyableGrid(self.splitter, 0, 5)
        for col, label in enumerate(("Time", "Kind", "Source", "Destination", "Info")):
            self.grid.SetColLabelValue(col, label)
        self.grid.SetColLabelAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)
        infoAttr = gridlib.GridCellAttr()
        infoAttr.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE)
        self.grid.SetColAttr(4, infoAttr)
        self.grid.SetRowLabelSize(0)
        self.grid.EnableEditing(False)
        self.grid.Bind(gridlib.EVT_GRID_SELECT_CELL, self.OnSelectCell)

        self.resultsWindow = wx.TextCtrl(
            self.splitter, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_RICH2
        )
        self.resultsWindow.SetFont(FONT_CODE)

        self.splitter.SplitHorizontally(self.grid, self.resultsWindow)
        vbox.Add(
            self.splitter,
            proportion=1,
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=dip(self, SP_XS),
        )

        self.pagination_sizer = wx.BoxSizer(wx.HORIZONTAL)

        self.first_page_button = ui.Button(self, label="<<")
        self.first_page_button.Bind(wx.EVT_BUTTON, self.OnFirstPage)
        self.first_page_button.Disable()
        self.pagination_sizer.Add(self.first_page_button, 0, wx.ALL, dip(self, SP_XS))

        self.prev_button = ui.Button(self, label="Previous")
        self.prev_button.Bind(wx.EVT_BUTTON, self.OnPrevPage)
        self.prev_button.Disable()
        self.pagination_sizer.Add(self.prev_button, 0, wx.ALL, dip(self, SP_XS))

        self.page_label = wx.StaticText(self, label="Page 1 of 1")
        self.pagination_sizer.Add(self.page_label, 0, wx.ALL | wx.CENTER, 5)

        self.page_field = ui.Field(
            self, value="1", size=wx.Size(50, -1), style=wx.TE_PROCESS_ENTER
        )
        self.page_input = self.page_field.ctrl
        self.page_input.Bind(wx.EVT_TEXT_ENTER, self.OnGoToPage)
        self.pagination_sizer.Add(self.page_field, 0, wx.ALL, dip(self, SP_XS))

        self.go_button = ui.Button(self, label="Go")
        self.go_button.Bind(wx.EVT_BUTTON, self.OnGoToPage)
        self.pagination_sizer.Add(self.go_button, 0, wx.ALL, dip(self, SP_XS))

        self.next_button = ui.Button(self, label="Next")
        self.next_button.Bind(wx.EVT_BUTTON, self.OnNextPage)
        self.next_button.Disable()
        self.pagination_sizer.Add(self.next_button, 0, wx.ALL, dip(self, SP_XS))

        self.last_page_button = ui.Button(self, label=">>")
        self.last_page_button.Bind(wx.EVT_BUTTON, self.OnLastPage)
        self.last_page_button.Disable()
        self.pagination_sizer.Add(self.last_page_button, 0, wx.ALL, dip(self, SP_XS))

        self.items_per_page_choices = [25, 50, 100, 500, 1000, 10000]
        self.items_per_page_dropdown = ui.Picker(
            self,
            value=str(self.items_per_page),
            choices=[str(c) for c in self.items_per_page_choices],
        )
        self.items_per_page_dropdown.Bind(wx.EVT_COMBOBOX, self.OnItemsPerPageChange)
        self.pagination_sizer.Add(
            wx.StaticText(self, label="Rows per page:"), 0, wx.ALL | wx.CENTER, 5
        )
        self.pagination_sizer.Add(self.items_per_page_dropdown, 0, wx.ALL, dip(self, SP_XS))

        vbox.Add(self.pagination_sizer, 0, wx.CENTER | wx.BOTTOM, 5)
        # ShowItems, not Hide(True): wx.Sizer.Hide is overloaded on index, so the bool
        # resolved to index 1 and hid the Previous button rather than the whole row.
        self.pagination_sizer.ShowItems(False)

        self.SetSizer(vbox)
        apply_theme(self)

    def UpdateProcessButtonState(self):
        if not self.jsLogComplete and path_exists(str(GetJsLogPath(self.analysisDir))):
            self.jsLogButton.Enable()
        else:
            self.jsLogButton.Disable()

    def ProcessJsLog(self, event=None):
        # A busy cursor rather than a progress dialog, matching BehaviorPanel and PayloadsPanel:
        # parsing is a single pass with nothing to report part way. event defaults to None so the
        # auto-process step can call this directly.
        with wx.BusyCursor():
            jslog = JsLog(self.analysisDir)
            self.results["js_log"] = jslog
            conversations, drops = AssembleConversations(jslog, self.analysisDir)
            dnsRows = AssembleDns(jslog)
            newPaths = DropExtractedFiles(self.analysisDir, drops)
            self._LiveAppendPayloads(newPaths)
            self.allRows = (
                conversations
                + self._BuildHttpRows(jslog)
                + dnsRows
                + self._BuildEventRows(jslog)
            )
            self.LoadKindFilter()
            self.pagination_sizer.ShowItems(True)
            self.current_page = 1
            self.AddTableData()
            self.grid.Show()
            self.jsLogButton.Disable()

        self.resultsWindow.SetValue(self.Summarize(jslog, conversations, dnsRows, newPaths))
        self.jsLogComplete = True

    def _LiveAppendPayloads(self, newPaths):
        # Push reconstructed drops into the Payloads and Yara tabs if they are already loaded; both
        # AddPayload methods guard on load state and otherwise defer to their first-open path.
        if not newPaths:
            return
        frame = self.GetTopLevelParent()
        for attr in ("payloadsTab", "yaraTab"):
            panel = getattr(frame, attr, None)
            if panel is None:
                continue
            for rel in newPaths:
                try:
                    panel.AddPayload(rel)
                except Exception:
                    pass

    def Summarize(self, jslog, conversations, dnsRows, newPaths):
        content = f'• {jslog.get("path", "")}\n'
        content += f'\tLines: {jslog.get("total_lines", 0)}\n'
        content += f'\tEvents: {jslog.get("parsed_lines", 0)}\n'
        if jslog.get("malformed_lines", 0):
            content += f'\tMalformed lines: {jslog.get("malformed_lines")}\n'
        content += f"\tConversations: {len(conversations)}\n"
        content += f"\tDNS lookups: {len(dnsRows)}\n"
        if newPaths:
            content += f"\tFiles dropped: {len(newPaths)}\n"
        content += "\nSelect a row to view its detail."
        return content

    # -- row builders -------------------------------------------------------
    def _Body(self, body):
        if isinstance(body, dict):
            return body.get("text") or ""
        if body is None:
            return ""
        return str(body)

    def _FormatHeaders(self, headers):
        if not isinstance(headers, dict):
            return ""
        return "\n".join(f"{k}: {v}" for k, v in headers.items())

    def _BuildHttpRows(self, jslog):
        # Pair http_request with its http_response / http_error by request_id; http_request_body
        # (emitted separately) folds into the request's detail.
        reqs = {r.get("request_id"): r for r in jslog.get("http_requests", [])}
        reqBody = {
            ev.get("request_id"): self._Body(ev.get("body"))
            for ev in jslog.get("events", [])
            if ev.get("event") == "http_request_body"
        }
        rows = []
        seen = set()
        for resp in jslog.get("http_responses", []):
            rid = resp.get("request_id")
            seen.add(rid)
            rows.append(self._HttpRow(reqs.get(rid), resp, None, reqBody.get(rid)))
        for err in jslog.get("http_errors", []):
            rid = err.get("request_id")
            seen.add(rid)
            rows.append(self._HttpRow(reqs.get(rid), None, err, reqBody.get(rid)))
        for rid, req in reqs.items():
            if rid not in seen:
                rows.append(self._HttpRow(req, None, None, reqBody.get(rid)))
        return rows

    def _HttpRow(self, req, resp, err, reqBody):
        req = req or {}
        method = req.get("method", "")
        url = req.get("url", "")
        status = ""
        if resp:
            status = f'{resp.get("status", "")} {resp.get("status_text", "")}'.strip()
        error = err.get("error", "") if err else ""
        info = " ".join(p for p in (method, url, status, error) if p)

        sections = [f"{method} {url}  [{req.get('transport', '')}]".strip()]
        if req.get("headers"):
            sections.append("--- request headers ---\n" + self._FormatHeaders(req["headers"]))
        if reqBody:
            sections.append("--- request body ---\n" + reqBody[:BODY_TEXT_CAP])
        if resp:
            sections.append(f"HTTP {status}")
            if resp.get("headers"):
                sections.append("--- response headers ---\n" + self._FormatHeaders(resp["headers"]))
            respBody = self._Body(resp.get("body"))
            if respBody:
                sections.append("--- response body ---\n" + respBody[:BODY_TEXT_CAP])
        if error:
            sections.append("Error: " + error)

        ts = (resp or err or req).get("ts", "")
        return {
            "kind": "HTTP",
            "ts": ts,
            "src": req.get("transport", ""),
            "dst": url,
            "info": info,
            "detail": "\n\n".join(sections),
        }

    def _BuildEventRows(self, jslog):
        # Everything the network views do not cover (console/init/eval/warning/module_intercept*/
        # socket_*/...) is preserved here exactly as before: a row plus the raw event JSON on select.
        rows = []
        for ev in jslog.get("events", []):
            if ev.get("event") in NETWORK_EVENTS:
                continue
            rows.append(
                {
                    "kind": "Event",
                    "ts": ev.get("ts", ""),
                    "src": ev.get("source", ""),
                    "dst": "",
                    "info": self.EventSummary(ev),
                    "detail": json.dumps(ev, indent=4),
                }
            )
        return rows

    def EventSummary(self, event):
        name = event.get("event", "")
        if name == "console":
            parts = [event.get("level", ""), event.get("message", "")]
        else:
            parts = [
                f"{key}: {value}"
                for key, value in event.items()
                if key not in ("ts", "event", "source")
            ]
        return " ".join(str(part) for part in parts if part)

    # -- kind filter + grid -------------------------------------------------
    def LoadKindFilter(self):
        counts = {}
        for row in self.allRows:
            counts[row["kind"]] = counts.get(row["kind"], 0) + 1

        self.categoryDropdown.Clear()
        self.categoryDropdown.Append(f"{ALL} ({len(self.allRows)})")
        for kind in KIND_ORDER:
            if counts.get(kind):
                self.categoryDropdown.Append(f"{kind} ({counts[kind]})")
        self.categoryDropdown.SetSelection(0)
        self.category = ALL

    def OnCatView(self, event):
        selected = self.categoryDropdown.GetValue()
        # Labels carry a trailing " (count)" that is not part of the kind.
        self.category = selected.rsplit(" (", 1)[0]
        self.current_page = 1
        self.AddTableData()

    def GetRows(self):
        if self.category == ALL:
            return self.allRows
        return [r for r in self.allRows if r["kind"] == self.category]

    def _InfoCell(self, info):
        return " ".join(str(info).split()).replace("\x00", "")[:512]

    def ClearGrid(self):
        self.grid.ClearGrid()
        rows = self.grid.GetNumberRows()
        if rows > 0:
            self.grid.DeleteRows(0, rows)

    def AddTableData(self):
        rows = self.GetRows()
        self.numevents = len(rows)
        self.UpdatePaginationControls()
        self.ClearGrid()

        start_index = (self.current_page - 1) * self.items_per_page
        end_index = start_index + self.items_per_page
        self.pageRows = rows[start_index:end_index]

        for i, row in enumerate(self.pageRows):
            self.grid.AppendRows(1)
            self.grid.SetCellValue(i, 0, str(row.get("ts", "")))
            self.grid.SetCellValue(i, 1, row.get("kind", ""))
            self.grid.SetCellValue(i, 2, str(row.get("src", "")))
            self.grid.SetCellValue(i, 3, str(row.get("dst", "")))
            self.grid.SetCellValue(i, 4, self._InfoCell(row.get("info", "")))

        self.grid.AutoSizeColumns()
        for col, cap in ((2, ADDR_COL_MAX), (3, ADDR_COL_MAX), (4, INFO_COL_MAX)):
            if self.grid.GetColSize(col) > cap:
                self.grid.SetColSize(col, cap)
        self.grid.AutoSizeRows()
        self.ApplyAlternateRowShading()
        self.Layout()

    def ApplyAlternateRowShading(self):
        numRows = self.grid.GetNumberRows()

        for row in range(numRows):
            if row % 2 == 0:
                attr = gridlib.GridCellAttr()
                attr.SetBackgroundColour(GRID_ROW_ALT)
                self.grid.SetRowAttr(row, attr)
        self.grid.ForceRefresh()

    def OnSelectCell(self, event):
        row = event.GetRow()
        if 0 <= row < len(self.pageRows):
            self.resultsWindow.SetValue(self.pageRows[row].get("detail", "").replace("\x00", ""))
        event.Skip()

    def UpdatePaginationControls(self):
        total_pages = (self.numevents + self.items_per_page - 1) // self.items_per_page
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
        total_pages = (self.numevents + self.items_per_page - 1) // self.items_per_page
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
        total_pages = (self.numevents + self.items_per_page - 1) // self.items_per_page
        self.current_page = total_pages
        self.AddTableData()

    def OnGoToPage(self, event):
        total_pages = (self.numevents + self.items_per_page - 1) // self.items_per_page
        try:
            page_num = int(self.page_input.GetValue())
            if 1 <= page_num <= total_pages:
                self.current_page = page_num
                self.AddTableData()
            else:
                ui.message(
                    f"Page number must be between 1 and {total_pages}.",
                    "Invalid Page Number",
                    wx.OK | wx.ICON_ERROR,
                )
        except ValueError:
            ui.message(
                "Please enter a valid integer page number.",
                "Invalid Input",
                wx.OK | wx.ICON_ERROR,
            )
