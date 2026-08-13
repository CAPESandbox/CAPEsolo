from pathlib import Path

import wx
import wx.grid as gridlib

from .custom_grid import CopyableGrid
from .key_event import KeyEventHandlerMixin
from .theme import FONT_CODE, GRID_ROW_ALT, apply_theme
from CAPEsolo.capelib.network import FormatTime, NetworkData
from CAPEsolo.capelib.network_decrypt import DecryptStreams, StreamRows
from CAPEsolo.capelib.path_utils import path_exists

ALL_KINDS = "<All traffic>"

# Kinds in the order they are most useful to look at, rather than alphabetically. Plaintext
# leads: a decrypted request with its body says more than the handshake that carried it.
KIND_ORDER = ("Plaintext", "DNS", "HTTP", "TLS", "Flow")

# A capture path can be long and Info carries a whole HTTP request line, so autosizing
# either alone takes the width and pushes the rest of the row off screen.
ADDR_COL_MAX = 220
INFO_COL_MAX = 520

PCAP_WILDCARD = (
    "Captures (*.pcapng;*.pcap)|*.pcapng;*.pcap|All files (*.*)|*.*"
)


class NetworkPanel(wx.Panel, KeyEventHandlerMixin):
    """Correlate a capture taken outside the guest with the analysis TLS secrets."""

    def __init__(self, parent):
        super(NetworkPanel, self).__init__(parent)
        self.parent = parent
        self.analysisDir = parent.analysisDir
        self.results = {}
        self.decrypted = {}
        # Every row, and the subset the grid currently shows; row indices map through
        # viewRows back to the record whose detail is displayed.
        self.rows = []
        self.viewRows = []
        self.filterKinds = [ALL_KINDS]
        self.BindKeyEvents()
        self.InitUI()

    def InitUI(self):
        vbox = wx.BoxSizer(wx.VERTICAL)

        vbox.AddSpacer(10)
        hboxFile = wx.BoxSizer(wx.HORIZONTAL)
        hboxFile.Add(
            wx.StaticText(self, label="Capture:"),
            flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL,
            border=5,
        )
        self.pcapPath = wx.TextCtrl(self)
        self.pcapPath.SetValue("<pcapng captured outside the guest>")
        self.pcapPath.Bind(wx.EVT_TEXT, self.OnPathChanged)
        browseBtn = wx.Button(self, label="Browse...")
        browseBtn.Bind(wx.EVT_BUTTON, self.OnBrowse)
        hboxFile.Add(self.pcapPath, proportion=1, flag=wx.EXPAND | wx.RIGHT, border=5)
        hboxFile.Add(browseBtn, proportion=0)
        vbox.Add(hboxFile, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=10)

        hboxTop = wx.BoxSizer(wx.HORIZONTAL)
        self.processButton = wx.Button(self, label="Process Capture")
        self.processButton.Bind(wx.EVT_BUTTON, self.ProcessCapture)
        self.processButton.Disable()
        hboxTop.Add(self.processButton, proportion=0, flag=wx.RIGHT, border=15)
        hboxTop.Add(
            wx.StaticText(self, label="Show:"),
            flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL,
            border=5,
        )
        self.kindDropdown = wx.ComboBox(self, style=wx.CB_READONLY)
        self.kindDropdown.Bind(wx.EVT_COMBOBOX, self.OnKindView)
        hboxTop.Add(self.kindDropdown, proportion=1, flag=wx.EXPAND)
        vbox.Add(hboxTop, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=10)

        # List and detail live in a splitter so a long capture list cannot squeeze the detail
        # pane out: a grid's best size is all-rows tall, which otherwise wins in a box sizer and
        # the frame is capped at 75% of screen height. The user drags the sash to rebalance.
        self.splitter = wx.SplitterWindow(self, style=wx.SP_LIVE_UPDATE | wx.SP_3DSASH)
        self.splitter.SetMinimumPaneSize(80)
        self.splitter.SetSashGravity(0.7)

        self.grid = CopyableGrid(self.splitter, 0, 7)
        for col, label in enumerate(
            ("Time", "Kind", "Source", "Destination", "Keys", "Seen", "Info")
        ):
            self.grid.SetColLabelValue(col, label)
        self.grid.SetColLabelAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)
        # Keys and Seen read as short flags and stay centred; the rest line up on the left.
        for col in (0, 2, 3, 6):
            attr = gridlib.GridCellAttr()
            attr.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE)
            self.grid.SetColAttr(col, attr)
        self.grid.SetRowLabelSize(0)
        self.grid.EnableEditing(False)
        self.grid.Bind(gridlib.EVT_GRID_SELECT_CELL, self.OnSelectCell)
        self.grid.Hide()

        self.resultsWindow = wx.TextCtrl(
            self.splitter, style=wx.TE_MULTILINE | wx.TE_READONLY
        )
        self.resultsWindow.SetFont(FONT_CODE)
        self.resultsWindow.SetValue(
            "Select a pcapng captured outside the guest, then process it.\n\n"
            "TLS secrets are taken from the analysis: tlsdump/tlsdump.log (capemon in\n"
            "lsass, for Schannel) and aux_/sslkeylogfile/sslkeys.log. They are merged into\n"
            "one Wireshark-readable key log, and each TLS session is matched against it."
        )
        # Only the detail pane shows until a capture is processed; the grid is split in on top
        # in ProcessCapture.
        self.splitter.Initialize(self.resultsWindow)
        vbox.Add(
            self.splitter,
            proportion=1,
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=5,
        )

        self.SetSizer(vbox)
        apply_theme(self)

    def GetPcapPath(self):
        value = self.pcapPath.GetValue().strip().strip('"')
        if not value or value.startswith("<"):
            return ""

        return value

    def OnPathChanged(self, event):
        self.UpdateProcessButtonState()
        event.Skip()

    def OnBrowse(self, event):
        # Must be absolute and exist: wxFileDialog hands defaultDir to
        # SHCreateItemFromParsingName, which rejects a relative path outright.
        current = self.GetPcapPath()
        initialDir = Path(current).parent if current else Path(self.analysisDir)
        initialDir = initialDir.absolute()
        if not initialDir.is_dir():
            initialDir = Path.cwd()

        with wx.FileDialog(
            self,
            "Choose a capture file",
            wildcard=PCAP_WILDCARD,
            style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST,
            defaultDir=str(initialDir),
        ) as fileDialog:
            if fileDialog.ShowModal() == wx.ID_CANCEL:
                return

            self.pcapPath.SetValue(fileDialog.GetPath())

        self.UpdateProcessButtonState()

    def UpdateProcessButtonState(self):
        pcap = self.GetPcapPath()
        self.processButton.Enable(bool(pcap) and path_exists(pcap))

    def ProcessCapture(self, event):
        pcap = self.GetPcapPath()
        if not pcap or not path_exists(pcap):
            wx.MessageBox(
                "Choose a capture file first.", "Network", wx.OK | wx.ICON_INFORMATION
            )
            return

        # A busy cursor rather than a progress dialog, matching the other panels: the walk
        # is a single pass with nothing meaningful to report part way through.
        try:
            with wx.BusyCursor():
                self.results = NetworkData(self.analysisDir, pcap)
                # Stream reassembly and decryption is the slow half, so it runs under the
                # same cursor. A failure here must not lose the metadata already parsed.
                try:
                    self.decrypted = DecryptStreams(self.analysisDir, pcap)
                except Exception as e:
                    self.decrypted = {"error": str(e)}
        except Exception as e:
            wx.MessageBox(
                f"Failed to process the capture:\n{e}", "Error", wx.OK | wx.ICON_ERROR
            )
            return

        self.rows = (
            StreamRows(self.decrypted, FormatTime)
            + list(self.results.get("events", []))
            + list(self.results.get("flows", []))
        )
        self.rows.sort(key=lambda row: (row.get("time") or 0.0))
        self.LoadKindFilter()
        if not self.splitter.IsSplit():
            self.grid.Show()
            height = self.splitter.GetClientSize().height
            sash = int(height * 0.6) if height > 200 else 300
            self.splitter.SplitHorizontally(self.grid, self.resultsWindow, sash)
        self.AddTableData()

    def LoadKindFilter(self, selected=ALL_KINDS):
        counts = {}
        for row in self.rows:
            counts[row["kind"]] = counts.get(row["kind"], 0) + 1

        # Names held in a parallel list rather than parsed back out of the labels, which
        # carry a trailing count.
        kinds = [kind for kind in KIND_ORDER if kind in counts]
        kinds += sorted(kind for kind in counts if kind not in KIND_ORDER)
        self.filterKinds = [ALL_KINDS] + kinds

        self.kindDropdown.Clear()
        self.kindDropdown.Append(f"{ALL_KINDS} ({len(self.rows)})")
        for kind in kinds:
            self.kindDropdown.Append(f"{kind} ({counts[kind]})")

        index = self.filterKinds.index(selected) if selected in self.filterKinds else 0
        self.kindDropdown.SetSelection(index)

    def GetFilterKind(self):
        index = self.kindDropdown.GetSelection()
        if 0 <= index < len(self.filterKinds):
            return self.filterKinds[index]

        return ALL_KINDS

    def OnKindView(self, event):
        self.AddTableData()

    def ClearGrid(self):
        self.grid.ClearGrid()
        rows = self.grid.GetNumberRows()
        if rows > 0:
            self.grid.DeleteRows(0, rows)

    def AddTableData(self):
        selected = self.GetFilterKind()
        if selected == ALL_KINDS:
            self.viewRows = list(self.rows)
        else:
            self.viewRows = [row for row in self.rows if row["kind"] == selected]

        self.ClearGrid()
        for row, data in enumerate(self.viewRows):
            repeats = data.get("repeats", 1)
            self.grid.AppendRows(1)
            self.grid.SetCellValue(row, 0, FormatTime(data.get("time")))
            self.grid.SetCellValue(row, 1, data["kind"])
            self.grid.SetCellValue(row, 2, str(data["src"]))
            self.grid.SetCellValue(row, 3, str(data["dst"]))
            self.grid.SetCellValue(row, 4, data.get("keys", ""))
            self.grid.SetCellValue(row, 5, str(repeats) if repeats > 1 else "")
            # A host name or header value is attacker controlled text; a NUL terminates the
            # native cell and drops the rest of the line with no error anywhere.
            info = " ".join(str(data["info"]).split()).replace("\x00", "")
            self.grid.SetCellValue(row, 6, info[:512])

        self.grid.AutoSizeColumns()
        for col, limit in ((2, ADDR_COL_MAX), (3, ADDR_COL_MAX), (6, INFO_COL_MAX)):
            if self.grid.GetColSize(col) > limit:
                self.grid.SetColSize(col, limit)
        self.grid.AutoSizeRows()
        self.ApplyAlternateRowShading()
        self.resultsWindow.SetValue(self.Summarize())
        self.Layout()

    def ApplyAlternateRowShading(self):
        numRows = self.grid.GetNumberRows()

        for row in range(numRows):
            if row % 2 == 0:
                attr = gridlib.GridCellAttr()
                attr.SetBackgroundColour(GRID_ROW_ALT)
                self.grid.SetRowAttr(row, attr)
        self.grid.ForceRefresh()

    def _DecryptionLines(self):
        """Report what stream reassembly produced, and when it produced nothing, why.

        The usual reason is not a missing secret: a capture truncated to a fixed frame size
        cannot be reassembled at all, so no TLS record is ever complete. Saying that plainly
        beats an empty Plaintext filter with no explanation.
        """
        decrypted = self.decrypted or {}
        if not decrypted:
            return []

        if not decrypted.get("available"):
            return [
                "Plaintext:  unavailable - " + (decrypted.get("error") or "dependencies missing")
            ]

        counts = {
            key: len(decrypted.get(key) or ())
            for key in ("http_ex", "https_ex", "smtp_ex")
        }
        streams = sum(counts.values())
        lines = [
            f'Plaintext:  {streams} stream(s) reassembled '
            f'({counts["https_ex"]} decrypted, {counts["http_ex"]} cleartext, '
            f'{counts["smtp_ex"]} smtp)'
        ]

        converted = decrypted.get("converted") or {}
        if converted.get("path"):
            if converted.get("reused"):
                lines.append(
                    "            reusing the classic pcap rewritten from an earlier run"
                )
            else:
                lines.append(
                    f'            rewritten as classic pcap for reassembly: '
                    f'{converted.get("written", 0)} frame(s), '
                    f'{converted.get("duplicates", 0)} duplicate(s) dropped, '
                    f'{converted.get("wrapped", 0)} given a link header'
                )

            # The file other tools want, so name it rather than leaving it to be found.
            lines.append(f'Pcap:      {converted["path"]}')
            lines.append(
                "           A normalised copy, readable by tcpdump, Suricata and Zeek."
            )
            lines.append(
                "           The pcapng remains the capture of record: frames that had no"
            )
            lines.append(
                "           link header were given one with synthetic all-zero MAC"
            )
            lines.append("           addresses, and per-layer duplicates were dropped.")

        if decrypted.get("error"):
            lines.append(f'            {decrypted["error"]}')
        elif not streams:
            if not decrypted.get("secrets"):
                lines.append(
                    "            no TLS secrets, so no session could be decrypted"
                )
            lines.append(
                "            if the capture was taken with a frame size limit, the streams"
            )
            lines.append(
                "            cannot be reassembled - re-capture with whole packets"
            )

        return lines

    def Summarize(self):
        """What was read, what the secrets cover, and what is missing."""
        if not self.results:
            return "No capture processed."

        counts = self.results.get("counts", {})
        keylog = self.results.get("keylog", {})
        sessions = self.results.get("sessions", {})
        lines = [
            f'Capture:   {self.results.get("pcap", "")}',
            f'Frames:    {counts.get("frames", 0)} read, '
            f'{counts.get("packets", 0)} unique, '
            f'{counts.get("duplicates", 0)} captured more than once, '
            f'{counts.get("not_ip", 0)} non-IP',
        ]

        total = sessions.get("total", 0)
        withKeys = sessions.get("with_keys", 0)
        lines.append(f"TLS:       {withKeys} of {total} session(s) have secrets")
        lines.extend(self._DecryptionLines())

        secrets = keylog.get("labels", {})
        if secrets:
            detail = ", ".join(f"{name} x{count}" for name, count in sorted(secrets.items()))
            lines.append(f"Secrets:   {detail}")
        else:
            # The most common reason for an unreadable capture, and both switches are
            # analysis-time decisions that cannot be fixed after the fact.
            lines.append(
                "Secrets:   none found. Enable 'tlsdump' for Schannel and 'sslkeylogfile'"
            )
            lines.append(
                "           in analysis.conf before the run; secrets cannot be recovered"
            )
            lines.append("           from a capture afterwards.")

        for relPath, found in (keylog.get("sources") or {}).items():
            state = "not present" if found is None else f"{found} usable line(s)"
            lines.append(f"           {relPath}: {state}")

        if keylog.get("skipped"):
            lines.append(
                f'           {keylog["skipped"]} unrecognised secret line(s) ignored'
            )

        if keylog.get("path"):
            lines.append(f'Key log:   {keylog["path"]}')
            lines.append(
                "           Load this in Wireshark (TLS > (Pre)-Master-Secret log) to"
            )
            lines.append("           decrypt the capture there.")

        hosts = self.results.get("hosts", {})
        if hosts:
            lines.append("")
            lines.append("Resolved:")
            for ip, names in sorted(hosts.items()):
                lines.append(f'    {ip}  {", ".join(names)}')

        for warning in self.results.get("warnings", []):
            lines.append("")
            lines.append(f"Warning: {warning}")

        lines.append("")
        lines.append("Select a row to view its detail.")

        return "\n".join(lines)

    def OnSelectCell(self, event):
        row = event.GetRow()
        if 0 <= row < len(self.viewRows):
            detail = str(self.viewRows[row].get("detail", ""))
            self.resultsWindow.SetValue(detail.replace("\x00", ""))
        event.Skip()
