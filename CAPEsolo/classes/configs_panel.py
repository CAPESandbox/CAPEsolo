import hashlib
import importlib
import importlib.util
import json
import os
from contextlib import suppress
from pathlib import Path

import wx
import wx.grid as gridlib

from .custom_grid import CopyableGrid
from .key_event import KeyEventHandlerMixin
from .theme import FONT_CODE, GRID_ROW_ALT, apply_theme
from CAPEsolo.capelib.path_utils import path_exists, path_mkdir

# Host-side only: a file handed back by a config parser via "dump_files". Deliberately
# outside the monitor's range so it can't collide with a code in cape\cape.h.
PARSER_EXTRACTED = 0x10000

# A payload is named by its sha256 and a config value can be a long list, so autosizing
# either column alone can take the whole width and push the rest of the row off screen.
FILE_COL_MAX = 320
VALUE_COL_MAX = 500


def DumpParserFiles(cfg, analysisDir, newPayloads):
    """Write files handed back by a config parser into the CAPE folder.

    A parser only receives the file data, never the analysis paths, so it returns the raw
    bytes in "dump_files" and we do the writing. Each blob is named by its own sha256 and
    the bytes are replaced by that hash in the config, so a payload is never rendered into
    the results window or serialised into the JSON report.
    """
    dumped = {}
    capeDir = Path(analysisDir) / "CAPE"
    try:
        dumpFiles = cfg.get("dump_files") or {}
        if isinstance(dumpFiles, dict):
            dumpFiles = [dumpFiles]

        for entry in dumpFiles:
            for label, blob in entry.items():
                if not isinstance(blob, (bytes, bytearray)):
                    continue
                blob = bytes(blob)
                sha256 = hashlib.sha256(blob).hexdigest()
                dumped[label] = sha256
                destPath = capeDir / sha256
                # Content addressed, so an existing file is the same file. Skipping the
                # write also keeps re-extraction from duplicating the files.json entry
                # and the Payloads/Yara tab entries.
                if path_exists(str(destPath)):
                    continue

                if not path_exists(str(capeDir)):
                    path_mkdir(str(capeDir), exist_ok=True)
                destPath.write_bytes(blob)
                relPath = f"CAPE/{sha256}"
                metaEntry = {
                    "path": relPath,
                    "filepath": "",
                    "pids": [],
                    "ppids": [],
                    "metadata": f"{PARSER_EXTRACTED};?;?;?",
                    "category": "CAPE",
                }
                # Append-writes are atomic
                with open(Path(analysisDir) / "files.json", "a") as fh:
                    print(json.dumps(metaEntry, ensure_ascii=False), file=fh)
                newPayloads.append(relPath)
    except Exception as e:
        print(f"CAPE parser: Failed to write dumped file - {e}")
    finally:
        # Unconditional: a write failure or a malformed dump_files must not leave raw
        # bytes behind in the config.
        if dumped:
            cfg["dump_files"] = dumped
        else:
            cfg.pop("dump_files", None)

    return cfg


def FlattenConfig(cfg):
    """One (field, value) pair per config key, so that a grid row is a single field.

    A parser returns either one config dict or a list of them. Some hand back map objects
    for multi-value fields, which neither display nor serialise as anything useful.
    """
    fields = []
    for entry in cfg if isinstance(cfg, list) else [cfg]:
        if not isinstance(entry, dict):
            continue

        for key, value in entry.items():
            if isinstance(value, map):
                value = list(value)
            fields.append((key, value))

    return fields


def SummariseValue(value):
    """Collapse a config value onto the single line a grid cell can show.

    Whitespace is folded out: a value lifted from a binary can carry newlines, and the row
    would otherwise grow to the height of the entire value once rows are autosized. The
    detail pane is where the value keeps its original shape.
    """
    if isinstance(value, (list, tuple, set)):
        summary = f"[{len(value)}] " + ", ".join(str(item) for item in value)
    elif isinstance(value, dict):
        summary = ", ".join(f"{key}: {item}" for key, item in value.items())
    else:
        summary = str(value)

    return " ".join(summary.split())


def FormatValue(value):
    """The full value, expanded over as many lines as it needs, for the detail pane."""
    if isinstance(value, (tuple, set)):
        value = list(value)

    if isinstance(value, (list, dict)):
        # default=str because a parser may put bytes or an enum in a config, which json
        # cannot serialise on its own.
        with suppress(TypeError, ValueError):
            return json.dumps(value, indent=4, default=str)

    return str(value)


def Extract(configHits, analysisDir, jsonResults=False, newPayloads=None):
    """Run the config parser for every CAPE name yara matched.

    Returns the list of {path: config} the JSON report expects when *jsonResults* is set,
    and otherwise one entry per hit for the panel to render: either "fields" for a config
    that was extracted or "error" describing why there is none.
    """
    entries = []
    configs = []
    if newPayloads is None:
        newPayloads = []
    CAPE_PARSERS = ("core", "community")
    customParsers = os.path.join(os.path.expanduser("~"), "Desktop", "custom")

    for hit in configHits:
        decoderModule = ""
        hitPath = list(hit.keys())[0]
        hitName = hit.get(hitPath, "")
        modPath = os.path.join(customParsers, f"{hitName}.py")

        for parser in CAPE_PARSERS:
            try:
                decoderModule = importlib.import_module(f"cape_parsers.CAPE.{parser}.{hitName}", __package__)
            except (ImportError, IndexError, AttributeError):
                continue
            except SyntaxError as e:
                print(f"CAPE parser: Fix your code in {parser}/{hitName} - {e}")
            except Exception as e:
                print(f"CAPE parser: Fix your code in {parser}/{hitName} - {e}")

        if not decoderModule:
            try:
                spec = importlib.util.spec_from_file_location(hitName, modPath)
                decoderModule = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(decoderModule)
            except (FileNotFoundError, ImportError, AttributeError):
                # Nothing under cape_parsers and nothing on the Desktop either. Recorded
                # rather than skipped in silence: this is the path a family with no parser
                # at all takes, and the tab otherwise showed no trace of the hit, which
                # reads as "no config in this file" instead of "no parser for this family".
                entries.append(
                    {
                        "path": str(hitPath),
                        "family": hitName,
                        "error": f"No parser for {hitName}",
                    }
                )
                continue
            except SyntaxError as e:
                print(f"CAPE parser: Fix your code in {modPath} - {e}")
            except Exception as e:
                print(f"CAPE parser: Fix your code in {modPath} - {e}")

        if decoderModule:
            cfg = ""
            if analysisDir not in hitPath:
                hitPath = Path(analysisDir) / hitPath
            filedata = Path(hitPath).read_bytes()
            with suppress(Exception):
                if hasattr(decoderModule, "extract_config"):
                    cfg = decoderModule.extract_config(filedata)
                else:
                    cfg = decoderModule.config(filedata)
            if cfg:
                for entry in cfg if isinstance(cfg, list) else [cfg]:
                    if isinstance(entry, dict) and "dump_files" in entry:
                        DumpParserFiles(entry, analysisDir, newPayloads)

                if jsonResults:
                    configs.append({hitPath: cfg})

                entries.append(
                    {
                        "path": str(hitPath),
                        "family": hitName,
                        "fields": FlattenConfig(cfg),
                    }
                )
            else:
                # A parser that ran and returned nothing used to leave no trace at all,
                # which looked identical to the hit never having been processed.
                entries.append(
                    {
                        "path": str(hitPath),
                        "family": hitName,
                        "error": "Parser extracted no config",
                    }
                )
        else:
            entries.append(
                {
                    "path": str(hitPath),
                    "family": hitName,
                    "error": f"No parser for {hitName}",
                }
            )

    if jsonResults:
        return configs

    return entries


class ConfigsPanel(wx.Panel, KeyEventHandlerMixin):
    def __init__(self, parent):
        super(ConfigsPanel, self).__init__(parent)
        self.configHits = parent.configHits
        self.configsComplete = False
        self.analysisDir = parent.analysisDir
        self.capesoloRoot = parent.capesoloRoot
        # One entry per grid row, each keeping the value it was flattened from so the detail
        # pane can expand a list or nested dict the cell had to collapse onto one line.
        self.rows = []
        self.BindKeyEvents()
        self.InitUI()

    def InitUI(self):
        vbox = wx.BoxSizer(wx.VERTICAL)

        vbox.AddSpacer(10)
        self.configsButton = wx.Button(self, label="Extract Configs")
        self.configsButton.Bind(wx.EVT_BUTTON, self.ExtractConfigs)
        self.configsButton.Disable()
        vbox.Add(self.configsButton, proportion=0, flag=wx.ALL, border=5)

        self.grid = CopyableGrid(self, 0, 4)
        for col, label in enumerate(("File", "Family", "Field", "Value")):
            self.grid.SetColLabelValue(col, label)
        self.grid.SetColLabelAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)
        for col in range(4):
            attr = gridlib.GridCellAttr()
            attr.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE)
            self.grid.SetColAttr(col, attr)
        self.grid.SetRowLabelSize(0)
        self.grid.EnableEditing(False)
        self.grid.Bind(gridlib.EVT_GRID_SELECT_CELL, self.OnSelectCell)
        self.grid.Hide()
        vbox.Add(
            self.grid,
            proportion=2,
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=5,
        )

        self.resultsWindow = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.resultsWindow.SetFont(FONT_CODE)
        self.resultsWindow.SetValue("Extract after Yara Processing.")
        vbox.Add(
            self.resultsWindow,
            proportion=1,
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=5,
        )

        self.SetSizer(vbox)
        apply_theme(self)

    def ExtractConfigs(self, event):
        newPayloads = []
        entries = Extract(self.configHits, self.analysisDir, newPayloads=newPayloads)
        # Shown before the rows go in, so the Layout that AddTableData ends with is the one
        # that sizes it, matching SignaturesPanel.
        self.grid.Show()
        self.AddTableData(entries)
        if newPayloads:
            self.UpdatePayloadPanels(newPayloads)
        self.configsButton.Disable()
        self.configsComplete = True

    def ClearGrid(self):
        self.grid.ClearGrid()
        rows = self.grid.GetNumberRows()
        if rows > 0:
            self.grid.DeleteRows(0, rows)

    def AddTableData(self, entries):
        """Rebuild the grid, one row per config field.

        Extraction can be re-run while the tab is open, so this replaces the previous rows
        rather than appending to them.
        """
        self.rows = []
        for entry in entries:
            if "error" in entry:
                self.rows.append(
                    {
                        "path": entry["path"],
                        "family": entry["family"],
                        "field": "",
                        "value": entry["error"],
                    }
                )
                continue

            for field, value in entry["fields"]:
                self.rows.append(
                    {
                        "path": entry["path"],
                        "family": entry["family"],
                        "field": field,
                        "value": value,
                    }
                )

        self.ClearGrid()
        for row, data in enumerate(self.rows):
            self.grid.AppendRows(1)
            self.grid.SetCellValue(row, 0, data["path"])
            self.grid.SetCellValue(row, 1, data["family"])
            self.grid.SetCellValue(row, 2, data["field"])
            # A config value is arbitrary data lifted out of a binary. A NUL terminates the
            # native cell, dropping the rest of the value with no error anywhere.
            summary = SummariseValue(data["value"]).replace("\x00", "")
            self.grid.SetCellValue(row, 3, summary[:512])

        self.grid.AutoSizeColumns()
        for col, limit in ((0, FILE_COL_MAX), (3, VALUE_COL_MAX)):
            if self.grid.GetColSize(col) > limit:
                self.grid.SetColSize(col, limit)
        self.grid.AutoSizeRows()
        self.ApplyAlternateRowShading()
        self.resultsWindow.SetValue(self.Summarize(entries))
        self.Layout()

    def ApplyAlternateRowShading(self):
        numRows = self.grid.GetNumberRows()

        for row in range(numRows):
            if row % 2 == 0:
                attr = gridlib.GridCellAttr()
                attr.SetBackgroundColour(GRID_ROW_ALT)
                self.grid.SetRowAttr(row, attr)
        self.grid.ForceRefresh()

    def Summarize(self, entries):
        if not entries:
            return "No config hits to extract."

        extracted = [entry for entry in entries if "error" not in entry]
        families = sorted({entry["family"] for entry in extracted})
        if families:
            content = f'{len(extracted)} config(s) extracted: {", ".join(families)}\n'
            content += "Select a row to view the full value of that field."
        else:
            content = "No configs extracted."

        problems = [
            f'    {entry["path"]}: {entry["error"]}'
            for entry in entries
            if "error" in entry
        ]
        if problems:
            content += "\n\nProblems:\n" + "\n".join(problems)

        return content

    def FormatRow(self, data):
        """The full detail for one field, for the pane below the grid."""
        lines = [f'File:   {data["path"]}', f'Family: {data["family"]}']
        if data["field"]:
            lines.append(f'Field:  {data["field"]}')
        lines.append("")
        lines.append(FormatValue(data["value"]))

        return "\n".join(lines)

    def OnSelectCell(self, event):
        row = event.GetRow()
        if 0 <= row < len(self.rows):
            detail = self.FormatRow(self.rows[row])
            self.resultsWindow.SetValue(detail.replace("\x00", ""))
        event.Skip()

    def UpdatePayloadPanels(self, newPayloads):
        """Feed parser-dumped payloads to the Payloads and Yara tabs.

        Both tabs load once and have already run by the time configs can be extracted, so
        they are updated in place rather than reloaded. Any CAPE name the new yara hits
        produce is appended to configHits, so re-running the extraction picks it up.
        """
        frame = self.GetMainFrame()
        payloadsTab = getattr(frame, "payloadsTab", None)
        yaraTab = getattr(frame, "yaraTab", None)
        for relPath in newPayloads:
            if payloadsTab:
                payloadsTab.AddPayload(relPath)
            if yaraTab:
                yaraTab.AddPayload(relPath)

    def GetMainFrame(self):
        parent = self.GetParent()
        while parent and not isinstance(parent, wx.Frame):
            parent = parent.GetParent()

        return parent

    def UpdateConfigsButtonState(self):
        if self.configHits and not self.configsComplete:
            self.configsButton.Enable()
        else:
            self.configsButton.Disable()
