"""Typed editor for analysis.conf, generated from analysis_conf.default.

The Start panel used to show the default file verbatim in a text box: every key free text,
no types, no validation, and the ";" comments that document several keys rendered as just
more text. This builds controls from that same file instead, so the file stays the single
source of both the key list and the documentation - a comment added there becomes a tooltip
here with no second place to update.

Writing is generation, never accumulation. The old path appended the runtime keys to the
editor's text and wrote the result back into it, so a second launch in one session appended
them again and configparser - which is strict - then refused the file with
DuplicateOptionError before the analysis could start.
"""

import configparser
import logging

import wx

from . import ui_kit as ui
from .theme import FONT_CODE, SP_SM, SP_XS, apply_theme, dip

log = logging.getLogger(__name__)

SECTION = "analysis"

# Which group each key is rendered under. Anything in the default file that is missing here
# lands in OTHER_GROUP, so a key added to the file can never be silently dropped from the UI.
KEY_GROUPS = (
    (
        "Result server",
        ("ip", "port", "id"),
    ),
    (
        "Behaviour",
        ("category", "terminate_processes", "syscall", "file_type", "exports"),
    ),
    (
        "Limits",
        ("upload_max_size", "enable_trim", "do_upload_max_size"),
    ),
)
OTHER_GROUP = "Auxiliary modules"

# Auxiliary modules are bare checkbox labels, so more fit across a row than the label-plus-
# field pairs in the other groups.
AUX_COLUMNS = 5
FIELD_COLUMNS = 4

# Free-text keys wide enough for their content; everything else takes the narrow default.
WIDE_KEYS = ("file_type", "exports", "upload_max_size", "ip")


class ConfKey:
    """One key from the default file: its value, its documentation, and its control."""

    def __init__(self, name, value, comment, enabled):
        self.name = name
        self.value = value
        self.comment = comment
        # A key commented out in the default file (";do_upload_max_size = 0") stays visible
        # but is not written unless the user turns it on.
        self.enabled = enabled
        self.control = None
        self.toggle = None

    def IsBoolean(self):
        """Whether the analyzer will read this key as a boolean.

        Mirrors lib/core/config.py, which tries getboolean before getint before str. Matching
        that order is what makes a value round-trip to the same type the analyzer sees - it is
        why "enable_trim = 1" is a checkbox here and not a number field.
        """
        return _Coerce(self.value) in (True, False)

    def Read(self):
        """Current value as it should appear in the file."""
        if self.control is None:
            return self.value

        if self.IsBoolean():
            return _BooleanText(self.value, self.control.GetValue())

        return self.control.GetValue().strip()

    def Write(self, value):
        if self.control is None:
            self.value = value
            return

        if self.IsBoolean():
            self.control.SetValue(_Coerce(value) is True)
        else:
            self.control.SetValue(value)


# Ways a boolean is written in the default file. Order matters only in that the first pair
# whose members match the original text wins.
_BOOLEAN_STYLES = (("1", "0"), ("True", "False"), ("true", "false"), ("yes", "no"), ("on", "off"))


def _BooleanText(original, value):
    """Render a boolean the way the default file writes that particular key.

    "enable_trim = 1" and "amsi = True" are both booleans to configparser, but rewriting the
    first as "True" churns the file for no reason and loses the author's intent, so each key
    keeps the style it was written in.
    """
    text = str(original).strip()
    for truthy, falsy in _BOOLEAN_STYLES:
        if text in (truthy, falsy):
            return truthy if value else falsy

    return str(value)


def _Coerce(value):
    """Value as configparser would type it: bool, then int, then the original string."""
    text = str(value).strip()
    lowered = text.lower()
    if lowered in configparser.ConfigParser.BOOLEAN_STATES:
        return configparser.ConfigParser.BOOLEAN_STATES[lowered]

    try:
        return int(text)
    except ValueError:
        return text


def ParseDefault(text):
    """Read the default file into ConfKey objects, preserving order and comments.

    configparser is not used for this pass: it discards comments and commented-out keys, and
    both are wanted - the comments become tooltips and a disabled key stays discoverable.
    """
    keys = []
    comment = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            comment = []
            continue

        if stripped.startswith("["):
            continue

        if stripped.startswith((";", "#")):
            body = stripped.lstrip(";#").strip()
            # A commented-out assignment is a disabled key; anything else is documentation
            # for whatever key comes next.
            if "=" in body and not body.endswith("="):
                name, _, value = body.partition("=")
                name = name.strip()
                if name and " " not in name:
                    keys.append(ConfKey(name, value.strip(), " ".join(comment), False))
                    comment = []
                    continue

            comment.append(body)
            continue

        if "=" not in line:
            continue

        name, _, value = line.partition("=")
        keys.append(ConfKey(name.strip(), value.strip(), " ".join(comment), True))
        comment = []

    return keys


class AnalysisConfPanel(wx.Panel):
    """Form view of analysis.conf, with the raw text still available behind a toggle."""

    def __init__(self, parent):
        super(AnalysisConfPanel, self).__init__(parent)
        self.keys = []
        # Keys typed into the raw view that the default file does not define. Kept so that
        # switching back to the form and saving cannot quietly discard them.
        self.passthrough = {}
        self.InitUi()

    def InitUi(self):
        self.vbox = wx.BoxSizer(wx.VERTICAL)

        modeBox = wx.BoxSizer(wx.HORIZONTAL)
        self.formRadio = ui.Radio(self, label="Form", style=wx.RB_GROUP)
        self.rawRadio = ui.Radio(self, label="Raw")
        self.formRadio.SetValue(True)
        for radio in (self.formRadio, self.rawRadio):
            radio.Bind(wx.EVT_RADIOBUTTON, self.OnModeChanged)
            modeBox.Add(radio, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=dip(self, SP_SM))
        self.vbox.Add(modeBox, flag=wx.BOTTOM, border=dip(self, SP_XS))

        # Built by Load once the keys are known.
        self.formSizer = wx.BoxSizer(wx.VERTICAL)
        self.vbox.Add(self.formSizer, proportion=0, flag=wx.EXPAND)

        self.rawEditor = wx.TextCtrl(self, style=wx.TE_MULTILINE)
        self.rawEditor.SetFont(FONT_CODE)
        self.vbox.Add(self.rawEditor, proportion=1, flag=wx.EXPAND | wx.TOP, border=dip(self, SP_XS))
        self.rawEditor.Hide()

        self.SetSizer(self.vbox)

    def Load(self, path):
        """Parse the default file and build the controls."""
        try:
            with open(path, "r") as hfile:
                text = hfile.read()
        except OSError as e:
            ui.message(
                f"Failed to load {path}: {e}", "Error", wx.OK | wx.ICON_ERROR
            )
            return

        self.keys = ParseDefault(text)
        self.BuildForm()
        self.rawEditor.SetValue(self.GetText())

    def BuildForm(self):
        self.formSizer.Clear(delete_windows=True)

        grouped = {name: [] for name, _ in KEY_GROUPS}
        grouped[OTHER_GROUP] = []
        placement = {}
        for group, names in KEY_GROUPS:
            for name in names:
                placement[name] = group

        for key in self.keys:
            grouped[placement.get(key.name, OTHER_GROUP)].append(key)

        # Auxiliary modules first: it is the longest group and the one most often changed.
        order = [OTHER_GROUP] + [name for name, _ in KEY_GROUPS]
        for group in order:
            keys = grouped.get(group)
            if not keys:
                continue

            box = wx.StaticBoxSizer(wx.VERTICAL, self, group)
            columns = AUX_COLUMNS if group == OTHER_GROUP else FIELD_COLUMNS
            grid = wx.FlexGridSizer(cols=columns, hgap=12, vgap=6)
            for key in keys:
                grid.Add(self.BuildControl(box.GetStaticBox(), key), flag=wx.ALIGN_CENTER_VERTICAL)
            box.Add(grid, flag=wx.ALL, border=dip(self, SP_XS))
            self.formSizer.Add(box, flag=wx.EXPAND | wx.BOTTOM, border=dip(self, SP_XS))

        self.Layout()

    def BuildControl(self, parent, key):
        """One control for one key, with its comment as the tooltip."""
        if key.IsBoolean():
            key.control = ui.Check(parent, label=key.name)
            key.control.SetValue(_Coerce(key.value) is True)
            item = key.control
        else:
            row = wx.BoxSizer(wx.HORIZONTAL)
            label = wx.StaticText(parent, label=f"{key.name}:")
            width = 150 if key.name in WIDE_KEYS else 70
            field = ui.Field(parent, value=key.value, size=wx.Size(width, -1))
            # key.control is what the save path reads GetValue off, so it stays the
            # TextCtrl; the sizer gets the drawn wrapper.
            key.control = field.ctrl
            row.Add(label, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=dip(self, SP_XS))
            row.Add(field, flag=wx.ALIGN_CENTER_VERTICAL)
            item = row

        if not key.enabled:
            # Disabled in the default file, so it needs an explicit opt-in before it is
            # written; the checkbox in front of it is that switch.
            wrapper = wx.BoxSizer(wx.HORIZONTAL)
            key.toggle = ui.Check(parent, label="")
            key.toggle.SetToolTip(f"Write {key.name} to analysis.conf")
            wrapper.Add(key.toggle, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=dip(self, 2))
            wrapper.Add(item, flag=wx.ALIGN_CENTER_VERTICAL)
            item = wrapper

        if key.comment:
            key.control.SetToolTip(key.comment)

        return item

    def OnModeChanged(self, event):
        """Hand the current state across when the view changes, in whichever direction."""
        if self.rawRadio.GetValue():
            self.rawEditor.SetValue(self.GetText())
            self.formSizer.ShowItems(False)
            self.rawEditor.Show()
        else:
            self.SetText(self.rawEditor.GetValue())
            self.rawEditor.Hide()
            self.formSizer.ShowItems(True)

        self.Layout()
        # The pane the panel sits in only resizes when its own handler runs.
        parent = self.GetParent()
        while parent and not isinstance(parent, wx.Frame):
            if hasattr(parent, "OnCollapsiblePaneChanged"):
                parent.OnCollapsiblePaneChanged(None)
                break
            parent = parent.GetParent()

        event.Skip()

    def IsRaw(self):
        return self.rawRadio.GetValue()

    def GetText(self, extra=None):
        """Render the current state as analysis.conf.

        @param extra: runtime keys (timeout, package, ...) written after the configured ones.
                      They are generated afresh every launch rather than appended to previous
                      output, which is what stops duplicate keys accumulating.
        """
        # In raw mode the text box is authoritative: it is what the user has been editing.
        if self.IsRaw():
            return _WithExtra(self.rawEditor.GetValue(), extra)

        lines = [f"[{SECTION}]"]
        for key in self.keys:
            if key.toggle is not None and not key.toggle.GetValue():
                continue
            lines.append(f"{key.name} = {key.Read()}")

        for name, value in self.passthrough.items():
            lines.append(f"{name} = {value}")

        for name, value in (extra or {}).items():
            lines.append(f"{name} = {value}")

        return "\n".join(lines) + "\n"

    def SetText(self, text):
        """Parse analysis.conf text back into the controls."""
        parser = configparser.ConfigParser(allow_no_value=True, interpolation=None, strict=False)
        try:
            parser.read_string(text)
        except configparser.Error as e:
            ui.message(
                f"analysis.conf could not be parsed, so the form was left as it was:\n{e}",
                "Invalid configuration",
                wx.OK | wx.ICON_ERROR,
            )
            return

        if not parser.has_section(SECTION):
            return

        values = dict(parser.items(SECTION))
        known = set()
        for key in self.keys:
            known.add(key.name)
            if key.name in values:
                key.Write(values[key.name])
                if key.toggle is not None:
                    key.toggle.SetValue(True)
            elif key.toggle is not None:
                key.toggle.SetValue(False)

        # Anything the default file does not define is kept verbatim so it survives a trip
        # through the form. Runtime keys are excluded: they are regenerated each launch.
        self.passthrough = {
            name: value
            for name, value in values.items()
            if name not in known and name not in RUNTIME_KEYS
        }


# Written by the Start panel at launch from its own controls, never edited here.
RUNTIME_KEYS = frozenset(
    ("enforce_timeout", "timeout", "file_name", "clock", "package", "options")
)


def _WithExtra(text, extra):
    """Append the runtime keys to raw text, replacing any copy already present."""
    if not extra:
        return text if text.endswith("\n") else text + "\n"

    kept = [
        line
        for line in text.splitlines()
        if line.partition("=")[0].strip() not in extra
    ]
    kept.extend(f"{name} = {value}" for name, value in extra.items())

    return "\n".join(kept) + "\n"
