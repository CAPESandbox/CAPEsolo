import logging

import wx

from .key_event import KeyEventHandlerMixin
from .theme import FONT_CODE, apply_theme


class WxTextCtrlHandler(logging.Handler):
    def __init__(self, textctrl):
        super(WxTextCtrlHandler, self).__init__()
        self.textctrl = textctrl

    def emit(self, record):
        msg = self.format(record)
        wx.CallAfter(self.textctrl.AppendText, msg + "\n")


class LoggerWindow(wx.Frame, KeyEventHandlerMixin):
    def __init__(
        self, parent, title, mainWindowPosition, mainWindowSize, maximized=False, *args, **kwargs
    ):
        super(LoggerWindow, self).__init__(parent, title=title, *args, **kwargs)
        self.analysisDir = parent.analysisDir
        self.analysisLogPath = parent.analysisLogPath
        self.BindKeyEvents()
        self.mainWindowPosition = mainWindowPosition
        self.mainWindowSize = mainWindowSize
        self.maximized = maximized
        self.InitUI()

    def InitUI(self):
        panel = wx.Panel(self)
        vbox = wx.BoxSizer(wx.VERTICAL)

        self.resultsWindow = wx.TextCtrl(
            panel, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_RICH2
        )
        self.resultsWindow.SetFont(FONT_CODE)
        vbox.Add(self.resultsWindow, proportion=1, flag=wx.EXPAND | wx.ALL, border=5)
        copyPathBtn = wx.Button(panel, label="Copy Log")
        copyPathBtn.Bind(wx.EVT_BUTTON, self.OnCopyPath)
        vbox.Add(copyPathBtn, proportion=0, flag=wx.ALL | wx.CENTER, border=5)
        panel.SetSizer(vbox)
        # Theme the frame, not just the panel: apply_window_theme only fires for a wx.Frame,
        # so themeing the panel alone left the title bar light while the app was dark.
        apply_theme(self)

        fileHandler = logging.FileHandler(self.analysisLogPath)
        wxHandler = WxTextCtrlHandler(self.resultsWindow)
        logging.basicConfig(
            level=logging.DEBUG,
            handlers=[fileHandler, wxHandler],
            format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        )

        # When the main frame is maximized it fills the screen, so the docked-beside
        # geometry below would push this window off-screen with ~zero width; maximize
        # over the start panel instead.
        if self.maximized:
            self.Maximize()
        else:
            # Offset a copy rather than the caller's wx.Point: the caller reuses the object it
            # passed in, so mutating it here would silently move whatever it positions next.
            position = wx.Point(self.mainWindowPosition)
            position.x += self.mainWindowSize.x
            screenWidth, _ = wx.DisplaySize()
            self.SetSize(
                int(screenWidth * 0.98 - self.mainWindowSize.x), self.mainWindowSize.y
            )
            self.SetPosition(position)

    def OnCopyPath(self, event):
        if wx.TheClipboard.Open():
            fileData = wx.FileDataObject()
            fileData.AddFile(self.analysisLogPath)
            wx.TheClipboard.SetData(fileData)
            wx.TheClipboard.Close()
            wx.MessageBox(
                f"Analysis log copied: {self.analysisLogPath}",
                "Info",
                wx.OK | wx.ICON_INFORMATION,
            )
        else:
            wx.LogError("Unable to open the clipboard.")
