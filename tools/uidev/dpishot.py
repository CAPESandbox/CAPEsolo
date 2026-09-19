"""Render ui_kit at a forced 2x DIP scale.

GDK_SCALE has no effect under Xvfb here - the layout came back identical - so the scale is
forced where the code actually reads it: theme.dip(). Everything drawn by ui_kit and the
status bar goes through it, so doubling it is the same geometry a 200% display produces.
Fonts are point-sized and scale separately, so they are bumped too, otherwise the check
would only prove that padding grew around unchanged text.
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import winstubs  # noqa: E402

winstubs.install(tempfile.mkdtemp(prefix="capesolo-dpi-"))

sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "CAPEsolo"))
os.chdir(os.path.join(REPO, "CAPEsolo"))

import wx  # noqa: E402

app = wx.App()
from CAPEsolo.classes import theme  # noqa: E402

theme._init()
theme.set_theme("dark")

SCALE = 2
_realDip = theme.dip
theme.dip = lambda window, value: int(_realDip(window, value) * SCALE)
# ui_kit and status_bar imported dip by name, so rebind it there as well.
from CAPEsolo.classes import status_bar, ui_kit  # noqa: E402

ui_kit.dip = theme.dip
status_bar.dip = theme.dip
for font in theme._FONTS:
    font.SetPointSize(font.GetPointSize() * SCALE)

import gallery  # noqa: E402

frame = gallery.GalleryFrame(wx.Size(1400, 1100))
frame.Show()
frame.Refresh()
for _ in range(10):
    app.Yield()
    wx.MilliSleep(40)

width, height = frame.GetClientSize()
bitmap = wx.Bitmap(width, height)
memory = wx.MemoryDC(bitmap)
memory.Blit(0, 0, width, height, wx.ClientDC(frame), 0, 0)
memory.SelectObject(wx.NullBitmap)
bitmap.ConvertToImage().SaveFile("/tmp/shots/p7_gallery_2x.png", wx.BITMAP_TYPE_PNG)
print("/tmp/shots/p7_gallery_2x.png", width, height)
