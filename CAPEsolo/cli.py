# Copyright (C) 2024 enzok
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import json
import logging
import os
import sys
import time
from ctypes import windll
from pathlib import Path

import wx
import wx.adv
_orig_Button = wx.Button
import wx.lib.buttons as buttons

def _custom_draw_label(self, dc, width, height, dx=0, dy=0):
    dc.SetFont(self.GetFont())
    if self.IsEnabled():
        dc.SetTextForeground(self.GetForegroundColour())
    else:
        bg = self.GetBackgroundColour()
        if bg.Red() > 80 and bg.Green() < 40:
            # Destructive warnings (red background) get a soft red-grey disabled text
            disabled_color = wx.Colour(160, 110, 110)
        else:
            # Standard buttons get a highly legible muted slate grey text
            disabled_color = wx.Colour(139, 148, 158)
        dc.SetTextForeground(disabled_color)
    label = self.GetLabel()
    tw, th = dc.GetTextExtent(label)
    if not self.up:
        dx = dy = self.labelDelta
    dc.DrawText(label, (width-tw)//2+dx, (height-th)//2+dy)

buttons.GenButton.DrawLabel = _custom_draw_label
wx.Button = buttons.GenButton
buttons.GenButton.GetDefaultSize = staticmethod(_orig_Button.GetDefaultSize)

CAPESOLO_ROOT = os.path.dirname(__file__)
sys.path.append(CAPESOLO_ROOT)
os.chdir(CAPESOLO_ROOT)

from classes.main_frame import MainFrame
from classes.splash_screen import SplashScreen
from lib.common.defines import KERNEL32
from utils.update_yara import UpdateYara

log = logging.getLogger(__name__)
for handler in log.handlers[:]:
    log.removeHandler(handler)

ANALYSIS_CONF = os.path.join(CAPESOLO_ROOT, "analysis_conf")
MUTEX_NAME = "solo_mutex"


class CapesoloApp(wx.App):
    def OnInit(self):
        hWnd = windll.kernel32.GetConsoleWindow()
        windll.user32.ShowWindow(hWnd, 6)
        splash = SplashScreen(CAPESOLO_ROOT)
        splash.Show()
        time.sleep(2)
        screenWidth, screenHeight = wx.DisplaySize()
        frameWidth = int(screenWidth * 0.37)
        frameHeight = int(screenHeight * 0.75)
        if frameWidth < 710:
            frameWidth = 710

        frame = MainFrame(
            rootDir=CAPESOLO_ROOT, parent=None, size=wx.Size(frameWidth, frameHeight)
        )
        frameX = int(screenWidth * 0.01)
        frameY = int(screenHeight * 0.02)
        frame.SetPosition(wx.Point(frameX, frameY))
        frame.Show()
        # The Start panel scrolls vertically only, so a too-narrow frame clips its widest
        # always-visible row (the bottom action bar) rather than scrolling. Widen the frame if
        # the initial width does not give the Start panel's content its full width.
        startTab = frame.startTab
        chrome = frame.GetSize().width - startTab.GetClientSize().width
        needed = min(startTab.GetSizer().GetMinSize().width + chrome, screenWidth)
        if frame.GetSize().width < needed:
            frame.SetSize(wx.Size(needed, frameHeight))
        return True


def _seed_user_config():
    """Copy the packaged cfg.ini to the user (public) config path if it isn't there yet, so the
    user has an editable copy. Best-effort: a missing user file is fine (config_paths skips it)."""
    import shutil

    from CAPEsolo.capelib.config_paths import packaged_config_path, user_config_path

    user = user_config_path()
    if user.exists():
        return
    try:
        user.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(str(packaged_config_path()), str(user))
    except OSError:
        pass


def main():
    mutex = acquire_lock()
    try:
        _seed_user_config()
        parser = argparse.ArgumentParser(description="Capesolo utility functions.")
        parser.add_argument(
            "--update_yara",
            help="Update yara rules from CAPEv2 and community",
            action="store_true",
        )
        parser.add_argument(
            "--headless-analyze",
            dest="headless_analyze",
            help="Run a single headless analysis for the given sample path",
            type=str,
        )
        parser.add_argument(
            "--package",
            default="Auto-detect",
            help="Analysis package for headless mode (default: Auto-detect)",
        )
        parser.add_argument(
            "--options",
            default="",
            help=(
                "Comma-separated analyzer options for headless mode. "
                "idbg is rejected: interactive debugging needs the MCP server."
            ),
        )
        parser.add_argument(
            "--timeout",
            default=200,
            type=int,
            help="Analysis timeout in seconds for headless mode",
        )
        parser.add_argument(
            "--enforce-timeout",
            action="store_true",
            help="Force full timeout in headless mode",
        )
        parser.add_argument(
            "--headless-html-report",
            action="store_true",
            help="Generate HTML report on successful headless completion",
        )
        parser.add_argument(
            "--headless-json",
            action="store_true",
            help="Also print the JSON report to stdout (it is written to disk regardless)",
        )
        parser.add_argument(
            "--no-report",
            action="store_true",
            help="Skip report generation entirely on headless completion",
        )

        args = parser.parse_args()

        if args.update_yara:
            _ = UpdateYara(Path(CAPESOLO_ROOT))
            return 0

        if args.headless_analyze:
            try:
                from CAPEsolo.mcp_server import AnalysisJobManager
            except ImportError as e:
                print(f"Headless mode unavailable: {e}")
                return 1

            manager = AnalysisJobManager()
            # Refuse before anything is staged or detonated, so the operator gets the
            # reason immediately rather than watching a job stall to its timeout.
            if "idbg" in {
                opt.split("=", 1)[0].strip().lower()
                for opt in (args.options or "").split(",")
                if opt.strip()
            }:
                print(
                    "Interactive debugging is not available in headless mode - there is no "
                    "channel to drive the debugger, so the sample would stall at its first "
                    "breakpoint. Use the MCP server with interactive_debug=true instead."
                )
                return 1

            run = manager.run_single(
                sample_path=args.headless_analyze,
                package=args.package,
                options=args.options,
                timeout=args.timeout,
                enforce_timeout=args.enforce_timeout,
                run_from_current_directory=True,
            )
            if not run.get("accepted"):
                print(run.get("error", "Headless analysis was not accepted"))
                return 1

            job_id = run["job_id"]
            status = run["status"]
            state = status.get("state")
            print(f"job_id={job_id}")
            print(f"state={state}")
            if state != "completed":
                if status.get("error"):
                    print(status["error"])
                return 1

            # Report by default: the VM is reverted after a run, so finishing with nothing
            # but a job id throws the analysis away. stdout stays quiet unless asked,
            # because the report embeds strings for the target and every payload.
            if not args.no_report:
                results = manager.get_results(
                    job_id=job_id, include_strings=True, write_file=True
                )
                if results.get("written"):
                    print(f"report={results.get('report_path')}")
                else:
                    print(f"report write failed: {results.get('write_error', 'unknown error')}")

                if args.headless_json:
                    print(json.dumps(results.get("results", {}), indent=2))

            if args.headless_html_report:
                report = manager.render_html_report(job_id=job_id)
                print(json.dumps(report, indent=2))

            return 0

        app = CapesoloApp()
        app.MainLoop()
        return 0
    finally:
        release_lock(mutex)

def acquire_lock():
    mutex = KERNEL32.CreateMutexA(None, False, MUTEX_NAME)
    last_error = KERNEL32.GetLastError()
    if last_error == 183:
        print("Another instance is already running.")
        KERNEL32.CloseHandle(mutex)
        sys.exit(1)

    return mutex

def release_lock(mutex):
    KERNEL32.CloseHandle(mutex)


if __name__ == "__main__":
    sys.exit(main())
