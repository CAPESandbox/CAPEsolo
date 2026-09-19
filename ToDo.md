# ToDo

## Windows review findings (2026-09-19)

First pass of the GUI rework actually run on real wxMSW (Windows 11, build 26200,
wxPython 4.3.1 / wxWidgets 3.3.3), via `tools/uidev/` (smoke.py, shoot.py) plus the
`pytest` suite. All fixed in the working tree; re-run `tools/uidev/smoke.py` and
`pytest tests/` after pulling to confirm.

Confirmed working, no change needed:
- wxPython 4.3.1 installed satisfies the `>=4.3.0` pin.
- `smoke.py` passes in full, including the modal-loop checks (`UIDEV_MODAL=1`)
  that Xvfb could never run.
- Windows 11 native dark-mode opt-in is taken (`native_dark_mode_allowed()` ->
  `(True, "Windows build 26200")`) and a live right-click context menu (custom_grid's
  Copy menu) renders dark with legible white text.
- All existing `pytest tests/` pass unchanged (187 tests).

Bugs found and fixed:
- **`classes/main_frame.py` `InitUi()`**: `self.panel.SetSizer(sizer)` was never
  followed by a `Layout()` call. `SetSizer()` does not apply the layout itself, so
  `self.panel` (and everything in it - tabBar, notebook, statusBar) stayed collapsed
  to placeholder sizes until something later resized the frame to a genuinely
  different size. `cli.py`'s startup width correction reads `startTab.GetClientSize()`
  right after `Show()`, before that ever happened, so it computed a wildly inflated
  "chrome" value and launched the window far wider than designed - reproduced on a
  2560x1440 display: **2028px actual vs. ~947px intended (37% of screen)**. Fixed by
  adding `self.panel.Layout()` right after `SetSizer()`; confirmed width computation
  now lands at ~1117px. Fixes the width-sanity part of the "One real analysis" item
  below.
- **`cli.py` `OnInit()`**: native dark mode was enabled/disabled from `theme.is_dark()`
  before the theme was ever read from `cfg.ini` (that only happened later, inside
  `MainFrame.InitUi()`). A user with `[gui] theme = light` still got the hardcoded
  `DEFAULT_THEME` (dark) at this point, permanently enabling Windows dark-mode chrome
  for a light-themed session - the opt-in cannot be reversed once windows exist. Fixed
  by calling `theme._init()` (idempotent) before `_EnableNativeDarkMode()`.
- **`classes/ui_kit.py` `Dialog`/`dialog_buttons()`**: switching from `wx.Button` +
  `SetDefault()`/`CreateStdDialogButtonSizer` to owner-drawn `ui.Button` dropped
  Enter-to-submit, since there is no native "default button" wxWidgets can find among
  owner-drawn controls. Affected `SettingsDialog`, and `PrototypeDialog` /
  `BreakpointDialog` in `debug_controls.py`. Fixed generically in
  `Dialog._OnCharHook()`: Enter/Numpad-Enter now fires the dialog's `wx.ID_OK` button
  via `Button._Fire()`, unless focus is on a `Button` (which already handles its own
  Enter) or a multiline `wx.TextCtrl` (where Enter should insert a newline).
- **`classes/start_panel.py` `_DownloadCredentialsDialog`**: rebound `EVT_CHAR_HOOK` to
  its own handler that only understood Enter and called `event.Skip()` for everything
  else, including Escape - the comment claiming "Escape still cancels via the dialog's
  built-in ID_CANCEL handling" was wrong; there is no such native handling for
  owner-drawn buttons (see above). Fixed by deleting the override: the base
  `ui.Dialog._OnCharHook` (now handling both Enter and Escape) covers it.
- **`classes/process_tree_window.py` `InitUI()`**: called `apply_theme(self)` *after*
  `SetWindowTheme(hwnd, "", "")` on the tree control, and `apply_theme()` walks every
  child and unconditionally re-applies `DarkMode_Explorer` to it - silently undoing
  the override that exists specifically to keep the tree's +/- expander icons visible
  against the dark palette. Fixed by moving the `SetWindowTheme(..., "", "")` call to
  run after `apply_theme(self)` instead of before.
- **`classes/ui_kit.py` `Radio._Group()`**: the sibling-group lookup broke out of its
  scan-for-group-start loop on reaching `self` *before* checking whether `self` itself
  starts a new group, so any radio button other than the first `RB_GROUP` radio under
  a parent computed the wrong group (grabbed the *previous* group's members instead of
  its own). Latent today - no current screen puts two radio groups on one parent - but
  would have silently broken selection/keyboard nav for the first panel that does.
  Fixed the loop ordering; verified `_Group()` on a 2-group `[A(group), B, C(group), D]`
  layout now returns `[C, D]` for C (was `[A, B]`) and still returns `[A, B]` for A.
- **`classes/ui_kit.py` `TabBar._OnLeave`**: never reset the cursor set by `_OnMotion`
  (`CURSOR_HAND` while hovering a tab), so moving off a hovered tab straight onto the
  page content left a stuck hand cursor. Fixed by resetting to `CURSOR_ARROW` in
  `_OnLeave`.
- **`classes/theme.py` `_style_widget()`**: only styled `wx.Panel` backgrounds, so a
  `wx.SplitterWindow` (used by `NetworkPanel` and `JsConsolePanel`) was left at the OS
  default background. `NetworkPanel`'s empty-state `ui.Notice` is parented directly to
  its splitter and reads the mismatched background at construction time, producing a
  visible seam around the card on the dark palette. Fixed by giving
  `wx.SplitterWindow` the same `BG_CARD` treatment as panels.
- **`classes/theme.py` `_style_widget()`**: the "force `BORDER_SIMPLE` on every input"
  block (added because MSW does not theme a bare `wx.TextCtrl` border) walks every
  `wx.TextCtrl` in the app, including the one inside `ui_kit.Field` - which builds its
  `TextCtrl` with `BORDER_NONE` on purpose and draws its own rounded, focus-aware border
  around it. Forcing `BORDER_SIMPLE` back on drew a second, square native border inside
  the rounded one: a plain grey box around the text in every `ui.Field` (Start tab,
  behaviour filters, credentials dialog, ...), most visible on the light palette against
  its near-white fill. Fixed by skipping the border-forcing for a `TextCtrl` whose parent
  is a `ui_kit.Field`.
- **`classes/behavior_panel.py` `ApplyAlternateRowShading()`**: `RefreshTheme()`
  (`main_frame.py`) calls this by name after a live theme toggle to rebuild per-row
  colouring `apply_theme()` cannot reach through its generic walk. It only ever restriped
  *uncategorised* rows, though - the behaviour-category row colours `AddTableData()` sets
  via `SetCellBackgroundColour()` are baked-in `wx.Colour` values that do not follow
  `BEHAVIOR_CATEGORY_COLORS` being mutated to the new palette, so a Dark -> Light toggle
  left every categorised call row painted with its old dark, near-black fill under the
  new palette's near-black text - unreadable. Fixed by recording each row's category in
  `AddTableData()` (`self._rowCategories`) and having `ApplyAlternateRowShading()`
  recolour categorised rows from the current `BACKGNDCLR` before falling back to the
  plain stripe for rows with no category colour.
- **`classes/theme.py` `apply_theme()`**: recolouring a widget (`SetBackgroundColour`,
  etc.) does not by itself repaint it, and `RefreshTheme()`'s single top-level
  `self.Refresh()` does not reach separate native child windows on MSW (each is its own
  HWND; `Refresh()` there only invalidates that one window). `tabBar`/`statusBar` already
  had to be refreshed by hand for this reason - same bug, just not yet given the same
  treatment everywhere else. Reported as: the Start tab's "Download by hash" path field
  (`ui.Field`, disabled by default) kept the old palette's `BG_DISABLED` fill after a
  Dark <-> Light toggle, since nothing told that specific owner-drawn control to
  repaint. Fixed by having `apply_theme()` call `widget.Refresh()` on every widget it
  visits during its walk, which also made the hand-picked `tabBar`/`statusBar`/
  `self.panel` refreshes in `RefreshTheme()` mostly redundant (`self.panel` still needs
  one, since its colour is corrected *after* the walk already refreshed it once with the
  wrong one) - trimmed accordingly.
- **`classes/theme.py` `_style_widget()`**: the repaint fix above turned out not to be
  the whole story for the download-path field - a screenshot after the fix still showed
  it with the OS's pale disabled fill in dark mode. Two compounding bugs, both specific
  to a *disabled* `wx.TextCtrl`: (1) `apply_native_theme()` puts every native control
  under `SetWindowTheme(..., "DarkMode_Explorer"/"Explorer", ...)`; Windows paints a
  themed Edit control's disabled background itself and ignores whatever
  `SetBackgroundColour`/`SetForegroundColour` wx asks for, so the colour never reached
  the control in the first place, in either palette - not a stale repaint. (2) even set
  correctly, the generic `wx.TextCtrl` branch always applied the *enabled* `BG_INPUT`/
  `FG_PRIMARY` pair regardless of `IsEnabled()`, so a disabled field's native control
  never matched the `BG_DISABLED` backdrop `ui.Field`'s own owner-drawn wrapper already
  paints around it. Fixed (1) by stripping the subtheme instead, for a `wx.TextCtrl`
  parented to a `ui.Field` specifically (`SetWindowTheme(hwnd, "", "")`, same technique
  `process_tree_window.py` already uses on its tree for the same reason), which falls
  back to classic GDI rendering that does honour our colours in every state; fixed (2) by
  branching the generic `wx.TextCtrl` styling on `w.IsEnabled()` to pick `BG_DISABLED`/
  `FG_DISABLED` instead of the enabled pair.
- **`classes/ui_kit.py` `Field`**: still wrong after the two fixes above and a real
  restart, so (1)'s diagnosis was itself wrong - and testing confirmed it: the subtheme
  was never the cause. The actual mechanism is plainer and platform-level, not
  UxTheme-specific at all - Windows always paints a `WS_DISABLED` Edit control's
  background through `WM_CTLCOLORSTATIC`, not `WM_CTLCOLOREDIT`, and `WM_CTLCOLORSTATIC`
  ignores whatever brush `SetBackgroundColour`/`SetForegroundColour` supplies; stripping
  the subtheme (undone above) never touched that message-routing decision. Fixed at the
  actual source instead: a new `_FieldTextCtrl(wx.TextCtrl)` used for `Field.ctrl` that
  overrides `Enable()`/`Disable()` to toggle `SetEditable()` rather than the real wx
  enabled state, so the control never goes `WS_DISABLED` and always routes through
  `WM_CTLCOLOREDIT`; `IsEnabled()` is overridden to mirror `IsEditable()`, so
  `Field._OnPaint` and theme.py's per-widget styling (which both ask "is this control
  enabled" to choose `BG_INPUT`/`BG_DISABLED`) keep working unchanged. Only two call
  sites in the whole app `Enable()`/`Disable()` a `Field.ctrl` directly
  (`downloadPathInput`, `hashInput` in `start_panel.py`), so the blast radius is small.

## Windows verification (GUI modernization)

The GUI rework on `gui-modernize` was written and rendered on **wxGTK 4.2.4
(wxWidgets 3.2.9) under Xvfb on Linux**. The owner-drawn controls in
`classes/ui_kit.py` are platform-neutral, but nothing below has been seen on
wxMSW. All of it needs a pass on a real Windows box.

### Environment

- [x] Confirm the installed wxPython is **>= 4.3.0** (`python -c "import wx; print(wx.version())"`).
      `pyproject.toml` pins it; the Linux dev box only had 4.2.4, which lacks the
      dark mode opt-in below. Confirmed 4.3.1 / wxWidgets 3.3.3 on Windows 11.

### Native dark mode opt-in

`CapesoloApp._EnableNativeDarkMode()` in `CAPEsolo/cli.py` calls
`wx.App.MSWEnableDarkMode()` before the first window is created. It covers the
widgets we cannot owner-draw: scrollbars, tooltips, the grid cell editor and the
common dialogs. It is guarded with `getattr`, so on 4.2.x and on GTK it silently
does nothing.

**It is now skipped on Windows 10** (`theme.native_dark_mode_allowed()`, build
< 22000). Reported from a Windows 10 guest: with the opt-in taken, right-click
menus render white text on a white background. wxMSW draws the items itself once
dark mode is on and fills them from the `DarkMode::Menu` /
`DarkMode_ImmersiveStart::Menu` visual-style classes, which Windows 11 added; on
10 the lookup fails, the system paints the background light and the text is drawn
light. A light menu is off-theme but legible, so the whole opt-in is declined
there. Override per machine with `[gui] native_dark_mode = always | never | auto`.

- [x] **Windows 11**: confirm the opt-in is taken (the log says "Enabling native
      dark mode: Windows build NNNNN") and that right-click menus are dark and
      legible in every menu we raise - `custom_grid.py`, `process_tree_window.py`,
      `patch_dialog.py`, `debug_controls.py`, `start_panel.py`. Confirmed taken on
      build 26200 and `custom_grid.py`'s Copy menu renders dark/legible; the other
      menus (`process_tree_window.py`, `patch_dialog.py`, `debug_controls.py`,
      `start_panel.py`) still want an eyeball pass.
- [ ] **Windows 10**: confirm menus are light and readable, and that nothing else
      regressed by losing the opt-in. Specifically scrollbars in the Start tab and
      in every grid - those come from `apply_native_theme()`'s `DarkMode_Explorer`
      call, not from the opt-in, so they should still be dark.
- [ ] **Windows 10, forced on** (`native_dark_mode = always`): confirm the escape
      hatch works and reproduce the menu problem, so the version cut-off can be
      revisited when wxWidgets or the OS changes.
- [x] Decided: popup menus are **not** owner-drawn by CAPEsolo on Windows 10. They stay
      system-drawn and light there. `wxMenuItem` does accept `SetBackgroundColour` /
      `SetTextColour` / `SetFont` on MSW, which would darken the items, but the frame,
      gutter and border around them stay system-drawn, and a dark strip inside a light
      shell is not worth the code. Not a wanted feature.
- [ ] Confirm the enum resolution picked a real constant. The code probes
      `wx.MSW_DARK_MODE_ALWAYS` then `wx.App.DarkMode_Always`; if neither exists
      it falls back to the no-argument call, which follows the *system* theme
      rather than forcing dark. Fix the name once the real one is known.
- [ ] Check what else it fixes and what it misses. Known upstream gaps: some
      TaskDialog-based dialogs still render light, and wxTimePickerCtrl /
      wxDatePickerCtrl / wxCalendarCtrl / the Windows 10 print dialog are
      documented as unsupported.
- [ ] Grid cell editor (double-click a cell in Configs / Payloads / Yara /
      Network / PE) - the in-place editor is a native `wx.TextCtrl`.
- [ ] Decide whether a theme toggle should prompt for a restart. The opt-in
      cannot be reversed once windows exist, so toggling light -> dark leaves the
      native widgets light until the next launch.

### Rendering

- [ ] Screenshot every tab in both palettes and compare against the GTK renders.
- [ ] Disabled states. Native MSW controls ignore `SetForegroundColour` when
      disabled, which is what made the old UI illegible. Any widget that is still
      native and gets `Disable()`d will show the same grey-on-grey.
- [ ] DPI. Check at 100%, 150% and 200% scaling. The geometry was verified on
      Linux by forcing `theme.dip()` to 2x (padding, radii, the tab indicator and
      the status bar all scale, nothing clips), but `FromDIP` returns the real
      scale only on a display that has one.
- [ ] Fonts. `theme._resolve_face()` picks the first installed face from a
      preference list; confirm it lands on Segoe UI / Cascadia Mono and not a
      fallback.
- [ ] `ui_kit.Picker` popup placement and dismissal on a multi-monitor setup.
- [ ] `ListCtrl` column headers. Under GTK the header renders dark even on the
      light palette - it is drawn by the toolkit, not by us. On wxMSW it is a
      native header control; check whether it follows `MSWEnableDarkMode` or
      stays light against the dark palette (Exports, Patch History, and every
      debugger list).
- [ ] Control borders. `BORDER_STRONG` was raised in both palettes to clear 3:1
      against the card, which is what outlines fields and pickers. Confirm it
      reads as an outline and not as a heavy box on MSW.

### Functional

- [ ] One real analysis: pick a target, Launch, let it run, Kill, then
      Auto-process and open the reports. The Start tab layout changed
      (`StartPanel` is now a `wx.Panel` wrapping a `ScrolledPanel`) and
      `cli.py` still reads `frame.startTab.GetSizer().GetMinSize()` at startup to
      widen the frame - [x] confirmed sane (~1117px on a 2560px display) after
      fixing the missing `self.panel.Layout()` in `main_frame.py` (see Windows
      review findings above); the live analysis run itself is still open.
- [ ] The analyzer option string. `AddTargetOptions()` now reads ui_kit controls;
      the headless smoke test covers it, but confirm against a live capemon run.
- [ ] Debugger tab: breakpoint rows are `ui.Picker` / `ui.Field` now.
- [ ] `DownloadKeysDialog` - it is raised from `_InitDownloadBroker` via
      `CallAfter` at startup and is modal.
- [x] Dialog buttons. `ui.dialog_buttons()` relies on wxDialog's built-in
      wxID_OK / wxID_CANCEL handling firing for owner-drawn buttons. Verified on
      GTK, including a dialog-level handler refusing to close; confirm on MSW for
      the patch, breakpoint, prototype and credentials dialogs. On MSW, closing via
      a real click works, but Enter-to-submit did not (see Windows review findings
      above) - fixed in `Dialog._OnCharHook()`.

### Accessibility and keyboard

`ui_kit` attaches a `wx.Accessible` to each control so screen readers get a role,
a name and a state instead of "window". None of it can be exercised on the dev
box: wxGTK is built without `wxUSE_ACCESSIBILITY`, so `wx.Accessible()` raises
`NotImplementedError` and the code latches the whole layer off. **MSAA is
therefore completely unverified.**

- [ ] Run NVDA (or Narrator) over the Start tab. Every button, checkbox, radio
      button, picker, tab and card should announce its role and its state.
- [ ] Confirm `_PickerAccessible` declining its name is right on MSW - it is meant
      to let the reader fall back to the neighbouring "Package" / "Path:" label.
- [ ] Confirm the tab strip reports as a page tab list with the open tab selected.
- [ ] Mnemonics. `&Launch` underlines the L and Alt+L activates it. On MSW the
      underline is usually hidden until Alt is pressed; ours is always drawn.
      Decide whether to follow the platform convention.
- [ ] Tab order through the Start tab and the dialogs. Not verified anywhere -
      Xvfb has no window manager to drive focus.
- [ ] High-contrast mode. Windows overrides system colours; the app draws its own,
      so it will ignore the setting entirely. Decide whether that is acceptable.

### Rendering (continued)

- [ ] Glyphs. They are stroked from a vector table at paint time with a 1.6 DIP
      pen. Check they do not turn muddy at 100% scaling on a real display, and
      that the filled ones (play, stop, settings) read correctly at 14 DIP.
- [ ] `ui.Notice`. The empty states are laid out for a results pane; confirm the
      wrapped detail line does not clip in a narrow window.

## Tooling

`tools/uidev/` builds the UI off screen and is wired into CI
(`.github/workflows/ci.yml`). The `ui` job runs on `windows-latest`, so the
renders and the smoke test are wxMSW - the toolkit that ships. The `tests` job
stays on Linux: it never opens a window.

The harness still runs on Linux under `xvfb-run` and is the faster loop for
layout work, but it is a GTK approximation: native controls are drawn by GTK,
nothing MSW-only can be exercised, and the live modal-dialog checks are skipped
there (wxGTK's nested loop cannot be ended from code with no window manager).

- [ ] Record the visual regression baseline from the first green Windows run.
      The GTK baseline was deleted; `vrt.py` records any shot it has no baseline
      for, and the `ui-renders` artifact carries the result. Commit those PNGs to
      `tools/uidev/baseline/`.
- [ ] Re-shoot `docs/images/frame-dark.png` and `frame-light.png` from the
      Windows renders. The committed ones are GTK and do not show what a user
      sees.
- [ ] Decide whether the `ui` CI job should gate on `vrt.py` once the baseline is
      stable. It is `continue-on-error` today and only uploads the renders.


## Deferred cleanup

- [x] `FlatNotebook` styling branch deleted from `classes/theme.py`.
- [x] `classes/status_bar.py`: pixel constants now go through `theme.dip()`.
- [x] `wx.Button = buttons.GenButton` monkeypatch removed from `cli.py`, along with
      the label-sniffing colour heuristic in `theme.py` it fed.
- [x] Raw pixel literals in the panels replaced with the `SP_*` spacing scale.
