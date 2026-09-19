# uidev - UI development harness

CAPEsolo runs on Windows. These scripts build the real panels off screen so a UI change can
be reviewed as a picture, and so a broken panel is caught without launching the application.

They run on both Windows and Linux. **Windows is the reference platform** - it is what
ships, and it is what CI uses. Linux + Xvfb still works and is the faster loop for layout
work, with the caveats at the bottom.

Nothing here is imported by the application. It is developer tooling and is not shipped in
the wheel.

## Requirements

* wxPython 4.2+ (`pip install wxPython` on Windows, `apt install python3-wxgtk4.0` on
  Debian/Ubuntu - there is no manylinux wheel).
* On Linux only: `xvfb` for the off-screen X server (`apt install xvfb`), and every command
  below prefixed with `xvfb-run -a`.
* Nothing else. The Windows-only and heavyweight imports (pywin32, bson, gevent, sflock,
  yara) are answered by `winstubs.py`, so no CAPEsolo runtime dependency has to be
  installed - including on Windows, so a render never depends on which ones a host has.

## Scripts

### `smoke.py` - does every panel still build?

```
python tools\uidev\smoke.py
```

Constructs MainFrame and each result panel in both themes, switches the theme at runtime,
opens the dialogs, drives four real modal loops, and reports the first exception with a
traceback. Exit code is non-zero on failure. Takes about 35 s. This is the check to run
after any widget change.

The modal-loop checks are skipped where there is no window manager: under Xvfb wxGTK's
nested loop cannot be ended from code, so they would hang rather than fail. `UIDEV_MODAL=1`
forces them; `UIDEV_TIMEOUT` (seconds, default 300) arms a watchdog that dumps every
thread's stack and exits, so a stall names the line it stalled on.

### `shoot.py` - render one target to a PNG

```
python tools\uidev\shoot.py frame --theme dark -o C:\temp\frame.png
python tools\uidev\shoot.py yara  --theme light --size 1180x800 -o C:\temp\yara.png
```

Targets: `frame`, `start`, `gallery`, and one per result panel (`behavior`, `configs`,
`debugger`, `js`, `network`, `payloads`, `signatures`, `strings`, `target`, `yara`).

Pass an absolute path to `-o`: the script chdirs into the package directory, the way the
application does.

On Linux, a segfault printed *after* the path line is a wxGTK teardown artifact under Xvfb;
the PNG is already written. Filter it with `| grep -vi segmentation` in scripts.

### `gallery.py` - the ui_kit specimen sheet

Not run directly - it is the `gallery` target of `shoot.py`. Every `ui_kit` primitive in
every state (idle/hover/disabled, checked/unchecked, expanded/collapsed, all three notice
kinds, every glyph) on one page, so a change to the drawing code is checked at a glance.

A window cannot be made taller than the display work area, so the full sheet does not fit
in one capture. `UIDEV_SECTIONS` selects a subset:

```
set UIDEV_SECTIONS=glyphs,states
python tools\uidev\shoot.py gallery --size 1180x520 -o C:\temp\glyphs.png
```

Sections: `tabs`, `buttons`, `glyphs`, `toggles`, `inputs`, `states`, `surfaces`.

### `vrt.py` - visual regression

```
python tools\uidev\vrt.py            # compare against tools\uidev\baseline
python tools\uidev\vrt.py --update   # re-record the baseline
```

Renders the shot list in `vrt.py`, compares each PNG with the recorded baseline pixel by
pixel, and writes the changed pixels to `--out` as a red-on-grey diff image. A shot with no
baseline is recorded instead of compared. Exit code is non-zero if any shot moved by more
than `--tolerance` (default 0.1% of pixels).

**The baseline is wxMSW.** It is recorded by CI on `windows-latest`; a Linux/GTK render will
differ everywhere and comparing the two says nothing. It also carries one machine's font
stack, so even on Windows a different DPI or font package shifts text by a pixel and lights
the whole image up - **a mismatch is a prompt to look at the diff image, not a failure on
its own**. This is why CI does not gate on it; it renders the same shots and uploads them
as artifacts.

### `dpishot.py` - fake a HiDPI display

```
python tools\uidev\dpishot.py frame -o C:\temp\frame-2x.png
```

Multiplies what `theme.dip()` returns and scales every font in `theme._FONTS`, rather than
relying on a display scale the harness cannot set. It catches hardcoded pixel values that
would not scale on a 150%/200% display. It is an approximation, not a substitute for a real
HiDPI machine.

### `winstubs.py`

The import hook the other scripts install. Appended to the end of `sys.meta_path`, so it
only sees modules that every real finder already declined. `CAPEsolo`, `wx` and `msvcrt`
are never stubbed - the first two must fail loudly, and stubbing `msvcrt` makes the
stdlib's `subprocess` take its Windows path and then fail to find `_winapi`.

It also redirects the home directory to a fixed path (`C:\capesolo-uidev-home`, or
`/tmp/capesolo-uidev-home`), because the Start tab renders a download path derived from it
and the account name would otherwise end up in the baseline. Off Windows it additionally
fabricates `%SystemRoot%` and friends, which the analyzer modules read at import time; on
Windows those are left alone.

## Caveats

* **On Linux, native controls (combo popups, grid scrollbars, the ListCtrl header) are
  drawn by GTK, not Windows.** Everything `ui_kit` draws is identical on both. Anything
  MSW-only - the native dark mode opt-in, popup menu theming, DPI awareness - cannot be
  checked there at all.
* `PackageDropdown()` lists `modules\packages`; if that directory is absent the package
  picker only ever offers "Auto-detect" in a render. Harness artifact, not a bug.
* The harness writes its config to a temp directory (`CAPESOLO_CFG`), so a run cannot touch
  a real `cfg.ini`.
