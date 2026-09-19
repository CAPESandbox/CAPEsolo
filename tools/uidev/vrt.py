#!/usr/bin/env python3
"""Visual regression check: render the UI and diff it against a recorded baseline.

    python tools/uidev/vrt.py            # compare
    python tools/uidev/vrt.py --update   # re-record

Each shot in SHOTS is rendered by shoot.py in its own process (wx wants one frame per
process) and compared with tools/uidev/baseline/<name>.png pixel by pixel. Changed pixels
are written to an output directory as a red-on-grey diff so the move can be seen rather
than guessed at. A shot with no baseline yet is recorded instead of compared.

The baseline is recorded by CI on Windows, because wxMSW is what ships; a GTK render of the
same shot differs everywhere and comparing the two is meaningless. It also carries one
machine's font stack, so a different DPI or font package will shift text by a pixel and
report a large difference. Read the diff image before concluding anything: this is a review
aid, not a gate.

PNG handling is done here with zlib rather than through wx or Pillow, so a comparison needs
no display and no third-party package.
"""

import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
BASELINE = HERE / "baseline"

# (name, shoot.py target, theme, WxH, UIDEV_SECTIONS)
#
# Kept deliberately short. Every shot is a file in the repository forever, and the value is
# in covering each *kind* of surface once - the frame chrome, a card layout, a data grid,
# and the drawing primitives - not in photographing every panel.
SHOTS = (
    ("frame-dark", "frame", "dark", "1180x800", ""),
    ("frame-light", "frame", "light", "1180x800", ""),
    ("start-dark", "start", "dark", "1180x800", ""),
    ("behavior-dark", "behavior", "dark", "1180x800", ""),
    ("gallery-buttons-dark", "gallery", "dark", "1180x420", "buttons"),
    ("gallery-glyphs-dark", "gallery", "dark", "1180x260", "glyphs"),
    ("gallery-inputs-dark", "gallery", "dark", "1180x360", "toggles,inputs"),
    ("gallery-states-dark", "gallery", "dark", "1180x320", "states"),
    ("gallery-buttons-light", "gallery", "light", "1180x420", "buttons"),
)


# --- PNG -------------------------------------------------------------------


def read_png(path):
    """Return (width, height, rows) for an 8-bit non-interlaced PNG; rows are RGB bytes."""
    data = Path(path).read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError(f"{path}: not a PNG")

    offset = 8
    header = None
    pixels = bytearray()
    while offset < len(data):
        (length,) = struct.unpack(">I", data[offset : offset + 4])
        kind = data[offset + 4 : offset + 8]
        body = data[offset + 8 : offset + 8 + length]
        offset += 12 + length  # length, type, body, crc

        if kind == b"IHDR":
            width, height, depth, colour, _, _, interlace = struct.unpack(">IIBBBBB", body)
            if depth != 8 or interlace or colour not in (2, 6):
                raise ValueError(f"{path}: unsupported PNG (depth {depth}, colour {colour})")
            header = (width, height, 4 if colour == 6 else 3)
        elif kind == b"IDAT":
            pixels += body
        elif kind == b"IEND":
            break

    if header is None:
        raise ValueError(f"{path}: no IHDR")

    width, height, channels = header
    return width, height, _unfilter(zlib.decompress(bytes(pixels)), width, height, channels)


def _unfilter(raw, width, height, channels):
    """Undo the per-row PNG filters, returning one RGB bytearray per row."""
    stride = width * channels
    previous = bytearray(stride)
    rows = []

    for y in range(height):
        start = y * (stride + 1)
        filterType = raw[start]
        line = bytearray(raw[start + 1 : start + 1 + stride])

        if filterType == 1:  # Sub
            for i in range(channels, stride):
                line[i] = (line[i] + line[i - channels]) & 0xFF
        elif filterType == 2:  # Up
            for i in range(stride):
                line[i] = (line[i] + previous[i]) & 0xFF
        elif filterType == 3:  # Average
            for i in range(stride):
                left = line[i - channels] if i >= channels else 0
                line[i] = (line[i] + ((left + previous[i]) >> 1)) & 0xFF
        elif filterType == 4:  # Paeth
            for i in range(stride):
                left = line[i - channels] if i >= channels else 0
                upLeft = previous[i - channels] if i >= channels else 0
                up = previous[i]
                estimate = left + up - upLeft
                distLeft = abs(estimate - left)
                distUp = abs(estimate - up)
                distUpLeft = abs(estimate - upLeft)
                if distLeft <= distUp and distLeft <= distUpLeft:
                    nearest = left
                elif distUp <= distUpLeft:
                    nearest = up
                else:
                    nearest = upLeft
                line[i] = (line[i] + nearest) & 0xFF
        elif filterType != 0:
            raise ValueError(f"unknown PNG filter {filterType}")

        previous = line
        if channels == 4:  # drop alpha, the harness never renders transparency
            line = bytearray(b for index, b in enumerate(line) if index % 4 != 3)
        rows.append(line)

    return rows


def write_png(path, rows, width):
    """Write RGB *rows* as a PNG, all rows unfiltered."""
    raw = bytearray()
    for row in rows:
        raw.append(0)
        raw += row

    def chunk(kind, body):
        return (
            struct.pack(">I", len(body))
            + kind
            + body
            + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", width, len(rows), 8, 2, 0, 0, 0)
    Path(path).write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(bytes(raw), 6))
        + chunk(b"IEND", b"")
    )


# --- comparison ------------------------------------------------------------


def render(name, target, theme, size, sections, out):
    env = dict(os.environ, UIDEV_SECTIONS=sections)
    result = subprocess.run(
        [
            sys.executable,
            str(HERE / "shoot.py"),
            target,
            "--theme",
            theme,
            "--size",
            size,
            "-o",
            str(out),
        ],
        cwd=str(REPO),
        env=env,
        capture_output=True,
        text=True,
    )
    # wxGTK segfaults on teardown under Xvfb, after the file is written. The file existing
    # is the real success signal, not the exit status.
    if not out.exists():
        raise SystemExit(
            f"{name}: shoot.py produced nothing\n{result.stdout}\n{result.stderr}"
        )


def compare(baseline, candidate, diffPath):
    """Return (changedPixels, totalPixels), writing a diff image when anything changed."""
    baseWidth, baseHeight, baseRows = read_png(baseline)
    newWidth, newHeight, newRows = read_png(candidate)

    if (baseWidth, baseHeight) != (newWidth, newHeight):
        return None, f"size changed: {baseWidth}x{baseHeight} -> {newWidth}x{newHeight}"

    changed = 0
    diffRows = []
    for baseRow, newRow in zip(baseRows, newRows):
        out = bytearray(len(baseRow))
        for x in range(0, len(baseRow), 3):
            if baseRow[x : x + 3] == newRow[x : x + 3]:
                # Keep the unchanged picture as a dim grey ghost so the red is placeable.
                grey = (baseRow[x] + baseRow[x + 1] + baseRow[x + 2]) // 6 + 40
                out[x] = out[x + 1] = out[x + 2] = grey
            else:
                changed += 1
                out[x], out[x + 1], out[x + 2] = 255, 40, 40
        diffRows.append(out)

    if changed:
        write_png(diffPath, diffRows, baseWidth)
    return (changed, baseWidth * baseHeight), None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--update", action="store_true", help="re-record the baseline")
    parser.add_argument("--out", default="/tmp/capesolo-vrt", help="where diffs are written")
    parser.add_argument(
        "--tolerance",
        type=float,
        default=0.1,
        help="percentage of pixels allowed to differ before a shot fails",
    )
    parser.add_argument("--only", default="", help="comma-separated shot names")
    args = parser.parse_args()

    wanted = [name.strip() for name in args.only.split(",") if name.strip()]
    shots = [shot for shot in SHOTS if not wanted or shot[0] in wanted]
    if not shots:
        raise SystemExit(f"--only matched nothing; known: {[s[0] for s in SHOTS]}")

    outDir = Path(args.out)
    outDir.mkdir(parents=True, exist_ok=True)
    BASELINE.mkdir(parents=True, exist_ok=True)
    workDir = Path(tempfile.mkdtemp(prefix="capesolo-vrt-"))
    failures = []

    for name, target, theme, size, sections in shots:
        candidate = workDir / f"{name}.png"
        render(name, target, theme, size, sections, candidate)
        recorded = BASELINE / f"{name}.png"

        if args.update or not recorded.exists():
            shutil.copyfile(candidate, recorded)
            print(f"recorded {name}")
            continue

        counts, error = compare(recorded, candidate, outDir / f"{name}.diff.png")
        if error:
            failures.append(f"{name}: {error}")
            print(f"FAIL {name}: {error}")
            continue

        changed, total = counts
        percentage = 100.0 * changed / total
        if percentage > args.tolerance:
            failures.append(f"{name}: {percentage:.2f}% of pixels changed")
            print(f"FAIL {name}: {percentage:.2f}% changed -> {outDir / (name + '.diff.png')}")
        else:
            print(f"ok   {name}: {percentage:.2f}% changed")

    shutil.rmtree(workDir, ignore_errors=True)
    if failures:
        print(f"\n{len(failures)} shot(s) moved. Look at the diffs in {outDir}.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
