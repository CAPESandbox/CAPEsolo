"""Shared VirusTotal helpers for the Info and Payloads tabs.

vt_lookup/vt_upload do blocking network calls, so they run on a daemon thread and the result is
marshalled back to the UI thread with wx.CallAfter - the same pattern start_panel uses for downloads.
These are the GUI's own (post-launch) VT calls: they use the configured community key from cfg.ini
if present, otherwise the embedded public key. The private/encrypted download key is never used here.
"""

import configparser
import os
import time
from contextlib import suppress
from pathlib import Path
from threading import Thread

import wx

from CAPEsolo.capelib.config_paths import config_paths
from CAPEsolo.capelib.virustotal import vt_lookup, vt_upload

from . import ui_kit as ui

_community_key_cache = None  # None = not read yet; "" = read, none configured


def _community_key():
    """The plaintext VT community key for the GUI's own lookups/uploads: env
    CAPESOLO_VT_COMMUNITY_KEY wins, else [virustotal] community_key in cfg.ini. "" -> public key."""
    global _community_key_cache
    if _community_key_cache is None:
        value = os.environ.get("CAPESOLO_VT_COMMUNITY_KEY", "").strip()
        if not value:
            config = configparser.ConfigParser()
            with suppress(configparser.Error):
                config.read(config_paths())
            value = config.get("virustotal", "community_key", fallback="").strip()
        _community_key_cache = value
    return _community_key_cache

# Session cache keyed by sha256 so re-clicking, or looking up the same hash on both the Info tab and
# a payload, does not re-hit VT. The public key is shared and rate-limited (~4/min), so this matters.
# Successful and not-found results are kept for the session; error results (429 / connection) are
# kept only briefly, so a genuine retry is possible once the shared quota frees.
_vt_cache = {}          # sha256 -> (timestamp, result)
_VT_ERROR_TTL = 60      # seconds an error result is served from cache before a re-lookup is allowed


def seed_vt_cache(sha256, result):
    """Pre-populate the lookup cache with a VT result obtained elsewhere - specifically the download
    broker fetching info with the analyst's key at download time - so the Info tab shows it without a
    (throttled) public-key request. Only successful results are seeded."""
    if sha256 and result and not result.get("error"):
        _vt_cache[sha256] = (time.time(), result)


def peek_vt_cache(sha256):
    """Return a cached VT result for *sha256* WITHOUT making a request, or None. Only definitive
    results (not transient errors) are returned, so callers can display them by default - e.g. the
    Info tab showing download-time VT info without spending a lookup."""
    entry = _vt_cache.get(sha256)
    if entry is not None:
        _, result = entry
        if result and not result.get("error"):
            return result
    return None


def cached_vt_lookup(sha256):
    entry = _vt_cache.get(sha256)
    if entry is not None:
        ts, result = entry
        if not result.get("error") or (time.time() - ts) < _VT_ERROR_TTL:
            return result
    result = vt_lookup(sha256, apikey=_community_key())
    _vt_cache[sha256] = (time.time(), result)
    return result


def run_vt_lookup_async(sha256, on_done):
    """Look up *sha256* off the UI thread (cached) and deliver the result dict via on_done(result)."""

    def worker():
        result = cached_vt_lookup(sha256)
        wx.CallAfter(on_done, result)

    Thread(target=worker, daemon=True).start()


def run_vt_upload_async(path, sha256, on_done):
    """Upload *path* off the UI thread and deliver the result dict via on_done(result)."""

    def worker():
        result = vt_upload(str(path), sha256 or "", apikey=_community_key())
        if sha256 and not result.get("error"):
            _vt_cache.pop(sha256, None)  # it's on VT now; a later lookup should re-query
        wx.CallAfter(on_done, result)

    Thread(target=worker, daemon=True).start()


def confirm_vt_upload(window, path):
    """Confirm a publish to VirusTotal. Returns True only if the user explicitly agrees."""
    msg = (
        f"Upload '{Path(path).name}' to VirusTotal?\n\n"
        "The file will be sent to VirusTotal and become publicly downloadable to their "
        "community. This cannot be undone."
    )
    return (
        ui.message(msg, "Upload to VirusTotal", wx.YES_NO | wx.ICON_WARNING, window) == wx.YES
    )


def format_vt_rows(result):
    """Compact (label, value) rows for a vt_lookup result. Error dicts return [] (caller shows msg)."""
    if result.get("error"):
        return []
    if not result.get("found"):
        return [("VirusTotal", "Not found")]

    rows = []
    if not result.get("summary") and not result.get("detection"):
        rows.append(("VirusTotal", "Present, analysis pending"))
    candidates = [
        ("VT Detections", result.get("summary")),
        ("VT Detection", result.get("detection")),
        ("VT First Seen", result.get("first_seen")),
        ("VT Last Seen", result.get("last_seen")),
        ("VT Link", result.get("permalink")),
    ]
    rows.extend((label, str(value)) for label, value in candidates if value)
    return rows
