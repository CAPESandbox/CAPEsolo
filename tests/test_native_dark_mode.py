"""Tests for the wxMSW dark mode opt-in decision.

The opt-in is all or nothing and one part of it - popup menus - is broken on Windows 10,
so the decision is made before the call. It cannot be exercised on the dev box, hence
these: they pin the rule itself, with the platform faked.

No display and no wx.App needed:

    ./.venv/Scripts/python.exe -m pytest tests/test_native_dark_mode.py
"""

from collections import namedtuple

import pytest

from CAPEsolo.classes import theme

WindowsVersion = namedtuple("WindowsVersion", "major minor build")

WINDOWS_10_22H2 = 19045
WINDOWS_11_21H2 = 22000
WINDOWS_11_23H2 = 22631


@pytest.fixture
def windows(monkeypatch):
    """Make the module believe it is running on Windows at a given build."""

    def run(build, setting="auto"):
        monkeypatch.setattr(theme.sys, "platform", "win32")
        monkeypatch.setattr(
            theme.sys,
            "getwindowsversion",
            lambda: WindowsVersion(10, 0, build),
            raising=False,
        )
        monkeypatch.setattr(theme, "_read_gui_setting", lambda key, fallback: setting)
        return theme.native_dark_mode_allowed()

    return run


def test_windows_11_takes_the_opt_in(windows):
    allowed, reason = windows(WINDOWS_11_23H2)
    assert allowed
    assert str(WINDOWS_11_23H2) in reason


def test_the_cut_off_is_inclusive(windows):
    allowed, _ = windows(WINDOWS_11_21H2)
    assert allowed


def test_windows_10_does_not(windows):
    """The reported bug: dark mode leaves popup menu text white on white."""
    allowed, reason = windows(WINDOWS_10_22H2)
    assert not allowed
    assert str(WINDOWS_10_22H2) in reason
    assert "menu" in reason


def test_cfg_can_force_it_on_anywhere(windows):
    allowed, reason = windows(WINDOWS_10_22H2, setting="always")
    assert allowed
    assert "cfg.ini" in reason


def test_cfg_can_force_it_off_anywhere(windows):
    allowed, reason = windows(WINDOWS_11_23H2, setting="never")
    assert not allowed
    assert "cfg.ini" in reason


@pytest.mark.parametrize("setting", ("always", "on", "true", "yes", "1"))
def test_spellings_that_mean_on(windows, setting):
    allowed, _ = windows(WINDOWS_10_22H2, setting=setting)
    assert allowed


@pytest.mark.parametrize("setting", ("never", "off", "false", "no", "0"))
def test_spellings_that_mean_off(windows, setting):
    allowed, _ = windows(WINDOWS_11_23H2, setting=setting)
    assert not allowed


def test_not_windows(monkeypatch):
    monkeypatch.setattr(theme.sys, "platform", "linux")
    monkeypatch.setattr(theme, "_read_gui_setting", lambda key, fallback: "auto")
    allowed, reason = theme.native_dark_mode_allowed()
    assert not allowed
    assert reason == "not Windows"


def test_unknown_setting_falls_through_to_the_version_rule(windows):
    """A typo must not silently turn the opt-in on."""
    allowed, _ = windows(WINDOWS_10_22H2, setting="yes-please")
    assert not allowed


def test_a_failing_version_probe_is_declined_not_raised(monkeypatch):
    """Nothing in the GUI may fail to start because a platform probe is unavailable."""

    def explode():
        raise OSError("no version")

    monkeypatch.setattr(theme.sys, "platform", "win32")
    monkeypatch.setattr(theme, "_read_gui_setting", lambda key, fallback: "auto")
    monkeypatch.setattr(theme.sys, "getwindowsversion", explode, raising=False)

    allowed, reason = theme.native_dark_mode_allowed()
    assert not allowed
    assert "build" in reason
