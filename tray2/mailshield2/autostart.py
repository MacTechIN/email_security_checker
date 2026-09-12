"""Windows 로그인 시 자동 실행(HKCU Run 키). 관리자 권한이 필요하지 않다."""

from __future__ import annotations

import logging
import sys

from .paths import executable_command

log = logging.getLogger(__name__)

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "MailShield2Tray"


def _winreg():
    if sys.platform != "win32":
        return None
    import winreg

    return winreg


def is_enabled() -> bool:
    winreg = _winreg()
    if winreg is None:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, VALUE_NAME)
            return bool(value)
    except OSError:
        return False


def enable() -> None:
    winreg = _winreg()
    if winreg is None:
        return
    command = executable_command() + " --autostart"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, VALUE_NAME, 0, winreg.REG_SZ, command)
    log.info("자동 시작 등록: %s", command)


def disable() -> None:
    winreg = _winreg()
    if winreg is None:
        return
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, VALUE_NAME)
        log.info("자동 시작 해제")
    except FileNotFoundError:
        pass


def apply(enabled: bool) -> None:
    if enabled:
        enable()
    else:
        disable()
