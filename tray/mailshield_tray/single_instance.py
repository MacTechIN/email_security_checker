"""명명된 뮤텍스로 사용자 세션당 하나의 인스턴스만 허용한다."""

from __future__ import annotations

import sys

MUTEX_NAME = r"Local\MailShieldTray"
ERROR_ALREADY_EXISTS = 183


class SingleInstance:
    def __init__(self, name: str = MUTEX_NAME) -> None:
        self._name = name
        self._handle = None
        self.already_running = False

    def acquire(self) -> bool:
        if sys.platform != "win32":
            return True
        import win32api
        import win32event

        self._handle = win32event.CreateMutex(None, False, self._name)
        self.already_running = win32api.GetLastError() == ERROR_ALREADY_EXISTS
        return not self.already_running

    def release(self) -> None:
        if self._handle is not None and sys.platform == "win32":
            import win32api

            try:
                win32api.CloseHandle(self._handle)
            except Exception:
                pass
            self._handle = None
