"""Windows Toast 알림. windows-toasts를 사용하고, 실패하면 로그로만 남긴다."""

from __future__ import annotations

import logging
from typing import Callable

log = logging.getLogger(__name__)


class Notifier:
    def __init__(self, app_name: str, on_activated: Callable[[], None] | None = None) -> None:
        self._app_name = app_name
        self._on_activated = on_activated
        self._toaster = None
        try:
            from windows_toasts import WindowsToaster

            self._toaster = WindowsToaster(app_name)
        except Exception as exception:  # 지원하지 않는 Windows 또는 패키지 문제
            log.warning("Toast 알림을 사용할 수 없어 로그로 대체합니다: %s", exception)

    @property
    def available(self) -> bool:
        return self._toaster is not None

    def show(self, title: str, body: str) -> None:
        log.warning("%s: %s", title, body)
        if self._toaster is None:
            return
        try:
            from windows_toasts import Toast

            toast = Toast()
            toast.text_fields = [title, body]
            if self._on_activated is not None:
                callback = self._on_activated
                toast.on_activated = lambda _args: callback()
            self._toaster.show_toast(toast)
        except Exception:
            log.exception("Toast 표시 실패")
