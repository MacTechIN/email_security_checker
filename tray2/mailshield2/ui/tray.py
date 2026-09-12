"""pystray 트레이 아이콘. 메뉴 콜백은 pystray 스레드에서 오므로 App이 UI 스레드로 넘긴다."""

from __future__ import annotations

from typing import Callable

import pystray
from pystray import Menu, MenuItem

from .. import APP_DISPLAY_NAME
from . import icons


class TrayIcon:
    def __init__(
        self,
        *,
        get_state: Callable[[], str],
        get_status_text: Callable[[], str],
        is_paused: Callable[[], bool],
        is_autostart: Callable[[], bool],
        on_toggle_pause: Callable[[], None],
        on_open_incidents: Callable[[], None],
        on_open_settings: Callable[[], None],
        on_open_logs: Callable[[], None],
        on_toggle_autostart: Callable[[], None],
        on_about: Callable[[], None],
        on_quit: Callable[[], None],
    ) -> None:
        self._get_state = get_state
        self._get_status_text = get_status_text
        self._is_paused = is_paused
        self._is_autostart = is_autostart
        self._on_toggle_pause = on_toggle_pause
        self._on_open_incidents = on_open_incidents
        self._on_open_settings = on_open_settings
        self._on_open_logs = on_open_logs
        self._on_toggle_autostart = on_toggle_autostart
        self._on_about = on_about
        self._on_quit = on_quit
        self._images: dict[str, object] = {}
        self._icon = pystray.Icon(
            name="MailShield2Tray",
            icon=self._image(icons.STATE_UNCONFIGURED),
            title=APP_DISPLAY_NAME,
            menu=Menu(self._build_items),
        )

    def _image(self, state: str):
        if state not in self._images:
            self._images[state] = icons.render(state, 64)
        return self._images[state]

    def _build_items(self):
        yield MenuItem(lambda item: self._get_status_text(), None, enabled=False)
        yield Menu.SEPARATOR
        yield MenuItem(lambda item: "감시 재개" if self._is_paused() else "감시 일시 중지", lambda icon, item: self._on_toggle_pause())
        yield MenuItem("최근 위험 메일 보기...", lambda icon, item: self._on_open_incidents(), default=True)
        yield MenuItem("계정 설정...", lambda icon, item: self._on_open_settings())
        yield MenuItem("로그 폴더 열기", lambda icon, item: self._on_open_logs())
        yield Menu.SEPARATOR
        yield MenuItem("Windows 시작 시 자동 실행", lambda icon, item: self._on_toggle_autostart(), checked=lambda item: self._is_autostart())
        yield MenuItem("정보...", lambda icon, item: self._on_about())
        yield Menu.SEPARATOR
        yield MenuItem("종료", lambda icon, item: self._on_quit())

    def start(self) -> None:
        self._icon.run_detached()

    def stop(self) -> None:
        try:
            self._icon.stop()
        except Exception:
            pass

    def refresh(self) -> None:
        state = self._get_state()
        self._icon.icon = self._image(state)
        self._icon.title = f"{APP_DISPLAY_NAME} - {self._get_status_text()}"
        try:
            self._icon.update_menu()
        except Exception:
            pass

    def notify_fallback(self, title: str, body: str) -> None:
        """Toast를 쓸 수 없을 때 pystray의 풍선 알림을 사용한다."""
        try:
            self._icon.notify(body, title)
        except Exception:
            pass
