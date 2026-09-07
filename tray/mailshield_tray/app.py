"""앱 조립: 설정·자격증명·감시·알림·트레이를 연결하고 UI 스레드(Tk)에서 상태를 관리한다."""

from __future__ import annotations

import logging
import os
import queue
import threading
import time
import tkinter as tk
from typing import Callable

from . import APP_DISPLAY_NAME, APP_NAME, autostart, paths
from .auth import Authenticator, CredentialStore, GoogleOAuth
from .monitor import (
    STATUS_AUTH_ERROR,
    STATUS_CONNECTING,
    STATUS_RECONNECTING,
    STATUS_STOPPED,
    STATUS_WATCHING,
    Monitor,
)
from .notify import Notifier
from .scanner import ScanResult
from .store import CheckpointStore, IncidentLog, Settings
from .ui import dialogs, icons
from .ui.tray import TrayIcon

log = logging.getLogger(__name__)

ALERT_HOLD_SECONDS = 60  # 위험 감지 후 아이콘을 빨간색으로 유지하는 시간


class UiDispatcher:
    """다른 스레드의 작업을 Tk 메인 스레드에서 실행한다."""

    def __init__(self, root: tk.Tk) -> None:
        self._root = root
        self._queue: queue.Queue[Callable[[], None]] = queue.Queue()
        self._root.after(100, self._pump)

    def __call__(self, func: Callable[[], None]) -> None:
        self._queue.put(func)

    def _pump(self) -> None:
        for _ in range(50):
            try:
                func = self._queue.get_nowait()
            except queue.Empty:
                break
            try:
                func()
            except Exception:
                log.exception("UI 작업 실패")
        self._root.after(100, self._pump)


class App:
    def __init__(self, open_settings_on_start: bool = False) -> None:
        self.root = tk.Tk()
        self.root.withdraw()
        self.root.title(APP_DISPLAY_NAME)
        self.dispatch = UiDispatcher(self.root)

        self.settings = Settings.load()
        self.store = CredentialStore()
        self.oauth = GoogleOAuth(self.store)
        self.checkpoints = CheckpointStore()
        self.incidents = IncidentLog()
        self.notifier = Notifier(APP_NAME, on_activated=lambda: self.dispatch(self.open_incidents))

        self._paused = False
        self._folder_status: dict[str, tuple[str, str]] = {}
        self._last_alert_at = 0.0
        self._monitor: Monitor | None = None
        self._settings_dialog: dialogs.AccountDialog | None = None
        self._incidents_window: dialogs.IncidentsWindow | None = None

        self.tray = TrayIcon(
            get_state=self.current_state,
            get_status_text=self.status_text,
            is_paused=lambda: self._paused,
            is_autostart=lambda: self.settings.autostart,
            on_toggle_pause=lambda: self.dispatch(self.toggle_pause),
            on_open_incidents=lambda: self.dispatch(self.open_incidents),
            on_open_settings=lambda: self.dispatch(self.open_settings),
            on_open_logs=lambda: self.dispatch(self.open_logs),
            on_toggle_autostart=lambda: self.dispatch(self.toggle_autostart),
            on_about=lambda: self.dispatch(lambda: dialogs.show_about(self.root)),
            on_quit=lambda: self.dispatch(self.quit),
        )
        self._open_settings_on_start = open_settings_on_start or not self.settings.account.configured

    # --- 상태 ---
    def current_state(self) -> str:
        if not self.settings.account.configured:
            return icons.STATE_UNCONFIGURED
        if self._paused:
            return icons.STATE_PAUSED
        statuses = [status for status, _ in self._folder_status.values()]
        if any(status == STATUS_AUTH_ERROR for status in statuses):
            return icons.STATE_ERROR
        if time.monotonic() - self._last_alert_at < ALERT_HOLD_SECONDS:
            return icons.STATE_ALERT
        if statuses and all(status == STATUS_WATCHING for status in statuses):
            return icons.STATE_WATCHING
        if any(status in (STATUS_CONNECTING, STATUS_RECONNECTING) for status in statuses):
            return icons.STATE_CONNECTING
        if statuses and all(status == STATUS_STOPPED for status in statuses):
            return icons.STATE_PAUSED
        return icons.STATE_CONNECTING

    def status_text(self) -> str:
        state = self.current_state()
        label = icons.state_label(state)
        if state == icons.STATE_ERROR:
            detail = next((d for s, d in self._folder_status.values() if s == STATUS_AUTH_ERROR and d), "")
            return f"{label}: {detail}" if detail else label
        if state == icons.STATE_WATCHING:
            names = [d for s, d in self._folder_status.values() if s == STATUS_WATCHING and d]
            return f"{label} ({self.settings.account.email}: {', '.join(names)})"
        if state == icons.STATE_UNCONFIGURED:
            return f"{label} - 계정 설정을 열어 연결하십시오"
        return label

    def _refresh_tray(self) -> None:
        self.tray.refresh()

    # --- 감시 콜백(워커 스레드) ---
    def _on_status(self, folder_spec: str, status: str, detail: str) -> None:
        def apply() -> None:
            previous = self._folder_status.get(folder_spec, ("", ""))
            self._folder_status[folder_spec] = (status, detail)
            if status == STATUS_AUTH_ERROR and previous[0] != STATUS_AUTH_ERROR:
                self.notifier.show(f"{APP_NAME} 인증 필요", detail or "계정 설정에서 인증 정보를 갱신하십시오.")
            self._refresh_tray()

        self.dispatch(apply)

    def _on_result(self, result: ScanResult) -> None:
        def apply() -> None:
            self.incidents.append(result)
            if result.risk == "high":
                self._last_alert_at = time.monotonic()
                self.notifier.show(f"{APP_NAME} 위험 메일 감지", f"{result.folder}: {result.subject}\n{result.summary}")
                self.root.after(ALERT_HOLD_SECONDS * 1000 + 500, self._refresh_tray)
            elif self.settings.notify_safe_mail:
                self.notifier.show(f"{APP_NAME} 새 메일", f"{result.folder}: {result.subject}\n위험 요소 없음")
            self._refresh_tray()

        self.dispatch(apply)

    # --- 감시 제어 ---
    def start_monitor(self) -> None:
        if not self.settings.account.configured:
            self._refresh_tray()
            return
        self._folder_status = {}
        authenticator = Authenticator(self.settings.account, self.store, self.oauth)
        self._monitor = Monitor(self.settings, authenticator, self.checkpoints, self._on_result, self._on_status)
        self._monitor.start()
        self._refresh_tray()

    def stop_monitor(self) -> None:
        monitor, self._monitor = self._monitor, None
        if monitor is None:
            return
        threading.Thread(target=monitor.stop, name="monitor-stop", daemon=True).start()

    def toggle_pause(self) -> None:
        self._paused = not self._paused
        if self._paused:
            self.stop_monitor()
            log.info("사용자가 감시를 일시 중지했습니다.")
        else:
            log.info("사용자가 감시를 재개했습니다.")
            self.start_monitor()
        self._refresh_tray()

    # --- 메뉴 동작(UI 스레드) ---
    def open_settings(self) -> None:
        if self._settings_dialog is not None and self._settings_dialog.winfo_exists():
            self._settings_dialog.lift()
            self._settings_dialog.focus_force()
            return
        self._settings_dialog = dialogs.AccountDialog(self.root, self.settings, self.store, self.oauth, self.dispatch, self._on_settings_saved)

    def _on_settings_saved(self, settings: Settings) -> None:
        self.settings = settings
        self._paused = False
        self.stop_monitor()
        self.start_monitor()
        log.info("계정 설정 저장: %s (%s)", settings.account.email, settings.account.auth_method)

    def open_incidents(self) -> None:
        if self._incidents_window is not None and self._incidents_window.winfo_exists():
            self._incidents_window.refresh()
            self._incidents_window.lift()
            self._incidents_window.focus_force()
            return
        self._incidents_window = dialogs.IncidentsWindow(self.root, self.incidents)

    def open_logs(self) -> None:
        try:
            os.startfile(str(paths.data_dir()))  # type: ignore[attr-defined]
        except OSError:
            log.exception("로그 폴더 열기 실패")

    def toggle_autostart(self) -> None:
        self.settings.autostart = not self.settings.autostart
        try:
            autostart.apply(self.settings.autostart)
        except OSError:
            log.exception("자동 시작 설정 변경 실패")
        self.settings.save()
        self._refresh_tray()

    def quit(self) -> None:
        log.info("종료 요청")
        monitor, self._monitor = self._monitor, None
        self.tray.stop()
        if monitor is not None:
            monitor.stop(timeout=5)
        self.root.after(0, self.root.destroy)

    # --- 실행 ---
    def run(self) -> None:
        self.tray.start()
        if self.settings.account.configured:
            # 계정이 연결된 뒤에만 자동 시작을 동기화한다. 개발용 실행이 레지스트리를 건드리지 않게 한다.
            try:
                autostart.apply(self.settings.autostart)
            except OSError:
                log.debug("자동 시작 동기화 실패", exc_info=True)
        self.start_monitor()
        if self._open_settings_on_start:
            self.root.after(300, self.open_settings)
        log.info("%s 시작", APP_DISPLAY_NAME)
        try:
            self.root.mainloop()
        finally:
            self.tray.stop()
            log.info("%s 종료", APP_DISPLAY_NAME)
