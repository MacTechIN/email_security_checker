"""IMAP IDLE 폴더 감시. code_snipt/realtime_email_monitor.pyw의 watch_folder를 이식하고 보강했다.

보강 사항:
- EXISTS 알림이 idle_done 응답에만 실리는 환경(Python 3.14 + imapclient 3.x) 대응
- 매 IDLE 주기마다 마지막 UID 이후를 조회해 알림 누락에도 안전
- SPECIAL-USE 플래그로 보낸편지함 탐색
- UIDVALIDITY·마지막 UID 체크포인트 영속화와 재시작 시 제한적 따라잡기
- 다른 스레드에서 소켓을 닫아 즉시 중지
"""

from __future__ import annotations

import logging
import ssl
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

import imapclient
from imapclient import IMAPClient
from imapclient.exceptions import LoginError

from .auth import AuthError, Authenticator
from .scanner import ScanResult, scan_message
from .store import FOLDER_AUTO_SENT, CheckpointStore, Settings

log = logging.getLogger(__name__)

SENT_FOLDER_CANDIDATES = ("[Gmail]/Sent Mail", "[Gmail]/보낸편지함", "Sent Items", "Sent Messages", "Sent", "보낸편지함")

STATUS_CONNECTING = "connecting"
STATUS_WATCHING = "watching"
STATUS_RECONNECTING = "reconnecting"
STATUS_AUTH_ERROR = "auth_error"
STATUS_STOPPED = "stopped"

ResultCallback = Callable[[ScanResult], None]
StatusCallback = Callable[[str, str, str], None]  # (folder_spec, status, detail)


def find_sent_folder(client: IMAPClient) -> str | None:
    try:
        name = client.find_special_folder(imapclient.SENT)
    except Exception:  # 서버가 SPECIAL-USE/XLIST를 지원하지 않는 경우
        name = None
    if name:
        return name if isinstance(name, str) else name.decode("utf-8", errors="replace")
    try:
        names = {item[2] if isinstance(item[2], str) else item[2].decode("utf-8", errors="replace") for item in client.list_folders()}
    except Exception:
        return None
    for candidate in SENT_FOLDER_CANDIDATES:
        if candidate in names:
            return candidate
    return None


def _status_int(status: dict, key: str, default: int = 0) -> int:
    for variant in (key.encode(), key):
        if variant in status:
            return int(status[variant])
    return default


def new_uids(client: IMAPClient, last_uid: int) -> list[int]:
    """IMAP의 N:*는 N이 마지막 UID보다 크면 마지막 메시지를 되돌려 주므로 걸러낸다."""
    found = client.search(["UID", f"{last_uid + 1}:*"])
    return sorted(int(uid) for uid in found if int(uid) > last_uid)


@dataclass
class ConnectionReport:
    ok: bool
    message: str
    folders: dict[str, str] = field(default_factory=dict)  # spec -> 실제 이름


def test_connection(settings: Settings, authenticator: Authenticator) -> ConnectionReport:
    account = settings.account
    client: IMAPClient | None = None
    try:
        client = IMAPClient(account.imap_host, port=account.imap_port, ssl=True, ssl_context=ssl.create_default_context(), timeout=30)
        authenticator.login(client)
        resolved: dict[str, str] = {}
        for spec in account.folders:
            name = find_sent_folder(client) if spec == FOLDER_AUTO_SENT else spec
            if not name:
                return ConnectionReport(False, "보낸편지함 폴더를 찾지 못했습니다. 폴더 이름을 직접 지정하십시오.", resolved)
            client.select_folder(name, readonly=True)
            resolved[spec] = name
        return ConnectionReport(True, "연결 성공: " + ", ".join(resolved.values()), resolved)
    except AuthError as exception:
        return ConnectionReport(False, str(exception))
    except LoginError as exception:
        return ConnectionReport(False, f"서버가 인증을 거부했습니다: {exception}")
    except (OSError, ssl.SSLError) as exception:
        return ConnectionReport(False, f"네트워크/TLS 연결 실패: {exception}")
    except Exception as exception:  # 예상하지 못한 IMAP 오류
        return ConnectionReport(False, f"연결 실패: {exception}")
    finally:
        if client is not None:
            try:
                client.logout()
            except Exception:
                pass


class FolderWatcher(threading.Thread):
    def __init__(
        self,
        settings: Settings,
        authenticator: Authenticator,
        folder_spec: str,
        checkpoints: CheckpointStore,
        on_result: ResultCallback,
        on_status: StatusCallback,
    ) -> None:
        super().__init__(name=f"imap-{folder_spec}", daemon=True)
        self._settings = settings
        self._account = settings.account
        self._auth = authenticator
        self._spec = folder_spec
        self._checkpoints = checkpoints
        self._on_result = on_result
        self._on_status = on_status
        self._stop = threading.Event()
        self._client_lock = threading.Lock()
        self._client: IMAPClient | None = None
        self.resolved_name: str | None = None

    # --- 제어 ---
    def request_stop(self) -> None:
        self._stop.set()
        with self._client_lock:
            client = self._client
        if client is not None:
            try:
                client.shutdown()  # IDLE 대기 중인 소켓을 닫아 즉시 깨운다.
            except Exception:
                pass

    def _set_client(self, client: IMAPClient | None) -> None:
        with self._client_lock:
            self._client = client

    def _status(self, status: str, detail: str = "") -> None:
        try:
            self._on_status(self._spec, status, detail)
        except Exception:
            log.exception("상태 콜백 실패")

    # --- 실행 ---
    def run(self) -> None:
        backoff = 5
        while not self._stop.is_set():
            client: IMAPClient | None = None
            try:
                self._status(STATUS_CONNECTING)
                client = IMAPClient(self._account.imap_host, port=self._account.imap_port, ssl=True, ssl_context=ssl.create_default_context(), timeout=60)
                self._set_client(client)
                self._auth.login(client)
                folder = find_sent_folder(client) if self._spec == FOLDER_AUTO_SENT else self._spec
                if not folder:
                    raise RuntimeError("보낸편지함 폴더를 찾지 못했습니다.")
                self.resolved_name = folder
                client.select_folder(folder, readonly=True)
                last_uid = self._initial_uid(client, folder)
                log.info("%s 감시 시작 (마지막 UID=%s)", folder, last_uid)
                self._status(STATUS_WATCHING, folder)
                backoff = 5
                self._watch_loop(client, folder, last_uid)
            except AuthError as exception:
                log.warning("%s 인증 문제: %s", self._spec, exception)
                self._status(STATUS_AUTH_ERROR, str(exception))
                self._wait(min(max(backoff, 60), 300))
                backoff = min(backoff * 2, 300)
            except LoginError as exception:
                log.warning("%s 서버 인증 거부: %s", self._spec, exception)
                self._status(STATUS_AUTH_ERROR, "서버가 인증을 거부했습니다. 앱 비밀번호 또는 Google 로그인을 확인하십시오.")
                self._wait(min(max(backoff, 60), 300))
                backoff = min(backoff * 2, 300)
            except Exception as exception:
                if self._stop.is_set():
                    break
                log.warning("%s 감시 연결 오류(%s); %s초 후 재연결", self._spec, exception.__class__.__name__, backoff)
                log.debug("연결 오류 상세", exc_info=True)
                self._status(STATUS_RECONNECTING, f"{backoff}초 후 재연결")
                self._wait(backoff)
                backoff = min(backoff * 2, 300)
            finally:
                self._set_client(None)
                if client is not None:
                    try:
                        client.logout()
                    except Exception:
                        pass
        self._status(STATUS_STOPPED)

    def _wait(self, seconds: float) -> None:
        self._stop.wait(seconds)

    def _initial_uid(self, client: IMAPClient, folder: str) -> int:
        status = client.folder_status(folder, ["UIDVALIDITY", "UIDNEXT"])
        uidvalidity = _status_int(status, "UIDVALIDITY")
        newest = _status_int(status, "UIDNEXT", 1) - 1
        stored = self._checkpoints.get(self._account.email, folder)
        last_uid = newest
        if stored and stored[0] == uidvalidity and stored[1] < newest:
            gap = newest - stored[1]
            limit = max(0, int(self._settings.catch_up_limit))
            if gap > limit:
                log.info("%s: 미확인 메일 %s건 중 최근 %s건만 따라잡습니다.", folder, gap, limit)
                last_uid = newest - limit
            else:
                last_uid = stored[1]
        elif stored and stored[0] != uidvalidity:
            log.info("%s: UIDVALIDITY 변경(%s→%s), 최신 위치에서 다시 시작합니다.", folder, stored[0], uidvalidity)
        self._checkpoints.set(self._account.email, folder, uidvalidity, last_uid)
        self._uidvalidity = uidvalidity
        return last_uid

    def _watch_loop(self, client: IMAPClient, folder: str, last_uid: int) -> None:
        idle_timeout = max(5, int(self._settings.idle_timeout_seconds))
        idle_started = time.monotonic()
        while not self._stop.is_set():
            client.idle()
            responses = list(client.idle_check(timeout=idle_timeout))
            _, done_responses = client.idle_done()
            responses.extend(done_responses or [])
            # 알림 유무와 관계없이 증분 조회. 알림이 누락되는 환경에서도 안전하다.
            for uid in new_uids(client, last_uid):
                if self._stop.is_set():
                    return
                fetched = client.fetch([uid], [b"RFC822"])
                raw = fetched.get(uid, {}).get(b"RFC822")
                if raw:
                    result = scan_message(raw, folder, uid)
                    log.info("분석 결과: %s", result.to_dict())
                    try:
                        self._on_result(result)
                    except Exception:
                        log.exception("결과 콜백 실패")
                last_uid = max(last_uid, uid)
                self._checkpoints.set(self._account.email, folder, self._uidvalidity, last_uid)
            # 공급자 IDLE 유지 제한(대개 29분) 전에 세션을 갱신한다.
            if time.monotonic() - idle_started > 20 * 60:
                client.noop()
                idle_started = time.monotonic()


class Monitor:
    """계정 하나의 폴더 감시 스레드 묶음."""

    def __init__(self, settings: Settings, authenticator: Authenticator, checkpoints: CheckpointStore, on_result: ResultCallback, on_status: StatusCallback) -> None:
        self._settings = settings
        self._auth = authenticator
        self._checkpoints = checkpoints
        self._on_result = on_result
        self._on_status = on_status
        self._watchers: list[FolderWatcher] = []
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        with self._lock:
            return any(w.is_alive() for w in self._watchers)

    def start(self) -> None:
        with self._lock:
            if any(w.is_alive() for w in self._watchers):
                return
            self._watchers = [
                FolderWatcher(self._settings, self._auth, spec, self._checkpoints, self._on_result, self._on_status)
                for spec in self._settings.account.folders
            ]
            for watcher in self._watchers:
                watcher.start()
        log.info("실시간 감시 시작: %s", ", ".join(self._settings.account.folders))

    def stop(self, timeout: float = 10) -> None:
        with self._lock:
            watchers = list(self._watchers)
        for watcher in watchers:
            watcher.request_stop()
        deadline = time.monotonic() + timeout
        for watcher in watchers:
            watcher.join(max(0.1, deadline - time.monotonic()))
        log.info("실시간 감시 중지")

    def restart(self) -> None:
        self.stop()
        self.start()
