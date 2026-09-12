"""네트워크 없이 FolderWatcher의 IDLE 루프·체크포인트·폴더 탐색을 가짜 IMAPClient로 검증한다."""

from __future__ import annotations

import threading
import time
from email.message import EmailMessage

import imapclient
import pytest

from mailshield2 import monitor
from mailshield2.auth import AuthError
from mailshield2.store import FOLDER_AUTO_SENT, AccountSettings, CheckpointStore, Settings


def _raw(subject: str, body: str) -> bytes:
    message = EmailMessage()
    message["From"] = "x@example.com"
    message["Subject"] = subject
    message.set_content(body)
    return message.as_bytes()


class FakeClient:
    """imapclient.IMAPClient의 사용 부분만 흉내 낸다. EXISTS는 idle_done에만 실린다(실환경 재현)."""

    instances: list["FakeClient"] = []

    def __init__(self, host, port=993, ssl=True, ssl_context=None, timeout=None):
        self.uidvalidity = 100
        self.messages: dict[int, bytes] = {1: _raw("old", "old")}
        self.idle_cycles = 0
        self.pending_exists = False
        self.shutdown_called = False
        self.selected = None
        self.logged_out = False
        FakeClient.instances.append(self)

    # 폴더
    def find_special_folder(self, flag):
        assert flag == imapclient.SENT
        return "[Gmail]/Sent Mail"

    def list_folders(self):
        return [((b"\\HasNoChildren",), b"/", "INBOX"), ((b"\\HasNoChildren", b"\\Sent"), b"/", "[Gmail]/Sent Mail")]

    def select_folder(self, name, readonly=False):
        self.selected = name
        return {}

    def folder_status(self, folder, what):
        return {b"UIDVALIDITY": self.uidvalidity, b"UIDNEXT": max(self.messages, default=0) + 1}

    # IDLE
    def idle(self):
        pass

    def idle_check(self, timeout=None):
        self.idle_cycles += 1
        time.sleep(0.01)
        if self.shutdown_called:
            raise OSError("socket closed")
        return []

    def idle_done(self):
        if self.pending_exists:
            self.pending_exists = False
            return b"IDLE terminated", [(len(self.messages), b"EXISTS")]
        return b"IDLE terminated", []

    def noop(self):
        return b"OK", []

    # 조회
    def search(self, criteria):
        assert criteria[0] == "UID"
        start = int(criteria[1].split(":")[0])
        found = sorted(uid for uid in self.messages if uid >= start)
        return found or [max(self.messages)]  # IMAP "N:*" 규칙: 범위 밖이면 마지막 메시지

    def fetch(self, uids, parts):
        return {uid: {b"RFC822": self.messages[uid], b"SEQ": uid} for uid in uids if uid in self.messages}

    def shutdown(self):
        self.shutdown_called = True

    def logout(self):
        self.logged_out = True

    # 테스트 도우미
    def deliver(self, subject: str, body: str) -> int:
        uid = max(self.messages) + 1
        self.messages[uid] = _raw(subject, body)
        self.pending_exists = True
        return uid


class OkAuth:
    def login(self, client):
        pass


class FailingAuth:
    def login(self, client):
        raise AuthError("앱 비밀번호가 저장되어 있지 않습니다.")


@pytest.fixture
def fake_imap(monkeypatch):
    FakeClient.instances.clear()
    monkeypatch.setattr(monitor, "IMAPClient", FakeClient)
    yield FakeClient


def _settings() -> Settings:
    settings = Settings(account=AccountSettings(email="me@gmail.com", imap_host="imap.gmail.com", folders=["INBOX", FOLDER_AUTO_SENT]))
    settings.idle_timeout_seconds = 5
    return settings


def _wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def test_new_mail_detected_via_idle_done_and_checkpoint_saved(fake_imap):
    results, statuses = [], []
    checkpoints = CheckpointStore()
    watcher = monitor.FolderWatcher(_settings(), OkAuth(), "INBOX", checkpoints, results.append, lambda *a: statuses.append(a))
    watcher.start()
    assert _wait_for(lambda: fake_imap.instances and fake_imap.instances[0].idle_cycles >= 1)
    client = fake_imap.instances[0]
    uid = client.deliver("테스트", "901231-1234567")
    assert _wait_for(lambda: len(results) == 1)
    assert results[0].uid == uid
    assert results[0].risk == "high"
    assert checkpoints.get("me@gmail.com", "INBOX") == (100, uid)
    # 알림이 없는 주기에서 마지막 메시지를 다시 처리하지 않는다.
    assert _wait_for(lambda: client.idle_cycles >= 5)
    assert len(results) == 1
    watcher.request_stop()
    watcher.join(3)
    assert not watcher.is_alive()
    assert statuses[-1][1] == monitor.STATUS_STOPPED


def test_sent_folder_resolved_by_special_use(fake_imap):
    statuses = []
    watcher = monitor.FolderWatcher(_settings(), OkAuth(), FOLDER_AUTO_SENT, CheckpointStore(), lambda r: None, lambda *a: statuses.append(a))
    watcher.start()
    assert _wait_for(lambda: any(s[1] == monitor.STATUS_WATCHING for s in statuses))
    assert watcher.resolved_name == "[Gmail]/Sent Mail"
    assert fake_imap.instances[0].selected == "[Gmail]/Sent Mail"
    watcher.request_stop()
    watcher.join(3)


def test_catch_up_from_checkpoint_after_restart(fake_imap):
    checkpoints = CheckpointStore()
    checkpoints.set("me@gmail.com", "INBOX", 100, 1)  # 이전 실행에서 UID 1까지 처리
    results = []
    settings = _settings()
    watcher = monitor.FolderWatcher(settings, OkAuth(), "INBOX", checkpoints, results.append, lambda *a: None)
    # 앱이 꺼진 사이 도착한 메일 두 통
    original_init = fake_imap.__init__

    def init_with_backlog(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        self.messages[2] = _raw("missed 1", "a")
        self.messages[3] = _raw("missed 2", "b")

    fake_imap.__init__ = init_with_backlog
    try:
        watcher.start()
        assert _wait_for(lambda: len(results) == 2)
        assert [r.uid for r in results] == [2, 3]
        assert checkpoints.get("me@gmail.com", "INBOX") == (100, 3)
    finally:
        fake_imap.__init__ = original_init
        watcher.request_stop()
        watcher.join(3)


def test_uidvalidity_change_restarts_from_newest(fake_imap):
    checkpoints = CheckpointStore()
    checkpoints.set("me@gmail.com", "INBOX", 999, 0)  # 다른 UIDVALIDITY의 오래된 체크포인트
    results = []
    watcher = monitor.FolderWatcher(_settings(), OkAuth(), "INBOX", checkpoints, results.append, lambda *a: None)
    watcher.start()
    assert _wait_for(lambda: fake_imap.instances and fake_imap.instances[0].idle_cycles >= 2)
    assert results == []
    assert checkpoints.get("me@gmail.com", "INBOX") == (100, 1)
    watcher.request_stop()
    watcher.join(3)


def test_auth_error_reports_status_and_retries_slowly(fake_imap):
    statuses = []
    watcher = monitor.FolderWatcher(_settings(), FailingAuth(), "INBOX", CheckpointStore(), lambda r: None, lambda *a: statuses.append(a))
    watcher.start()
    assert _wait_for(lambda: any(s[1] == monitor.STATUS_AUTH_ERROR for s in statuses))
    detail = next(s[2] for s in statuses if s[1] == monitor.STATUS_AUTH_ERROR)
    assert "앱 비밀번호" in detail
    watcher.request_stop()
    watcher.join(3)
    assert not watcher.is_alive()


def test_new_uids_filters_imap_last_message_rule():
    class C:
        def search(self, criteria):
            return [39325]

    assert monitor.new_uids(C(), 39325) == []
    assert monitor.new_uids(C(), 39324) == [39325]


def test_test_connection_reports_resolved_folders(fake_imap):
    report = monitor.test_connection(_settings(), OkAuth())
    assert report.ok
    assert report.folders == {"INBOX": "INBOX", FOLDER_AUTO_SENT: "[Gmail]/Sent Mail"}
    assert fake_imap.instances[0].logged_out


def test_test_connection_auth_error_message(fake_imap):
    report = monitor.test_connection(_settings(), FailingAuth())
    assert not report.ok
    assert "앱 비밀번호" in report.message
