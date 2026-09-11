"""--verify 점검 모드: 트레이를 띄우지 않고 설정·연결을 검사해 종료 코드로 알린다."""

from mailshield_tray import __main__ as entry
from mailshield_tray import monitor
from mailshield_tray.monitor import ConnectionReport
from mailshield_tray.store import AccountSettings, Settings


def test_verify_reports_unconfigured(monkeypatch):
    monkeypatch.setattr(entry, "_verify", entry._verify)  # 원본 사용
    assert entry._verify(gui=False) == 2


def test_verify_success_and_failure(monkeypatch):
    Settings(account=AccountSettings(email="a@gmail.com", imap_host="imap.gmail.com")).save()
    monkeypatch.setattr(monitor, "test_connection", lambda s, a: ConnectionReport(True, "연결 성공: INBOX"))
    assert entry._verify(gui=False) == 0
    monkeypatch.setattr(monitor, "test_connection", lambda s, a: ConnectionReport(False, "서버가 인증을 거부했습니다"))
    assert entry._verify(gui=False) == 1


def test_cli_flags_parse():
    import argparse
    parser = argparse.ArgumentParser()
    for flag in ("--settings", "--setup", "--verify", "--gui", "--autostart", "--console", "--uninstall-cleanup"):
        parser.add_argument(flag, action="store_true")
    args = parser.parse_args(["--verify", "--gui"])
    assert args.verify and args.gui and not args.setup
