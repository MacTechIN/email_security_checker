"""진입점: python -m mailshield_tray  또는 MailShieldTray.exe

옵션:
  --settings            시작 후 계정 설정 창을 연다
  --setup               처음 설정 마법사를 연다(설치기가 설치 직후 호출)
  --verify [--gui]      설정·자격증명·IMAP 연결을 점검하고 종료 코드로 알린다(0 정상, 1 연결 실패, 2 미설정)
  --autostart           Windows 로그인 자동 실행에서 호출됨(표시용)
  --console             로그를 콘솔에도 출력한다
  --uninstall-cleanup   자격증명·상태·자동 시작 항목을 제거하고 종료한다(설치 제거기가 호출)
  --version
"""

from __future__ import annotations

import argparse
import logging
import sys

from . import APP_DISPLAY_NAME, VERSION


def _cleanup() -> int:
    from . import autostart, paths
    from .auth import CredentialStore
    from .store import CheckpointStore, IncidentLog, Settings

    settings = Settings.load()
    if settings.account.email:
        try:
            CredentialStore().delete_all(settings.account.email)
        except Exception:
            pass
    try:
        autostart.disable()
    except Exception:
        pass
    CheckpointStore().clear()
    IncidentLog().clear()
    for name in ("settings.json", "state.json", "google_client.json"):
        try:
            (paths.data_dir() / name).unlink(missing_ok=True)
        except OSError:
            pass
    return 0


def _verify(gui: bool) -> int:
    """설치·설정 검증용. 트레이 앱을 띄우지 않고 실제 IMAP 연결까지 확인한다."""
    from .auth import Authenticator, CredentialStore, GoogleOAuth
    from .monitor import test_connection
    from .store import Settings

    log = logging.getLogger("mailshield_tray.verify")
    settings = Settings.load()
    if not settings.account.configured:
        code, text = 2, "계정이 설정되어 있지 않습니다. 처음 설정 마법사를 실행하십시오."
    else:
        store = CredentialStore()
        report = test_connection(settings, Authenticator(settings.account, store, GoogleOAuth(store)))
        code = 0 if report.ok else 1
        text = report.message
    log.info("verify 결과 코드=%s: %s", code, text)
    try:
        print(f"[{'OK' if code == 0 else 'FAIL'}] {text}")
    except Exception:
        pass
    if gui:
        try:
            import tkinter as tk
            from tkinter import messagebox

            root = tk.Tk()
            root.withdraw()
            (messagebox.showinfo if code == 0 else messagebox.showwarning)(APP_DISPLAY_NAME, text)
            root.destroy()
        except Exception:
            pass
    return code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mailshield_tray", description=APP_DISPLAY_NAME)
    parser.add_argument("--settings", action="store_true")
    parser.add_argument("--setup", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--gui", action="store_true")
    parser.add_argument("--autostart", action="store_true")
    parser.add_argument("--console", action="store_true")
    parser.add_argument("--uninstall-cleanup", action="store_true")
    parser.add_argument("--version", action="version", version=f"{APP_DISPLAY_NAME} {VERSION}")
    args = parser.parse_args(argv)

    if args.uninstall_cleanup:
        return _cleanup()

    from .logging_setup import configure_logging

    configure_logging(console=args.console)
    log = logging.getLogger("mailshield_tray")

    if args.verify:
        return _verify(gui=args.gui)

    from .single_instance import SingleInstance

    instance = SingleInstance()
    if not instance.acquire():
        log.info("이미 실행 중인 인스턴스가 있어 종료합니다.")
        try:
            import tkinter as tk
            from tkinter import messagebox

            root = tk.Tk()
            root.withdraw()
            messagebox.showinfo(APP_DISPLAY_NAME, "MailShield Tray가 이미 실행 중입니다. 작업 표시줄 트레이 아이콘을 확인하십시오.")
            root.destroy()
        except Exception:
            pass
        return 0

    try:
        from .app import App

        App(open_settings_on_start=args.settings, open_setup_on_start=args.setup).run()
        return 0
    except Exception:
        log.exception("치명적 오류로 종료")
        return 1
    finally:
        instance.release()


if __name__ == "__main__":
    sys.exit(main())
