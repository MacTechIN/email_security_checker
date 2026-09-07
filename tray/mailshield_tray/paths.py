"""로컬 데이터 경로. 모든 파일은 %LOCALAPPDATA%\\MailShield 아래에 둔다."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def data_dir() -> Path:
    base = os.getenv("MAILSHIELD_DATA_DIR") or os.getenv("LOCALAPPDATA") or str(Path.home())
    path = Path(base) / "MailShield"
    path.mkdir(parents=True, exist_ok=True)
    return path


def log_path() -> Path:
    return data_dir() / "tray.log"


def settings_path() -> Path:
    return data_dir() / "settings.json"


def state_path() -> Path:
    return data_dir() / "state.json"


def incidents_path() -> Path:
    return data_dir() / "incidents.jsonl"


def google_client_path() -> Path:
    """OAuth 데스크톱 클라이언트 파일 위치. 앱 리소스에 내장된 파일이 있으면 우선한다."""
    bundled = resource_dir() / "google_client.json"
    if bundled.exists():
        return bundled
    return data_dir() / "google_client.json"


def resource_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent)) / "resources"
    return Path(__file__).resolve().parent / "resources"


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def executable_command() -> str:
    """자동 시작 레지스트리에 등록할 실행 명령."""
    if is_frozen():
        return f'"{sys.executable}"'
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    interpreter = pythonw if pythonw.exists() else Path(sys.executable)
    launcher = Path(__file__).resolve().parent.parent / "MailShieldTray.pyw"
    return f'"{interpreter}" "{launcher}"'
