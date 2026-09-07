"""설정(settings.json), 체크포인트(state.json), 사건 기록(incidents.jsonl).

비밀값(앱 비밀번호, OAuth 토큰)은 여기 저장하지 않는다. auth.CredentialStore가 담당한다.
"""

from __future__ import annotations

import json
import threading
from collections import deque
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable

from . import paths
from .scanner import ScanResult

AUTH_OAUTH = "oauth"
AUTH_APP_PASSWORD = "app_password"
FOLDER_AUTO_SENT = "__SENT__"  # 런타임에 SPECIAL-USE 플래그로 실제 이름을 찾는다.


@dataclass
class AccountSettings:
    email: str = ""
    imap_host: str = ""
    imap_port: int = 993
    auth_method: str = AUTH_APP_PASSWORD
    folders: list[str] = field(default_factory=lambda: ["INBOX", FOLDER_AUTO_SENT])
    provider: str = ""

    @property
    def configured(self) -> bool:
        return bool(self.email and self.imap_host and self.folders)


@dataclass
class Settings:
    account: AccountSettings = field(default_factory=AccountSettings)
    autostart: bool = True
    notify_safe_mail: bool = False
    idle_timeout_seconds: int = 25
    catch_up_limit: int = 200

    @classmethod
    def load(cls, path: Path | None = None) -> "Settings":
        path = path or paths.settings_path()
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return cls()
        account = AccountSettings(**{k: v for k, v in data.get("account", {}).items() if k in AccountSettings.__dataclass_fields__})
        settings = cls(account=account)
        for key in ("autostart", "notify_safe_mail", "idle_timeout_seconds", "catch_up_limit"):
            if key in data:
                setattr(settings, key, data[key])
        return settings

    def save(self, path: Path | None = None) -> None:
        path = path or paths.settings_path()
        payload = asdict(self)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)


class CheckpointStore:
    """폴더별 UIDVALIDITY와 마지막 처리 UID를 원자적으로 저장한다."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or paths.state_path()
        self._lock = threading.Lock()
        self._data: dict[str, dict[str, int]] = self._read()

    def _read(self) -> dict[str, dict[str, int]]:
        if not self._path.exists():
            return {}
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    @staticmethod
    def _key(account: str, folder: str) -> str:
        return f"{account.lower()}|{folder}"

    def get(self, account: str, folder: str) -> tuple[int, int] | None:
        with self._lock:
            entry = self._data.get(self._key(account, folder))
        if not entry:
            return None
        return int(entry.get("uidvalidity", 0)), int(entry.get("last_uid", 0))

    def set(self, account: str, folder: str, uidvalidity: int, last_uid: int) -> None:
        with self._lock:
            self._data[self._key(account, folder)] = {"uidvalidity": int(uidvalidity), "last_uid": int(last_uid)}
            self._flush()

    def clear(self) -> None:
        with self._lock:
            self._data = {}
            self._flush()

    def _flush(self) -> None:
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self._path)


class IncidentLog:
    """최근 사건을 메모리에 유지하고 마스킹된 형태로 jsonl에 덧붙인다."""

    def __init__(self, path: Path | None = None, keep: int = 200) -> None:
        self._path = path or paths.incidents_path()
        self._lock = threading.Lock()
        self._recent: deque[dict] = deque(maxlen=keep)
        self._load_tail(keep)

    def _load_tail(self, keep: int) -> None:
        if not self._path.exists():
            return
        try:
            lines = self._path.read_text(encoding="utf-8").splitlines()[-keep:]
        except OSError:
            return
        for line in lines:
            try:
                self._recent.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    def append(self, result: ScanResult) -> None:
        record = result.to_dict()
        with self._lock:
            self._recent.append(record)
            try:
                with self._path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            except OSError:
                pass

    def recent(self, limit: int = 50, risky_only: bool = True) -> list[dict]:
        with self._lock:
            items: Iterable[dict] = list(self._recent)
        if risky_only:
            items = [item for item in items if item.get("risk") == "high"]
        return list(items)[-limit:][::-1]

    def clear(self) -> None:
        with self._lock:
            self._recent.clear()
            try:
                self._path.unlink(missing_ok=True)
            except OSError:
                pass
