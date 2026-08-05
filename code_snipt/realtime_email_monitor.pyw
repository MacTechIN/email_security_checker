"""MailShield 실시간 이메일 감시 프로토타입.

운영 전 검증용 코드입니다. 계정 정보는 환경변수로 주입하며 코드에 저장하지 않습니다.
필수 패키지: imapclient
선택 패키지: win10toast

환경변수 예시:
  MAILSHIELD_EMAIL=user@example.com
  MAILSHIELD_IMAP_HOST=imap.example.com
  MAILSHIELD_IMAP_PORT=993
  MAILSHIELD_APP_PASSWORD=앱비밀번호
  MAILSHIELD_FOLDERS=INBOX,Sent
"""

from __future__ import annotations

import email
import hashlib
import logging
import os
import re
import ssl
import threading
import time
from email import policy
from email.header import decode_header
from pathlib import Path
from typing import Iterable

from imapclient import IMAPClient

try:
    from win10toast import ToastNotifier
except ImportError:  # Windows 알림 패키지가 없으면 로그로 대체
    ToastNotifier = None


APP_NAME = "MailShield"
LOG_PATH = Path(os.getenv("LOCALAPPDATA", Path.home())) / "MailShield" / "monitor.log"
STOP_EVENT = threading.Event()
TOAST = ToastNotifier() if ToastNotifier else None


def configure_logging() -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=LOG_PATH,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(threadName)s %(message)s",
        encoding="utf-8",
    )


def env_required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"환경변수 {name}이(가) 설정되지 않았습니다.")
    return value


def decode_header_value(value: str | None) -> str:
    if not value:
        return ""
    result: list[str] = []
    for part, charset in decode_header(value):
        if isinstance(part, bytes):
            result.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            result.append(part)
    return "".join(result)


def mask(value: str, keep: int = 2) -> str:
    value = value.strip()
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "*" * min(8, len(value) - keep)


def extract_text(message: email.message.Message) -> str:
    chunks: list[str] = []
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_disposition() == "attachment":
                continue
            if part.get_content_type() == "text/plain":
                try:
                    chunks.append(part.get_content())
                except (LookupError, UnicodeError):
                    continue
    elif message.get_content_type() == "text/plain":
        try:
            chunks.append(message.get_content())
        except (LookupError, UnicodeError):
            pass
    return "\n".join(chunks)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def scan_message(raw_message: bytes, folder: str, uid: int) -> dict:
    """최소 로컬 분석. 운영 버전에서는 DLP·URL·악성코드 엔진으로 교체한다."""
    message = email.message_from_bytes(raw_message, policy=policy.default)
    subject = decode_header_value(message.get("Subject"))
    sender = decode_header_value(message.get("From"))
    text = extract_text(message)
    findings: list[str] = []

    # 운영용 탐지 엔진으로 교체할 초기 후보 패턴이다. 값 자체는 저장하지 않는다.
    patterns: Iterable[tuple[str, str]] = (
        (r"\b\d{6}[- ]?[1-4]\d{6}\b", "주민등록번호 의심 패턴"),
        (r"\b(?:\d[ -]?){13,19}\b", "카드·계좌번호 의심 패턴"),
        (r"(?i)(password|passwd|비밀번호|인증번호|api[_ -]?key|secret)", "인증정보 키워드"),
    )
    for pattern, label in patterns:
        if re.search(pattern, text):
            findings.append(label)

    attachments: list[dict] = []
    for part in message.walk():
        filename = part.get_filename()
        if not filename:
            continue
        payload = part.get_payload(decode=True) or b""
        lower_name = filename.lower()
        attachment = {
            "name": filename,
            "size": len(payload),
            "sha256": sha256_bytes(payload) if payload else None,
        }
        attachments.append(attachment)
        if lower_name.endswith((".exe", ".scr", ".js", ".vbs", ".ps1", ".bat", ".cmd")):
            findings.append(f"실행 가능 첨부파일: {filename}")
        if re.search(r"\.(pdf|docx?|xlsx?)\.(exe|scr|js|vbs)$", lower_name):
            findings.append(f"이중 확장자 의심: {filename}")

    result = {
        "folder": folder,
        "uid": uid,
        "subject": mask(subject, 12),
        "sender": mask(sender, 4),
        "findings": findings,
        "attachments": attachments,
        "risk": "high" if findings else "safe",
    }
    return result


def notify(title: str, message: str) -> None:
    logging.warning("%s: %s", title, message)
    if TOAST:
        try:
            TOAST.show_toast(title, message, duration=8, threaded=True)
        except Exception:
            logging.exception("Windows 알림 표시 실패")


def watch_folder(host: str, port: int, user: str, password: str, folder: str) -> None:
    backoff = 5
    while not STOP_EVENT.is_set():
        client: IMAPClient | None = None
        try:
            context = ssl.create_default_context()
            client = IMAPClient(host, port=port, ssl=True, ssl_context=context, timeout=60)
            client.login(user, password)
            client.select_folder(folder, readonly=True)
            status = client.folder_status(folder, ["UIDVALIDITY", "UIDNEXT"])
            last_uid = int(status.get(b"UIDNEXT", status.get("UIDNEXT", 1))) - 1
            logging.info("%s 감시 시작 (마지막 UID=%s)", folder, last_uid)
            backoff = 5

            while not STOP_EVENT.is_set():
                client.idle()
                responses = client.idle_check(timeout=25)
                client.idle_done()
                if not responses:
                    continue
                latest = client.search(["UID", f"{last_uid + 1}:*"])
                for uid in latest:
                    fetched = client.fetch([uid], [b"RFC822"])
                    raw = fetched.get(uid, {}).get(b"RFC822")
                    if not raw:
                        continue
                    result = scan_message(raw, folder, int(uid))
                    logging.info("분석 결과: %s", result)
                    if result["risk"] == "high":
                        notify("MailShield 위험 메일 감지", f"{folder}: {result['subject']} / {', '.join(result['findings'])}")
                    last_uid = max(last_uid, int(uid))
        except Exception:
            logging.exception("%s 감시 연결 오류; %s초 후 재연결", folder, backoff)
            STOP_EVENT.wait(backoff)
            backoff = min(backoff * 2, 300)
        finally:
            if client:
                try:
                    client.logout()
                except Exception:
                    pass


def main() -> None:
    configure_logging()
    host = env_required("MAILSHIELD_IMAP_HOST")
    user = env_required("MAILSHIELD_EMAIL")
    password = env_required("MAILSHIELD_APP_PASSWORD")
    port = int(os.getenv("MAILSHIELD_IMAP_PORT", "993"))
    folders = [item.strip() for item in os.getenv("MAILSHIELD_FOLDERS", "INBOX,Sent").split(",") if item.strip()]
    if not folders:
        raise RuntimeError("감시할 폴더가 없습니다.")

    workers = [
        threading.Thread(target=watch_folder, args=(host, port, user, password, folder), name=f"imap-{folder}", daemon=True)
        for folder in folders
    ]
    for worker in workers:
        worker.start()
    logging.info("%s 실시간 감시 시작: %s", APP_NAME, ", ".join(folders))
    try:
        while not STOP_EVENT.wait(1):
            pass
    except KeyboardInterrupt:
        logging.info("사용자 중지 요청")
    finally:
        STOP_EVENT.set()
        for worker in workers:
            worker.join(timeout=10)
        logging.info("%s 감시 종료", APP_NAME)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        logging.basicConfig(level=logging.ERROR)
        logging.exception("에이전트 시작 실패")
