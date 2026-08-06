"""Gmail IMAP 연결 진단 도구.

환경변수:
  MAILSHIELD_GMAIL_ADDRESS
  MAILSHIELD_GMAIL_APP_PASSWORD

Gmail 계정에서 IMAP을 활성화하고 2단계 인증 기반 앱 비밀번호를 사용해야 합니다.
이 도구는 본문·첨부파일을 다운로드하지 않고 폴더 접근과 최신 헤더만 확인합니다.
"""

from __future__ import annotations

import email
import getpass
import imaplib
import os
import sys
from email.header import decode_header


HOST = "imap.gmail.com"
PORT = 993


def decode_header_value(value: str | None) -> str:
    if not value:
        return ""
    output: list[str] = []
    for part, charset in decode_header(value):
        if isinstance(part, bytes):
            output.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            output.append(part)
    return "".join(output).replace("\r", " ").replace("\n", " ")


def first_folder(mail: imaplib.IMAP4_SSL, candidates: list[str]) -> str | None:
    status, folders = mail.list()
    if status != "OK" or not folders:
        return None
    names = [item.decode("utf-8", errors="replace") for item in folders if isinstance(item, bytes)]
    for candidate in candidates:
        if any(candidate.lower() in name.lower() for name in names):
            return candidate
    return None


def check_folder(mail: imaplib.IMAP4_SSL, folder: str) -> None:
    status, _ = mail.select(folder, readonly=True)
    if status != "OK":
        print(f"[실패] 폴더 접근: {folder}")
        return
    status, data = mail.search(None, "ALL")
    if status != "OK" or not data or not data[0]:
        print(f"[성공] {folder}: 메일 없음 또는 검색 완료")
        return
    latest_id = data[0].split()[-1]
    status, fetched = mail.fetch(latest_id, "(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE)])")
    if status != "OK":
        print(f"[실패] 헤더 조회: {folder}")
        return
    for part in fetched:
        if isinstance(part, tuple):
            message = email.message_from_bytes(part[1])
            print(f"[성공] {folder}: 최신 메일")
            print(f"       From: {decode_header_value(message.get('From'))}")
            print(f"       Subject: {decode_header_value(message.get('Subject'))}")
            print(f"       Date: {decode_header_value(message.get('Date'))}")
            return


def main() -> int:
    address = os.getenv("MAILSHIELD_GMAIL_ADDRESS", "").strip()
    password = os.getenv("MAILSHIELD_GMAIL_APP_PASSWORD", "").strip()
    if not address:
        address = input("Gmail 주소: ").strip()
    if not password:
        password = getpass.getpass("Gmail 앱 비밀번호: ").strip()
    # Google 화면에서 표시하는 4자리 그룹 공백·하이픈을 허용한다.
    password = password.replace(" ", "").replace("-", "")
    if not address or not password:
        print("Gmail 주소와 앱 비밀번호가 필요합니다.", file=sys.stderr)
        return 2

    mail: imaplib.IMAP4_SSL | None = None
    try:
        print(f"{HOST}:{PORT} TLS 연결 중...")
        mail = imaplib.IMAP4_SSL(HOST, PORT, timeout=30)
        mail.login(address, password)
        print("[성공] Gmail IMAP 인증")
        check_folder(mail, "INBOX")
        sent = first_folder(mail, ["Sent", "보낸편지함"])
        if sent:
            check_folder(mail, sent)
        else:
            print("[주의] 보낸편지함 폴더를 자동으로 찾지 못했습니다.")
        print("Gmail 연결 테스트 완료")
        return 0
    except imaplib.IMAP4.error:
        print("[실패] 인증 거부: IMAP 활성화, 2단계 인증, 앱 비밀번호를 확인하십시오.", file=sys.stderr)
        return 1
    except OSError as exception:
        print(f"[실패] 네트워크/TLS 연결: {exception}", file=sys.stderr)
        return 1
    finally:
        if mail is not None:
            try:
                mail.logout()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
