"""브라우저 OAuth 2.0 + Gmail IMAP XOAUTH2 연결 확인 도구."""
from __future__ import annotations

import base64
import imaplib
import os
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

SCOPES = ["https://mail.google.com/"]
ROOT = Path(__file__).resolve().parent


def credentials() -> Credentials:
    token_path = ROOT / "token.json"
    client_path = ROOT / "credentials.json"
    creds = None
    if token_path.exists():
        creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not client_path.exists():
                raise FileNotFoundError("credentials.json이 code_snipt 폴더에 없습니다.")
            flow = InstalledAppFlow.from_client_secrets_file(str(client_path), SCOPES)
            creds = flow.run_local_server(host="localhost", port=0, access_type="offline", prompt="consent")
        token_path.write_text(creds.to_json(), encoding="utf-8")
    return creds


def main() -> int:
    creds = credentials()
    address = os.getenv("MAILSHIELD_GMAIL_ADDRESS", "wooriszhome@gmail.com")
    payload = f"user={address}\1auth=Bearer {creds.token}\1\1".encode()
    mail = imaplib.IMAP4_SSL("imap.gmail.com", 993, timeout=30)
    mail.authenticate("XOAUTH2", lambda _: base64.b64encode(payload))
    status, _ = mail.select("INBOX", readonly=True)
    print(f"[성공] OAuth/XOAUTH2 Gmail 인증, INBOX={status}")
    mail.logout()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
