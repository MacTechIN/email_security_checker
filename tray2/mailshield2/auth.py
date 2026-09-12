"""자격증명 저장(Windows Credential Manager)과 IMAP 인증.

- 앱 비밀번호와 Google OAuth 토큰은 keyring을 통해 Credential Manager에만 저장한다.
- 디스크의 평문 파일에는 어떤 비밀값도 쓰지 않는다.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

import keyring
from keyring.errors import KeyringError

from . import paths
from .store import AUTH_OAUTH, AccountSettings

if TYPE_CHECKING:  # pragma: no cover
    from imapclient import IMAPClient

log = logging.getLogger(__name__)

SERVICE_PASSWORD = "MailShield/imap"
SERVICE_OAUTH = "MailShield/google-oauth"
# Windows Credential Manager 항목당 약 1280자 제한이 있어 긴 값은 나눠 저장한다.
CHUNK_SIZE = 1000
GOOGLE_SCOPES = ["https://mail.google.com/"]


class AuthError(Exception):
    """사용자 조치가 필요한 인증 문제(비밀번호 없음, 재로그인 필요 등)."""


class CredentialStore:
    def get_app_password(self, email: str) -> str | None:
        return self._get(SERVICE_PASSWORD, email)

    def set_app_password(self, email: str, password: str) -> None:
        self._set(SERVICE_PASSWORD, email, password.replace(" ", "").replace("-", ""))

    def delete_app_password(self, email: str) -> None:
        self._delete(SERVICE_PASSWORD, email)

    def get_oauth_token(self, email: str) -> str | None:
        return self._get(SERVICE_OAUTH, email)

    def set_oauth_token(self, email: str, token_json: str) -> None:
        self._set(SERVICE_OAUTH, email, token_json)

    def delete_oauth_token(self, email: str) -> None:
        self._delete(SERVICE_OAUTH, email)

    def delete_all(self, email: str) -> None:
        self.delete_app_password(email)
        self.delete_oauth_token(email)

    # --- 내부: 청크 저장 ---
    @staticmethod
    def _key(email: str, index: int) -> str:
        return email.lower() if index == 0 else f"{email.lower()}#{index}"

    def _get(self, service: str, email: str) -> str | None:
        try:
            first = keyring.get_password(service, self._key(email, 0))
        except KeyringError as exception:
            log.warning("자격증명 조회 실패: %s", exception)
            return None
        if first is None:
            return None
        parts = [first]
        index = 1
        while True:
            try:
                chunk = keyring.get_password(service, self._key(email, index))
            except KeyringError:
                break
            if chunk is None:
                break
            parts.append(chunk)
            index += 1
        return "".join(parts)

    def _set(self, service: str, email: str, value: str) -> None:
        self._delete(service, email)
        chunks = [value[i : i + CHUNK_SIZE] for i in range(0, len(value), CHUNK_SIZE)] or [""]
        for index, chunk in enumerate(chunks):
            keyring.set_password(service, self._key(email, index), chunk)

    def _delete(self, service: str, email: str) -> None:
        index = 0
        while True:
            key = self._key(email, index)
            try:
                if keyring.get_password(service, key) is None:
                    break
                keyring.delete_password(service, key)
            except KeyringError:
                break
            index += 1


class GoogleOAuth:
    """google-auth 기반 데스크톱 OAuth. 토큰은 CredentialStore에만 저장한다."""

    def __init__(self, store: CredentialStore, client_path: Path | None = None) -> None:
        self._store = store
        self._client_path = client_path or paths.google_client_path()

    @property
    def client_path(self) -> Path:
        return self._client_path

    def has_client(self) -> bool:
        return self._client_path.exists()

    def install_client_file(self, source: Path) -> None:
        """사용자가 고른 OAuth 클라이언트 JSON을 데이터 폴더로 복사한다."""
        data = json.loads(source.read_text(encoding="utf-8"))
        if "installed" not in data:
            raise AuthError("데스크톱 앱 유형의 OAuth 클라이언트 파일이 아닙니다. Google Cloud Console에서 '데스크톱 앱'으로 만든 JSON을 선택하십시오.")
        target = paths.data_dir() / "google_client.json"
        target.write_text(json.dumps(data), encoding="utf-8")
        self._client_path = target

    def authorize_interactive(self, email: str):
        """브라우저를 열어 동의를 받고 토큰을 저장한다. UI 스레드 밖에서 호출한다."""
        from google_auth_oauthlib.flow import InstalledAppFlow

        if not self.has_client():
            raise AuthError("Google OAuth 클라이언트 파일(google_client.json)이 없습니다. 계정 설정에서 파일을 선택하십시오.")
        flow = InstalledAppFlow.from_client_secrets_file(str(self._client_path), GOOGLE_SCOPES)
        creds = flow.run_local_server(
            host="localhost",
            port=0,
            access_type="offline",
            prompt="consent",
            login_hint=email,
            authorization_prompt_message="",
            success_message="MailShield 인증이 완료되었습니다. 이 창을 닫아도 됩니다.",
            open_browser=True,
            timeout_seconds=300,  # 브라우저 응답이 없으면 5분 후 포기해 UI 버튼이 되살아나게 한다.
        )
        self._store.set_oauth_token(email, creds.to_json())
        return creds

    def load(self, email: str):
        from google.oauth2.credentials import Credentials

        token_json = self._store.get_oauth_token(email)
        if not token_json:
            return None
        try:
            return Credentials.from_authorized_user_info(json.loads(token_json), GOOGLE_SCOPES)
        except (ValueError, json.JSONDecodeError):
            return None

    def access_token(self, email: str) -> str:
        from google.auth.exceptions import RefreshError
        from google.auth.transport.requests import Request

        creds = self.load(email)
        if creds is None:
            raise AuthError("Google 계정 로그인이 필요합니다. 계정 설정에서 'Google 로그인'을 실행하십시오.")
        if not creds.valid:
            if not creds.refresh_token:
                raise AuthError("Google 토큰이 만료되었습니다. 계정 설정에서 다시 로그인하십시오.")
            try:
                creds.refresh(Request())
            except RefreshError as exception:
                raise AuthError("Google 토큰 갱신이 거부되었습니다(테스트 모드 앱은 7일 후 만료). 다시 로그인하십시오.") from exception
            self._store.set_oauth_token(email, creds.to_json())
        return creds.token


class Authenticator:
    """monitor가 IMAP 연결마다 호출한다."""

    def __init__(self, account: AccountSettings, store: CredentialStore, oauth: GoogleOAuth) -> None:
        self._account = account
        self._store = store
        self._oauth = oauth

    def login(self, client: "IMAPClient") -> None:
        email = self._account.email
        if self._account.auth_method == AUTH_OAUTH:
            token = self._oauth.access_token(email)
            client.oauth2_login(email, token)
            return
        password = self._store.get_app_password(email)
        if not password:
            raise AuthError("앱 비밀번호가 저장되어 있지 않습니다. 계정 설정에서 입력하십시오.")
        client.login(email, password)
