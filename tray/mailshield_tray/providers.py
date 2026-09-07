"""이메일 도메인으로 IMAP 공급자를 판별한다.

1단계는 잘 알려진 공급자 표만 사용한다. DNS·Autoconfig 자동 탐지는 2단계(FN-101) 범위다.
"""

from __future__ import annotations

from dataclasses import dataclass

from .store import AUTH_APP_PASSWORD, AUTH_OAUTH


@dataclass(frozen=True)
class Provider:
    key: str
    display: str
    imap_host: str
    imap_port: int = 993
    supports_oauth: bool = False
    default_auth: str = AUTH_APP_PASSWORD
    help_url: str = ""


GMAIL = Provider(
    key="gmail",
    display="Gmail / Google Workspace",
    imap_host="imap.gmail.com",
    supports_oauth=True,
    default_auth=AUTH_OAUTH,
    help_url="https://myaccount.google.com/apppasswords",
)

_PROVIDERS: dict[str, Provider] = {
    "gmail.com": GMAIL,
    "googlemail.com": GMAIL,
    "naver.com": Provider("naver", "Naver", "imap.naver.com", help_url="https://help.naver.com/service/5640/contents/8380"),
    "daum.net": Provider("daum", "Daum / Kakao", "imap.daum.net"),
    "hanmail.net": Provider("daum", "Daum / Kakao", "imap.daum.net"),
    "kakao.com": Provider("kakao", "Kakao Mail", "imap.kakao.com"),
    "outlook.com": Provider("outlook", "Outlook.com", "outlook.office365.com"),
    "hotmail.com": Provider("outlook", "Outlook.com", "outlook.office365.com"),
    "live.com": Provider("outlook", "Outlook.com", "outlook.office365.com"),
    "yahoo.com": Provider("yahoo", "Yahoo", "imap.mail.yahoo.com"),
    "icloud.com": Provider("icloud", "iCloud", "imap.mail.me.com"),
    "me.com": Provider("icloud", "iCloud", "imap.mail.me.com"),
}


def detect(email_address: str) -> Provider | None:
    address = email_address.strip().lower()
    if "@" not in address:
        return None
    domain = address.rsplit("@", 1)[1]
    return _PROVIDERS.get(domain)


def guess_host(email_address: str) -> str:
    """알려진 공급자가 아니면 관례적인 imap.<도메인>을 제안한다. 사용자가 수정할 수 있다."""
    provider = detect(email_address)
    if provider:
        return provider.imap_host
    if "@" in email_address:
        return "imap." + email_address.strip().lower().rsplit("@", 1)[1]
    return ""
