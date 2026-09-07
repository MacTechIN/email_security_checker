"""메일 1차 분석. code_snipt/realtime_email_monitor.pyw의 scan_message를 이식했다.

운영 버전에서는 DLP·URL·악성코드 엔진으로 교체한다. 탐지된 값 자체는 저장하지 않는다.
"""

from __future__ import annotations

import email
import hashlib
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from email import policy
from email.header import decode_header
from typing import Iterable

EXECUTABLE_SUFFIXES = (".exe", ".scr", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".com", ".pif", ".msi", ".hta")
DOUBLE_EXTENSION = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|hwp|txt|jpe?g|png)\.(exe|scr|js|vbs|bat|cmd|com|pif)$")

# (정규식, 라벨). 1단계에서는 프로토타입 규칙을 유지하고 오탐 데이터로 보정한다.
TEXT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b\d{6}[- ]?[1-4]\d{6}\b"), "주민등록번호 의심 패턴"),
    (re.compile(r"(?i)(password|passwd|비밀번호|인증번호|api[_ -]?key|secret)"), "인증정보 키워드"),
)
CARD_PATTERN = re.compile(r"\b(?:\d[ -]?){13,19}\b")
RRN_PATTERN = TEXT_PATTERNS[0][0]


@dataclass
class Attachment:
    name: str
    size: int
    sha256: str | None


@dataclass
class ScanResult:
    folder: str
    uid: int
    subject: str
    sender: str
    findings: list[str] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    risk: str = "safe"
    scanned_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def summary(self) -> str:
        return ", ".join(self.findings) if self.findings else "위험 요소 없음"


def decode_header_value(value: str | None) -> str:
    if not value:
        return ""
    result: list[str] = []
    for part, charset in decode_header(value):
        if isinstance(part, bytes):
            result.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            result.append(part)
    return "".join(result).replace("\r", " ").replace("\n", " ")


def mask(value: str, keep: int = 2) -> str:
    """앞부분 일부만 남기고 가린다. 짧은 값도 절반 이상은 가려 사건 목록에서 식별만 가능하게 한다."""
    value = value.strip()
    if len(value) <= 2:
        return "*" * len(value)
    keep = min(keep, (len(value) + 1) // 2)
    return value[:keep] + "*" * min(8, len(value) - keep)


def extract_text(message: email.message.Message) -> str:
    chunks: list[str] = []
    parts: Iterable[email.message.Message] = message.walk() if message.is_multipart() else (message,)
    for part in parts:
        if part.get_content_disposition() == "attachment":
            continue
        if part.get_content_type() != "text/plain":
            continue
        try:
            chunks.append(part.get_content())
        except (LookupError, UnicodeError, KeyError):
            continue
    return "\n".join(chunks)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def luhn_valid(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        number = int(char)
        if index % 2 == 1:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def find_card_numbers(text: str) -> bool:
    """주민등록번호와 겹치는 13자리 숫자열은 제외하고, 카드번호는 Luhn 체크섬을 요구한다."""
    rrn_spans = [match.span() for match in RRN_PATTERN.finditer(text)]
    for match in CARD_PATTERN.finditer(text):
        start, end = match.span()
        if any(start <= r_end and r_start <= end for r_start, r_end in rrn_spans):
            continue
        digits = re.sub(r"\D", "", match.group())
        if 13 <= len(digits) <= 19 and luhn_valid(digits):
            return True
    return False


def scan_message(raw_message: bytes, folder: str, uid: int) -> ScanResult:
    message = email.message_from_bytes(raw_message, policy=policy.default)
    subject = decode_header_value(message.get("Subject"))
    sender = decode_header_value(message.get("From"))
    text = f"{subject}\n{extract_text(message)}"
    findings: list[str] = []

    for pattern, label in TEXT_PATTERNS:
        if pattern.search(text):
            findings.append(label)
    if find_card_numbers(text):
        findings.append("카드·계좌번호 의심 패턴")

    attachments: list[Attachment] = []
    for part in message.walk():
        filename = part.get_filename()
        if not filename:
            continue
        payload = part.get_payload(decode=True) or b""
        lower_name = filename.lower()
        attachments.append(Attachment(name=filename, size=len(payload), sha256=sha256_bytes(payload) if payload else None))
        if lower_name.endswith(EXECUTABLE_SUFFIXES):
            findings.append(f"실행 가능 첨부파일: {filename}")
        if DOUBLE_EXTENSION.search(lower_name):
            findings.append(f"이중 확장자 의심: {filename}")

    return ScanResult(
        folder=folder,
        uid=uid,
        subject=mask(subject, 12),
        sender=mask(sender, 4),
        findings=findings,
        attachments=attachments,
        risk="high" if findings else "safe",
    )
