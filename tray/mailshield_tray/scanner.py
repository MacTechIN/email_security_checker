"""메일 1차 분석: 개인정보·민감정보·위험 첨부파일 탐지.

- 탐지된 값 원문은 저장하지 않고 항목 라벨과 건수만 남긴다.
- 위험도: high(고유식별정보·금융·인증정보·실행 첨부) / medium(연락처·주소·실명·생년월일·건강정보) / safe
- 운영 버전에서는 DLP·URL·악성코드 엔진으로 교체한다. 여기 규칙은 오탐 데이터로 계속 보정한다.
"""

from __future__ import annotations

import email
import hashlib
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from email import policy
from email.header import decode_header
from email.utils import getaddresses
from typing import Iterable

from . import threats
from .threats import RISK_HIGH, RISK_MEDIUM, RISK_SAFE

# ---------------------------------------------------------------------------
# 규칙 정의
# ---------------------------------------------------------------------------

Span = tuple[int, int]

# 개인정보 검사 전에 지워낼 링크. 추적 파라미터의 긴 숫자 ID와 토큰 이름이 오탐을 만든다.
URL_PATTERN = re.compile(
    r"""(?xi)
    \b(?:https?|ftp)://[^\s<>"']+
  | \bwww\.[\w-]+(?:\.[\w-]+)+[^\s<>"']*
"""
)


@dataclass(frozen=True)
class Rule:
    key: str
    label: str
    risk: str
    pattern: re.Pattern[str]
    validator: object | None = None  # Callable[[re.Match], bool]


def _valid_yymmdd(digits: str) -> bool:
    month, day = int(digits[2:4]), int(digits[4:6])
    return 1 <= month <= 12 and 1 <= day <= 31


def _rrn_valid(match: re.Match) -> bool:
    digits = re.sub(r"\D", "", match.group())
    return len(digits) == 13 and _valid_yymmdd(digits[:6])


def _luhn_valid(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        number = int(char)
        if index % 2 == 1:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def _card_valid(match: re.Match) -> bool:
    digits = re.sub(r"\D", "", match.group())
    return 13 <= len(digits) <= 19 and _luhn_valid(digits)


# 라벨 뒤에 온 일반 명사를 이름으로 오인하지 않기 위한 조사 목록.
# 이름에 흔한 '은/이/가'는 제외한다(김지은, 박서이 같은 실제 이름을 놓치지 않도록).
_NAME_TAIL_PARTICLES = ("는", "를", "을", "에", "의", "와", "과", "도", "만", "요", "서", "게", "께")


def _name_valid(value: str) -> bool:
    """한국 성씨로 시작하고, 조사로 끝나는 일반 명사가 아니어야 이름으로 본다."""
    if value[:1] not in KOREAN_SURNAMES:
        return False
    # '담당자 연락처는', '신청자 주소를'처럼 라벨+명사+조사 형태를 걸러낸다.
    return not (len(value) >= 3 and value.endswith(_NAME_TAIL_PARTICLES))


def _account_valid(match: re.Match) -> bool:
    digits = re.sub(r"\D", "", match.group("number"))
    return 10 <= len(digits) <= 14


def _birth_valid(match: re.Match) -> bool:
    year, month, day = int(match.group("y")), int(match.group("m")), int(match.group("d"))
    return 1900 <= year <= datetime.now().year and 1 <= month <= 12 and 1 <= day <= 31


# 흔한 한국 성씨. 실명 탐지의 정밀도를 높이기 위해 첫 글자를 검사한다.
KOREAN_SURNAMES = set(
    "김이박최정강조윤장임한오서신권황안송류전홍고문양손배백허유남심노하곽성차주우구민나진지엄채원천방공현함변염여추도소석선설마길연위표명기반왕금옥육인맹제모탁국어은편용예경봉사부가복태목형피두감음빈동온"
)
_NAME_TITLES = (
    "님|씨|귀하|과장|부장|대리|팀장|차장|이사|대표|사장|전무|상무|교수|선생님|주임|사원|원장|박사|변호사|회계사|의사|간호사|실장|본부장|센터장|매니저|여사"
)
# 강한 라벨은 콜론 없이도 뒤따르는 이름을 인정하고, 약한 라벨은 콜론이 있어야 한다.
_NAME_LABELS_STRONG = "이름|성명|성함|담당자|신청자|신청인|고객명|예금주|수취인|수신인|수신자|발신인|보호자|환자명|작성자|대표자|계약자|가입자|명의자"
_NAME_LABELS_WEAK = "담당|고객|환자|학생|이용자|사용자|수신|발신|참석자|응모자"

RULES: tuple[Rule, ...] = (
    # --- high: 고유식별정보·금융·인증 ---
    Rule("rrn", "주민등록번호", RISK_HIGH, re.compile(r"(?<!\d)\d{6}[- ]?[1-4]\d{6}(?!\d)"), _rrn_valid),
    Rule("frn", "외국인등록번호", RISK_HIGH, re.compile(r"(?<!\d)\d{6}[- ]?[5-8]\d{6}(?!\d)"), _rrn_valid),
    Rule("driver", "운전면허번호", RISK_HIGH, re.compile(r"(?<![\d-])(?:1[1-9]|2[0-8])-\d{2}-\d{6}-\d{2}(?![\d-])")),
    Rule("passport", "여권번호", RISK_HIGH, re.compile(r"(?<![A-Za-z0-9])(?:[MSRODG]\d{8}|[A-Z]{2}\d{7})(?![A-Za-z0-9])")),
    Rule("card", "카드번호", RISK_HIGH, re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])"), _card_valid),
    Rule(
        "account",
        "계좌번호",
        RISK_HIGH,
        re.compile(
            r"(?:은행|계좌|농협|국민|신한|우리|하나|기업|카카오뱅크|토스뱅크|케이뱅크|새마을|우체국|수협|씨티|SC제일|대구|부산|광주|전북|경남|제주|산업)\s*(?:은행)?[^\d\n]{0,12}(?P<number>\d{2,6}(?:-\d{2,8}){1,4})"
        ),
        _account_valid,
    ),
    # 영문 키워드는 단어 경계를 요구한다. 경계가 없으면 `otpToken`, `passwordless` 같은 식별자에 걸린다.
    Rule("credential", "인증정보 키워드", RISK_HIGH, re.compile(r"(?i)(\b(?:password|passwd|otp|api[_ -]?key|secret[_ -]?key|access[_ -]?token)\b|pwd\s*[:=]|비밀번호|패스워드|인증번호|공인인증서|보안카드)")),
    # --- medium: 연락처·주소·실명·생년월일·건강 ---
    Rule("mobile", "휴대전화번호", RISK_MEDIUM, re.compile(r"(?<!\d)(?:\+82[- ]?1?0|010|011|016|017|018|019)[- .]?\d{3,4}[- .]?\d{4}(?!\d)")),
    Rule("phone", "유선전화번호", RISK_MEDIUM, re.compile(r"(?<!\d)(?:\+82[- ]?|0)(?:2|3[1-3]|4[1-4]|5[1-5]|6[1-4]|70|50\d?)[- .)]?\d{3,4}[- .]?\d{4}(?!\d)")),
    Rule("email", "이메일 주소", RISK_MEDIUM, re.compile(r"(?i)(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+(?![\w.-])")),
    Rule(
        "address",
        "주소",
        RISK_MEDIUM,
        re.compile(
            r"(?:서울|부산|대구|인천|광주|대전|울산|세종|경기|강원|충청?북|충청?남|전라?북|전라?남|경상?북|경상?남|제주)"
            r"(?:특별자치시|특별자치도|특별시|광역시|도|시)?\s*"
            r"(?:[가-힣]{1,6}(?:시|군|구)\s*){1,2}"
            r"(?:[가-힣0-9]{1,12}(?:로|길|동|읍|면|가)\s*)+\d+(?:-\d+)?"
        ),
    ),
    Rule("postal", "우편번호", RISK_MEDIUM, re.compile(r"(?:우편번호|우\.?편|zip(?:\s*code)?|postal)\s*[:：]?\s*\d{5}(?!\d)")),
    Rule(
        "birth",
        "생년월일",
        RISK_MEDIUM,
        # 두 자리 알터너티브를 먼저 둔다. 순서를 뒤집으면 '21일'에서 '2'만 잡혀 값 범위가 어긋난다.
        re.compile(r"(?:생년월일|생일|출생|birth(?:day|\s*date)?|DOB)\s*[:：]?\s*(?P<y>19\d{2}|20\d{2})\s*[.\-/년]\s*(?P<m>1[0-2]|0?[1-9])(?!\d)\s*[.\-/월]\s*(?P<d>3[01]|[12]\d|0?[1-9])(?!\d)\s*일?"),
        _birth_valid,
    ),
    Rule(
        "name",
        "실명",
        RISK_MEDIUM,
        re.compile(
            rf"(?:(?:{_NAME_LABELS_STRONG})\s*[:：]?\s*(?P<n1>[가-힣]{{2,4}})(?![가-힣]))"
            rf"|(?:(?:{_NAME_LABELS_WEAK})\s*[:：]\s*(?P<n3>[가-힣]{{2,4}})(?![가-힣]))"
            rf"|(?:(?<![가-힣])(?P<n2>[가-힣]{{2,4}})\s?(?:{_NAME_TITLES})(?:님)?(?![가-힣]))"
        ),
        lambda m: _name_valid(m.group("n1") or m.group("n3") or m.group("n2") or ""),
    ),
    Rule(
        "health",
        "건강·의료 정보 키워드",
        RISK_MEDIUM,
        re.compile(r"(진단서|진단명|병명|처방전|처방내역|진료기록|진료내역|검진결과|건강검진|투약|입원|수술\s*기록|장애\s*등급|정신과|산부인과|HIV|에이즈|암\s*진단|우울증|치료\s*경과)"),
    ),
    Rule("biz", "사업자등록번호", RISK_MEDIUM, re.compile(r"(?<!\d)\d{3}-\d{2}-\d{5}(?!\d)")),
)

_RULE_BY_KEY = {rule.key: rule for rule in RULES}


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
    risk: str = RISK_SAFE
    counts: dict[str, int] = field(default_factory=dict)
    # 로컬 시간대(한국이면 +09:00) 오프셋을 포함해 저장한다. 표시는 local_timestamp()를 쓴다.
    scanned_at: str = field(default_factory=lambda: datetime.now().astimezone().isoformat(timespec="seconds"))

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def summary(self) -> str:
        return ", ".join(self.findings) if self.findings else "위험 요소 없음"

    @property
    def risk_label(self) -> str:
        return {RISK_HIGH: "높음", RISK_MEDIUM: "주의"}.get(self.risk, "정상")


# ---------------------------------------------------------------------------
# 도우미
# ---------------------------------------------------------------------------


def local_timestamp(value: str) -> str:
    """저장된 ISO 8601 시각을 로컬 시간(한국이면 KST) 문자열로 바꾼다.

    0.1.5 이전에 UTC로 기록된 사건도 함께 변환한다.
    """
    if not value:
        return ""
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return value[:19].replace("T", " ")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)  # 예전 기록은 UTC로 저장했다
    return parsed.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def local_timezone_label() -> str:
    """표 머리글에 쓸 현재 시간대 표기. 한국이면 'UTC+9'."""
    offset = datetime.now().astimezone().utcoffset() or timedelta(0)
    minutes = round(offset.total_seconds() / 60)
    sign = "-" if minutes < 0 else "+"
    hours, remainder = divmod(abs(minutes), 60)
    return f"UTC{sign}{hours}" + (f":{remainder:02d}" if remainder else "")


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
        content_type = part.get_content_type()
        if content_type not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError, KeyError):
            continue
        if content_type == "text/html":
            content = _html_to_text(content)
        chunks.append(content)
    return "\n".join(chunks)


_TAG = re.compile(r"<(script|style)[^>]*>.*?</\1>|<[^>]+>", re.S | re.I)
_ENTITIES = {"&nbsp;": " ", "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&#39;": "'"}


def _html_to_text(html: str) -> str:
    text = _TAG.sub(" ", html)
    for entity, char in _ENTITIES.items():
        text = text.replace(entity, char)
    return re.sub(r"[ \t]+", " ", text)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _overlaps(span: Span, taken: list[Span]) -> bool:
    start, end = span
    return any(start < t_end and t_start < end for t_start, t_end in taken)


def _participants(message: email.message.Message) -> set[str]:
    addresses: set[str] = set()
    for header in ("From", "To", "Cc", "Reply-To", "Sender"):
        values = message.get_all(header, [])
        for _, address in getaddresses([decode_header_value(v) for v in values]):
            if address:
                addresses.add(address.lower())
    return addresses


def strip_urls(text: str) -> str:
    """URL을 같은 길이의 공백으로 지운다(오프셋 유지).

    링크의 추적 파라미터에는 긴 숫자 ID와 `otpToken` 같은 식별자가 들어 있어
    카드번호·인증정보 규칙의 오탐 원인이 된다. 링크 자체의 위험은 별도 URL 검사기가 맡는다.
    """
    return URL_PATTERN.sub(lambda m: " " * (m.end() - m.start()), text)


def scan_text(text: str, ignore_emails: set[str] | None = None) -> dict[str, int]:
    """본문에서 규칙별 탐지 건수를 돌려준다. 값 원문은 반환하지 않는다."""
    text = strip_urls(text)
    ignore_emails = {a.lower() for a in (ignore_emails or set())}
    counts: dict[str, int] = {}
    taken: list[Span] = []
    # RULES 순서가 우선순위다: 먼저 잡힌 고위험 구간과 겹치는 저위험 매치는 버린다.
    for rule in RULES:
        for match in rule.pattern.finditer(text):
            if _overlaps(match.span(), taken):
                continue
            if rule.validator is not None and not rule.validator(match):
                continue
            if rule.key == "email" and match.group().lower() in ignore_emails:
                continue
            counts[rule.key] = counts.get(rule.key, 0) + 1
            taken.append(match.span())
    return counts


@dataclass
class Evidence:
    """탐지 근거 한 건. 값은 가리고 주변 문맥만 보여 준다."""

    key: str
    label: str
    risk: str
    masked_value: str
    context: str
    in_url: bool = False  # 링크 안 문자열에서 매치됨(옛 규칙 재현에서만 True가 될 수 있다)


# 0.1.6 이전 인증정보 키워드 규칙(단어 경계 없음). 과거 판정을 재현할 때만 쓴다.
_LEGACY_CREDENTIAL = re.compile(r"(?i)(password|passwd|pwd\s*[:=]|비밀번호|패스워드|인증번호|otp|api[_ -]?key|secret[_ -]?key|access[_ -]?token|공인인증서|보안카드)")


def _value_span(match: re.Match) -> Span:
    """규칙이 값 그룹을 정의했으면 그 범위를, 아니면 매치 전체를 돌려준다.

    '예금주 홍길동'에서 라벨까지 가리지 않고 이름만 가리기 위한 것이다.
    """
    spans = [match.span(name) for name in match.re.groupindex if match.group(name) is not None]
    spans = [span for span in spans if span != (-1, -1)]
    if not spans:
        return match.span()
    return min(span[0] for span in spans), max(span[1] for span in spans)


def _mask_value(key: str, value: str) -> str:
    """식별 가능한 값은 가린다. 키워드처럼 값이 아닌 매치는 그대로 보여 준다."""
    if key in ("credential", "health"):
        return value
    if len(value) <= 4:
        return "*" * len(value)
    keep_tail = 2 if len(value) > 8 else 1
    return value[:3] + "*" * (len(value) - 3 - keep_tail) + value[-keep_tail:]


def explain_text(
    text: str,
    ignore_emails: set[str] | None = None,
    context_chars: int = 60,
    include_urls: bool = False,
) -> list[Evidence]:
    """scan_text와 같은 판정을 하되, 근거로 쓸 문맥을 함께 돌려준다.

    문맥에는 탐지된 값이 그대로 남지 않는다. 근처의 다른 탐지값도 함께 가린다.
    include_urls=True면 링크를 지우지 않고 검사한다(0.1.6 이전 동작 재현용).
    """
    ignore_emails = {a.lower() for a in (ignore_emails or set())}
    url_spans = [m.span() for m in URL_PATTERN.finditer(text)]
    stripped = text if include_urls else strip_urls(text)
    hits: list[tuple[Rule, Span, Span, str]] = []
    taken: list[Span] = []
    for rule in RULES:
        for match in rule.pattern.finditer(stripped):
            if _overlaps(match.span(), taken):
                continue
            if rule.validator is not None and not rule.validator(match):
                continue
            if rule.key == "email" and match.group().lower() in ignore_emails:
                continue
            taken.append(match.span())
            value_span = _value_span(match)
            hits.append((rule, match.span(), value_span, _mask_value(rule.key, stripped[slice(*value_span)])))

    # 마스킹은 길이를 그대로 유지하므로 원문 위치를 그대로 쓸 수 있다.
    chars = list(text)
    for _rule, _match_span, (start, end), masked in hits:
        chars[start:end] = list(masked)
    masked_text = "".join(chars)

    found: list[Evidence] = []
    for rule, (start, end), _value_range, masked in sorted(hits, key=lambda item: item[1]):
        left = max(0, start - context_chars)
        right = min(len(masked_text), end + context_chars)
        found.append(
            Evidence(
                key=rule.key,
                label=rule.label,
                risk=rule.risk,
                masked_value=masked,
                context=" ".join(masked_text[left:right].split()),
                in_url=any(u_start <= start < u_end for u_start, u_end in url_spans),
            )
        )
    return found


def explain_legacy_text(text: str, ignore_emails: set[str] | None = None, context_chars: int = 60) -> list[Evidence]:
    """0.1.6 이전 규칙으로 판정 근거를 재현한다.

    당시에는 링크를 지우지 않았고 영문 인증정보 키워드에 단어 경계가 없었다.
    과거 사건 기록이 지금 규칙으로는 재현되지 않을 때 '왜 잡혔는지' 보여 주기 위한 것이다.
    """
    found = explain_text(text, ignore_emails, context_chars, include_urls=True)
    for match in _LEGACY_CREDENTIAL.finditer(text):
        # 지금 규칙(단어 경계)으로 잡히는 매치는 위 결과에 이미 있으므로 건너뛴다.
        if _RULE_BY_KEY["credential"].pattern.match(text, match.start()):
            continue
        left = max(0, match.start() - context_chars)
        right = min(len(text), match.end() + context_chars)
        context = " ".join(text[left:right].split())
        found.append(
            Evidence(
                key="credential",
                label="인증정보 키워드(단어 일부 일치)",
                risk=RISK_HIGH,
                masked_value=match.group(),
                context=context,
                in_url=any(u.start() <= match.start() < u.end() for u in URL_PATTERN.finditer(text)),
            )
        )
    return found


def explain_message(raw_message: bytes, own_addresses: Iterable[str] = (), legacy: bool = False) -> list[Evidence]:
    """원본 메일에서 개인정보 탐지 근거를 뽑는다. 저장하지 않고 화면 표시용으로만 쓴다.

    legacy=True면 0.1.6 이전 규칙(링크 포함, 단어 경계 없음)으로 재현한다.
    """
    message = email.message_from_bytes(raw_message, policy=policy.default)
    subject = decode_header_value(message.get("Subject"))
    text = f"{subject}\n{extract_text(message)}"
    ignore = _participants(message) | {a.lower() for a in own_addresses}
    return explain_legacy_text(text, ignore) if legacy else explain_text(text, ignore)


def _format_findings(counts: dict[str, int]) -> list[str]:
    findings: list[str] = []
    for rule in RULES:
        number = counts.get(rule.key)
        if number:
            findings.append(f"{rule.label} {number}건" if rule.key not in ("credential", "health") else rule.label)
    return findings


def _risk_from_counts(counts: dict[str, int]) -> str:
    if any(_RULE_BY_KEY[key].risk == RISK_HIGH for key in counts):
        return RISK_HIGH
    if counts:
        return RISK_MEDIUM
    return RISK_SAFE


# ---------------------------------------------------------------------------
# 진입점
# ---------------------------------------------------------------------------


def scan_message(raw_message: bytes, folder: str, uid: int, own_addresses: Iterable[str] = ()) -> ScanResult:
    message = email.message_from_bytes(raw_message, policy=policy.default)
    subject = decode_header_value(message.get("Subject"))
    sender = decode_header_value(message.get("From"))
    text = f"{subject}\n{extract_text(message)}"

    ignore = _participants(message) | {a.lower() for a in own_addresses}
    counts = scan_text(text, ignore)
    findings = _format_findings(counts)

    # 랜섬웨어 협박 문구·확장자 언급
    ransom = threats.scan_ransomware_text(text)
    findings.extend(ransom.findings)

    attachments: list[Attachment] = []
    reports: list[threats.AttachmentReport] = []
    attachment_risk = RISK_SAFE
    for part in message.walk():
        filename = part.get_filename()
        if not filename:
            continue
        payload = part.get_payload(decode=True) or b""
        attachments.append(Attachment(name=filename, size=len(payload), sha256=sha256_bytes(payload) if payload else None))
        report = threats.analyze_attachment(filename, payload, part.get_content_type())
        reports.append(report)
        findings.extend(report.findings)
        attachment_risk = _max_risk(attachment_risk, report.risk)
    findings.extend(threats.ransomware_delivery_findings(reports))

    risk = _max_risk(_risk_from_counts(counts), ransom.risk, attachment_risk)
    return ScanResult(
        folder=folder,
        uid=uid,
        subject=mask(subject, 12),
        sender=mask(sender, 4),
        findings=findings,
        attachments=attachments,
        risk=risk,
        counts=counts,
    )


_RISK_ORDER = {RISK_SAFE: 0, RISK_MEDIUM: 1, RISK_HIGH: 2}


def _max_risk(*risks: str) -> str:
    return max(risks, key=lambda r: _RISK_ORDER.get(r, 0))
