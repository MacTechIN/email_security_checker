"""발신자 검증 (docs/06 우선순위 2·3). 헤더만으로 판정하며 네트워크를 쓰지 않는다.

- 수신 서버가 붙인 Authentication-Results의 dmarc/spf/dkim 결과
- 표시 이름에 실제와 다른 이메일 주소가 들어간 위장
- Reply-To가 From과 다른 도메인, 특히 무료 웹메일로 회신을 돌리는 BEC 전형
- 국내 기관·주요 서비스 이름을 쓰면서 공식 도메인이 아닌 발신(사칭). 목록은 docs/06 §5.5 KISA 조사 반영
- 제목이 RE:/FW:인데 In-Reply-To·References가 없는 가짜 스레드
"""

from __future__ import annotations

import email
import re
from dataclasses import dataclass, field
from email.utils import getaddresses

from .links import registered_domain
from .threats import RISK_HIGH, RISK_MEDIUM, RISK_SAFE

FREEMAIL = frozenset(
    "gmail.com googlemail.com naver.com daum.net hanmail.net kakao.com nate.com outlook.com hotmail.com live.com yahoo.com yahoo.co.kr "
    "mail.ru inbox.ru list.ru bk.ru yandex.ru yandex.com protonmail.com proton.me icloud.com me.com aol.com gmx.com zoho.com".split()
)

# 사칭 사전: (표시 이름·제목에서 찾을 키워드 정규식, 공식 등록 도메인들). KISA·ASEC·알약 사례 기반.
IMPERSONATION: tuple[tuple[str, re.Pattern[str], frozenset[str]], ...] = (
    ("국세청/홈택스", re.compile(r"국세청|홈택스|hometax|전자세금계산서|nts\b", re.I), frozenset({"nts.go.kr", "hometax.go.kr", "go.kr"})),
    ("행정안전부/정부24/국민비서", re.compile(r"행정안전부|정부24|국민비서|위택스|wetax", re.I), frozenset({"mois.go.kr", "gov.kr", "wetax.go.kr", "go.kr"})),
    ("경찰청/검찰청", re.compile(r"경찰청|경찰서|검찰청|대검찰청|사이버수사", re.I), frozenset({"police.go.kr", "spo.go.kr", "go.kr"})),
    ("국민건강보험/국민연금", re.compile(r"건강보험공단|건강검진|국민연금", re.I), frozenset({"nhis.or.kr", "nps.or.kr"})),
    ("금융위원회/금감원", re.compile(r"금융위원회|금융감독원|금감원", re.I), frozenset({"fsc.go.kr", "fss.or.kr", "go.kr"})),
    ("KISA/한국인터넷진흥원", re.compile(r"한국인터넷진흥원|KISA|보호나라|KrCERT", re.I), frozenset({"kisa.or.kr", "krcert.or.kr", "boho.or.kr"})),
    ("네이버", re.compile(r"네이버|naver|N 관리자|MYBOX", re.I), frozenset({"naver.com", "navercorp.com", "naver.co.kr"})),
    ("카카오", re.compile(r"카카오|kakao", re.I), frozenset({"kakao.com", "kakaocorp.com", "kakaobank.com", "kakaopay.com"})),
    ("Google", re.compile(r"\bgoogle\b|구글|gmail 팀", re.I), frozenset({"google.com", "accounts.google.com", "youtube.com"})),
    ("Microsoft", re.compile(r"microsoft|마이크로소프트|office ?365|outlook 팀", re.I), frozenset({"microsoft.com", "accountprotection.microsoft.com", "office.com", "live.com", "outlook.com"})),
    ("Apple", re.compile(r"\bapple\b|애플|icloud", re.I), frozenset({"apple.com", "icloud.com"})),
    ("우체국/택배", re.compile(r"우체국|CJ대한통운|대한통운|한진택배|롯데택배|로젠택배|택배", re.I), frozenset({"epost.go.kr", "koreapost.go.kr", "cjlogistics.com", "hanjin.co.kr", "lotteglogis.com", "ilogen.com"})),
    ("쿠팡", re.compile(r"쿠팡|coupang", re.I), frozenset({"coupang.com"})),
    ("은행", re.compile(r"(?:국민|신한|우리|하나|기업|농협|카카오|토스|케이)\s?은행|KB국민|kbstar|shinhan|wooribank|hanabank|ibk\b", re.I),
     frozenset({"kbstar.com", "kbcard.com", "shinhan.com", "wooribank.com", "hanabank.com", "kebhana.com", "ibk.co.kr", "nonghyup.com", "nhbank.com", "kakaobank.com", "toss.im", "kbanknow.com"})),
    ("텔레그램", re.compile(r"telegram|텔레그램", re.I), frozenset({"telegram.org"})),
)

REPLY_SUBJECT_RE = re.compile(r"(?i)^\s*(?:re|fw|fwd|답장|회신|전달)\s*[:：]")
AUTH_RESULT_RE = re.compile(r"(?i)\b(dmarc|spf|dkim)\s*=\s*([a-z]+)")


@dataclass
class SenderReport:
    findings: list[str] = field(default_factory=list)
    risk: str = RISK_SAFE
    counts: dict[str, int] = field(default_factory=dict)
    from_domain: str = ""

    def add(self, key: str, label: str, risk: str) -> None:
        self.counts[key] = self.counts.get(key, 0) + 1
        if label not in self.findings:
            self.findings.append(label)
        if risk == RISK_HIGH or (risk == RISK_MEDIUM and self.risk == RISK_SAFE):
            self.risk = risk


def _first_address(message: email.message.Message, header: str) -> tuple[str, str]:
    values = message.get_all(header, [])
    if not values:
        return "", ""
    pairs = getaddresses([str(v) for v in values])
    for name, address in pairs:
        if address:
            return name.strip(), address.strip().lower()
    return "", ""


def parse_auth_results(message: email.message.Message) -> dict[str, str]:
    """가장 위쪽(수신 서버가 마지막에 붙인) Authentication-Results 한 줄만 신뢰한다."""
    values = message.get_all("Authentication-Results", [])
    if not values:
        return {}
    results: dict[str, str] = {}
    for method, outcome in AUTH_RESULT_RE.findall(str(values[0])):
        results.setdefault(method.lower(), outcome.lower())
    return results


def analyze_sender(message: email.message.Message, own_addresses: tuple[str, ...] = ()) -> SenderReport:
    report = SenderReport()
    display, from_addr = _first_address(message, "From")
    from_domain = from_addr.rsplit("@", 1)[-1] if "@" in from_addr else ""
    report.from_domain = from_domain
    from_reg = registered_domain(from_domain) if from_domain else ""
    own_domains = {a.rsplit("@", 1)[-1].lower() for a in own_addresses if "@" in a}
    if from_addr in {a.lower() for a in own_addresses}:
        return report  # 본인이 보낸 메일(보낸편지함)은 발신자 검증 대상이 아니다

    # 1. 인증 결과
    auth = parse_auth_results(message)
    if auth.get("dmarc") == "fail":
        report.add("dmarc_fail", "발신 도메인 인증 실패(DMARC)", RISK_HIGH)
    elif auth.get("spf") in ("fail", "softfail") or auth.get("dkim") == "fail":
        report.add("auth_fail", "발신 서버 인증 실패(SPF/DKIM)", RISK_MEDIUM)

    # 2. 표시 이름에 다른 주소
    shown = re.search(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", display)
    if shown and shown.group().lower() != from_addr:
        report.add("display_addr", "표시 이름의 주소와 실제 발신 주소가 다름", RISK_HIGH)

    # 3. Reply-To 피벗
    _, reply_addr = _first_address(message, "Reply-To")
    if reply_addr and "@" in reply_addr:
        reply_reg = registered_domain(reply_addr.rsplit("@", 1)[-1])
        if reply_reg != from_reg:
            if reply_reg in FREEMAIL:
                report.add("replyto_freemail", "회신 주소가 무료 웹메일로 바뀜(BEC 전형)", RISK_HIGH)
            elif reply_reg not in own_domains:
                report.add("replyto_other", "회신 주소가 발신 도메인과 다름", RISK_MEDIUM)

    # 4. 기관·서비스 사칭
    subject = str(message.get("Subject", ""))
    haystack = f"{display} {subject}"
    for name, pattern, official in IMPERSONATION:
        if pattern.search(haystack) and from_reg and not any(from_reg == d or from_reg.endswith("." + d) or from_domain.endswith("." + d) or from_domain == d for d in official):
            if from_reg in FREEMAIL or from_reg not in own_domains:
                report.add("impersonation", f"{name} 사칭 의심(발신 도메인 {from_reg})", RISK_HIGH)
            break

    # 5. 가짜 스레드
    if REPLY_SUBJECT_RE.match(subject) and not message.get("In-Reply-To") and not message.get("References"):
        report.add("fake_thread", "답장 형식 제목이지만 원본 대화 참조가 없음", RISK_MEDIUM)

    return report
