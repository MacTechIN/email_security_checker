"""링크 검사기 (docs/06 우선순위 1). 외부 서비스 없이 메일 안의 링크를 뽑아 규칙으로 판정한다.

추출: HTML <a href>·<form action>, 본문 텍스트 URL, PDF 첨부의 /URI 주석
판정(높음): 표시 문자열과 실제 주소의 등록 도메인 불일치, javascript:/data: 스킴, IP 주소 호스트,
          퓨니코드(xn--)·혼합 문자 도메인, 숨긴 링크(display:none, font-size:0)
판정(주의): 단축 URL, 오픈 리다이렉트 파라미터(url=, redirect= … 안에 절대 URL), 저평판 TLD
링크 자체를 열거나 원격 자원을 받지 않는다(추적 픽셀 방지).
"""

from __future__ import annotations

import email
import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Iterable
from urllib.parse import parse_qsl, unquote, urlsplit

from .threats import RISK_HIGH, RISK_MEDIUM, RISK_SAFE

SHORTENERS = frozenset(
    "bit.ly t.co tinyurl.com goo.gl ow.ly is.gd buff.ly cutt.ly rebrand.ly t.ly shorturl.at rb.gy tiny.cc lnkd.in "
    "bl.ink short.io s.id han.gl vo.la me2.do url.kr c11.kr zrr.kr abit.ly".split()
)
REDIRECT_PARAMS = frozenset("url u redirect redirect_url redirect_uri redir return returnurl return_url next dest destination target goto link to continue rurl".split())
SUSPICIOUS_TLDS = frozenset(".top .xyz .icu .shop .pet .store .site .online .zip .mov .buzz .cfd .rest .click .club .work .live .life .fun .monster .quest .sbs .cyou .lol .bond".split())
# 등록 도메인 판별용 2단계 공개 접미사(일부). 완전한 PSL 대신 국내·주요 국가 위주.
SECOND_LEVEL_SUFFIXES = frozenset(
    "co.kr or.kr go.kr ac.kr ne.kr re.kr pe.kr ms.kr hs.kr es.kr sc.kr kg.kr seoul.kr busan.kr "
    "co.jp ne.jp or.jp ac.jp go.jp co.uk org.uk ac.uk gov.uk com.au net.au org.au com.cn com.tw com.hk com.sg com.br com.mx co.in co.nz".split()
)
URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"'()\[\]{}]+|\bwww\.[\w-]+(?:\.[\w-]+)+[^\s<>\"'()]*")
DOMAIN_LIKE_RE = re.compile(r"(?i)\b(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)")
# 표시 텍스트가 '주소를 주장'할 때만 불일치를 본다. 본문 속 'Ph.D.' 같은 낱말을 도메인으로 오인하지 않도록
# URL 형태(스킴·www)이거나 텍스트 전체가 도메인일 때만 인정하고, 최상위 라벨은 영문 2자 이상이어야 한다.
CLAIMED_URL_RE = re.compile(r"(?i)(?:https?://|www\.)([a-z0-9-]+(?:\.[a-z0-9-]+)+)")
CLAIMED_BARE_RE = re.compile(r"(?i)^\s*([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?:/[^\s]*)?\s*$")
# 정상 뉴스레터가 쓰는 클릭 추적·발송 대행 도메인. 불일치가 나도 '주의'로만 본다.
CLICK_TRACKERS = frozenset(
    "list-manage.com mailchimp.com mandrillapp.com sendgrid.net awstrack.me amazonses.com "
    "mailgun.org mailgun.net sparkpostmail.com hubspotlinks.com hs-sites.com aweber.com "
    "constantcontact.com rs6.net klaviyomail.com klclick.com braze.com iterable.com customeriomail.com "
    "mailerlite.com mlsend.com beehiiv.com substack.com ghost.io convertkit-mail.com sendinblue.com brevo.com "
    "exct.net exacttarget.com marketo.com mktoweb.com pardot.com eloqua.com postmarkapp.com pstmrk.it "
    "stibee.com stbe.me mailplug.co.kr cafe24.com bizmsg.kr licdn.com".split()
)
HIDDEN_STYLE_RE = re.compile(r"(?i)display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em|%)?\b|opacity\s*:\s*0(?![.\d])")
PDF_URI_RE = re.compile(rb"/URI\s*\(([^)]{4,2000})\)")


@dataclass
class Link:
    href: str
    text: str = ""
    source: str = "html"  # html | text | pdf | form
    hidden: bool = False


@dataclass
class LinkReport:
    links: list[Link] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    risk: str = RISK_SAFE
    counts: dict[str, int] = field(default_factory=dict)

    def add(self, key: str, label: str, risk: str) -> None:
        self.counts[key] = self.counts.get(key, 0) + 1
        if label not in self.findings:
            self.findings.append(label)
        if risk == RISK_HIGH or (risk == RISK_MEDIUM and self.risk == RISK_SAFE):
            self.risk = risk


class _AnchorCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self._current: Link | None = None
        self._depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self._current = Link(href=a["href"].strip(), source="html", hidden=bool(HIDDEN_STYLE_RE.search(a.get("style", ""))) or a.get("hidden") is not None)
            self._depth = 1
        elif tag == "form" and a.get("action"):
            self.links.append(Link(href=a["action"].strip(), text="<form>", source="form"))
        elif self._current is not None and tag == "img" and not self._current.text:
            self._current.text = (a.get("alt") or "").strip()

    def handle_data(self, data: str) -> None:
        if self._current is not None:
            self._current.text += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._current is not None:
            self._current.text = " ".join(self._current.text.split())
            self.links.append(self._current)
            self._current = None


def registered_domain(host: str) -> str:
    """등록 도메인(eTLD+1)을 돌려준다. 'news.naver.co.kr' → 'naver.co.kr'."""
    host = host.lower().strip(".")
    labels = host.split(".")
    if len(labels) < 2:
        return host
    if len(labels) >= 3 and ".".join(labels[-2:]) in SECOND_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _plausible_tld(domain: str) -> bool:
    tld = domain.rsplit(".", 1)[-1]
    return len(tld) >= 2 and tld.isalpha()


def _claimed_domain(text: str) -> str:
    """표시 텍스트가 주장하는 등록 도메인. 주소를 주장하지 않으면 빈 문자열."""
    match = CLAIMED_URL_RE.search(text) or CLAIMED_BARE_RE.match(text)
    if not match:
        return ""
    domain = match.group(1).lower()
    if not _plausible_tld(domain):
        return ""
    return registered_domain(domain)


def _host(url: str) -> str:
    try:
        parts = urlsplit(url if "://" in url else "http://" + url)
    except ValueError:
        return ""
    return (parts.hostname or "").lower()


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _mixed_script(host: str) -> bool:
    """퓨니코드를 풀었을 때 라틴 문자와 다른 문자(키릴 등)가 섞이면 True."""
    try:
        decoded = host.encode("ascii").decode("idna") if "xn--" in host else host
    except (UnicodeError, ValueError):
        return True
    scripts = set()
    for ch in decoded:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            scripts.add(name.split(" ")[0])
    return len(scripts - {"DIGIT", "FULL", "HYPHEN"}) > 1


def _redirect_target(url: str) -> str | None:
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    for key, value in parse_qsl(parts.query, keep_blank_values=False):
        if key.lower() in REDIRECT_PARAMS:
            inner = unquote(value)
            if re.match(r"(?i)^(?:https?:)?//", inner) or re.match(r"(?i)^www\.", inner):
                return inner
    return None


# --- 추출 ---

def extract_links(message: email.message.Message) -> list[Link]:
    links: list[Link] = []
    seen: set[tuple[str, str]] = set()
    parts: Iterable[email.message.Message] = message.walk() if message.is_multipart() else (message,)
    for part in parts:
        ctype = part.get_content_type()
        disposition = part.get_content_disposition()
        try:
            if ctype == "text/html" and disposition != "attachment":
                parser = _AnchorCollector()
                parser.feed(part.get_content())
                for link in parser.links:
                    key = (link.href, link.text)
                    if key not in seen:
                        seen.add(key)
                        links.append(link)
            elif ctype == "text/plain" and disposition != "attachment":
                for match in URL_RE.finditer(part.get_content()):
                    href = match.group().rstrip(".,;:")
                    if (href, "") not in seen:
                        seen.add((href, ""))
                        links.append(Link(href=href, source="text"))
            elif ctype == "application/pdf" or (part.get_filename() or "").lower().endswith(".pdf"):
                payload = part.get_payload(decode=True) or b""
                for match in PDF_URI_RE.finditer(payload[: 25 * 1024 * 1024]):
                    href = match.group(1).decode("latin-1", errors="replace").strip()
                    if (href, "<pdf>") not in seen:
                        seen.add((href, "<pdf>"))
                        links.append(Link(href=href, text="<pdf>", source="pdf"))
        except (LookupError, UnicodeError, KeyError, ValueError):
            continue
    return links


# --- 판정 ---

def analyze_links(links: list[Link], sender_domain: str = "") -> LinkReport:
    report = LinkReport(links=list(links))
    sender_reg = registered_domain(sender_domain) if sender_domain else ""
    for link in links:
        href = link.href.strip()
        lower = href.lower()
        if lower.startswith(("mailto:", "tel:", "sms:", "#")):
            continue
        if lower.startswith(("javascript:", "vbscript:", "data:")):
            report.add("scheme", "위험한 링크 스킴(javascript:/data:)", RISK_HIGH)
            continue
        host = _host(href)
        if not host:
            continue
        reg = registered_domain(host)

        if link.hidden:
            report.add("hidden", "숨겨진 링크", RISK_HIGH)
        if _is_ip(host):
            report.add("ip", "IP 주소로 된 링크", RISK_HIGH)
        if "xn--" in host or _mixed_script(host):
            report.add("idn", "퓨니코드·혼합 문자 도메인 링크", RISK_HIGH)
        if link.source == "html" and link.text:
            claimed = _claimed_domain(link.text)
            if claimed and claimed != reg and not claimed.endswith("." + reg) and not reg.endswith("." + claimed):
                if reg in CLICK_TRACKERS or host in CLICK_TRACKERS:
                    report.add("tracker", "발송 대행·클릭 추적 링크(표시 주소와 다름)", RISK_MEDIUM)
                else:
                    report.add("mismatch", "표시 주소와 실제 링크 불일치", RISK_HIGH)
        if reg in SHORTENERS or host in SHORTENERS:
            report.add("shortener", "단축 URL 링크", RISK_MEDIUM)
        inner = _redirect_target(href)
        if inner:
            inner_reg = registered_domain(_host(inner))
            if inner_reg and inner_reg != reg and inner_reg != sender_reg:
                report.add("redirect", "리다이렉트 파라미터로 다른 사이트 이동", RISK_MEDIUM)
        tld = "." + reg.rsplit(".", 1)[-1] if "." in reg else ""
        if tld in SUSPICIOUS_TLDS and reg != sender_reg:
            report.add("tld", f"저평판 최상위 도메인 링크({tld})", RISK_MEDIUM)
        if link.source == "form":
            report.add("form", "메일 안 입력 폼 전송 링크", RISK_HIGH)
    return report


def analyze_message_links(message: email.message.Message, sender_domain: str = "") -> LinkReport:
    return analyze_links(extract_links(message), sender_domain)
