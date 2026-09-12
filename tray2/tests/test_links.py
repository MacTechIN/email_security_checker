"""v2 링크 검사기: 추출과 판정."""

from email.message import EmailMessage

from mailshield2 import links
from mailshield2.links import Link, analyze_links, extract_links, registered_domain


def _html_message(html: str) -> EmailMessage:
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message["Subject"] = "제목"
    message.set_content("plain")
    message.add_alternative(html, subtype="html")
    return message


def test_registered_domain_handles_two_level_suffixes():
    assert registered_domain("news.naver.com") == "naver.com"
    assert registered_domain("mail.hometax.go.kr") == "hometax.go.kr"
    assert registered_domain("a.b.co.uk") == "b.co.uk"
    assert registered_domain("example.com") == "example.com"


def test_display_text_and_href_mismatch_is_high():
    message = _html_message('<a href="https://evil.example/login">https://www.naver.com</a>')
    report = analyze_links(extract_links(message))
    assert report.risk == "high"
    assert "표시 주소와 실제 링크 불일치" in report.findings


def test_same_site_subdomain_is_not_a_mismatch():
    message = _html_message('<a href="https://mail.naver.com/x">naver.com 바로가기</a>')
    assert analyze_links(extract_links(message)).risk == "safe"


def test_javascript_and_ip_links_are_high():
    message = _html_message('<a href="javascript:steal()">확인</a><a href="http://203.0.113.9/pay">결제</a>')
    report = analyze_links(extract_links(message))
    assert report.risk == "high"
    assert any("스킴" in f for f in report.findings)
    assert any("IP 주소" in f for f in report.findings)


def test_hidden_link_is_high():
    message = _html_message('<a href="https://evil.example" style="display:none">x</a>')
    assert analyze_links(extract_links(message)).risk == "high"


def test_shortener_and_redirect_parameter_are_medium():
    message = _html_message('<a href="https://bit.ly/abc">공지</a>'
                            '<a href="https://trusted.example/go?url=https%3A%2F%2Fevil.example%2Fx">안내</a>')
    report = analyze_links(extract_links(message))
    assert report.risk == "medium"
    assert "단축 URL 링크" in report.findings
    assert "리다이렉트 파라미터로 다른 사이트 이동" in report.findings


def test_form_action_in_mail_is_high():
    message = _html_message('<form action="https://evil.example/collect"><input type="password"></form>')
    assert analyze_links(extract_links(message)).risk == "high"


def test_punycode_domain_is_high():
    assert analyze_links([Link(href="https://xn--pypal-4ve.com/login", text="결제")]).risk == "high"


def test_plain_text_urls_are_extracted():
    message = EmailMessage()
    message["From"] = "a@example.com"
    message.set_content("확인: https://bit.ly/xyz 그리고 https://example.com/ok")
    hrefs = [l.href for l in extract_links(message)]
    assert "https://bit.ly/xyz" in hrefs and "https://example.com/ok" in hrefs


def test_pdf_attachment_links_are_extracted():
    message = EmailMessage()
    message["From"] = "a@example.com"
    message.set_content("문서 확인")
    pdf = b"%PDF-1.7\n/Annots [ << /A << /URI (https://evil.example/pay) >> >> ]\n%%EOF"
    message.add_attachment(pdf, maintype="application", subtype="pdf", filename="invoice.pdf")
    report = analyze_links(extract_links(message))
    assert any(l.source == "pdf" and "evil.example" in l.href for l in report.links)


def test_suspicious_tld_is_medium_but_sender_domain_is_exempt():
    assert analyze_links([Link(href="https://promo.top/a", text="x")]).risk == "medium"
    assert analyze_links([Link(href="https://promo.top/a", text="x")], sender_domain="promo.top").risk == "safe"


def test_clean_mail_has_no_link_findings():
    message = _html_message('<a href="https://example.com/notice">공지 확인</a>')
    report = analyze_links(extract_links(message), sender_domain="example.com")
    assert report.risk == "safe" and report.findings == []


# --- 표시 주소 판정 정밀화 (실제 뉴스레터 오탐 대응) ---

def test_prose_with_dotted_words_is_not_a_claimed_domain():
    """'Ph.D.' 같은 낱말을 도메인으로 오인해 불일치로 잡던 문제."""
    message = _html_message('<a href="https://www.linkedin.com/feed/x">JAE-HONG E. VP, Head of AI/DX | Ph.D. &amp; 25+ Years</a>')
    assert analyze_links(extract_links(message)).risk == "safe"


def test_known_click_tracker_is_medium_not_high():
    """정상 뉴스레터의 발송 대행 링크는 주의로만 본다."""
    message = _html_message('<a href="https://us.list-manage.com/abc">https://forum.moonshot.ai/</a>')
    report = analyze_links(extract_links(message))
    assert report.risk == "medium"
    assert "발송 대행·클릭 추적 링크(표시 주소와 다름)" in report.findings


def test_unknown_domain_mismatch_stays_high():
    message = _html_message('<a href="https://evil-login.top/x">https://www.kbstar.com/</a>')
    assert analyze_links(extract_links(message)).risk == "high"


def test_bare_domain_text_is_still_checked():
    message = _html_message('<a href="https://evil.example/x">naver.com</a>')
    assert analyze_links(extract_links(message)).risk == "high"
