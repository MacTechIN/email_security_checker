"""v2 발신자 검증: 인증 헤더, 표시명 위장, 회신 피벗, 기관 사칭, 가짜 스레드."""

from email.message import EmailMessage

from mailshield2.sender import analyze_sender, parse_auth_results


def _message(**headers) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = headers.pop("subject", "안내")
    message["From"] = headers.pop("from_", "보낸사람 <a@example.com>")
    for key, value in headers.items():
        message[key.replace("_", "-").title()] = value
    message.set_content("본문")
    return message


def test_dmarc_fail_is_high():
    message = _message(authentication_results="mx.google.com; dmarc=fail header.from=bank.com; spf=fail")
    report = analyze_sender(message)
    assert report.risk == "high"
    assert "발신 도메인 인증 실패(DMARC)" in report.findings


def test_spf_softfail_alone_is_medium():
    report = analyze_sender(_message(authentication_results="mx.google.com; spf=softfail; dkim=pass"))
    assert report.risk == "medium"


def test_parse_auth_results_uses_topmost_header_only():
    message = _message(authentication_results="mx.google.com; dmarc=pass")
    message["Authentication-Results"] = "relay.example; dmarc=fail"
    assert parse_auth_results(message)["dmarc"] == "pass"


def test_display_name_carrying_other_address_is_high():
    report = analyze_sender(_message(from_='"ceo@company.com" <attacker@evil.example>'))
    assert report.risk == "high"
    assert "표시 이름의 주소와 실제 발신 주소가 다름" in report.findings


def test_reply_to_freemail_pivot_is_high():
    report = analyze_sender(_message(from_="대표 <ceo@company.com>", reply_to="ceo.private@gmail.com"))
    assert report.risk == "high"
    assert "회신 주소가 무료 웹메일로 바뀜(BEC 전형)" in report.findings


def test_reply_to_same_domain_is_clean():
    assert analyze_sender(_message(from_="a@company.com", reply_to="b@company.com")).risk == "safe"


def test_agency_impersonation_from_wrong_domain_is_high():
    report = analyze_sender(_message(from_="국세청 홈택스 <notice@nts-service.top>", subject="전자세금계산서 발급 안내"))
    assert report.risk == "high"
    assert any("국세청" in f for f in report.findings)


def test_agency_mail_from_official_domain_is_clean():
    report = analyze_sender(_message(from_="국세청 <noreply@hometax.go.kr>", subject="전자세금계산서 발급 안내"))
    assert report.risk == "safe"


def test_naver_impersonation_from_freemail():
    report = analyze_sender(_message(from_="네이버 고객센터 <help@nobar69asli.shop>", subject="계정 복구 코드가 추가되었습니다"))
    assert any("네이버" in f for f in report.findings)


def test_fake_thread_subject_without_references_is_medium():
    report = analyze_sender(_message(subject="RE: 송금 건 확인"))
    assert report.risk == "medium"
    assert "답장 형식 제목이지만 원본 대화 참조가 없음" in report.findings


def test_real_reply_with_references_is_clean():
    assert analyze_sender(_message(subject="RE: 송금 건 확인", references="<abc@example.com>")).risk == "safe"


def test_own_sent_mail_is_skipped():
    report = analyze_sender(_message(from_="me@gmail.com", subject="RE: 내 메일"), own_addresses=("me@gmail.com",))
    assert report.risk == "safe" and report.findings == []
