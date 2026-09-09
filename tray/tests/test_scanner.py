from datetime import datetime, timezone
from email.message import EmailMessage

import pytest

from mailshield_tray import scanner


def _raw(subject: str, body: str, attachment: tuple[str, bytes] | None = None, html: bool = False) -> bytes:
    message = EmailMessage()
    message["From"] = "Sender Name <sender@example.com>"
    message["To"] = "me@example.com"
    message["Subject"] = subject
    if html:
        message.set_content("plain fallback")
        message.add_alternative(body, subtype="html")
    else:
        message.set_content(body)
    if attachment:
        name, data = attachment
        message.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
    return message.as_bytes()


def _scan(body: str, subject: str = "제목", **kwargs) -> scanner.ScanResult:
    return scanner.scan_message(_raw(subject, body, **kwargs), "INBOX", 1, own_addresses=("me@example.com",))


# --- 기본 ---

def test_safe_mail_has_no_findings():
    result = _scan("정상 업무 메일입니다. 회의 자료 검토 부탁드립니다.", subject="안녕하세요")
    assert result.risk == "safe"
    assert result.findings == []
    assert result.subject == "안녕하**"


def test_sender_and_subject_are_masked():
    result = _scan("x", subject="Confidential quarterly report")
    assert result.sender.startswith("Send")
    assert "example.com" not in result.sender


# --- 고위험 ---

def test_rrn_detected_without_card_or_phone_false_positive():
    result = _scan("테스트 901231-1234567")
    assert "주민등록번호 1건" in result.findings
    assert not any(f.startswith("카드번호") or "전화" in f for f in result.findings)
    assert result.risk == "high"


def test_rrn_requires_plausible_birth_date():
    assert scanner.scan_text("991399-1234567") == {}


def test_foreign_registration_number():
    assert scanner.scan_text("외국인등록번호 900101-5123456") == {"frn": 1}


def test_card_number_requires_luhn():
    assert "card" in scanner.scan_text("4111 1111 1111 1111 로 결제")
    assert "card" not in scanner.scan_text("1234-5678-9012-3456 로 결제")


def test_bank_account_with_bank_context():
    counts = scanner.scan_text("국민은행 123456-04-123456 예금주 홍길동")
    assert counts.get("account") == 1
    assert counts.get("name") == 1


def test_driver_license_and_passport():
    counts = scanner.scan_text("면허 11-12-123456-78 / 여권 M12345678")
    assert counts == {"driver": 1, "passport": 1}


def test_credential_keyword_in_subject():
    result = _scan("본문에는 아무것도 없음", subject="비밀번호 안내")
    assert "인증정보 키워드" in result.findings
    assert result.risk == "high"


# --- 주의 등급 ---

def test_mobile_and_landline_phone():
    counts = scanner.scan_text("연락처 010-1234-5678, 사무실 02-345-6789, +82 10 9876 5432")
    assert counts.get("mobile") == 2
    assert counts.get("phone") == 1


def test_email_addresses_exclude_participants_and_own():
    body = "문의: partner@other.com 또는 sender@example.com, me@example.com"
    result = _scan(body)
    assert "이메일 주소 1건" in result.findings
    assert result.risk == "medium"


def test_korean_address_and_postal_code():
    counts = scanner.scan_text("배송지: 서울특별시 강남구 테헤란로 152, 우편번호 06236")
    assert counts.get("address") == 1
    assert counts.get("postal") == 1


def test_real_name_with_title_or_label():
    assert scanner.scan_text("안녕하세요 김철수 과장님").get("name") == 1
    assert scanner.scan_text("성명: 박영희").get("name") == 1
    # 성씨가 아닌 일반 단어는 실명으로 보지 않는다.
    assert "name" not in scanner.scan_text("회의 자료 검토 부탁드립니다")
    assert "name" not in scanner.scan_text("감사합니다 팀장님")


def test_birth_date_and_health_keywords():
    counts = scanner.scan_text("생년월일 1990-05-21, 진단서 첨부")
    assert counts.get("birth") == 1
    assert counts.get("health") == 1


def test_business_registration_number():
    assert scanner.scan_text("사업자등록번호 123-45-67890") == {"biz": 1}


def test_html_body_is_scanned():
    result = _scan("<html><body><p>전화 <b>010-2222-3333</b></p></body></html>", html=True)
    assert "휴대전화번호 1건" in result.findings


def test_medium_only_findings_yield_medium_risk():
    result = _scan("담당자: 이민호 010-1111-2222")
    assert result.risk == "medium"
    assert set(result.counts) == {"name", "mobile"}


# --- 첨부·랜섬웨어 통합 ---

def test_executable_and_double_extension_attachment():
    result = _scan("파일 확인", attachment=("invoice.pdf.exe", b"MZ\x90\x00"))
    assert any(f.startswith("실행 가능 첨부파일") for f in result.findings)
    assert any(f.startswith("이중 확장자 의심") for f in result.findings)
    assert result.attachments[0].sha256 is not None
    assert result.risk == "high"


def test_disguised_pe_as_pdf_is_high():
    result = _scan("보고서", attachment=("report.pdf", b"MZ\x90\x00\x03\x00\x00\x00"))
    assert any("확장자 위장 Windows 실행 파일" in f for f in result.findings)
    assert result.risk == "high"


def test_ransom_note_in_body_is_high():
    body = "All your files have been encrypted. To get the decryption key, pay 0.5 bitcoin via Tor browser."
    result = _scan(body)
    assert any(f.startswith("랜섬웨어 협박 문구") for f in result.findings)
    assert result.risk == "high"


@pytest.mark.parametrize("value", ["901231-1234567", "4111 1111 1111 1111", "010-1234-5678", "partner@other.com"])
def test_raw_values_never_stored(value):
    result = _scan(f"값 {value}")
    dumped = str(result.to_dict())
    assert value not in dumped

# --- 시각 표기(로컬 시간) ---

def test_scanned_at_carries_local_offset():
    result = _scan("정상 본문")
    parsed = datetime.fromisoformat(result.scanned_at)
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == datetime.now().astimezone().utcoffset()


def test_local_timestamp_converts_old_utc_records():
    # 0.1.5 이전 기록은 UTC로 저장됐다. KST(+09:00) PC에서는 9시간 뒤로 보여야 한다.
    converted = scanner.local_timestamp("2026-09-09T10:25:59+00:00")
    expected = datetime(2026, 9, 9, 10, 25, 59, tzinfo=timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    assert converted == expected


def test_local_timestamp_converts_offset_records_to_same_instant():
    value = "2026-09-09T19:31:31+09:00"
    expected = datetime.fromisoformat(value).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    assert scanner.local_timestamp(value) == expected


def test_local_timestamp_treats_naive_value_as_utc():
    naive = scanner.local_timestamp("2026-09-09T10:00:00")
    assert naive == datetime(2026, 9, 9, 10, 0, 0, tzinfo=timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def test_local_timestamp_tolerates_bad_input():
    assert scanner.local_timestamp("") == ""
    assert scanner.local_timestamp("not-a-time") == "not-a-time"


def test_local_timezone_label_matches_offset():
    offset = datetime.now().astimezone().utcoffset()
    minutes = round(offset.total_seconds() / 60)
    hours, remainder = divmod(abs(minutes), 60)
    expected = f"UTC{'-' if minutes < 0 else '+'}{hours}" + (f":{remainder:02d}" if remainder else "")
    assert scanner.local_timezone_label() == expected

# --- URL 오탐 회귀 (2026-09-09 LinkedIn 알림 사례) ---

LINKEDIN_URL = (
    "https://www.linkedin.com/comm/feed/update/urn:li:activity:7501708252628275200"
    "?highlightedUpdateUrn=urn%3Ali%3Aactivity%3A7501708252628275200"
    "&midToken=AQE&eid=k8bwrs-mtu08k9r-kp&otpToken=ODYyZTM2NDc4MmEzMjE"
)


def test_tracking_url_digits_are_not_card_numbers():
    """LinkedIn activity ID가 Luhn을 우연히 통과해 카드번호로 잡히던 문제."""
    assert scanner.scan_text(f"게시물을 확인하세요 {LINKEDIN_URL}") == {}


def test_url_token_names_are_not_credential_keywords():
    """URL의 otpToken 파라미터가 인증정보 키워드로 잡히던 문제."""
    assert "credential" not in scanner.scan_text(f"자세히 보기 {LINKEDIN_URL}")


def test_otp_requires_word_boundary():
    assert "credential" not in scanner.scan_text("otpToken=abc, passwordless 로그인")
    assert scanner.scan_text("OTP 번호를 입력하세요").get("credential") == 1


def test_real_credential_keywords_still_detected():
    for text in ("비밀번호 안내드립니다", "your API key is attached", "access token 재발급"):
        assert "credential" in scanner.scan_text(text), text


def test_pii_outside_urls_is_still_detected():
    text = f"연락처 010-1234-5678 {LINKEDIN_URL} 주민번호 901231-1234567"
    counts = scanner.scan_text(text)
    assert counts.get("mobile") == 1
    assert counts.get("rrn") == 1


def test_strip_urls_preserves_offsets():
    text = f"앞 {LINKEDIN_URL} 뒤"
    stripped = scanner.strip_urls(text)
    assert len(stripped) == len(text)
    assert "linkedin.com" not in stripped
    assert stripped.startswith("앞 ") and stripped.endswith(" 뒤")


# --- 탐지 근거(증거) 추출 ---

def test_explain_reports_context_and_masks_value():
    [ev] = scanner.explain_text("담당자 연락처는 010-1234-5678 입니다")
    assert ev.key == "mobile"
    assert ev.label == "휴대전화번호"
    assert ev.masked_value == "010" + "*" * 8 + "78"
    assert "010-1234-5678" not in ev.masked_value
    assert "담당자 연락처는" in ev.context


def test_explain_keeps_keyword_matches_readable():
    [ev] = scanner.explain_text("비밀번호 안내드립니다")
    assert ev.key == "credential"
    assert ev.masked_value == "비밀번호"


def test_explain_agrees_with_scan_text():
    text = "성명: 박영희 010-1111-2222 / 주민번호 901231-1234567"
    counts: dict[str, int] = {}
    for ev in scanner.explain_text(text):
        counts[ev.key] = counts.get(ev.key, 0) + 1
    assert counts == scanner.scan_text(text)


def test_explain_finds_nothing_in_tracking_url():
    assert scanner.explain_text(f"확인하세요 {LINKEDIN_URL}") == []


def test_explain_message_uses_headers_for_ignored_addresses():
    raw = _raw("문의", "회신은 partner@other.com 으로 주세요")
    evidence = scanner.explain_message(raw, own_addresses=("me@example.com",))
    assert [e.key for e in evidence] == ["email"]
    assert "partner@other.com" not in evidence[0].masked_value


def test_label_followed_by_common_noun_is_not_a_name():
    """'담당자 연락처는' 처럼 라벨 뒤 일반 명사+조사를 실명으로 보지 않는다."""
    assert "name" not in scanner.scan_text("담당자 연락처는 010-1234-5678 입니다")
    assert "name" not in scanner.scan_text("신청자 주소를 확인해 주세요")


def test_label_followed_by_real_name_still_detected():
    for text in ("예금주 홍길동", "담당자 김철수", "담당자 김지은", "성명: 박영희"):
        assert scanner.scan_text(text).get("name") == 1, text


def test_evidence_context_masks_every_detected_value():
    """문맥에 탐지값 원문이 남으면 마스킹이 무의미하다. 근처의 다른 값도 함께 가린다."""
    text = "테스트 901231-1234567 테스트 901231-1234567"
    evidence = scanner.explain_text(text)
    assert len(evidence) == 2
    for ev in evidence:
        assert "901231-1234567" not in ev.context
        assert "901231-1234567" not in ev.masked_value
    assert "901" in evidence[0].context and "테스트" in evidence[0].context


def test_evidence_context_masks_neighbouring_other_rule():
    text = "담당자 김철수 연락처 010-1234-5678"
    for ev in scanner.explain_text(text):
        assert "010-1234-5678" not in ev.context
        assert "김철수" not in ev.context


def test_birth_date_value_span_covers_two_digit_day():
    """정규식 알터너티브 순서 때문에 '21'에서 '2'만 잡히던 문제."""
    [ev] = scanner.explain_text("생년월일 1990-05-21")
    assert len(ev.masked_value) == len("1990-05-21")
    assert "1990-05-21" not in ev.context


def test_birth_date_rejects_impossible_day():
    assert "birth" not in scanner.scan_text("생년월일 1990-05-99")


def test_evidence_masks_only_the_value_not_the_label():
    [ev] = scanner.explain_text("예금주 홍길동")
    assert ev.label == "실명"
    assert ev.context.startswith("예금주 ")
    assert "홍길동" not in ev.context
