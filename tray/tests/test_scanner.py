from email.message import EmailMessage

from mailshield_tray import scanner


def _raw(subject: str, body: str, attachment: tuple[str, bytes] | None = None) -> bytes:
    message = EmailMessage()
    message["From"] = "Sender Name <sender@example.com>"
    message["To"] = "me@example.com"
    message["Subject"] = subject
    message.set_content(body)
    if attachment:
        name, data = attachment
        message.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
    return message.as_bytes()


def test_safe_mail_has_no_findings():
    result = scanner.scan_message(_raw("안녕하세요", "정상 업무 메일입니다."), "INBOX", 1)
    assert result.risk == "safe"
    assert result.findings == []
    assert result.subject == "안녕하**"


def test_rrn_detected_without_card_false_positive():
    result = scanner.scan_message(_raw("테스트", "테스트 901231-1234567"), "INBOX", 2)
    assert "주민등록번호 의심 패턴" in result.findings
    assert "카드·계좌번호 의심 패턴" not in result.findings
    assert result.risk == "high"


def test_card_number_requires_luhn():
    valid = scanner.scan_message(_raw("카드", "4111 1111 1111 1111 로 결제"), "INBOX", 3)
    invalid = scanner.scan_message(_raw("카드", "1234-5678-9012-3456 로 결제"), "INBOX", 4)
    assert "카드·계좌번호 의심 패턴" in valid.findings
    assert "카드·계좌번호 의심 패턴" not in invalid.findings


def test_credential_keyword_in_subject():
    result = scanner.scan_message(_raw("비밀번호 안내", "본문에는 아무것도 없음"), "INBOX", 5)
    assert "인증정보 키워드" in result.findings


def test_executable_and_double_extension_attachment():
    result = scanner.scan_message(_raw("첨부", "파일 확인", ("invoice.pdf.exe", b"MZ")), "INBOX", 6)
    assert any(f.startswith("실행 가능 첨부파일") for f in result.findings)
    assert any(f.startswith("이중 확장자 의심") for f in result.findings)
    assert result.attachments[0].sha256 is not None


def test_sender_and_subject_are_masked():
    result = scanner.scan_message(_raw("Confidential quarterly report", "x"), "INBOX", 7)
    assert result.sender.startswith("Send")
    assert "*" in result.sender
    assert "example.com" not in result.sender
