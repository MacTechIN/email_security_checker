import io
import zipfile

from mailshield_tray import threats


def _zip(entries: dict[str, bytes], password_flag: bool = False) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(zipfile.ZipInfo(name), data)
    payload = bytearray(buffer.getvalue())
    if password_flag:
        # zipfile은 암호화 플래그를 쓸 수 없으므로 로컬 헤더(+6)와 중앙 디렉터리(+8)의 범용 비트 플래그를 직접 켠다.
        for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            start = 0
            while (pos := payload.find(signature, start)) != -1:
                payload[pos + offset] |= 0x1
                start = pos + 4
    return bytes(payload)


def _ooxml(kind: str, with_macro: bool) -> bytes:
    entries = {"[Content_Types].xml": b"<Types/>", f"{kind}/document.xml": b"<w:document/>"}
    if with_macro:
        entries[f"{kind}/vbaProject.bin"] = b"\xd0\xcf\x11\xe0 fake vba"
    return _zip(entries)


def test_sniff_types():
    assert threats.sniff_type(b"MZ\x90\x00") == "pe"
    assert threats.sniff_type(b"%PDF-1.7") == "pdf"
    assert threats.sniff_type(b"PK\x03\x04rest") == "zip"
    assert threats.sniff_type(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") == "ole"
    assert threats.sniff_type(b"  <!DOCTYPE html><html>") == "html"
    assert threats.sniff_type(b"hello") is None


def test_clean_docx_is_safe():
    report = threats.analyze_attachment("plan.docx", _ooxml("word", with_macro=False))
    assert report.risk == "safe"
    assert report.findings == []
    assert report.detected_type == "docx"


def test_docx_with_macro_is_high():
    report = threats.analyze_attachment("invoice.docx", _ooxml("word", with_macro=True))
    assert report.risk == "high"
    assert any("매크로 포함 Office 문서" in f for f in report.findings)


def test_macro_extension_flagged_even_without_payload():
    report = threats.analyze_attachment("sheet.xlsm", b"")
    assert report.risk == "high"


def test_ole_document_with_vba_stream():
    payload = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64 + b"_VBA_PROJECT" + b"\x00" * 16
    report = threats.analyze_attachment("old.doc", payload)
    assert any("매크로 포함 Office 문서(OLE)" in f for f in report.findings)
    assert report.risk == "high"


def test_zip_with_executable_and_nested_archive():
    payload = _zip({"readme.txt": b"hi", "setup.exe": b"MZ", "more.rar": b"Rar!"})
    report = threats.analyze_attachment("files.zip", payload)
    assert any("압축 파일 내 실행 파일" in f for f in report.findings)
    assert any("중첩 압축 파일" in f for f in report.findings)
    assert report.risk == "high"
    assert "setup.exe" in report.inner_names


def test_encrypted_zip_is_medium():
    report = threats.analyze_attachment("docs.zip", _zip({"a.pdf": b"%PDF"}, password_flag=True))
    assert any("암호 설정된 압축 파일" in f for f in report.findings)
    assert report.risk == "medium"


def test_zip_with_ransomware_named_files():
    report = threats.analyze_attachment("backup.zip", _zip({"photo.jpg.locky": b"x", "doc.docx.lockbit": b"y"}))
    assert any("랜섬웨어 확장자 파일 2개" in f for f in report.findings)
    assert report.risk == "high"


def test_pdf_with_javascript_is_high_and_plain_pdf_safe():
    risky = threats.analyze_attachment("form.pdf", b"%PDF-1.7 ... /OpenAction << /S /JavaScript /JS (app.alert(1)) >>")
    assert any("PDF 활성 콘텐츠" in f for f in risky.findings)
    assert risky.risk == "high"
    assert threats.analyze_attachment("plain.pdf", b"%PDF-1.4 hello").risk == "safe"


def test_disguised_executables():
    assert threats.analyze_attachment("photo.jpg", b"MZ\x90").risk == "high"
    assert threats.analyze_attachment("link.pdf", b"L\x00\x00\x00\x01\x14\x02\x00").risk == "high"
    html_as_pdf = threats.analyze_attachment("statement.pdf", b"<html><script>")
    assert any("HTML 위장" in f for f in html_as_pdf.findings)


def test_container_and_html_attachments():
    assert threats.analyze_attachment("delivery.iso", b"\x00" * 16).risk == "high"
    assert threats.analyze_attachment("invoice.html", b"<html>").risk == "medium"
    assert any("내부 검사 불가" in f for f in threats.analyze_attachment("x.rar", b"Rar!\x1a\x07\x00").findings)


def test_ransom_note_detection_levels():
    note = "Your files have been encrypted! Buy the decryption key with bitcoin. Download Tor browser and visit xyz.onion"
    report = threats.scan_ransomware_text(note)
    assert report.risk == "high"
    assert report.findings and report.findings[0].startswith("랜섬웨어 협박 문구")

    korean = "귀하의 모든 파일이 암호화되었습니다. 복호화 키를 받으려면 비트코인으로 송금하지 않으면 삭제됩니다."
    assert threats.scan_ransomware_text(korean).risk == "high"

    benign = "이번 분기 예산 파일을 첨부합니다. 검토 부탁드립니다."
    assert threats.scan_ransomware_text(benign).findings == []

    crypto_news = "Bitcoin price rose 5% today."
    assert threats.scan_ransomware_text(crypto_news).risk == "safe"


def test_ransomware_delivery_summary():
    reports = [threats.analyze_attachment("invoice.docm", b""), threats.analyze_attachment("docs.zip", _zip({"a.pdf": b"%PDF"}, password_flag=True))]
    summary = threats.ransomware_delivery_findings(reports)
    assert summary and "매크로 문서" in summary[0] and "암호 압축 파일" in summary[0]
    assert threats.ransomware_delivery_findings([threats.analyze_attachment("plan.pdf", b"%PDF-1.4")]) == []
