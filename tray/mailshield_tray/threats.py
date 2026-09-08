"""첨부파일 정적 검사와 랜섬웨어 지표 탐지 (외부 서비스 의존 없음).

첨부파일
- 매직 바이트로 실제 형식을 판별해 확장자 위장(예: report.pdf 이지만 실제는 PE 실행 파일)을 잡는다.
- Office 문서의 매크로(OOXML vbaProject.bin, OLE _VBA_PROJECT) 유무를 본다.
- ZIP 계열 압축 파일은 내부 목록을 읽어 실행 파일·이중 확장자·중첩 압축·암호 설정·압축 폭탄 지표를 본다.
- PDF의 활성 콘텐츠(JavaScript, Launch, OpenAction)를 본다.
- HTML/디스크 이미지/OneNote/바로 가기 등 악성코드 전달에 흔히 쓰이는 형식을 표시한다.

랜섬웨어
- 랜섬노트 문구(파일 암호화 통보, 복호화 대가, 비트코인·Tor 결제 안내)
- 알려진 랜섬웨어 암호화 확장자(첨부 이름·본문)
- 랜섬웨어 전달에 자주 쓰이는 조합(매크로 문서, 암호 압축 파일, 스크립트·바로 가기)

파일 원본은 분석 후 폐기되며 결과에는 라벨·해시·크기만 남는다.
실제 PC에서의 대량 암호화 행위 감시(파일 시스템 엔트로피·이름 변경 폭주)는 2단계 Windows Service 범위다.
"""

from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field

RISK_SAFE = "safe"
RISK_MEDIUM = "medium"
RISK_HIGH = "high"

MAX_INSPECT_BYTES = 25 * 1024 * 1024
ZIP_BOMB_TOTAL = 200 * 1024 * 1024
ZIP_BOMB_RATIO = 100
MAX_ZIP_ENTRIES = 2000

EXECUTABLE_SUFFIXES = (".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".ps1", ".psm1", ".bat", ".cmd", ".com", ".pif", ".msi", ".msp", ".hta", ".wsf", ".wsh", ".lnk", ".cpl", ".dll", ".jar", ".reg", ".inf", ".chm", ".sct", ".url")
MACRO_SUFFIXES = (".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam", ".sldm")
ARCHIVE_SUFFIXES = (".zip", ".7z", ".rar", ".gz", ".tgz", ".bz2", ".xz", ".tar", ".cab", ".arj", ".ace", ".z")
CONTAINER_SUFFIXES = (".iso", ".img", ".vhd", ".vhdx", ".udf", ".daa")
OFFICE_OOXML_SUFFIXES = (".docx", ".dotx", ".xlsx", ".xltx", ".pptx", ".potx") + MACRO_SUFFIXES
OFFICE_OLE_SUFFIXES = (".doc", ".dot", ".xls", ".xlt", ".ppt", ".pot", ".msg")
DOUBLE_EXTENSION = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|hwpx?|txt|jpe?g|png|gif|zip|mp[34]|avi)\.(exe|scr|js|jse|vbs|vbe|bat|cmd|com|pif|lnk|hta|wsf|ps1)$", re.I)

# 알려진 랜섬웨어 암호화 확장자(일부). 첨부 이름과 본문 모두에서 찾는다.
RANSOM_EXTENSIONS = (
    ".locky", ".zepto", ".odin", ".thor", ".osiris", ".cerber", ".cerber3", ".crypt", ".crypted", ".cryptolocker", ".encrypted", ".enc",
    ".locked", ".lock", ".wncry", ".wnry", ".wannacry", ".wcry", ".petya", ".ryk", ".ryuk", ".conti", ".lockbit", ".abcd", ".akira",
    ".phobos", ".eight", ".djvu", ".stop", ".makop", ".mallox", ".medusa", ".blackcat", ".alphv", ".hive", ".royal", ".play", ".clop",
    ".revil", ".sodinokibi", ".dharma", ".wallet", ".arena", ".gandcrab", ".krab", ".magniber", ".nemty", ".nefilim", ".maze", ".egregor",
    ".babyk", ".babuk", ".avos", ".avoslinux", ".blackbasta", ".basta", ".qlocker", ".deadbolt", ".ech0raix", ".cuba", ".rhysida", ".8base",
)
_RANSOM_EXT_PATTERN = re.compile(r"(?i)(?<![A-Za-z0-9])[\w-]+\.(?:" + "|".join(re.escape(e[1:]) for e in RANSOM_EXTENSIONS) + r")(?![A-Za-z0-9])")

# 랜섬노트 문구. 여러 신호가 함께 나타날 때만 판정해 오탐을 줄인다.
_RANSOM_NOTE_SIGNALS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("encrypted", re.compile(r"(?i)(your\s+(?:files|documents|data|network)\s+(?:have|has|are|were)\s+been\s+encrypted|files?\s+(?:are|is|were)\s+encrypted|(?:파일|문서|자료|데이터)(?:이|가|들이|은|는)?\s*(?:모두\s*)?암호화\s*(?:되었|됐|되어\s*있))")),
    ("decrypt", re.compile(r"(?i)(decrypt(?:ion|or|ing)?\s+(?:key|tool|software|your\s+files)|private\s+key|복호화\s*(?:키|도구|프로그램|비용|방법)|암호\s*해제\s*(?:키|도구|비용))")),
    ("payment", re.compile(r"(?i)(bitcoin|btc\b|monero|\bxmr\b|ransom|비트코인|모네로|몸값|송금하지\s*않으면|pay(?:ment)?\s+(?:in|within)\s+\d+\s*(?:hours|days))")),
    ("tor", re.compile(r"(?i)(\.onion\b|tor\s+browser|torproject\.org|토르\s*브라우저)")),
    ("threat", re.compile(r"(?i)(do\s+not\s+(?:try\s+to\s+)?(?:rename|modify|decrypt)|files?\s+will\s+be\s+(?:deleted|published|leaked)|leak\s+site|삭제(?:됩니다|될\s*것)|유출(?:하겟|하겠|됩니다)|경찰에\s*신고|복구\s*불가능)")),
)

# 매직 바이트 → 실제 형식
_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"%PDF", "pdf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"MSCF", "cab"),
    (b"{\\rtf", "rtf"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"\x89PNG", "png"),
    (b"GIF8", "gif"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"),
    (b"HWP Document File", "hwp3"),
)
_TYPE_LABEL = {"pe": "Windows 실행 파일", "elf": "Linux 실행 파일", "lnk": "Windows 바로 가기", "ole": "OLE 문서", "zip": "ZIP 컨테이너", "pdf": "PDF"}

# 위장 탐지: 확장자가 이 문서·이미지류인데 실제가 실행 파일이면 고위험
_BENIGN_SUFFIXES = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".hwp", ".hwpx", ".txt", ".csv", ".rtf", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp3", ".mp4", ".zip")

_PDF_ACTIVE = re.compile(rb"/(JavaScript|JS|Launch|OpenAction|AA|EmbeddedFile|RichMedia|XFA)\b")


@dataclass
class AttachmentReport:
    findings: list[str] = field(default_factory=list)
    risk: str = RISK_SAFE
    detected_type: str | None = None
    inner_names: list[str] = field(default_factory=list)

    def add(self, finding: str, risk: str) -> None:
        self.findings.append(finding)
        if risk == RISK_HIGH or (risk == RISK_MEDIUM and self.risk == RISK_SAFE):
            self.risk = risk


def sniff_type(payload: bytes) -> str | None:
    head = payload[:64]
    for magic, kind in _MAGIC:
        if head.startswith(magic):
            return kind
    if head.lstrip()[:5].lower() in (b"<!doc", b"<html") or head.lstrip()[:6].lower() == b"<scrip":
        return "html"
    return None


def _suffix(name: str) -> str:
    lower = name.lower().strip()
    dot = lower.rfind(".")
    return lower[dot:] if dot >= 0 else ""


def _zip_kind(zf: zipfile.ZipFile) -> str:
    names = set(zf.namelist())
    if "[Content_Types].xml" in names:
        if any(n.startswith("word/") for n in names):
            return "docx"
        if any(n.startswith("xl/") for n in names):
            return "xlsx"
        if any(n.startswith("ppt/") for n in names):
            return "pptx"
        return "ooxml"
    if "META-INF/MANIFEST.MF" in names and any(n.endswith(".class") for n in names):
        return "jar"
    if "AndroidManifest.xml" in names:
        return "apk"
    if "Contents/content.hpf" in names or any(n.startswith("Contents/") for n in names) and "mimetype" in names:
        return "hwpx"
    return "zip"


def _inspect_zip(payload: bytes, name: str, report: AttachmentReport, depth: int = 0) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(payload))
        infos = zf.infolist()
    except (zipfile.BadZipFile, RuntimeError, OSError):
        report.add(f"손상되었거나 열 수 없는 압축 파일: {name}", RISK_MEDIUM)
        return
    kind = _zip_kind(zf)
    report.detected_type = kind
    if kind in ("docx", "xlsx", "pptx", "ooxml"):
        if any(n.lower().endswith("vbaproject.bin") for n in zf.namelist()):
            report.add(f"매크로 포함 Office 문서: {name}", RISK_HIGH)
        if any("oleObject" in n or n.lower().endswith((".bin", ".exe")) and "embeddings/" in n.lower() for n in zf.namelist()):
            report.add(f"Office 문서 내 포함 개체(OLE): {name}", RISK_MEDIUM)
        return
    if kind == "hwpx":
        return
    if kind in ("jar", "apk"):
        report.add(f"실행 가능 패키지({kind.upper()}): {name}", RISK_HIGH)
        return

    total_uncompressed = sum(i.file_size for i in infos)
    total_compressed = max(1, sum(i.compress_size for i in infos))
    if len(infos) > MAX_ZIP_ENTRIES:
        report.add(f"압축 파일 항목 과다({len(infos)}개): {name}", RISK_MEDIUM)
    if total_uncompressed > ZIP_BOMB_TOTAL or (total_uncompressed > 10 * 1024 * 1024 and total_uncompressed / total_compressed > ZIP_BOMB_RATIO):
        report.add(f"압축 폭탄 의심(해제 시 {total_uncompressed // (1024 * 1024)}MB): {name}", RISK_HIGH)
    if any(i.flag_bits & 0x1 for i in infos):
        report.add(f"암호 설정된 압축 파일(내용 검사 불가): {name}", RISK_MEDIUM)

    executables, nested, ransom_named = [], [], []
    for info in infos[:MAX_ZIP_ENTRIES]:
        inner = info.filename
        report.inner_names.append(inner)
        suffix = _suffix(inner)
        if suffix in EXECUTABLE_SUFFIXES or DOUBLE_EXTENSION.search(inner) or suffix in MACRO_SUFFIXES:
            executables.append(inner)
        elif suffix in ARCHIVE_SUFFIXES or suffix in CONTAINER_SUFFIXES:
            nested.append(inner)
        if _RANSOM_EXT_PATTERN.search(inner):
            ransom_named.append(inner)
    if executables:
        report.add(f"압축 파일 내 실행 파일·스크립트·매크로 {len(executables)}개: {name}", RISK_HIGH)
    if ransom_named:
        report.add(f"압축 파일 내 랜섬웨어 확장자 파일 {len(ransom_named)}개: {name}", RISK_HIGH)
    if nested:
        report.add(f"중첩 압축 파일 {len(nested)}개: {name}", RISK_MEDIUM)
        if depth < 1:
            for inner in nested[:5]:
                if _suffix(inner) == ".zip":
                    try:
                        data = zf.read(inner)
                    except (RuntimeError, KeyError, zipfile.BadZipFile, OSError):
                        continue
                    if len(data) <= MAX_INSPECT_BYTES:
                        _inspect_zip(data, f"{name}/{inner}", report, depth + 1)


def _inspect_ole(payload: bytes, name: str, report: AttachmentReport) -> None:
    report.detected_type = "ole"
    lowered = payload[:MAX_INSPECT_BYTES]
    if b"_VBA_PROJECT" in lowered or b"VBA/" in lowered or b"\x00M\x00a\x00c\x00r\x00o\x00s" in lowered:
        report.add(f"매크로 포함 Office 문서(OLE): {name}", RISK_HIGH)
    if b"HwpSummaryInformation" in lowered or b"H\x00w\x00p\x00" in lowered:
        report.detected_type = "hwp"
        if b"DefaultJScript" in lowered or b"JScriptVersion" in lowered:
            report.add(f"스크립트 포함 HWP 문서: {name}", RISK_HIGH)
    if b"\x00P\x00a\x00c\x00k\x00a\x00g\x00e" in lowered or b"\x01Ole10Native" in lowered:
        report.add(f"OLE 포함 개체(Package/Ole10Native): {name}", RISK_MEDIUM)


def _inspect_pdf(payload: bytes, name: str, report: AttachmentReport) -> None:
    report.detected_type = "pdf"
    actions = {m.group(1).decode() for m in _PDF_ACTIVE.finditer(payload[:MAX_INSPECT_BYTES])}
    risky = actions & {"JavaScript", "JS", "Launch", "RichMedia", "XFA"}
    if risky:
        report.add(f"PDF 활성 콘텐츠({', '.join(sorted(risky))}): {name}", RISK_HIGH if {"Launch", "JavaScript", "JS"} & risky else RISK_MEDIUM)
    elif "EmbeddedFile" in actions:
        report.add(f"PDF 내 포함 파일: {name}", RISK_MEDIUM)


def analyze_attachment(name: str, payload: bytes, content_type: str = "") -> AttachmentReport:
    report = AttachmentReport()
    suffix = _suffix(name)
    actual = sniff_type(payload) if payload else None
    report.detected_type = actual

    # 1) 확장자 자체가 실행·스크립트·바로 가기
    if suffix in EXECUTABLE_SUFFIXES:
        report.add(f"실행 가능 첨부파일: {name}", RISK_HIGH)
    if DOUBLE_EXTENSION.search(name):
        report.add(f"이중 확장자 의심: {name}", RISK_HIGH)
    if suffix in MACRO_SUFFIXES:
        report.add(f"매크로 사용 문서 형식({suffix}): {name}", RISK_HIGH)
    if _RANSOM_EXT_PATTERN.search(name):
        report.add(f"랜섬웨어 암호화 확장자 파일: {name}", RISK_HIGH)

    # 2) 매직 바이트와 확장자 불일치(위장)
    if actual in ("pe", "elf", "lnk") and suffix not in EXECUTABLE_SUFFIXES:
        report.add(f"확장자 위장 {_TYPE_LABEL[actual]}: {name}", RISK_HIGH)
    elif actual == "html" and suffix in _BENIGN_SUFFIXES and suffix not in (".txt",):
        report.add(f"HTML 위장 파일: {name}", RISK_MEDIUM)
    elif actual and suffix in (".jpg", ".jpeg", ".png", ".gif") and actual not in ("jpeg", "png", "gif"):
        report.add(f"이미지 확장자와 실제 형식 불일치({actual}): {name}", RISK_MEDIUM)

    # 3) 형식별 심층 검사
    if actual == "zip" or (actual is None and suffix in (".zip",) + OFFICE_OOXML_SUFFIXES):
        _inspect_zip(payload, name, report)
    elif actual == "ole":
        _inspect_ole(payload, name, report)
    elif actual == "pdf":
        _inspect_pdf(payload, name, report)
    elif actual in ("rar", "7z", "gzip", "bzip2", "xz", "cab") or suffix in ARCHIVE_SUFFIXES:
        report.add(f"내부 검사 불가 압축 형식({actual or suffix}): {name}", RISK_MEDIUM)
    elif suffix in CONTAINER_SUFFIXES:
        report.add(f"디스크 이미지 첨부(악성코드 전달에 자주 사용): {name}", RISK_HIGH)
    elif suffix in (".html", ".htm", ".shtml", ".xhtml", ".svg", ".one", ".onepkg", ".xll", ".ade", ".adp"):
        report.add(f"악성코드 전달에 자주 쓰이는 형식({suffix}): {name}", RISK_MEDIUM)
    elif actual is None and suffix in OFFICE_OLE_SUFFIXES and payload:
        report.add(f"Office 확장자이지만 문서 형식이 아님: {name}", RISK_MEDIUM)
    return report


@dataclass
class RansomwareReport:
    findings: list[str] = field(default_factory=list)
    risk: str = RISK_SAFE


def scan_ransomware_text(text: str) -> RansomwareReport:
    """본문에서 랜섬노트 문구와 랜섬웨어 확장자 언급을 찾는다."""
    report = RansomwareReport()
    hits = [key for key, pattern in _RANSOM_NOTE_SIGNALS if pattern.search(text)]
    if "encrypted" in hits and len(hits) >= 2:
        report.findings.append("랜섬웨어 협박 문구(" + ", ".join(hits) + ")")
        report.risk = RISK_HIGH
    elif len(hits) >= 3:
        report.findings.append("랜섬웨어 협박 문구 의심(" + ", ".join(hits) + ")")
        report.risk = RISK_HIGH
    elif hits and ("decrypt" in hits or "tor" in hits):
        report.findings.append("랜섬웨어 관련 문구(" + ", ".join(hits) + ")")
        report.risk = RISK_MEDIUM
    ext_hits = _RANSOM_EXT_PATTERN.findall(text)
    if len(ext_hits) >= 2:
        report.findings.append(f"랜섬웨어 암호화 확장자 언급 {len(ext_hits)}건")
        if report.risk != RISK_HIGH:
            report.risk = RISK_MEDIUM
    return report


def ransomware_delivery_findings(attachment_reports: list[AttachmentReport]) -> list[str]:
    """랜섬웨어 전달에 전형적인 첨부 조합을 요약한다(개별 첨부 판정과 별도로 사건 설명에 쓴다)."""
    joined = " ".join(f for r in attachment_reports for f in r.findings)
    vectors = []
    if "매크로" in joined:
        vectors.append("매크로 문서")
    if "암호 설정된 압축" in joined:
        vectors.append("암호 압축 파일")
    if "실행 가능 첨부파일" in joined or "압축 파일 내 실행" in joined or "확장자 위장" in joined:
        vectors.append("실행 파일·스크립트")
    if "디스크 이미지" in joined:
        vectors.append("디스크 이미지")
    if "바로 가기" in joined or ".lnk" in joined:
        vectors.append("바로 가기(LNK)")
    return [f"랜섬웨어 전달 경로 의심: {', '.join(vectors)}"] if vectors else []
