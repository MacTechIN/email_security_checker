# MailShield 2 (v2.0 기능 개선판)

v1(`tray/`)과 **완전히 분리된 별도 앱**입니다. 데이터 폴더·단일 인스턴스 뮤텍스·자동 시작 항목·설치 경로가 모두 달라 두 버전을 동시에 설치·실행할 수 있습니다.

v1 대비 추가된 것은 링크 검사, 발신자 검증, 협박 메일 탐지, 인증정보 등급 보정입니다. 검증된 `code_snipt/realtime_email_monitor.pyw`의 감시·탐지 로직을 재사용하고, 콘솔과 환경변수 없이 Windows 로그인과 함께 트레이에 상주하는 앱으로 만들었습니다.

## 기능

- 트레이 아이콘: 감시 중 / 위험 감지 / 연결 중 / 일시 중지 / 인증 필요 / 계정 미설정 상태 표시
- 개인정보 탐지(값 원문은 저장하지 않고 항목·건수만 기록)
  - 높음: 주민등록번호(생년월일 유효성), 외국인등록번호, 운전면허번호, 여권번호, 카드번호(Luhn), 계좌번호(은행 문맥), 인증정보 키워드
  - 주의: 휴대전화·유선전화, 이메일 주소(발신·수신자와 본인 주소 제외), 도로명·지번 주소, 우편번호, 생년월일, 실명(한국 성씨 + 직함/라벨), 건강·의료 키워드, 사업자등록번호
- 첨부파일 정적 검사(`threats.py`, 외부 서비스 없음): 매직 바이트로 확장자 위장 실행 파일 탐지, Office 매크로(OOXML `vbaProject.bin`, OLE `_VBA_PROJECT`), HWP 스크립트, ZIP 내부 실행 파일·이중 확장자·중첩 압축·암호 설정·압축 폭탄, PDF JavaScript/Launch, HTML·디스크 이미지·OneNote·LNK 등 전달 형식
- 랜섬웨어 지표: 랜섬노트 문구(암호화 통보 + 복호화 대가 + 비트코인/Tor + 협박, 복수 신호 결합), 알려진 암호화 확장자(첨부·압축 내부·본문), 전달 경로 요약(매크로 문서, 암호 압축, 실행 파일, 디스크 이미지, LNK). PC 내 대량 암호화 행위 감시는 2단계 서비스 범위
- Windows Toast 알림(windows-toasts), 클릭 시 최근 위험 메일 창
- 사건 목록에서 행을 두 번 누르면 탐지 근거 창이 열립니다. 원본 메일을 그때그때 읽어 항목별 문맥(값은 마스킹)과 Gmail 받은편지함 탭·라벨을 보여 주며, 원본과 근거는 저장하지 않습니다. 규칙이 개선된 뒤에는 과거 오탐이 '근거 없음'으로 표시됩니다
- 계정 설정 창: 이메일 입력 → 공급자 자동 판별(Gmail, Naver, Daum, Outlook 등) → Google 로그인(OAuth) 또는 앱 비밀번호, 연결 테스트
- 자격증명은 Windows Credential Manager(keyring)에만 저장, 평문 파일 저장 없음
- 폴더별 IMAP IDLE 감시(INBOX + 보낸편지함 자동 탐색), UIDVALIDITY·마지막 UID 체크포인트로 재시작 시 누락·중복 방지(따라잡기 상한 200건)
- 로그인 자동 시작(HKCU Run), 단일 인스턴스(명명된 뮤텍스), 회전 로그(5MB × 5)
- 단일 exe(PyInstaller)와 사용자별 설치기(Inno Setup, 관리자 권한 불필요)

## 폴더 구조

```text
tray/
  MailShield2Tray.pyw          개발용 실행기(콘솔 없음)
  mailshield2/
    __main__.py               진입점·옵션(--settings, --console, --uninstall-cleanup)
    app.py                    조립·상태 머신·UI 스레드 디스패처
    monitor.py                FolderWatcher/Monitor: IDLE 루프, 체크포인트, 보낸편지함 탐색
    scanner.py                1차 분석 규칙(주민번호, Luhn 카드번호, 인증정보 키워드, 실행 첨부)
    auth.py                   CredentialStore(keyring), GoogleOAuth, Authenticator
    store.py                  Settings, CheckpointStore, IncidentLog
    providers.py              도메인 → IMAP 공급자 표
    notify.py autostart.py single_instance.py paths.py logging_setup.py
    ui/tray.py ui/dialogs.py ui/icons.py
  tests/                      네트워크 없는 단위 테스트(가짜 IMAPClient 포함)
  build/                      PyInstaller spec, 아이콘 생성, 빌드 스크립트, Inno Setup 정의
```

## 개발 실행

```powershell
Set-Location "C:\Users\이상진\Documents\email_checker\tray"
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m mailshield2 --console     # 로그를 콘솔에도 출력
```

첫 실행 시 계정이 없으면 계정 설정 창이 자동으로 열립니다. Google 계정은 **Google 로그인(OAuth)** 을 권장합니다. OAuth 클라이언트 파일이 없으면 설정 창의 "OAuth 클라이언트 파일 선택"으로 `docs/05.Gmail연결설치매뉴얼.md` 3장에서 만든 데스크톱 앱 JSON을 지정합니다. 파일은 `%LOCALAPPDATA%\MailShield\google_client.json`으로 복사됩니다.

로컬 데이터: `%LOCALAPPDATA%\MailShield\` (tray.log, settings.json, state.json, incidents.jsonl). 비밀값은 여기에 없습니다.

## 빌드·설치기

```powershell
.\build\Build-MailShield2Tray.ps1            # 테스트 → 아이콘 → exe → 설치기
.\build\Build-MailShield2Tray.ps1 -SkipTests -SkipInstaller
```

산출물: `dist\MailShield2Tray.exe`, `output\MailShield2Tray-Setup-<버전>.exe`. Inno Setup 6이 설치되어 있어야 설치기가 만들어집니다.

OAuth 클라이언트 파일을 exe에 내장하려면 빌드 전에 `mailshield2/resources/google_client.json`으로 복사합니다(Git 제외). 내장하지 않으면 사용자가 설정 창에서 파일을 선택합니다. 배포용 빌드에는 테스트 모드가 아닌 프로덕션 OAuth 클라이언트가 필요합니다.

## 알려진 제한(1단계)

- 조직 정책 동기화, 중앙 서버 보고, Outlook 발송 전 차단은 2단계(.NET Service) 범위입니다.
- 테스트 모드 OAuth 앱의 토큰은 7일 후 만료되어 재로그인이 필요합니다. 트레이 아이콘이 "인증 필요" 상태가 되고 알림이 표시됩니다.
- 탐지 규칙은 프로토타입 수준이며 카드번호는 Luhn 체크섬으로 오탐을 줄였습니다. 운영용 DLP 엔진은 별도입니다.
- 코드 서명이 없어 설치 시 SmartScreen 경고가 나올 수 있습니다.
