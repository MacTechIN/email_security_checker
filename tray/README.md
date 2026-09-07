# MailShield Tray (1단계 Windows 상주형 앱)

`docs/02.개발계획서.md` 18장 전환 계획의 1단계 구현입니다. 검증된 `code_snipt/realtime_email_monitor.pyw`의 감시·탐지 로직을 재사용하고, 콘솔과 환경변수 없이 Windows 로그인과 함께 트레이에 상주하는 앱으로 만들었습니다.

## 기능

- 트레이 아이콘: 감시 중 / 위험 감지 / 연결 중 / 일시 중지 / 인증 필요 / 계정 미설정 상태 표시
- Windows Toast 알림(windows-toasts), 클릭 시 최근 위험 메일 창
- 계정 설정 창: 이메일 입력 → 공급자 자동 판별(Gmail, Naver, Daum, Outlook 등) → Google 로그인(OAuth) 또는 앱 비밀번호, 연결 테스트
- 자격증명은 Windows Credential Manager(keyring)에만 저장, 평문 파일 저장 없음
- 폴더별 IMAP IDLE 감시(INBOX + 보낸편지함 자동 탐색), UIDVALIDITY·마지막 UID 체크포인트로 재시작 시 누락·중복 방지(따라잡기 상한 200건)
- 로그인 자동 시작(HKCU Run), 단일 인스턴스(명명된 뮤텍스), 회전 로그(5MB × 5)
- 단일 exe(PyInstaller)와 사용자별 설치기(Inno Setup, 관리자 권한 불필요)

## 폴더 구조

```text
tray/
  MailShieldTray.pyw          개발용 실행기(콘솔 없음)
  mailshield_tray/
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
python -m mailshield_tray --console     # 로그를 콘솔에도 출력
```

첫 실행 시 계정이 없으면 계정 설정 창이 자동으로 열립니다. Google 계정은 **Google 로그인(OAuth)** 을 권장합니다. OAuth 클라이언트 파일이 없으면 설정 창의 "OAuth 클라이언트 파일 선택"으로 `docs/05.Gmail연결설치매뉴얼.md` 3장에서 만든 데스크톱 앱 JSON을 지정합니다. 파일은 `%LOCALAPPDATA%\MailShield\google_client.json`으로 복사됩니다.

로컬 데이터: `%LOCALAPPDATA%\MailShield\` (tray.log, settings.json, state.json, incidents.jsonl). 비밀값은 여기에 없습니다.

## 빌드·설치기

```powershell
.\build\Build-MailShieldTray.ps1            # 테스트 → 아이콘 → exe → 설치기
.\build\Build-MailShieldTray.ps1 -SkipTests -SkipInstaller
```

산출물: `dist\MailShieldTray.exe`, `output\MailShieldTray-Setup-<버전>.exe`. Inno Setup 6이 설치되어 있어야 설치기가 만들어집니다.

OAuth 클라이언트 파일을 exe에 내장하려면 빌드 전에 `mailshield_tray/resources/google_client.json`으로 복사합니다(Git 제외). 내장하지 않으면 사용자가 설정 창에서 파일을 선택합니다. 배포용 빌드에는 테스트 모드가 아닌 프로덕션 OAuth 클라이언트가 필요합니다.

## 알려진 제한(1단계)

- 조직 정책 동기화, 중앙 서버 보고, Outlook 발송 전 차단은 2단계(.NET Service) 범위입니다.
- 테스트 모드 OAuth 앱의 토큰은 7일 후 만료되어 재로그인이 필요합니다. 트레이 아이콘이 "인증 필요" 상태가 되고 알림이 표시됩니다.
- 탐지 규칙은 프로토타입 수준이며 카드번호는 Luhn 체크섬으로 오탐을 줄였습니다. 운영용 DLP 엔진은 별도입니다.
- 코드 서명이 없어 설치 시 SmartScreen 경고가 나올 수 있습니다.
