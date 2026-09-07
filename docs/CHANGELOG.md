# MailShield 변경 이력

커밋 단위로 버전을 부여한다. 0.0.x는 개발 중 누적 변경, 0.1.0은 MailShield Tray 1단계 첫 릴리스다.
버전 규칙: `MAJOR.MINOR.PATCH`. 커밋 1건 = PATCH 1 증가, 릴리스 시 MINOR 증가.

## 0.1.0 — 2026-09-08 — MailShield Tray 1단계 릴리스

- 변경 이력 문서(`docs/CHANGELOG.md`) 신설, 릴리스 태그 `v0.1.0`
- 이력 정리: 0.0.9 커밋에 실수로 포함됐던 77MB 빌드 산출물(`installer/publish/`)을 푸시 전 이력에서 제거(커밋 해시가 바뀜)
- 포함 산출물: `tray/dist/MailShieldTray.exe`, `tray/output/MailShieldTray-Setup-0.1.0.exe` (빌드 산출물은 저장소에 포함하지 않음)

## 0.0.x — 커밋별 이력

| 버전 | 날짜 | 커밋 | 유형 | 설명 |
|---|---|---|---|---|
| 0.0.25 | 2026-09-07 | `1fd4eb9` | docs | 개발계획서 18장의 단일 인스턴스 뮤텍스 이름을 구현(`Local\MailShieldTray`)과 일치시킴 |
| 0.0.24 | 2026-09-07 | `b92cdcc` | feat | **MailShield Tray 상주형 앱 1단계 구현.** `tray/` 패키지 신설: 폴더별 IMAP IDLE 감시(체크포인트·따라잡기 상한·즉시 중지), Luhn 기반 카드번호 탐지, Windows 자격 증명 관리자 저장(keyring), Google OAuth 데스크톱 로그인, pystray 트레이 아이콘·Tkinter 설정/사건 창·Toast 알림, 로그인 자동 시작, 단일 인스턴스, 회전 로그, PyInstaller 단일 exe·Inno Setup 사용자별 설치기, 단위 테스트 21개, CI tray 잡 |
| 0.0.23 | 2026-09-07 | `754c0ff` | docs | 개발 목표를 CLI 프로토타입에서 Windows RAM 상주형 앱으로 전환. 개발계획서 1.2.1 실행 형태 표 개편, 16.3 갱신, 18장(2단계 전환 계획·일차별 작업·완료 기준·결정 게이트) 추가, 상용 계획서·code_snipt README 연동 |
| 0.0.22 | 2026-09-07 | `7030930` | fix | 실시간 감시가 새 메일을 놓치던 결함 수정. Python 3.14 + imapclient 3.1 환경에서 EXISTS 알림이 `idle_done` 응답에만 실리므로 두 응답을 합쳐 처리하고, IMAP `N:*` 규칙으로 마지막 메일이 재처리되는 문제도 차단 |
| 0.0.21 | 2026-09-07 | `370e5fe` | chore | 다운로드된 Google OAuth 클라이언트 비밀 파일(`client_secret_*.json`)을 Git 추적에서 제외 |
| 0.0.20 | 2026-09-07 | `53136e4` | fix | OAuth IMAP 테스트의 XOAUTH2 이중 base64 인코딩 수정. Gmail의 `Invalid SASL argument` 거부 해소, OAuth 경로 실연결 성공 |
| 0.0.19 | 2026-09-07 | `80df38e` | docs | Gmail 매뉴얼의 앱 비밀번호 자리표시자를 명시적 안내 문구로 교체하고 그대로 실행 시 나는 오류를 설명 |
| 0.0.18 | 2026-09-07 | `cbe98b9` | fix | 보낸편지함을 IMAP SPECIAL-USE `\Sent` 플래그로 탐색. 옛 클라이언트가 만든 `Sent` 라벨 대신 실제 `[Gmail]/Sent Mail`을 선택 |
| 0.0.17 | 2026-09-07 | `f552bc5` | docs | Gmail 연결 설치 매뉴얼(`docs/05`) 신설: IMAP·2단계 인증, Google Cloud Console OAuth 클라이언트 생성, credentials.json 배치, PC 설치, 연결 테스트, 문제 해결 표, 재설치 체크리스트 |
| 0.0.16 | 2026-08-06 | `adf62bd` | feat | 브라우저 OAuth 2.0 + XOAUTH2 Gmail IMAP 연결 테스트 스크립트 추가 |
| 0.0.15 | 2026-08-06 | `97aa0c7` | docs | Gmail 앱 비밀번호 거부 시 안내 문구 보강 |
| 0.0.14 | 2026-08-06 | `51f5cb8` | fix | Gmail 인증 실패 시 비밀번호를 가린 안전한 서버 응답 진단 출력 |
| 0.0.13 | 2026-08-06 | `032ac91` | fix | 앱 비밀번호 입력의 공백·하이픈 자동 제거 |
| 0.0.12 | 2026-08-06 | `1fe3a2e` | feat | Gmail IMAP 연결 테스트 스크립트(`test_gmail_imap.py`) 추가: INBOX·보낸편지함 헤더 확인 |
| 0.0.11 | 2026-08-06 | `1911fa5` | fix | Inno Setup 서비스 등록 명령의 인용부호 오류 수정 |
| 0.0.10 | 2026-08-06 | `3f9b740` | build | Windows Service용 Installer.exe 패키징 정의(Inno Setup) 추가 |
| 0.0.9 | 2026-08-06 | `e3057b3` | fix | 서비스 설치 스크립트에 관리자 권한 요구 추가 |
| 0.0.8 | 2026-08-06 | `2150dad` | docs | 설치 시 PowerShell 작업 디렉터리 안내 명확화 |
| 0.0.7 | 2026-08-06 | `87642bc` | docs | 한국어 사용자 운영 매뉴얼(`docs/04`) 추가 |
| 0.0.6 | 2026-08-06 | `c513ccb` | docs | 설치 검증 순서 문서화 |
| 0.0.5 | 2026-08-06 | `2ffe5ce` | test | Windows Service 검증 스크립트 추가 |
| 0.0.4 | 2026-08-06 | `02a14a7` | build | 패키지 검증 스크립트 추가 |
| 0.0.3 | 2026-08-06 | `12410e2` | ci | 백엔드·에이전트 검증 GitHub Actions 워크플로 추가 |
| 0.0.2 | 2026-08-06 | `3f654f8` | test | 컨트롤 플레인 API 회귀 테스트 추가 |
| 0.0.1 | 2026-08-06 | `8632620` | feat | 컨트롤 플레인 API를 에이전트 키로 보호 |

## 다음 릴리스 후보

- 0.2.0: 1단계 완료 기준 충족(실계정 GUI 연결 확인, 재부팅 자동 시작, 24시간 자원 측정, 사용자 매뉴얼 갱신)
- 0.3.0: 2단계 .NET Windows Service + WPF Tray 이식 착수(개발계획서 18.3)
