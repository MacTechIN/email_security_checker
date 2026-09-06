# Email-Parshing_simplever.py 분석

## 보관 정보

- 원본: `C:\Users\이상진\Downloads\Email-Parshing_simplever.py`
- 보관본: `code_snipt/Email-Parshing_simplever.py`
- 용도: IMAP 연결 및 최신 수신 메일 헤더 조회 개념 검증용 참고 코드
- 상태: 참고용 원본 보관본이며 운영 코드로 직접 사용하지 않는다.

## 현재 동작

1. Gmail IMAP 서버 `imap.gmail.com:993`에 TLS로 연결한다.
2. 사용자가 입력한 이메일 주소와 앱 비밀번호로 로그인한다.
3. `INBOX`의 전체 메시지 ID를 검색한다.
4. 마지막 ID의 메일 원문 전체를 `RFC822`로 가져온다.
5. 제목, 발신자와 날짜 헤더를 디코딩해 콘솔에 출력한다.
6. 선택한 메일함을 닫고 IMAP 연결을 종료한다.

## 재사용 가능한 부분

- MIME 헤더의 분할 인코딩을 처리하는 `decode_mime_header()`
- `IMAP4_SSL` 연결, `select`, `search`, `fetch`, `logout` 기본 흐름
- 앱 비밀번호를 화면에 표시하지 않는 `getpass` 입력 방식
- 인증 오류와 일반 오류를 구분한 기본 예외 처리

## 현재 한계와 위험

- 서버가 Gmail로 하드코딩되어 범용 자동 탐지를 지원하지 않는다.
- OAuth가 없고 앱 비밀번호 로그인만 지원한다.
- `SEARCH ALL` 후 마지막 순번을 최신 메일로 간주하므로 날짜상 최신 메일을 보장하지 않는다.
- UID가 아닌 세션별 메시지 순번을 사용해 메일함 변경 시 안정성이 낮다.
- `RFC822`로 전체 메일을 내려받아 제목·발신자만 필요한 경우에도 데이터가 과도하게 수집된다.
- `fetch` 결과 상태와 응답 구조를 충분히 검증하지 않는다.
- 연결 성공 후 `select`가 실패한 경우와 읽기 전용 선택을 처리하지 않는다.
- 알 수 없는 문자셋 외에 `UnicodeDecodeError`를 별도로 처리하지 않는다.
- 예외 문자열에 공급자 응답이 그대로 출력되어 운영 로그에 불필요한 정보가 남을 수 있다.
- `except:`가 모든 예외를 숨겨 종료 실패를 진단하기 어렵다.
- 시간 제한, 재시도, 취소, 인증서 정책, 로깅 필터와 테스트가 없다.
- 본문, 첨부파일, 개인정보, 스팸, 피싱, 악성코드 및 발송 이력 분석은 구현되어 있지 않다.

## MailShield 적용 방향

이 코드는 `FN-101 계정 연결`, `FN-102 진단 범위`, `FN-201 헤더 분석`의 초기 연결 참고자료로만 사용한다. 실제 구현은 다음과 같이 분리한다.

- `ServerDiscovery`: DNS MX·TXT·SRV, Autoconfig/Autodiscover 및 공급자 메타데이터로 연결 후보 탐색
- `AuthRouter`: 공급자별 OAuth를 우선하고 일반 IMAP은 앱 비밀번호 정책 적용
- `ImapConnector`: UID, 읽기 전용 메일함, 타임아웃, 제한된 범위 검색 및 부분 가져오기 지원
- `MimeParser`: 헤더, 본문, URL, 첨부파일을 크기 제한과 함께 안전하게 파싱
- `DlpScanner`: 주민등록번호, 카드·계좌정보, 개인신상과 인증정보 탐지·마스킹
- `ThreatScanner`: 스팸, 피싱, 악성 URL과 파일 해시 분석
- `FileProvenanceTracker`: 등록 프로그램 생성 파일과 이메일 첨부·발송 이벤트 연결

## 실시간 모니터링 전환 설계

- `imapclient`의 IDLE 기능으로 연결을 유지하고 새 메시지 변경 신호를 받는다.
- `INBOX`와 `Sent`는 폴더별 독립 연결을 사용한다. 구현 방식은 스레드뿐 아니라 비동기 작업 또는 관리되는 작업자 프로세스도 가능하다.
- IDLE 알림 뒤 마지막 UID보다 큰 메시지만 가져오며 UIDVALIDITY와 체크포인트를 저장한다.
- 공급자별 IDLE 유지 제한 전에 세션을 갱신하고 단절·절전 복귀 시 지수 백오프로 재연결한다.
- IDLE 미지원 서버에는 공급자 정책을 준수하는 증분 폴링을 적용하며 1초 반복 조회는 금지한다.
- 보낸편지함 감시는 발송 후 기록을 빠르게 발견하는 기능이다. 발송 전 차단에는 Outlook 연동 또는 메일 게이트웨이가 필요하다.
- `.pyw`는 콘솔만 숨길 뿐 Windows Service가 아니다. `pystray`는 프로토타입 UI에 사용할 수 있지만 운영 제품은 자동 복구·권한 분리·업데이트가 가능한 서비스로 구현한다.

## 최종 Windows 앱 형태

- 개발·개인 테스트에서는 감시 코드를 `realtime_email_monitor.pyw`로 저장하고 더블클릭하거나 `pythonw.exe`로 실행해 콘솔 창 없이 백그라운드 감시를 확인한다.
- 위험 이벤트의 로컬 안내에는 Windows Toast 알림을 사용하고, 트레이 UI에서 연결 상태와 일시 중지를 제공한다.
- 운영 배포에서는 `.pyw` 단독 실행 대신 Windows Service가 감시 작업자를 관리한다. 서비스는 자동 시작, 예외 복구, 중복 실행 방지, 정책 동기화와 보안 로그 필터링을 담당한다.
- 백그라운드 감시는 RAM에 상주하지만 메일 원문을 계속 보관하지 않는다. 새 이벤트를 처리한 뒤 원문과 첨부파일은 정책상 필요한 경우를 제외하고 폐기한다.

## 추가된 실시간 감시 프로토타입

- 파일: `realtime_email_monitor.pyw`
- 의존성: `requirements-realtime.txt`
- 설정: `MAILSHIELD_EMAIL`, `MAILSHIELD_IMAP_HOST`, `MAILSHIELD_IMAP_PORT`, `MAILSHIELD_APP_PASSWORD`, `MAILSHIELD_FOLDERS`
- 동작: 폴더별 독립 IMAP 연결, IDLE 대기, UID 증분 조회, 재연결 백오프, 기본 개인정보·위험 첨부파일 후보 탐지, Windows Toast 알림

개발 테스트 예시:

```powershell
$env:MAILSHIELD_EMAIL = "user@example.com"
$env:MAILSHIELD_IMAP_HOST = "imap.example.com"
$env:MAILSHIELD_IMAP_PORT = "993"
$env:MAILSHIELD_APP_PASSWORD = "앱 비밀번호"
$env:MAILSHIELD_FOLDERS = "INBOX,Sent"
pythonw .\realtime_email_monitor.pyw
```

이 프로토타입은 공급자 자동 탐지, OAuth, UIDVALIDITY 영속 체크포인트, 등록 프로그램 파일 출처 연계, 정교한 카드·계좌번호 검증, 악성코드 샌드박스를 아직 포함하지 않는다. 운영 배포 전에는 Windows Service 래퍼와 조직 정책 서버를 연결해야 한다.

## Gmail 연결 테스트

처음부터 다시 설정하는 전체 절차(Google Cloud Console OAuth 클라이언트 생성, `credentials.json` 배치, 앱 비밀번호 발급, 문제 해결)는 `docs/05.Gmail연결설치매뉴얼.md`를 참조합니다.

`test_gmail_imap.py`는 Gmail IMAP SSL 연결, INBOX·Sent 접근과 최신 메일의 제목·발신자·날짜 헤더만 확인합니다. 본문과 첨부파일은 다운로드하지 않습니다.

Gmail에서 IMAP을 활성화하고 2단계 인증을 설정한 뒤 앱 비밀번호를 발급합니다.

```powershell
$env:MAILSHIELD_GMAIL_ADDRESS = "your-account@gmail.com"
$env:MAILSHIELD_GMAIL_APP_PASSWORD = "16자리 앱 비밀번호"
python .\test_gmail_imap.py
```

실패 시 2단계 인증과 앱 비밀번호 발급 여부, Google Workspace 관리자의 IMAP·앱 비밀번호 허용 정책, 계정 보안 경고와 네트워크 993/TLS 차단 여부를 확인합니다. 스크립트는 앱 비밀번호의 표시용 공백·하이픈을 자동 제거합니다. 일반 Gmail 비밀번호를 코드나 환경변수에 사용하지 마십시오. Google은 일반적으로 OAuth/Sign in with Google을 앱 비밀번호보다 권장합니다.

## 우선 개선 순서

1. 서버 하드코딩을 제거하고 자동 탐지 결과를 입력받는 커넥터로 전환한다.
2. Google·Microsoft OAuth와 일반 IMAP 앱 비밀번호 경로를 분리한다.
3. `UID SEARCH`와 `UID FETCH`를 사용하고 최근 N개 또는 기간 조건을 서버에서 제한한다.
4. 최초 목록에서는 필요한 헤더만 부분 조회하고 심층 분석 대상으로 선정된 메일만 본문을 가져온다.
5. MIME 구조, 중첩 첨부, 다중 문자셋, 손상 메시지와 대용량 메시지 테스트를 추가한다.
6. 개인정보 원문과 인증정보가 로그에 남지 않도록 구조화 로그와 마스킹을 적용한다.
