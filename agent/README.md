# MailShield.Agent

상용 MailShield Windows Service의 초기 스캐폴드입니다.

## 책임

- Windows 로그인·시작 시 자동 실행
- Agent 상태 heartbeat와 구조화 로그
- 정책 동기화 및 공급자별 메일 감시 모듈의 호스트
- IMAP IDLE, Outlook 이벤트, DLP, 파일 출처 추적 모듈의 수명주기 관리
- 장애 발생 시 서비스 프로세스 유지와 모듈별 재시작 기반 제공

## 빌드

Windows에 .NET 8 SDK를 설치한 뒤 실행합니다.

```powershell
dotnet restore
dotnet build -c Release
```

현재 개발 환경에는 사용자 영역에 .NET 8 SDK를 설치해 빌드 검증을 완료했습니다.

## 다음 구현 순서

1. `AgentOptions`와 환경변수·DPAPI 기반 설정 로더
2. 장치 등록·heartbeat API 클라이언트
3. 암호화된 정책 캐시와 오프라인 큐
4. Python 프로토타입에서 추출한 IMAP IDLE 커넥터
5. DLP·파일 출처 추적 이벤트 버스
6. 서명된 MSI/MSIX 설치 및 Windows Service 복구 정책

## Heartbeat

에이전트는 `ControlPlaneUrl`의 `/api/v1/agent/heartbeat`로 장치 ID, 에이전트 버전, 운영체제와 상태를 보고합니다. 서버가 중단되어도 로컬 감시를 계속합니다. 운영 환경에서는 설치·등록 과정에서 발급한 DeviceId와 장치 인증서·요청 서명을 사용해야 합니다.

정책은 Windows DPAPI(CurrentUser)로 암호화된 `LocalApplicationData\MailShield\policy.bin`에 저장됩니다. 서버 연결 실패 시 마지막으로 저장된 정책을 사용하며, 사용자·장치가 바뀌면 DPAPI 복호화가 실패해 정책을 적용하지 않습니다.

`DlpScanner`는 정책의 개인정보 탐지·보호 확장자 목록을 사용해 제목, 본문과 첨부파일 메타데이터를 평가합니다. 카드·계좌번호는 상용 단계에서 체크섬·문맥 검증을 추가해야 하며, 현재 모듈은 커넥터 연결 전의 정책 적용 지점입니다.

`MailEventPipeline`은 IMAP IDLE 또는 공급자 API 커넥터가 전달한 `MailEvent`를 DLP 정책으로 평가해 `MailSecurityIncident`로 변환합니다. 커넥터는 폴더별 독립 연결, UID 체크포인트, IDLE 갱신과 재연결을 구현하고 이 파이프라인에 이벤트를 전달해야 합니다.

`ImapIdleSource`는 MailKit 기반의 연결 구현입니다. `INBOX`와 `Sent`에 인스턴스를 각각 만들고 `ReadEventsAsync()`를 별도 작업으로 실행해야 합니다. 운영 환경에서는 앱 비밀번호를 설정 파일에 저장하지 말고 Windows Credential Manager·DPAPI에서 읽어야 하며, UID 체크포인트를 `lastUid` 메모리 변수보다 영속 저장소로 교체해야 합니다.
