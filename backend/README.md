# MailShield Control Plane

Agent heartbeat와 장치 상태 확인을 위한 FastAPI 개발 서버입니다.

## 실행

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8443 --reload
```

개발용 `appsettings.json`의 `ControlPlaneUrl`을 `http://127.0.0.1:8443`으로 설정하면 Windows Agent가 heartbeat를 전송할 수 있습니다.

## API

- `GET /healthz`: 서버 상태
- `POST /api/v1/agent/heartbeat`: Agent 장치 상태 등록·갱신
- `GET /api/v1/agents/{device_id}`: 장치 상태 확인

현재 장치 상태는 개발 편의를 위해 메모리에 저장됩니다. 상용 스키마는 `migrations/001_devices.sql`에 정의되어 있습니다.

상용 전환 시:

- `agent_devices`에 `tenant_id + device_id`를 기준으로 장치 상태를 저장합니다.
- `agent_audit_events`에 heartbeat와 장치 상태 변경을 감사 이벤트로 저장합니다.
- 모든 쿼리에 `tenant_id`를 적용하고 PostgreSQL RLS를 활성화합니다.
- 장치 인증서 또는 요청 서명, rate limit, 만료 장치 정리 작업을 추가합니다.
