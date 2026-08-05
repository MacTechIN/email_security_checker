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

현재 장치 상태는 메모리에 저장됩니다. 상용 버전에서는 PostgreSQL, 테넌트 격리, 장치 인증서 또는 서명 검증, rate limit, 감사 로그를 추가해야 합니다.
