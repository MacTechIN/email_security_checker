from datetime import datetime, timezone
import hmac
import os
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

app = FastAPI(title="MailShield Control Plane", version="0.1.0")


class HeartbeatRequest(BaseModel):
    tenantId: UUID
    deviceId: str = Field(min_length=1, max_length=128)
    agentVersion: str = Field(min_length=1, max_length=64)
    operatingSystem: str = Field(min_length=1, max_length=256)
    status: str = Field(pattern="^(online|degraded|offline)$")
    reportedAtUtc: datetime


class DeviceState(HeartbeatRequest):
    lastSeenAtUtc: datetime


class PolicyResponse(BaseModel):
    tenantId: UUID
    deviceId: str
    version: int = 1
    mode: str = "monitor"
    protectedExtensions: list[str] = []
    externalRecipientWarning: bool = True
    piiDetection: bool = True


from .storage import DeviceStore

device_store = DeviceStore()


def require_agent_key(x_mailshield_agent_key: str | None = Header(default=None)) -> None:
    expected = os.getenv("MAILSHIELD_AGENT_API_KEY", "").strip()
    if not expected:
        return  # 개발 모드: 운영에서는 반드시 환경변수를 설정한다.
    if not x_mailshield_agent_key or not hmac.compare_digest(x_mailshield_agent_key, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid agent credentials")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/agent/heartbeat", response_model=DeviceState, dependencies=[Depends(require_agent_key)])
def agent_heartbeat(payload: HeartbeatRequest) -> DeviceState:
    now = datetime.now(timezone.utc)
    state = {**payload.model_dump(), "lastSeenAtUtc": now}
    return DeviceState.model_validate(device_store.upsert(state))


@app.get("/api/v1/agents/{tenant_id}/{device_id}", response_model=DeviceState, dependencies=[Depends(require_agent_key)])
def get_agent(tenant_id: UUID, device_id: str) -> DeviceState:
    state = device_store.get(tenant_id, device_id)
    if state is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="device not found")
    return state


@app.get("/api/v1/agents/{tenant_id}/{device_id}/policy", response_model=PolicyResponse, dependencies=[Depends(require_agent_key)])
def get_policy(tenant_id: UUID, device_id: str) -> PolicyResponse:
    return PolicyResponse(tenantId=tenant_id, deviceId=device_id)
