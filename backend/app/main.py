from datetime import datetime, timezone
from uuid import UUID

from fastapi import FastAPI, HTTPException, status
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


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/agent/heartbeat", response_model=DeviceState)
def agent_heartbeat(payload: HeartbeatRequest) -> DeviceState:
    now = datetime.now(timezone.utc)
    state = {**payload.model_dump(), "lastSeenAtUtc": now}
    return DeviceState.model_validate(device_store.upsert(state))


@app.get("/api/v1/agents/{tenant_id}/{device_id}", response_model=DeviceState)
def get_agent(tenant_id: UUID, device_id: str) -> DeviceState:
    state = device_store.get(tenant_id, device_id)
    if state is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="device not found")
    return state


@app.get("/api/v1/agents/{tenant_id}/{device_id}/policy", response_model=PolicyResponse)
def get_policy(tenant_id: UUID, device_id: str) -> PolicyResponse:
    return PolicyResponse(tenantId=tenant_id, deviceId=device_id)
