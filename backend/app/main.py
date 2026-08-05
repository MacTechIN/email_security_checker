from datetime import datetime, timezone
from typing import Dict

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

app = FastAPI(title="MailShield Control Plane", version="0.1.0")


class HeartbeatRequest(BaseModel):
    deviceId: str = Field(min_length=1, max_length=128)
    agentVersion: str = Field(min_length=1, max_length=64)
    operatingSystem: str = Field(min_length=1, max_length=256)
    status: str = Field(pattern="^(online|degraded|offline)$")
    reportedAtUtc: datetime


class DeviceState(HeartbeatRequest):
    lastSeenAtUtc: datetime


# 개발용 저장소. 상용 버전에서는 PostgreSQL 장치 테이블로 교체한다.
device_states: Dict[str, DeviceState] = {}


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/agent/heartbeat", response_model=DeviceState)
def agent_heartbeat(payload: HeartbeatRequest) -> DeviceState:
    now = datetime.now(timezone.utc)
    state = DeviceState(**payload.model_dump(), lastSeenAtUtc=now)
    device_states[payload.deviceId] = state
    return state


@app.get("/api/v1/agents/{device_id}", response_model=DeviceState)
def get_agent(device_id: str) -> DeviceState:
    state = device_states.get(device_id)
    if state is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="device not found")
    return state
