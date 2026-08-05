from datetime import datetime, timezone
from uuid import UUID

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)
TENANT = "00000000-0000-0000-0000-000000000001"


def heartbeat_payload() -> dict:
    return {
        "tenantId": TENANT,
        "deviceId": "test-device",
        "agentVersion": "0.1.0",
        "operatingSystem": "Windows Test",
        "status": "online",
        "reportedAtUtc": datetime.now(timezone.utc).isoformat(),
    }


def test_healthz() -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_heartbeat_and_device_read() -> None:
    response = client.post("/api/v1/agent/heartbeat", json=heartbeat_payload())
    assert response.status_code == 200
    assert response.json()["deviceId"] == "test-device"

    response = client.get(f"/api/v1/agents/{TENANT}/test-device")
    assert response.status_code == 200
    assert response.json()["tenantId"] == TENANT


def test_policy_read() -> None:
    response = client.get(f"/api/v1/agents/{TENANT}/test-device/policy")
    assert response.status_code == 200
    assert response.json()["mode"] == "monitor"


def test_invalid_heartbeat_is_rejected() -> None:
    payload = heartbeat_payload()
    payload["status"] = "invalid"
    response = client.post("/api/v1/agent/heartbeat", json=payload)
    assert response.status_code == 422
