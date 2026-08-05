from __future__ import annotations

import os
from datetime import datetime
from typing import Any
from uuid import UUID


class DeviceStore:
    def __init__(self) -> None:
        self.database_url = os.getenv("DATABASE_URL", "").strip()
        self.memory: dict[tuple[UUID, str], dict[str, Any]] = {}

    def upsert(self, state: dict[str, Any]) -> dict[str, Any]:
        if not self.database_url:
            self.memory[(state["tenantId"], state["deviceId"])] = state
            return state

        import psycopg

        query = """
        INSERT INTO agent_devices
          (tenant_id, device_id, agent_version, operating_system, status, last_seen_at_utc, updated_at_utc)
        VALUES (%s, %s, %s, %s, %s, %s, now())
        ON CONFLICT (tenant_id, device_id) DO UPDATE SET
          agent_version = EXCLUDED.agent_version,
          operating_system = EXCLUDED.operating_system,
          status = EXCLUDED.status,
          last_seen_at_utc = EXCLUDED.last_seen_at_utc,
          updated_at_utc = now()
        RETURNING tenant_id, device_id, agent_version, operating_system, status, last_seen_at_utc;
        """
        with psycopg.connect(self.database_url) as connection:
            params = (state["tenantId"], state["deviceId"], state["agentVersion"], state["operatingSystem"], state["status"], state["lastSeenAtUtc"])
            row = connection.execute(query, params).fetchone()
            connection.commit()
        if row is None:
            raise RuntimeError("device upsert returned no row")
        return dict(zip(("tenantId", "deviceId", "agentVersion", "operatingSystem", "status", "lastSeenAtUtc"), row))

    def get(self, tenant_id: UUID, device_id: str) -> dict[str, Any] | None:
        if not self.database_url:
            return self.memory.get((tenant_id, device_id))

        import psycopg

        query = """
        SELECT tenant_id, device_id, agent_version, operating_system, status, last_seen_at_utc
        FROM agent_devices WHERE tenant_id = %s AND device_id = %s
        """
        with psycopg.connect(self.database_url) as connection:
            row = connection.execute(query, (tenant_id, device_id)).fetchone()
        if row is None:
            return None
        return dict(zip(("tenantId", "deviceId", "agentVersion", "operatingSystem", "status", "lastSeenAtUtc"), row))
