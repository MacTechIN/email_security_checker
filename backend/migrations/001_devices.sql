-- MailShield Control Plane PostgreSQL 초기 장치 스키마
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS agent_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    device_id VARCHAR(128) NOT NULL,
    agent_version VARCHAR(64) NOT NULL,
    operating_system VARCHAR(256) NOT NULL,
    status VARCHAR(16) NOT NULL CHECK (status IN ('online', 'degraded', 'offline')),
    last_seen_at_utc TIMESTAMPTZ NOT NULL,
    registered_at_utc TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at_utc TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_agent_devices_tenant_last_seen
    ON agent_devices (tenant_id, last_seen_at_utc DESC);

CREATE TABLE IF NOT EXISTS agent_audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    device_id VARCHAR(128) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    event_json JSONB NOT NULL,
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_agent_audit_events_tenant_created
    ON agent_audit_events (tenant_id, created_at_utc DESC);

-- 운영 환경에서는 모든 조회·수정 쿼리에 tenant_id를 포함하고,
-- PostgreSQL RLS 정책을 활성화해 테넌트 간 접근을 차단한다.
