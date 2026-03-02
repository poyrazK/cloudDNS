CREATE TABLE IF NOT EXISTS dns_zones (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    vpc_id UUID,
    description TEXT,
    role TEXT DEFAULT 'master',
    master_server TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dns_records (
    id UUID PRIMARY KEY,
    zone_id UUID REFERENCES dns_zones(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    content TEXT NOT NULL,
    ttl INTEGER NOT NULL,
    priority INTEGER,
    weight INTEGER,
    port INTEGER,
    network CIDR,
    health_check_type TEXT DEFAULT 'NONE' CHECK (health_check_type IN ('NONE', 'HTTP', 'TCP')),
    health_check_target TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Migration for existing tables
ALTER TABLE dns_records ADD COLUMN IF NOT EXISTS weight INTEGER;
ALTER TABLE dns_records ADD COLUMN IF NOT EXISTS port INTEGER;
ALTER TABLE dns_records ADD COLUMN IF NOT EXISTS health_check_type TEXT DEFAULT 'NONE';
ALTER TABLE dns_records ADD COLUMN IF NOT EXISTS health_check_target TEXT;

CREATE TABLE IF NOT EXISTS record_health (
    record_id UUID PRIMARY KEY REFERENCES dns_records(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'UNKNOWN' CHECK (status IN ('HEALTHY', 'UNHEALTHY', 'UNKNOWN')),
    last_check TIMESTAMPTZ,
    error_message TEXT
);

ALTER TABLE dns_zones ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'master';
ALTER TABLE dns_zones ADD COLUMN IF NOT EXISTS master_server TEXT;

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id UUID NOT NULL,
    details TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dns_zone_changes (
    id UUID PRIMARY KEY,
    zone_id UUID REFERENCES dns_zones(id) ON DELETE CASCADE,
    serial BIGINT NOT NULL, -- The serial after this change
    action TEXT NOT NULL,   -- 'ADD' or 'DELETE'
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    content TEXT NOT NULL,
    ttl INTEGER NOT NULL,
    priority INTEGER,
    weight INTEGER,
    port INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Migration for existing tables
ALTER TABLE dns_zone_changes ADD COLUMN IF NOT EXISTS weight INTEGER;
ALTER TABLE dns_zone_changes ADD COLUMN IF NOT EXISTS port INTEGER;

CREATE TABLE IF NOT EXISTS dnssec_keys (
    id UUID PRIMARY KEY,
    zone_id UUID REFERENCES dns_zones(id) ON DELETE CASCADE,
    key_type TEXT NOT NULL, -- 'KSK' or 'ZSK'
    algorithm INTEGER NOT NULL, -- 13 for ECDSAP256SHA256
    private_key BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_dns_records_name ON dns_records(name);
CREATE INDEX idx_dns_records_network ON dns_records USING gist (network inet_ops);

CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,  -- SHA-256 hash
    key_prefix TEXT NOT NULL,       -- First 8 chars for display
    role TEXT NOT NULL DEFAULT 'admin',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ,
    CONSTRAINT role_check CHECK (role IN ('admin', 'writer', 'reader'))
);
