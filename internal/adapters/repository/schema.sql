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

-- Index for case-insensitive zone lookup (used by GetZoneLongestMatch)
CREATE INDEX idx_dns_zones_name_lower ON dns_zones (LOWER(name));

-- Expression index for efficient suffix-match zone lookup via reversed name
-- Enables PostgreSQL to use index range scan instead of full table scan
CREATE INDEX IF NOT EXISTS idx_dns_zones_name_reverse ON dns_zones (REVERSE(name));

-- Composite indexes for split-horizon DNS queries
-- Covers zone_id + LOWER(name) + type pattern used by DeleteRecordsByNameAndType
CREATE INDEX IF NOT EXISTS idx_dns_records_zone_name_type ON dns_records(zone_id, LOWER(name), type);

-- Unique constraint for catalog zone PTR records (used by AddZoneToCatalog ON CONFLICT)
CREATE UNIQUE INDEX IF NOT EXISTS idx_dns_records_zone_name_type_content ON dns_records(zone_id, LOWER(name), type, content);

-- Covers zone_id + LOWER(name) pattern used by DeleteRecordsByName
CREATE INDEX IF NOT EXISTS idx_dns_records_zone_name ON dns_records(zone_id, LOWER(name));

-- Covers zone_id used by DeleteRecordsForZone bulk deletes
CREATE INDEX IF NOT EXISTS idx_dns_records_zone_id ON dns_records(zone_id);

-- Tenant-scoped zone listing (ListZones, tenant isolation)
CREATE INDEX IF NOT EXISTS idx_dns_zones_tenant_id ON dns_zones(tenant_id);

-- Index for zone+type queries (GetDNSKEYs, GetRecords by type)
CREATE INDEX IF NOT EXISTS idx_dns_records_zone_type ON dns_records(zone_id, type);

-- Partial index for health check probing
CREATE INDEX IF NOT EXISTS idx_dns_records_health_active ON dns_records(health_check_type)
  WHERE health_check_type IN ('HTTP', 'TCP');

-- Index for audit logs tenant lookup
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_id ON audit_logs(tenant_id);

-- Index for zone changes by zone+serial
CREATE INDEX IF NOT EXISTS idx_dns_zone_changes_zone_serial ON dns_zone_changes(zone_id, serial);

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

-- Enable case-insensitive text type for DNS names
CREATE EXTENSION IF NOT EXISTS citext;

-- Migrate dns_records.name to citext for case-insensitive index usage
ALTER TABLE dns_records ALTER COLUMN name TYPE citext;

-- Migrate dns_zones.name to citext for case-insensitive zone lookups
ALTER TABLE dns_zones ALTER COLUMN name TYPE citext;

-- Catalog Zones (RFC 9432)
CREATE TABLE IF NOT EXISTS catalog_zones (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    zone_name TEXT NOT NULL UNIQUE,
    version TEXT NOT NULL DEFAULT '1',
    serial BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Index for catalog zone lookup by tenant
CREATE INDEX IF NOT EXISTS idx_catalog_zones_tenant_id ON catalog_zones(tenant_id);

-- Add catalog relationship to dns_zones
ALTER TABLE dns_zones ADD COLUMN IF NOT EXISTS catalog_id UUID REFERENCES catalog_zones(id);
ALTER TABLE dns_zones ADD COLUMN IF NOT EXISTS catalog_zone_name TEXT;

-- Index for dns_zones catalog_zone_name lookups (used by GetZoneByCatalogName)
CREATE INDEX IF NOT EXISTS idx_dns_zones_catalog_zone_name ON dns_zones(catalog_zone_name) WHERE catalog_zone_name IS NOT NULL;