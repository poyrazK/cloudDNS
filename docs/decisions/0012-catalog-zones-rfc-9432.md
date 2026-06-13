# ADR 0012: RFC 9432 Catalog Zones

## Status
Accepted

## Date
2026-06-10

## Context

RFC 9432 defines Catalog Zones (CATZ type 53) and Catalog Zone Transfer (CZTR type 54) for publishing zone metadata in DNS. This enables slave DNS servers to automatically discover, provision, and synchronize zones from a master server without manual configuration.

cloudDNS needed to support the slave-side catalog zone workflow:
1. A catalog zone exists on the master server containing zone metadata (name, ID, group) as PTR records
2. Slave servers poll the catalog zone periodically (or on demand)
3. Zone entries are fetched via AXFR from the catalog zone
4. Each zone is then fetched via AXFR from the master and provisioned locally

Key design decisions were required:
- How to model catalog zones in the existing PostgreSQL schema
- How to store zone inventory entries (PTR records with custom content format)
- How to handle the polling loop lifecycle
- How to avoid O(n) scans when checking zone existence

## Decision

### Schema

A new `catalog_zones` table stores catalog zone metadata:

```sql
CREATE TABLE catalog_zones (
    id          UUID PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    zone_name   TEXT NOT NULL,
    version     TEXT NOT NULL DEFAULT '1',
    serial      UINT NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

Zone entries are stored as PTR records in the existing `dns_records` table, within the catalog zone's own zone. The content format is `zone_name:zone_id[:group_id]` (e.g., `foo.example.com.:uuid-123:group1`).

The `dns_zones` table gains two new columns:
- `catalog_id` — FK to `catalog_zones(id)` linking a zone to its source catalog
- `catalog_zone_name` — the zone's name within the catalog (used for targeted lookups)

### API

Seven REST endpoints for catalog zone management:

| Method | Path | Description |
|--------|------|-------------|
| POST | `/catalog-zones` | Create a catalog zone |
| GET | `/catalog-zones` | List all catalog zones for tenant |
| GET | `/catalog-zones/{id}` | Get a specific catalog zone |
| DELETE | `/catalog-zones/{id}` | Delete a catalog zone |
| POST | `/catalog-zones/{id}/entries` | Add a zone to the catalog |
| DELETE | `/catalog-zones/{id}/entries/{zone_name}` | Remove a zone from the catalog |
| GET | `/catalog-zones/{id}/entries` | List all entries in a catalog zone |

### Storage

Catalog entries are stored as PTR records with reversed zone names (e.g., `foo.example.com.` → `com.example.foo.`). This enables lexicographic range queries for efficient deletion of exact matches without LIKE.

Removing an entry uses a prefix range query:
```sql
DELETE FROM dns_records
WHERE zone_id = $1 AND type = 'PTR'
  AND content >= $2 AND content < $3  -- $2 = "zoneName:", $3 = "zoneName:\xff"
```

This correctly distinguishes `foo.example.com.` from `foobar.example.com.`.

### Polling

The server starts a background poller when `CATALOG_POLLING_ENABLED=true`. The poller:
1. Queries CZTR (RFC 9432 Catalog Zone Transfer) to verify master support
2. Queries SOA to detect serial changes (skip if unchanged)
3. Performs AXFR on the catalog zone to fetch all PTR records
4. For each entry, calls `syncZoneFromCatalog` which:
   - Checks if zone already exists via `GetZoneByCatalogName` (O(1), not `ListZones` (O(n))
   - Creates the zone record with `catalog_zone_name` set
   - Performs AXFR on the zone to fetch all records
   - Rolls back zone creation if AXFR fails

### Tenant Isolation

All catalog operations are tenant-scoped. The `tenant_id` is propagated through the service layer to the repository with `WHERE tenant_id = $2` filters on all queries. The poller uses `CATALOG_TENANT_ID` (required env var) or falls back to `NodeID` with a warning log.

## Consequences

### Positive
- Slave servers can auto-provision zones from a master without manual configuration
- Zone metadata (name, ID, group) is published in DNS using standard record types
- Serial-based change detection avoids unnecessary re-syncs
- TTL cleanup goroutine prevents unbounded memory growth in the poller state
- Targeted `GetZoneByCatalogName` query replaces O(n) `ListZones` scan

### Negative
- New `catalog_zones` table and two new columns on `dns_zones` require schema migration
- Catalog zone itself must be provisioned as a regular zone before entries can be added
- `ON CONFLICT DO NOTHING` silently ignores duplicate entries — callers can't detect this

### Neutral
- The REST API for catalog management is separate from the DNS protocol
- The poller runs as a background goroutine; if it fails, it logs and continues (next interval)
- `PollCatalogZone` and `SyncZonesFromCatalog` service methods are stubs — actual AXFR fetch is done by the server poller in `client.go`

## Alternatives Considered

### Alternative 1: Store entries in a separate table
**Why rejected:** Using PTR records in the existing `dns_records` table keeps catalog entries in one place and leverages existing query patterns. A separate table would add complexity without significant benefit.

### Alternative 2: Use CNAME records for catalog entries
**Why rejected:** RFC 9432 specifies PTR records with the content format `zone_name:zone_id[:group_id]`. CNAME doesn't support this content format and doesn't enable the lexicographic range deletion pattern.

### Alternative 3: Include zone data in the catalog zone itself via AXFR
**Why rejected:** AXFR on a catalog zone only transfers the catalog metadata (PTR records). Individual zone data is fetched via separate AXFR requests. This is the design in RFC 9432 and keeps the catalog zone lightweight.
