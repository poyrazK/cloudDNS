# Implementation Plan: Full Incremental Zone Transfer (IXFR)

## 1. Background & Motivation
Currently, `cloudDNS` supports **AXFR** (Full Zone Transfer) for synchronizing slave zones. While functional, AXFR is inefficient for large zones with frequent, small changes, as it transfers the entire zone data every time. **IXFR** (Incremental Zone Transfer, RFC 1995) allows transferring only the differences (deltas) between versions, significantly reducing bandwidth and processing time.

## 2. Objective
Implement full IXFR support (both as a master and a slave) to optimize zone synchronization.

## 3. Scope
*   **Database Schema**: Enhance `dns_zone_changes` to track rigorous deltas (SOA pairs) for IXFR history.
*   **Repository Layer**: Implement methods to retrieve "diffs" between two serials.
*   **DNS Server (Master)**: Handle IXFR requests (Type 251) by responding with the chain of changes or falling back to AXFR if history is missing.
*   **DNS Client (Slave)**: Implement IXFR client logic to request and apply incremental updates upon NOTIFY.

## 4. Architectural Changes

### 4.1 Database Schema Enhancements
We need to ensure `dns_zone_changes` can reconstruct the exact add/delete sequence required by RFC 1995. The current schema tracks individual record changes, but IXFR requires "transactional" boundaries marked by SOA records.

**Current `dns_zone_changes`:**
```sql
CREATE TABLE IF NOT EXISTS dns_zone_changes (
    id UUID PRIMARY KEY,
    zone_id UUID REFERENCES dns_zones(id),
    serial BIGINT NOT NULL,
    action TEXT NOT NULL,   -- 'ADD' or 'DELETE'
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    content TEXT NOT NULL,
    -- ... other fields
);
```

**Proposed Changes:**
No strict schema migration is *required* if we enforce a convention: every atomic update (transaction) must record the **Old SOA (DELETE)** and **New SOA (ADD)** along with the changed records. The `serial` column in `dns_zone_changes` represents the *resulting* serial of that transaction.

### 4.2 Repository Layer
New methods needed in `PostgresRepository`:

*   `GetIXFRChain(ctx context.Context, zoneID string, clientSerial uint32, currentSerial uint32) ([]domain.IXFRChunk, error)`
    *   Retrieves the sequence of changes from `clientSerial` to `currentSerial`.
    *   Returns an ordered list of "chunks" (Delete List + Add List) wrapped in SOA records.

### 4.3 DNS Server (Master Side)
Update `handleIXFR` in `server.go`:
1.  Check if `clientSerial` is known in the history.
2.  If known, fetch the chain of changes.
3.  Construct the IXFR response packet:
    *   `Header`: SOA (Current)
    *   `Body`: [SOA(Old), DeletedRecords..., SOA(New), AddedRecords...] * N
    *   `Footer`: SOA (Current)
4.  If `clientSerial` is too old or unknown (gap in history), **fallback to AXFR**.

### 4.4 DNS Client (Slave Side)
Update `refreshZone` in `client.go`:
1.  Attempt `performIXFR` first.
2.  Send IXFR query with `Current Serial` in Authority section.
3.  Parse response:
    *   If single SOA => Up to date.
    *   If full zone (AXFR style) => Replace local zone.
    *   If incremental chunks => Apply `DELETE`s and `ADD`s transactionally to the local database.

## 5. Detailed Steps

### Phase 1: Database & Repository (Foundation)
1.  **Refine `RecordZoneChange`**: Ensure that every high-level "Update Zone" operation logs the *entire* changeset, including the SOA rotation, with the same `created_at` timestamp or a transaction ID.
2.  **Implement `GetIXFRChain`**: Write the SQL query to fetch changes grouped by serial.
    *   *Challenge*: Constructing the proper RFC 1995 packet structure from rows.

### Phase 2: Server-Side (Master)
1.  **Modify `handleIXFR`**:
    *   Currently, it might just return "Up to date" or "Fallback".
    *   Wire up `GetIXFRChain`.
    *   Logic to assemble the complex response packet (multiple chunks).
2.  **UDP vs TCP**: IXFR responses can be large. Ensure TCP fallback is handled correctly if it doesn't fit in UDP.

### Phase 3: Client-Side (Slave)
1.  **Implement `performIXFR`**:
    *   Construct IXFR query.
    *   Handle the TCP connection state machine.
    *   Distinguish between a "fallback AXFR" response (where the server says "I don't have that history, here is everything") and a true IXFR response.
2.  **Transactional Apply**: The slave must apply changes atomically. If the connection drops halfway, the zone must not be corrupted.

## 6. Verification Plan
1.  **Unit Tests**:
    *   Test `GetIXFRChain` with various gaps in history.
    *   Test packet construction for multi-chunk IXFR.
2.  **Integration Test**:
    *   Setup Master and Slave.
    *   Make a change on Master (Serial 1 -> 2).
    *   Verify Slave requests IXFR and receives only the delta.
    *   Make multiple changes (2 -> 3 -> 4).
    *   Simulate Slave being offline, then coming back. Verify it fetches 2->3 and 3->4 (or a condensed 2->4).
    *   Simulate "history expiration" (Slave has Serial 1, Master has 100, history only goes back to 50). Verify fallback to AXFR.

## 7. Migration & Rollback
*   **Migration**: Non-breaking. Old slaves will continue to use AXFR. New slaves will attempt IXFR.
*   **Rollback**: If IXFR logic is buggy, feature flag `ENABLE_IXFR=false` can force fallback to AXFR everywhere.
