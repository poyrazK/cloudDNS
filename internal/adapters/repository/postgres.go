package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"strings"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

type PostgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

func (r *PostgresRepository) GetRecords(ctx context.Context, name string, qType domain.RecordType, clientIP string) ([]domain.Record, error) {
	// For Split-Horizon, we query records where:
	// 1. The name and type match.
	// 2. The clientIP is within the record's network CIDR OR the network is NULL (global).
	// In Postgres, '$2::inet <<= network' checks if the network CIDR contains the client IP.
	// RFC 1034: Domain name comparisons must be case-insensitive.
	query := `SELECT id, zone_id, name, type, content, ttl, priority, network FROM dns_records 
	          WHERE LOWER(name) = LOWER($1) AND (network IS NULL OR $2::inet <<= network)`
	
	var rows *sql.Rows
	var errQuery error

	if qType != "" {
		query += " AND type = $3"
		rows, errQuery = r.db.QueryContext(ctx, query, name, clientIP, string(qType))
	} else {
		rows, errQuery = r.db.QueryContext(ctx, query, name, clientIP)
	}

	if errQuery != nil {
		return nil, errQuery
	}
	defer func() { if errClose := rows.Close(); errClose != nil { log.Printf("failed to close rows: %v", errClose) } }()

	var records []domain.Record
	for rows.Next() {
		var rec domain.Record
		var priority sql.NullInt32
		if errScan := rows.Scan(&rec.ID, &rec.ZoneID, &rec.Name, &rec.Type, &rec.Content, &rec.TTL, &priority, &rec.Network); errScan != nil {
			return nil, errScan
		}
		if priority.Valid {
			p := int(priority.Int32)
			rec.Priority = &p
		}
		records = append(records, rec)
	}

	return records, nil
}

func (r *PostgresRepository) GetIPsForName(ctx context.Context, name string, clientIP string) ([]string, error) {
	// Optimized query returning only content for Type A
	query := `SELECT content FROM dns_records 
	          WHERE LOWER(name) = LOWER($1) AND type = 'A' AND (network IS NULL OR $2::inet <<= network)`
	
	rows, errQuery := r.db.QueryContext(ctx, query, name, clientIP)
	if errQuery != nil {
		return nil, errQuery
	}
	defer func() { if errClose := rows.Close(); errClose != nil { log.Printf("failed to close rows: %v", errClose) } }()

	var ips []string
	for rows.Next() {
		var ip string
		if errScan := rows.Scan(&ip); errScan != nil {
			return nil, errScan
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func (r *PostgresRepository) GetZone(ctx context.Context, name string) (*domain.Zone, error) {
	query := `SELECT id, tenant_id, name, vpc_id, description, created_at, updated_at FROM dns_zones WHERE LOWER(name) = LOWER($1)`
	var z domain.Zone
	errRow := r.db.QueryRowContext(ctx, query, name).Scan(&z.ID, &z.TenantID, &z.Name, &z.VPCID, &z.Description, &z.CreatedAt, &z.UpdatedAt)
	if errors.Is(errRow, sql.ErrNoRows) {
		return nil, nil
	}
	if errRow != nil {
		return nil, errRow
	}
	return &z, nil
}

func (r *PostgresRepository) ListRecordsForZone(ctx context.Context, zoneID string) ([]domain.Record, error) {
	query := `SELECT id, zone_id, name, type, content, ttl, priority, network FROM dns_records WHERE zone_id = $1`
	rows, errQuery := r.db.QueryContext(ctx, query, zoneID)
	if errQuery != nil {
		return nil, errQuery
	}
	defer func() { if errClose := rows.Close(); errClose != nil { log.Printf("failed to close rows: %v", errClose) } }()

	var records []domain.Record
	for rows.Next() {
		var rec domain.Record
		var priority sql.NullInt32
		if errScan := rows.Scan(&rec.ID, &rec.ZoneID, &rec.Name, &rec.Type, &rec.Content, &rec.TTL, &priority, &rec.Network); errScan != nil {
			return nil, errScan
		}
		if priority.Valid {
			p := int(priority.Int32)
			rec.Priority = &p
		}
		records = append(records, rec)
	}
	return records, nil
}

func (r *PostgresRepository) CreateZone(ctx context.Context, zone *domain.Zone) error {
	query := `INSERT INTO dns_zones (id, tenant_id, name, vpc_id, description, created_at, updated_at) 
			  VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := r.db.ExecContext(ctx, query, zone.ID, zone.TenantID, zone.Name, zone.VPCID, zone.Description, zone.CreatedAt, zone.UpdatedAt)
	return err
}

func (r *PostgresRepository) CreateZoneWithRecords(ctx context.Context, zone *domain.Zone, records []domain.Record) error {
	tx, errTx := r.db.BeginTx(ctx, nil)
	if errTx != nil {
		return errTx
	}
	defer func() {
		if errRollback := tx.Rollback(); errRollback != nil && !errors.Is(errRollback, sql.ErrTxDone) {
			log.Printf("failed to rollback transaction: %v", errRollback)
		}
	}()

	// 1. Insert Zone
	zoneQuery := `INSERT INTO dns_zones (id, tenant_id, name, vpc_id, description, created_at, updated_at) 
			      VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, errExec := tx.ExecContext(ctx, zoneQuery, zone.ID, zone.TenantID, zone.Name, zone.VPCID, zone.Description, zone.CreatedAt, zone.UpdatedAt)
	if errExec != nil {
		return errExec
	}

	// 2. Insert Records
	recordQuery := `INSERT INTO dns_records (id, zone_id, name, type, content, ttl, priority, created_at, updated_at) 
			        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	for _, rec := range records {
		_, errExecRecord := tx.ExecContext(ctx, recordQuery, rec.ID, rec.ZoneID, rec.Name, rec.Type, rec.Content, rec.TTL, rec.Priority, rec.CreatedAt, rec.UpdatedAt)
		if errExecRecord != nil {
			return errExecRecord
		}
	}

	return tx.Commit()
}

func (r *PostgresRepository) CreateRecord(ctx context.Context, record *domain.Record) error {
	query := `INSERT INTO dns_records (id, zone_id, name, type, content, ttl, priority, network, created_at, updated_at) 
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	_, err := r.db.ExecContext(ctx, query, record.ID, record.ZoneID, record.Name, record.Type, record.Content, record.TTL, record.Priority, record.Network, record.CreatedAt, record.UpdatedAt)
	return err
}

func (r *PostgresRepository) ListZones(ctx context.Context, tenantID string) ([]domain.Zone, error) {
	query := `SELECT id, tenant_id, name, vpc_id, description, created_at, updated_at FROM dns_zones`
	var rows *sql.Rows
	var errQuery error

	if tenantID != "" {
		query += " WHERE tenant_id = $1"
		rows, errQuery = r.db.QueryContext(ctx, query, tenantID)
	} else {
		rows, errQuery = r.db.QueryContext(ctx, query)
	}

	if errQuery != nil {
		return nil, errQuery
	}
	defer func() { if errClose := rows.Close(); errClose != nil { log.Printf("failed to close rows: %v", errClose) } }()

	var zones []domain.Zone
	for rows.Next() {
		var z domain.Zone
		if errScan := rows.Scan(&z.ID, &z.TenantID, &z.Name, &z.VPCID, &z.Description, &z.CreatedAt, &z.UpdatedAt); errScan != nil {
			return nil, errScan
		}
		zones = append(zones, z)
	}
	return zones, nil
}

func (r *PostgresRepository) DeleteZone(ctx context.Context, zoneID string, tenantID string) error {
	query := `DELETE FROM dns_zones WHERE id = $1 AND tenant_id = $2`
	_, err := r.db.ExecContext(ctx, query, zoneID, tenantID)
	return err
}

func (r *PostgresRepository) DeleteRecord(ctx context.Context, recordID string, zoneID string) error {
	query := `DELETE FROM dns_records WHERE id = $1 AND zone_id = $2`
	_, err := r.db.ExecContext(ctx, query, recordID, zoneID)
	return err
}

func (r *PostgresRepository) DeleteRecordsByNameAndType(ctx context.Context, zoneID string, name string, qType domain.RecordType) error {
	query := `DELETE FROM dns_records WHERE zone_id = $1 AND LOWER(name) = LOWER($2) AND type = $3`
	_, err := r.db.ExecContext(ctx, query, zoneID, name, string(qType))
	return err
}

func (r *PostgresRepository) DeleteRecordsByName(ctx context.Context, zoneID string, name string) error {
	query := `DELETE FROM dns_records WHERE zone_id = $1 AND LOWER(name) = LOWER($2)`
	_, err := r.db.ExecContext(ctx, query, zoneID, name)
	return err
}

func (r *PostgresRepository) DeleteRecordSpecific(ctx context.Context, zoneID string, name string, qType domain.RecordType, content string) error {
	query := `DELETE FROM dns_records WHERE zone_id = $1 AND LOWER(name) = LOWER($2) AND type = $3 AND content = $4`
	_, err := r.db.ExecContext(ctx, query, zoneID, name, string(qType), content)
	return err
}

func (r *PostgresRepository) RecordZoneChange(ctx context.Context, change *domain.ZoneChange) error {
	query := `INSERT INTO dns_zone_changes (id, zone_id, serial, action, name, type, content, ttl, priority, created_at) 
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	_, err := r.db.ExecContext(ctx, query, change.ID, change.ZoneID, change.Serial, change.Action, change.Name, string(change.Type), change.Content, change.TTL, change.Priority, change.CreatedAt)
	return err
}

func (r *PostgresRepository) ListZoneChanges(ctx context.Context, zoneID string, fromSerial uint32) ([]domain.ZoneChange, error) {
	query := `SELECT id, zone_id, serial, action, name, type, content, ttl, priority, created_at 
	          FROM dns_zone_changes WHERE zone_id = $1 AND serial > $2 ORDER BY serial ASC, created_at ASC`
	rows, errQuery := r.db.QueryContext(ctx, query, zoneID, fromSerial)
	if errQuery != nil {
		return nil, errQuery
	}
	defer func() { if errClose := rows.Close(); errClose != nil { log.Printf("failed to close rows: %v", errClose) } }()

	var changes []domain.ZoneChange
	for rows.Next() {
		var c domain.ZoneChange
		var priority sql.NullInt32
		if errScan := rows.Scan(&c.ID, &c.ZoneID, &c.Serial, &c.Action, &c.Name, &c.Type, &c.Content, &c.TTL, &priority, &c.CreatedAt); errScan != nil {
			return nil, errScan
		}
		if priority.Valid {
			p := int(priority.Int32)
			c.Priority = &p
		}
		changes = append(changes, c)
	}
	return changes, nil
}

func (r *PostgresRepository) SaveAuditLog(ctx context.Context, log *domain.AuditLog) error {
	query := `INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id, details, created_at) 
			  VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := r.db.ExecContext(ctx, query, log.ID, log.TenantID, log.Action, log.ResourceType, log.ResourceID, log.Details, log.CreatedAt)
	return err
}

func (r *PostgresRepository) GetAuditLogs(ctx context.Context, tenantID string) ([]domain.AuditLog, error) {
	query := `SELECT id, tenant_id, action, resource_type, resource_id, details, created_at FROM audit_logs WHERE tenant_id = $1 ORDER BY created_at DESC`
	rows, errQuery := r.db.QueryContext(ctx, query, tenantID)
	if errQuery != nil {
		return nil, errQuery
	}
	defer func() { if errClose := rows.Close(); errClose != nil { log.Printf("failed to close rows: %v", errClose) } }()

	var logs []domain.AuditLog
	for rows.Next() {
		var l domain.AuditLog
		if errScan := rows.Scan(&l.ID, &l.TenantID, &l.Action, &l.ResourceType, &l.ResourceID, &l.Details, &l.CreatedAt); errScan != nil {
			return nil, errScan
		}
		logs = append(logs, l)
	}
	return logs, nil
}

func (r *PostgresRepository) Ping(ctx context.Context) error {
	return r.db.PingContext(ctx)
}

func (r *PostgresRepository) CreateKey(ctx context.Context, key *domain.DNSSECKey) error {
	query := `INSERT INTO dnssec_keys (id, zone_id, key_type, algorithm, private_key, public_key, active, created_at, updated_at) 
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := r.db.ExecContext(ctx, query, key.ID, key.ZoneID, key.KeyType, key.Algorithm, key.PrivateKey, key.PublicKey, key.Active, key.CreatedAt, key.UpdatedAt)
	return err
}

func (r *PostgresRepository) ListKeysForZone(ctx context.Context, zoneID string) ([]domain.DNSSECKey, error) {
	query := `SELECT id, zone_id, key_type, algorithm, private_key, public_key, active, created_at, updated_at FROM dnssec_keys WHERE zone_id = $1`
	rows, errQuery := r.db.QueryContext(ctx, query, zoneID)
	if errQuery != nil {
		return nil, errQuery
	}
	defer func() { if errClose := rows.Close(); errClose != nil { log.Printf("failed to close rows: %v", errClose) } }()

	var keys []domain.DNSSECKey
	for rows.Next() {
		var k domain.DNSSECKey
		if errScan := rows.Scan(&k.ID, &k.ZoneID, &k.KeyType, &k.Algorithm, &k.PrivateKey, &k.PublicKey, &k.Active, &k.CreatedAt, &k.UpdatedAt); errScan != nil {
			return nil, errScan
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func (r *PostgresRepository) UpdateKey(ctx context.Context, key *domain.DNSSECKey) error {
	query := `UPDATE dnssec_keys SET active = $1, updated_at = $2 WHERE id = $3`
	_, err := r.db.ExecContext(ctx, query, key.Active, key.UpdatedAt, key.ID)
	return err
}

// ConvertPacketRecordToDomain is a helper to bridge wire format and domain model
func ConvertPacketRecordToDomain(pRec packet.DNSRecord, zoneID string) (domain.Record, error) {
	rec := domain.Record{
		ZoneID: zoneID,
		Name:   pRec.Name,
		TTL:    int(pRec.TTL),
	}

	switch pRec.Type {
	case packet.A, packet.AAAA:
		rec.Type = domain.RecordType(pRec.Type.String()) // assuming QueryType has String() or I use mapping
		rec.Content = pRec.IP.String()
	case packet.CNAME, packet.NS, packet.PTR:
		rec.Type = domain.RecordType(pRec.Type.String())
		rec.Content = pRec.Host
	case packet.MX:
		rec.Type = domain.TypeMX
		p := int(pRec.Priority)
		rec.Priority = &p
		rec.Content = pRec.Host
	case packet.TXT:
		rec.Type = domain.TypeTXT
		rec.Content = pRec.Txt
	case packet.SOA:
		rec.Type = domain.TypeSOA
		rec.Content = fmt.Sprintf("%s %s %d %d %d %d %d", 
			pRec.MName, pRec.RName, pRec.Serial, pRec.Refresh, pRec.Retry, pRec.Expire, pRec.Minimum)
	default:
		return rec, fmt.Errorf("unsupported record type for conversion: %d", pRec.Type)
	}

	// Manual mapping if String() is not what we want
	switch pRec.Type {
	case packet.A: rec.Type = domain.TypeA
	case packet.AAAA: rec.Type = domain.TypeAAAA
	case packet.CNAME: rec.Type = domain.TypeCNAME
	case packet.NS: rec.Type = domain.TypeNS
	case packet.PTR: rec.Type = domain.TypePTR
	}

	return rec, nil
}

// ConvertDomainToPacketRecord is a helper to bridge domain model and wire format
func ConvertDomainToPacketRecord(rec domain.Record) (packet.DNSRecord, error) {
	name := rec.Name
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	ttl := uint32(0)
	if rec.TTL > 0 {
		if rec.TTL >= 0 && int64(rec.TTL) <= math.MaxUint32 {
			ttl = uint32(rec.TTL) // #nosec G115
		}
	}

	pRec := packet.DNSRecord{
		Name:  name,
		TTL:   ttl,
		Class: 1, // IN
	}

	switch rec.Type {
	case domain.TypeA:
		pRec.Type = packet.A
		pRec.IP = net.ParseIP(rec.Content)
	case domain.TypeAAAA:
		pRec.Type = packet.AAAA
		pRec.IP = net.ParseIP(rec.Content)
	case domain.TypeCNAME:
		pRec.Type = packet.CNAME
		pRec.Host = rec.Content
		if !strings.HasSuffix(pRec.Host, ".") {
			pRec.Host += "."
		}
	case domain.TypeNS:
		pRec.Type = packet.NS
		pRec.Host = rec.Content
		if !strings.HasSuffix(pRec.Host, ".") {
			pRec.Host += "."
		}
	case domain.TypeMX:
		pRec.Type = packet.MX
		if rec.Priority != nil {
			prio := uint16(0)
			if *rec.Priority > 0 {
				if *rec.Priority > 65535 {
					prio = 65535
				} else {
					prio = uint16(*rec.Priority)
				}
			}
			pRec.Priority = prio
		}
		pRec.Host = rec.Content
		if !strings.HasSuffix(pRec.Host, ".") {
			pRec.Host += "."
		}
	case domain.TypeTXT:
		pRec.Type = packet.TXT
		pRec.Txt = rec.Content
	case domain.TypePTR:
		pRec.Type = packet.PTR
		pRec.Host = rec.Content
		if !strings.HasSuffix(pRec.Host, ".") {
			pRec.Host += "."
		}
	case domain.TypeSOA:
		pRec.Type = packet.SOA
		// SOA content: "mname rname serial refresh retry expire minimum"
		parts := strings.Fields(rec.Content)
		if len(parts) >= 7 {
			pRec.MName = parts[0]
			if !strings.HasSuffix(pRec.MName, ".") { pRec.MName += "." }
			pRec.RName = parts[1]
			if !strings.HasSuffix(pRec.RName, ".") { pRec.RName += "." }
			if _, err := fmt.Sscanf(parts[2], "%d", &pRec.Serial); err != nil {
				return pRec, fmt.Errorf("failed to parse SOA serial: %w", err)
			}
			if _, err := fmt.Sscanf(parts[3], "%d", &pRec.Refresh); err != nil {
				return pRec, fmt.Errorf("failed to parse SOA refresh: %w", err)
			}
			if _, err := fmt.Sscanf(parts[4], "%d", &pRec.Retry); err != nil {
				return pRec, fmt.Errorf("failed to parse SOA retry: %w", err)
			}
			if _, err := fmt.Sscanf(parts[5], "%d", &pRec.Expire); err != nil {
				return pRec, fmt.Errorf("failed to parse SOA expire: %w", err)
			}
			if _, err := fmt.Sscanf(parts[6], "%d", &pRec.Minimum); err != nil {
				return pRec, fmt.Errorf("failed to parse SOA minimum: %w", err)
			}
		}
	default:
		return pRec, fmt.Errorf("unsupported record type: %s", rec.Type)
	}

	return pRec, nil
}
