package repository

import (
	"context"
	"database/sql"
	"fmt"
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
	query := `SELECT id, zone_id, name, type, content, ttl, priority, network FROM dns_records 
	          WHERE name = $1 AND (network IS NULL OR $2::inet <<= network)`
	
	var rows *sql.Rows
	var err error

	if qType != "" {
		query += " AND type = $3"
		rows, err = r.db.QueryContext(ctx, query, name, clientIP, string(qType))
	} else {
		rows, err = r.db.QueryContext(ctx, query, name, clientIP)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []domain.Record
	for rows.Next() {
		var rec domain.Record
		var priority sql.NullInt32
		if err := rows.Scan(&rec.ID, &rec.ZoneID, &rec.Name, &rec.Type, &rec.Content, &rec.TTL, &priority, &rec.Network); err != nil {
			return nil, err
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
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 1. Insert Zone
	zoneQuery := `INSERT INTO dns_zones (id, tenant_id, name, vpc_id, description, created_at, updated_at) 
			      VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err = tx.ExecContext(ctx, zoneQuery, zone.ID, zone.TenantID, zone.Name, zone.VPCID, zone.Description, zone.CreatedAt, zone.UpdatedAt)
	if err != nil {
		return err
	}

	// 2. Insert Records
	recordQuery := `INSERT INTO dns_records (id, zone_id, name, type, content, ttl, priority, created_at, updated_at) 
			        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	for _, rec := range records {
		_, err = tx.ExecContext(ctx, recordQuery, rec.ID, rec.ZoneID, rec.Name, rec.Type, rec.Content, rec.TTL, rec.Priority, rec.CreatedAt, rec.UpdatedAt)
		if err != nil {
			return err
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
	query := `SELECT id, tenant_id, name, vpc_id, description, created_at, updated_at FROM dns_zones WHERE tenant_id = $1`
	rows, err := r.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var zones []domain.Zone
	for rows.Next() {
		var z domain.Zone
		if err := rows.Scan(&z.ID, &z.TenantID, &z.Name, &z.VPCID, &z.Description, &z.CreatedAt, &z.UpdatedAt); err != nil {
			return nil, err
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

func (r *PostgresRepository) SaveAuditLog(ctx context.Context, log *domain.AuditLog) error {
	query := `INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id, details, created_at) 
			  VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := r.db.ExecContext(ctx, query, log.ID, log.TenantID, log.Action, log.ResourceType, log.ResourceID, log.Details, log.CreatedAt)
	return err
}

func (r *PostgresRepository) GetAuditLogs(ctx context.Context, tenantID string) ([]domain.AuditLog, error) {
	query := `SELECT id, tenant_id, action, resource_type, resource_id, details, created_at FROM audit_logs WHERE tenant_id = $1 ORDER BY created_at DESC`
	rows, err := r.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []domain.AuditLog
	for rows.Next() {
		var l domain.AuditLog
		if err := rows.Scan(&l.ID, &l.TenantID, &l.Action, &l.ResourceType, &l.ResourceID, &l.Details, &l.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, nil
}

func (r *PostgresRepository) Ping(ctx context.Context) error {
	return r.db.PingContext(ctx)
}

// ConvertDomainToPacketRecord is a helper to bridge domain model and wire format
func ConvertDomainToPacketRecord(rec domain.Record) (packet.DnsRecord, error) {
	pRec := packet.DnsRecord{
		Name: rec.Name,
		TTL:  uint32(rec.TTL),
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
	case domain.TypeNS:
		pRec.Type = packet.NS
		pRec.Host = rec.Content
	case domain.TypeTXT:
		pRec.Type = packet.TXT
		pRec.Txt = rec.Content
	case domain.TypeSOA:
		pRec.Type = packet.SOA
		// SOA content is usually stored as a space-separated string in the DB
		// "ns1.example.com. admin.example.com. 2023101001 3600 600 1209600 3600"
		parts := strings.Fields(rec.Content)
		if len(parts) >= 7 {
			pRec.MName = parts[0]
			pRec.RName = parts[1]
			fmt.Sscanf(parts[2], "%d", &pRec.Serial)
			fmt.Sscanf(parts[3], "%d", &pRec.Refresh)
			fmt.Sscanf(parts[4], "%d", &pRec.Retry)
			fmt.Sscanf(parts[5], "%d", &pRec.Expire)
			fmt.Sscanf(parts[6], "%d", &pRec.Minimum)
		}
	default:
		return pRec, fmt.Errorf("unsupported record type: %s", rec.Type)
	}

	return pRec, nil
}
