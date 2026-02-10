package repository

import (
	"context"
	"database/sql"
	"fmt"
	"net"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

type PostgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

func (r *PostgresRepository) GetRecords(ctx context.Context, name string, qType domain.RecordType) ([]domain.Record, error) {
	query := `SELECT id, zone_id, name, type, content, ttl, priority FROM dns_records WHERE name = $1`
	
	var rows *sql.Rows
	var err error

	if qType != "" {
		query += " AND type = $2"
		rows, err = r.db.QueryContext(ctx, query, name, string(qType))
	} else {
		rows, err = r.db.QueryContext(ctx, query, name)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []domain.Record
	for rows.Next() {
		var rec domain.Record
		var priority sql.NullInt32
		if err := rows.Scan(&rec.ID, &rec.ZoneID, &rec.Name, &rec.Type, &rec.Content, &rec.TTL, &priority); err != nil {
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
	default:
		return pRec, fmt.Errorf("unsupported record type: %s", rec.Type)
	}

	return pRec, nil
}
