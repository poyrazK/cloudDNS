package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
	"github.com/stretchr/testify/assert"
)

type mockRecordIterator struct {
	records []domain.Record
	index   int
}

func (it *mockRecordIterator) Next() bool {
	if it.index >= len(it.records) {
		return false
	}
	it.index++
	return true
}

func (it *mockRecordIterator) Record() domain.Record {
	return it.records[it.index-1]
}

func (it *mockRecordIterator) Err() error {
	return nil
}

func (it *mockRecordIterator) Close() error {
	return nil
}

type mockServerRepo struct {
	mu      sync.RWMutex
	records []domain.Record
	zones   []domain.Zone
	changes []domain.ZoneChange
	keys    []domain.DNSSECKey
	apiKeys []domain.APIKey
	pingErr error

	failListZones        bool
	failCreateKey        bool
	failListRecords      bool
	failListRecordsStreaming bool
	failCreateRecord     bool
	failDeleteRecord     bool
	failRecordZoneChange bool
	failGetZone          bool
	failGetRecords       bool
	failCreateSOA        bool
	failDeleteSOA        bool
	failOnRecordName     string

	// mockGetIXFRChain overrides GetIXFRChain when set.
	mockGetIXFRChain func(ctx context.Context, zoneID string, fromSerial uint32, toSerial uint32) ([]domain.IXFRChunk, error)

	// mockListRecordsForZoneStreaming overrides ListRecordsForZoneStreaming when set.
	mockListRecordsForZoneStreaming func(ctx context.Context, zoneID string, tenantID string) (ports.RecordIterator, error)
}

func (m *mockServerRepo) GetAPIKeyByHash(_ context.Context, keyHash string) (*domain.APIKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, k := range m.apiKeys {
		if k.KeyHash == keyHash {
			return &k, nil
		}
	}
	return nil, nil
}

func (m *mockServerRepo) CreateAPIKey(_ context.Context, key *domain.APIKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.apiKeys = append(m.apiKeys, *key)
	return nil
}

func (m *mockServerRepo) ListAPIKeys(_ context.Context, tenantID string) ([]domain.APIKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []domain.APIKey
	for _, k := range m.apiKeys {
		if tenantID == "" || k.TenantID == tenantID {
			res = append(res, k)
		}
	}
	return res, nil
}

func (m *mockServerRepo) DeleteAPIKey(_ context.Context, _ string, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var next []domain.APIKey
	for _, k := range m.apiKeys {
		if k.ID == id {
			continue
		}
		next = append(next, k)
	}
	m.apiKeys = next
	return nil
}

func (m *mockServerRepo) GetRecords(_ context.Context, name string, qType domain.RecordType, clientIP string) ([]domain.Record, error) {
	if m.failGetRecords {
		return nil, errors.New("get records failed")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []domain.Record
	qName := strings.TrimSuffix(strings.ToLower(name), ".")
	for _, r := range m.records {
		rName := strings.TrimSuffix(strings.ToLower(r.Name), ".")
		if rName == qName && (qType == "" || strings.EqualFold(string(r.Type), string(qType))) {
			res = append(res, r)
		}
	}
	return res, nil
}

func (m *mockServerRepo) GetRecordsByNames(_ context.Context, names []string, qType domain.RecordType, clientIP string) (map[string][]domain.Record, error) {
	if m.failGetRecords {
		return nil, errors.New("get records failed")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string][]domain.Record)
	for _, name := range names {
		qName := strings.TrimSuffix(strings.ToLower(name), ".")
		for _, r := range m.records {
			rName := strings.TrimSuffix(strings.ToLower(r.Name), ".")
			if rName == qName && (qType == "" || strings.EqualFold(string(r.Type), string(qType))) {
				result[name] = append(result[name], r)
			}
		}
	}
	return result, nil
}

func (m *mockServerRepo) GetIPsForName(_ context.Context, name string, clientIP string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []string
	qName := strings.TrimSuffix(strings.ToLower(name), ".")
	for _, r := range m.records {
		rName := strings.TrimSuffix(strings.ToLower(r.Name), ".")
		if rName == qName && r.Type == domain.TypeA {
			res = append(res, r.Content)
		}
	}
	return res, nil
}

func (m *mockServerRepo) GetZone(_ context.Context, name string) (*domain.Zone, error) {
	if m.failGetZone {
		return nil, errors.New("get zone failed")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	qName := strings.TrimSuffix(strings.ToLower(name), ".")
	for _, z := range m.zones {
		zName := strings.TrimSuffix(strings.ToLower(z.Name), ".")
		if zName == qName {
			return &z, nil
		}
	}
	return nil, nil
}

func (m *mockServerRepo) GetZoneLongestMatch(_ context.Context, qName string) (*domain.Zone, error) {
	if m.failGetZone {
		return nil, errors.New("get zone failed")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Find longest matching zone
	qNameClean := strings.TrimSuffix(strings.ToLower(qName), ".")
	var bestMatch *domain.Zone
	bestLen := 0
	for _, z := range m.zones {
		zName := strings.TrimSuffix(strings.ToLower(z.Name), ".")
		if len(zName) > bestLen && strings.HasSuffix(qNameClean, "."+zName) {
			bestMatch = &z
			bestLen = len(zName)
		}
	}
	return bestMatch, nil
}

func (m *mockServerRepo) GetRecord(ctx context.Context, id string, zoneID string, tenantID string) (*domain.Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, r := range m.records {
		if r.ID == id && r.ZoneID == zoneID && (tenantID == "" || r.TenantID == tenantID) {
			return &r, nil
		}
	}
	return nil, nil
}

func (m *mockServerRepo) ListRecordsForZone(ctx context.Context, zoneID string, tenantID string) ([]domain.Record, error) {
	if m.failListRecords {
		return nil, errors.New("list records failed")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []domain.Record
	for _, r := range m.records {
		if r.ZoneID == zoneID && (tenantID == "" || r.TenantID == tenantID) {
			res = append(res, r)
		}
	}
	return res, nil
}

func (m *mockServerRepo) ListRecordsForZoneStreaming(ctx context.Context, zoneID string, tenantID string) (ports.RecordIterator, error) {
	if m.mockListRecordsForZoneStreaming != nil {
		return m.mockListRecordsForZoneStreaming(ctx, zoneID, tenantID)
	}
	if m.failListRecordsStreaming {
		return nil, errors.New("list records streaming failed")
	}
	records, err := m.ListRecordsForZone(ctx, zoneID, tenantID)
	if err != nil {
		return nil, err
	}
	return &sliceRecordIterator{records: records, index: 0}, nil
}

type sliceRecordIterator struct {
	records []domain.Record
	index   int
}

func (it *sliceRecordIterator) Next() bool {
	if it.index >= len(it.records) {
		return false
	}
	it.index++
	return true
}

func (it *sliceRecordIterator) Err() error {
	return nil
}

func (it *sliceRecordIterator) Record() domain.Record {
	if it.index < 1 || it.index > len(it.records) {
		return domain.Record{}
	}
	return it.records[it.index-1]
}

func (it *sliceRecordIterator) Close() error {
	return nil
}

func (m *mockServerRepo) CreateZone(ctx context.Context, zone *domain.Zone) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.zones = append(m.zones, *zone)
	return nil
}

func (m *mockServerRepo) CreateZoneWithRecords(ctx context.Context, zone *domain.Zone, records []domain.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.zones = append(m.zones, *zone)
	m.records = append(m.records, records...)
	return nil
}

func (m *mockServerRepo) UpdateRecordHealth(ctx context.Context, recordID string, status domain.HealthStatus, errMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, r := range m.records {
		if r.ID == recordID {
			m.records[i].HealthStatus = status
			return nil
		}
	}
	return nil
}

func (m *mockServerRepo) UpdateRecord(ctx context.Context, record *domain.Record) error {
	return nil
}

func (m *mockServerRepo) GetRecordsToProbe(ctx context.Context) ([]domain.Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []domain.Record
	for _, r := range m.records {
		if r.HealthCheckType != domain.HealthCheckNone {
			res = append(res, r)
		}
	}
	return res, nil
}

func (m *mockServerRepo) GetRecordsToProbeStreaming(ctx context.Context) (ports.RecordIterator, error) {
	return &mockRecordIterator{records: m.records}, nil
}

func (m *mockServerRepo) CreateRecord(ctx context.Context, record *domain.Record) error {
	if m.failCreateRecord || (m.failCreateSOA && record.Type == domain.TypeSOA) || (m.failOnRecordName != "" && record.Name == m.failOnRecordName) {
		return errors.New("create record failed")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if record.Type == domain.TypeSOA {
		// Replace existing SOA for the zone
		var next []domain.Record
		for _, r := range m.records {
			if r.ZoneID == record.ZoneID && r.Type == domain.TypeSOA {
				continue
			}
			next = append(next, r)
		}
		m.records = next
	}
	m.records = append(m.records, *record)
	return nil
}

func (m *mockServerRepo) BatchCreateRecords(ctx context.Context, records []domain.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, records...)
	return nil
}

func (m *mockServerRepo) ListZones(ctx context.Context, tenantID string) ([]domain.Zone, error) {
	if m.failListZones {
		return nil, errors.New("list zones failed")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []domain.Zone
	for _, z := range m.zones {
		if tenantID == "" || z.TenantID == tenantID {
			res = append(res, z)
		}
	}
	return res, nil
}
func (m *mockServerRepo) DeleteZone(ctx context.Context, zoneID string, tenantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. Delete Zone
	var nextZones []domain.Zone
	for _, z := range m.zones {
		if z.ID == zoneID && z.TenantID == tenantID {
			continue
		}
		nextZones = append(nextZones, z)
	}
	m.zones = nextZones

	// 2. Delete associated Records
	var nextRecords []domain.Record
	for _, r := range m.records {
		if r.ZoneID == zoneID && r.TenantID == tenantID {
			continue
		}
		nextRecords = append(nextRecords, r)
	}
	m.records = nextRecords

	return nil
}
func (m *mockServerRepo) DeleteRecord(ctx context.Context, recordID string, zoneID string, tenantID string) error {
	if m.failDeleteRecord {
		return errors.New("delete record failed")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var next []domain.Record
	for _, r := range m.records {
		if r.ID == recordID && r.ZoneID == zoneID && r.TenantID == tenantID {
			continue
		}
		next = append(next, r)
	}
	m.records = next
	return nil
}

func (m *mockServerRepo) DeleteRecordSpecific(ctx context.Context, zoneID string, name string, qType domain.RecordType, content string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// fmt.Printf("MOCK: DeleteRecordSpecific Zone=%s Name=%s Type=%s Content=%s\n", zoneID, name, qType, content)
	var next []domain.Record
	// Standardize input name
	stdName := strings.TrimSuffix(strings.ToLower(name), ".")
	for _, r := range m.records {
		// Standardize record name
		stdRName := strings.TrimSuffix(strings.ToLower(r.Name), ".")
		if r.ZoneID == zoneID && stdRName == stdName && r.Type == qType && r.Content == content {
			continue
		}
		next = append(next, r)
	}
	m.records = next
	return nil
}

func (m *mockServerRepo) DeleteRecordsByNameAndType(ctx context.Context, zoneID string, name string, qType domain.RecordType) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var next []domain.Record
	qName := strings.TrimSuffix(strings.ToLower(name), ".")
	for _, r := range m.records {
		rName := strings.TrimSuffix(strings.ToLower(r.Name), ".")
		if r.ZoneID == zoneID && rName == qName && r.Type == qType {
			continue
		}
		next = append(next, r)
	}
	m.records = next
	return nil
}

func (m *mockServerRepo) DeleteRecordsByName(ctx context.Context, zoneID string, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var next []domain.Record
	qName := strings.TrimSuffix(strings.ToLower(name), ".")
	for _, r := range m.records {
		rName := strings.TrimSuffix(strings.ToLower(r.Name), ".")
		if r.ZoneID == zoneID && rName == qName {
			continue
		}
		next = append(next, r)
	}
	m.records = next
	return nil
}

func (m *mockServerRepo) DeleteRecordsForZone(ctx context.Context, zoneID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var next []domain.Record
	for _, r := range m.records {
		if r.ZoneID == zoneID {
			continue
		}
		next = append(next, r)
	}
	m.records = next
	return nil
}

func (m *mockServerRepo) RecordZoneChange(ctx context.Context, change *domain.ZoneChange) error {
	if m.failRecordZoneChange || (m.failOnRecordName != "" && change.Name == m.failOnRecordName) {
		return errors.New("record zone change failed")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.changes = append(m.changes, *change)
	return nil
}

func (m *mockServerRepo) ApplyZoneUpdate(ctx context.Context, zoneID string, operations []domain.UpdateOperation, changes []domain.ZoneChange) (uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. Create a snapshot of current state for rollback
	oldRecords := make([]domain.Record, len(m.records))
	copy(oldRecords, m.records)
	oldChanges := make([]domain.ZoneChange, len(m.changes))
	copy(oldChanges, m.changes)

	// Simulate serial calculation like real implementation
	var newSerial uint32 = 1
	for _, r := range m.records {
		if r.ZoneID == zoneID && r.Type == domain.TypeSOA {
			parts := strings.Fields(r.Content)
			if len(parts) >= 3 {
				fmt.Sscanf(parts[2], "%d", &newSerial)
			}
		}
	}
	newSerial++

	// 2. Apply operations
	for _, op := range operations {
		switch op.Action {
		case domain.ActionAdd:
			if m.failCreateRecord || (m.failCreateSOA && op.Record.Type == domain.TypeSOA) || (m.failOnRecordName != "" && op.Record.Name == m.failOnRecordName) {
				m.records = oldRecords
				m.changes = oldChanges
				return 0, errors.New("create record failed")
			}
			m.records = append(m.records, op.Record)
		case domain.ActionDeleteRRSet:
			var next []domain.Record
			for _, r := range m.records {
				if r.ZoneID == zoneID && strings.EqualFold(r.Name, op.Record.Name) && r.Type == op.Record.Type {
					continue
				}
				next = append(next, r)
			}
			m.records = next
		case domain.ActionDeleteAll:
			var next []domain.Record
			for _, r := range m.records {
				if r.ZoneID == zoneID && strings.EqualFold(r.Name, op.Record.Name) {
					continue
				}
				next = append(next, r)
			}
			m.records = next
		case domain.ActionDeleteSpecific:
			if m.failDeleteRecord || (m.failDeleteSOA && op.Record.Type == domain.TypeSOA) {
				m.records = oldRecords
				m.changes = oldChanges
				return 0, errors.New("delete record failed")
			}
			var next []domain.Record
			for _, r := range m.records {
				if r.ZoneID == zoneID && strings.EqualFold(r.Name, op.Record.Name) && r.Type == op.Record.Type && r.Content == op.Record.Content {
					continue
				}
				next = append(next, r)
			}
			m.records = next
		}
	}

	// 3. Record historical changes
	if m.failRecordZoneChange {
		m.records = oldRecords
		m.changes = oldChanges
		return 0, errors.New("record zone change failed")
	}
	for i := range changes {
		changes[i].Serial = newSerial
		m.changes = append(m.changes, changes[i])
	}

	return newSerial, nil
}

func (m *mockServerRepo) ListZoneChanges(ctx context.Context, zoneID string, fromSerial uint32) ([]domain.ZoneChange, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []domain.ZoneChange
	for _, c := range m.changes {
		if c.ZoneID == zoneID && c.Serial > fromSerial {
			res = append(res, c)
		}
	}
	return res, nil
}

func (m *mockServerRepo) GetIXFRChain(ctx context.Context, zoneID string, fromSerial uint32, toSerial uint32) ([]domain.IXFRChunk, error) {
	if m.mockGetIXFRChain != nil {
		return m.mockGetIXFRChain(ctx, zoneID, fromSerial, toSerial)
	}
	changes, err := m.ListZoneChanges(ctx, zoneID, fromSerial)
	if err != nil {
		return nil, err
	}

	chunksMap := make(map[uint32]*domain.IXFRChunk)
	var serials []uint32

	for _, c := range changes {
		if c.Serial > toSerial {
			continue
		}
		chunk, ok := chunksMap[c.Serial]
		if !ok {
			chunk = &domain.IXFRChunk{Serial: c.Serial}
			chunksMap[c.Serial] = chunk
			serials = append(serials, c.Serial)
		}

		rec := domain.Record{
			Name:     c.Name,
			Type:     c.Type,
			Content:  c.Content,
			TTL:      c.TTL,
			Priority: c.Priority,
			Weight:   c.Weight,
			Port:     c.Port,
		}

		if c.Action == "DELETE" {
			chunk.Deleted = append(chunk.Deleted, rec)
		} else {
			chunk.Added = append(chunk.Added, rec)
		}
	}

	sort.Slice(serials, func(i, j int) bool {
		return serials[i] < serials[j]
	})

	var result []domain.IXFRChunk
	for _, s := range serials {
		result = append(result, *chunksMap[s])
	}

	return result, nil
}

func (m *mockServerRepo) SaveAuditLog(ctx context.Context, log *domain.AuditLog) error {
	return nil
}

func (m *mockServerRepo) GetAuditLogs(ctx context.Context, tenantID string) ([]domain.AuditLog, error) {
	return nil, nil
}

func (m *mockServerRepo) CreateKey(ctx context.Context, key *domain.DNSSECKey) error {
	if m.failCreateKey {
		return errors.New("create key failed")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys = append(m.keys, *key)
	return nil
}

func (m *mockServerRepo) ListKeysForZone(ctx context.Context, zoneID string) ([]domain.DNSSECKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []domain.DNSSECKey
	for _, k := range m.keys {
		if k.ZoneID == zoneID {
			res = append(res, k)
		}
	}
	return res, nil
}

func (m *mockServerRepo) UpdateKey(ctx context.Context, key *domain.DNSSECKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, k := range m.keys {
		if k.ID == key.ID {
			m.keys[i] = *key
			return nil
		}
	}
	return nil
}

func (m *mockServerRepo) GetDNSKEYs(ctx context.Context, zoneName string) ([]domain.Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []domain.Record
	for _, r := range m.records {
		if r.Name == zoneName && r.Type == "DNSKEY" {
			res = append(res, r)
		}
	}
	return res, nil
}

func (m *mockServerRepo) Ping(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.pingErr
}

func TestHandlePacketLocalHit(t *testing.T) {
	repo := &mockServerRepo{
		records: []domain.Record{
			{Name: "local.test.", Type: domain.TypeA, Content: "1.1.1.1", TTL: 60},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDNSPacket()
	req.Header.ID = 123
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "local.test.", QType: packet.A})

	buffer := packet.NewBytePacketBuffer()
	_ = req.Write(buffer)
	data := buffer.Buf[:buffer.Position()]

	var capturedResp []byte
	if err := srv.handlePacket(context.Background(),data, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}, func(resp []byte) error {
		capturedResp = resp
		return nil
	}, "udp"); err != nil {
		t.Fatalf("HandlePacket failed: %v", err)
	}

	resBuf := packet.NewBytePacketBuffer()
	resBuf.Load(capturedResp)
	resp := packet.NewDNSPacket()
	_ = resp.FromBuffer(resBuf)

	if len(resp.Answers) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(resp.Answers))
	}
	if resp.Answers[0].IP.String() != "1.1.1.1" {
		t.Errorf("Expected 1.1.1.1, got %s", resp.Answers[0].IP.String())
	}
}

func TestHandlePacketCacheHit(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{
			{ID: "zone-1", TenantID: "tenant-1", Name: "test."},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	// Pre-populate cache with tenant-aware key
	cacheKey := "tenant-1:cached.test.:1" // tenant_id:name:type (A record)
	cachedPacket := packet.NewDNSPacket()
	cachedPacket.Header.Response = true
	cachedPacket.Questions = append(cachedPacket.Questions, packet.DNSQuestion{Name: "cached.test.", QType: packet.A})
	cachedPacket.Answers = append(cachedPacket.Answers, packet.DNSRecord{
		Name: "cached.test.", Type: packet.A, IP: net.ParseIP("2.2.2.2"), TTL: 60, Class: 1,
	})
	buf := packet.NewBytePacketBuffer()
	_ = cachedPacket.Write(buf)
	srv.Cache.Set(cacheKey, buf.Buf[:buf.Position()], 60*time.Second)

	// Query
	req := packet.NewDNSPacket()
	req.Header.ID = 999
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "cached.test.", QType: packet.A})
	reqBuf := packet.NewBytePacketBuffer()
	_ = req.Write(reqBuf)

	var capturedResp []byte
	if err := srv.handlePacket(context.Background(),reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}, func(resp []byte) error {
		capturedResp = resp
		return nil
	}, "udp"); err != nil {
		t.Fatalf("handlePacket failed: %v", err)
	}

	resBuf := packet.NewBytePacketBuffer()
	resBuf.Load(capturedResp)
	resp := packet.NewDNSPacket()
	_ = resp.FromBuffer(resBuf)

	if resp.Header.ID != 999 {
		t.Errorf("Expected ID 999 (mapped from request), got %d", resp.Header.ID)
	}
	if len(resp.Answers) != 1 || resp.Answers[0].IP.String() != "2.2.2.2" {
		t.Errorf("Cache hit failed or data mismatch")
	}
}

type dummyPacketConn struct {
	net.PacketConn
}

func (d *dummyPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return len(p), nil
}

func TestWorkerPoolProcessing(t *testing.T) {
	repo := &mockServerRepo{
		records: []domain.Record{
			{Name: "worker.test.", Type: domain.TypeA, Content: "3.3.3.3", TTL: 60},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)
	srv.WorkerCount = 1

	// Start one worker
	go srv.udpWorker()

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "worker.test.", QType: packet.A})
	reqBuf := packet.NewBytePacketBuffer()
	_ = req.Write(reqBuf)

	dummy := &dummyPacketConn{}

	task := udpTask{
		addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		data: reqBuf.Buf[:reqBuf.Position()],
		conn: dummy,
	}

	srv.udpQueue <- task

	// Wait a bit for worker to pick it up
	time.Sleep(50 * time.Millisecond)

	if len(srv.udpQueue) != 0 {
		t.Errorf("Expected task to be consumed by worker")
	}
}

func TestHandlePacketNXDOMAIN(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "missing.test.", QType: packet.A})
	reqBuf := packet.NewBytePacketBuffer()
	_ = req.Write(reqBuf)

	var capturedResp []byte
	if err := srv.handlePacket(context.Background(),reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}, func(resp []byte) error {
		capturedResp = resp
		return nil
	}, "udp"); err != nil {
		t.Fatalf("handlePacket failed: %v", err)
	}

	resPacket := packet.NewDNSPacket()
	pBuf := packet.NewBytePacketBuffer()
	pBuf.Load(capturedResp)
	_ = resPacket.FromBuffer(pBuf)

	if resPacket.Header.ResCode != 3 {
		t.Errorf("Expected NXDOMAIN (3), got %d", resPacket.Header.ResCode)
	}
}

func TestHandlePacketNoQuestions(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDNSPacket()
	reqBuf := packet.NewBytePacketBuffer()
	_ = req.Write(reqBuf)

	var capturedResp []byte
	if err := srv.handlePacket(context.Background(),reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}, func(resp []byte) error {
		capturedResp = resp
		return nil
	}, "udp"); err != nil {
		t.Fatalf("handlePacket failed: %v", err)
	}

	resPacket := packet.NewDNSPacket()
	pBuf := packet.NewBytePacketBuffer()
	pBuf.Load(capturedResp)
	_ = resPacket.FromBuffer(pBuf)

	if resPacket.Header.ResCode != 4 {
		t.Errorf("Expected FORMERR (4) for no questions, got %d", resPacket.Header.ResCode)
	}
}

func TestHandlePacketEDNS(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "test.com.", QType: packet.A})
	// Add OPT record
	req.Resources = append(req.Resources, packet.DNSRecord{
		Type:           packet.OPT,
		UDPPayloadSize: 4096,
	})

	reqBuf := packet.NewBytePacketBuffer()
	_ = req.Write(reqBuf)

	if err := srv.handlePacket(context.Background(),reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}, func(resp []byte) error {
		return nil
	}, "udp"); err != nil {
		t.Errorf("HandlePacket failed with EDNS: %v", err)
	}
}

func TestHandlePacketTruncation(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer("127.0.0.1:0", repo, nil)

	// Inject many answers into mock repo
	for i := 0; i < 50; i++ {
		repo.records = append(repo.records, domain.Record{
			Name:    "big.test.",
			Type:    domain.TypeA,
			Content: "1.2.3.4",
			TTL:     300,
		})
	}

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "big.test.", QType: packet.A})
	// No OPT -> limit 512
	reqBuf := packet.NewBytePacketBuffer()
	_ = req.Write(reqBuf)

	if err := srv.handlePacket(context.Background(),reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}, func(resp []byte) error {
		resPacket := packet.NewDNSPacket()
		resBuffer := packet.NewBytePacketBuffer()
		resBuffer.Load(resp)
		_ = resPacket.FromBuffer(resBuffer)

		if !resPacket.Header.TruncatedMessage {
			t.Errorf("Expected TC bit to be set")
		}
		if len(resPacket.Answers) > 0 {
			t.Errorf("Expected answers to be cleared in truncated response, got %d", len(resPacket.Answers))
		}
		return nil
	}, "udp"); err != nil {
		t.Fatalf("handlePacket failed: %v", err)
	}
}

func TestHandleDoH(t *testing.T) {
	repo := &mockServerRepo{
		records: []domain.Record{
			{Name: "doh.test.", Type: domain.TypeA, Content: "1.2.3.4", TTL: 60},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "doh.test.", QType: packet.A})
	reqBuf := packet.NewBytePacketBuffer()
	_ = req.Write(reqBuf)

	w := &mockResponseWriter{}
	r, _ := http.NewRequest("POST", "/dns-query", bytes.NewReader(reqBuf.Buf[:reqBuf.Position()]))
	r.Header.Set("Content-Type", "application/dns-message")

	srv.handleDoH(w, r)

	if w.code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.code)
	}
	if w.header.Get("Content-Type") != "application/dns-message" {
		t.Errorf("Expected Content-Type application/dns-message")
	}
}

func TestSendTCPError(t *testing.T) {
	srv := NewServer("127.0.0.1:0", nil, nil)
	conn := &mockTCPConn{}

	srv.sendTCPError(conn, 1234, 4) // FORMERR

	if len(conn.captured) != 1 {
		t.Fatalf("Expected 1 error packet")
	}

	p := packet.NewDNSPacket()
	pBuf := packet.NewBytePacketBuffer()
	pBuf.Load(conn.captured[0])
	_ = p.FromBuffer(pBuf)

	if p.Header.ResCode != 4 || p.Header.ID != 1234 {
		t.Errorf("Invalid TCP error response")
	}
}

func TestServer_RunError(t *testing.T) {
	// Privileged port should fail on non-root
	srv := NewServer("127.0.0.1:1", nil, nil)
	err := srv.Run(context.Background())
	if err == nil {
		t.Errorf("Expected error when running on privileged port 1")
	}
}

func TestServer_Run_ContextCancel(t *testing.T) {
	srv := NewServer("127.0.0.1:0", nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Run(ctx)
	}()

	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("Expected nil error from Run on cancel, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("srv.Run blocked for too long after context cancellation")
	}
}

func TestServer_GracefulShutdown(t *testing.T) {
	srv := NewServer("127.0.0.1:0", nil, nil)

	// Create a cancellable context to simulate shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Run(ctx)
	}()

	// Wait for Run to return - this confirms all tracked goroutines have exited
	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("Expected nil error from Run on cancel, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("srv.Run did not return within 2 seconds - shutdown may be blocked")
	}

	// Run returned successfully within timeout - graceful shutdown is working
	// (tracked background goroutines: cache cleanup, rate limiter cleanup, DNSSEC automation)
}

type errorPacketConn struct {
	net.PacketConn
	WriteAttempts int
}

func (e *errorPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	e.WriteAttempts++
	return 0, errors.New("write error")
}
func (e *errorPacketConn) Close() error { return nil }

func TestHandleUDPConnection_Error(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer("127.0.0.1:0", repo, nil)
	
	// This test ensures that handleUDPConnection does not panic when encountering 
	// malformed data or write errors.
	pc := &errorPacketConn{}
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	
	// 1. Invalid payload - should not even attempt WriteTo
	srv.handleUDPConnection(context.Background(), pc, addr, []byte("invalid"))
	if pc.WriteAttempts > 0 {
		t.Errorf("Expected 0 WriteAttempts for invalid payload, got %d", pc.WriteAttempts)
	}
	
	// 2. Valid query - should attempt WriteTo (and fail)
	q := packet.NewDNSPacket()
	q.Questions = append(q.Questions, packet.DNSQuestion{Name: "test.com.", QType: packet.A})
	buf := packet.NewBytePacketBuffer()
	_ = q.Write(buf)
	
	srv.handleUDPConnection(context.Background(), pc, addr, buf.Buf[:buf.Position()])
	if pc.WriteAttempts == 0 {
		t.Error("Expected at least 1 WriteAttempt for valid query payload")
	}
}

type mockResponseWriter struct {
	http.ResponseWriter
	code   int
	header http.Header
	body   []byte
}

func (m *mockResponseWriter) Header() http.Header {
	if m.header == nil {
		m.header = make(http.Header)
	}
	return m.header
}
func (m *mockResponseWriter) Write(b []byte) (int, error) {
	m.body = append(m.body, b...)
	return len(b), nil
}
func (m *mockResponseWriter) WriteHeader(statusCode int) { m.code = statusCode }

func TestHealthCheck_PingError(t *testing.T) {
	repo := &mockServerRepo{pingErr: errors.New("db down")}
	srv := NewServer("127.0.0.1:0", repo, nil)

	ctx := context.Background()
	checks := srv.Repo.Ping(ctx)
	if checks == nil || checks.Error() != "db down" {
		t.Errorf("Expected 'db down' error, got %v", checks)
	}
}

func TestPrepareUpdate_ConvertError(t *testing.T) {
	srv := NewServer(":0", &mockServerRepo{}, nil)
	up := packet.DNSRecord{
		Name:  "test.com.",
		Type:  packet.UNKNOWN,
		Class: 1,
	}
	_, _, err := srv.prepareUpdate("z1", up)
	if err == nil {
		t.Errorf("Expected conversion error for packet.UNKNOWN, got nil")
	}
}

func TestHandleAXFR_ConvertError(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "axfr-fail.test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "axfr-fail.test.", Type: domain.TypeSOA, Content: "ns1. ns2. 1 2 3 4 5"},
			{ZoneID: "z1", Name: "bad.axfr-fail.test.", Type: domain.TypeA, Content: "not-an-ip"},
		},
	}
	srv := NewServer(":0", repo, nil)

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "axfr-fail.test.", QType: packet.AXFR})

	conn := &mockTCPConn{}
	srv.handleAXFR(context.Background(), conn, req, nil, nil)

	if len(conn.captured) < 2 {
		t.Errorf("Expected at least 2 records (Start SOA and End SOA)")
	}
}

func TestHandleUpdate_ApplyUpdateError(t *testing.T) {
	repo := &mockServerRepo{
		zones:   []domain.Zone{{ID: "z1", Name: "update-fail.test."}},
		records: []domain.Record{{ZoneID: "z1", Name: "update-fail.test.", Type: domain.TypeSOA, Content: "ns1. ns2. 1 2 3 4 5"}},
	}
	srv := NewServer(":0", repo, nil)

	req := packet.NewDNSPacket()
	req.Header.Opcode = packet.OpcodeUpdate
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "update-fail.test.", QType: packet.SOA})
	// Use an unknown type to trigger conversion error in applyUpdate
	req.Authorities = append(req.Authorities, packet.DNSRecord{Name: "bad.update-fail.test.", Type: 999, Class: 1})

	_ = srv.handleUpdate(context.Background(),req, nil, "127.0.0.1", func(resp []byte) error {
		res := packet.NewDNSPacket()
		pb := packet.NewBytePacketBuffer()
		pb.Load(resp)
		_ = res.FromBuffer(pb)
		if res.Header.ResCode != packet.RcodeServFail {
			t.Errorf("Expected SERVFAIL for conversion error, got %d", res.Header.ResCode)
		}
		return nil
	})
}

func TestHandleUpdate_IncrementSerialError(t *testing.T) {
	repo := &mockServerRepo{
		zones:   []domain.Zone{{ID: "z1", Name: "serial-fail.test."}},
		records: []domain.Record{{ZoneID: "z1", Name: "serial-fail.test.", Type: domain.TypeSOA, Content: "bad soa content"}},
		failRecordZoneChange: true, // Make the zone change recording fail
	}
	srv := NewServer(":0", repo, nil)

	req := packet.NewDNSPacket()
	req.Header.Opcode = packet.OpcodeUpdate
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "serial-fail.test.", QType: packet.SOA})
	req.Authorities = append(req.Authorities, packet.DNSRecord{Name: "new.serial-fail.test.", Type: packet.TXT, Txt: "test", Class: 1})

	_ = srv.handleUpdate(context.Background(),req, nil, "127.0.0.1", func(resp []byte) error {
		res := packet.NewDNSPacket()
		pb := packet.NewBytePacketBuffer()
		pb.Load(resp)
		_ = res.FromBuffer(pb)
		if res.Header.ResCode != packet.RcodeServFail {
			t.Errorf("Expected SERVFAIL for zone change failure, got %d", res.Header.ResCode)
		}
		return nil
	})
}

func TestHandleAXFR_NoSOA(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "nosoa.test."}},
		// No records
	}
	srv := NewServer(":0", repo, nil)

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "nosoa.test.", QType: packet.AXFR})

	conn := &mockTCPConn{}
	srv.handleAXFR(context.Background(), conn, req, nil, nil)

	if len(conn.captured) != 1 {
		t.Fatalf("Expected 1 error packet, got %d", len(conn.captured))
	}
	
	res := packet.NewDNSPacket()
	pb := packet.NewBytePacketBuffer()
	pb.Load(conn.captured[0])
	_ = res.FromBuffer(pb)
	if res.Header.ResCode != packet.RcodeServFail {
		t.Errorf("Expected SERVFAIL (2), got %d", res.Header.ResCode)
	}
}

func TestHandleAXFR_StreamingError(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "stream-fail.test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "stream-fail.test.", Type: domain.TypeSOA, Content: "ns1. ns2. 1 2 3 4 5"},
		},
		failListRecordsStreaming: true,
	}
	srv := NewServer(":0", repo, nil)

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "stream-fail.test.", QType: packet.AXFR})

	conn := &mockTCPConn{}
	srv.handleAXFR(context.Background(), conn, req, nil, nil)

	if len(conn.captured) != 1 {
		t.Fatalf("Expected 1 error packet, got %d", len(conn.captured))
	}

	res := packet.NewDNSPacket()
	pb := packet.NewBytePacketBuffer()
	pb.Load(conn.captured[0])
	_ = res.FromBuffer(pb)
	if res.Header.ResCode != packet.RcodeServFail {
		t.Errorf("Expected SERVFAIL (2), got %d", res.Header.ResCode)
	}
}

func TestHandleAXFR_TSIGUnknownKey(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "tsig.test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "tsig.test.", Type: domain.TypeSOA, Content: "ns1. ns2. 1 2 3 4 5"},
		},
	}
	srv := NewServer(":0", repo, nil)
	srv.TsigKeys = map[string]TsigKey{
		"real-key.": {Secret: []byte("secret"), TenantID: ""},
	}

	req := packet.NewDNSPacket()
	req.Header.ID = 1234
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "tsig.test.", QType: packet.AXFR})

	buf := packet.NewBytePacketBuffer()
	_ = req.Write(buf)
	_ = req.SignTSIG(buf, "unknown-key.", []byte("any"))

	conn := &mockTCPConn{}
	srv.handleAXFR(context.Background(), conn, req, buf.Buf[:buf.Position()], nil)

	if len(conn.captured) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(conn.captured))
	}

	res := packet.NewDNSPacket()
	pb := packet.NewBytePacketBuffer()
	pb.Load(conn.captured[0])
	_ = res.FromBuffer(pb)
	if res.Header.ResCode != packet.RcodeRefused {
		t.Errorf("Expected REFUSED (5), got %d", res.Header.ResCode)
	}
}

func TestHandleAXFR_TSIGVerifyFailed(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "tsig.test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "tsig.test.", Type: domain.TypeSOA, Content: "ns1. ns2. 1 2 3 4 5"},
		},
	}
	srv := NewServer(":0", repo, nil)
	srv.TsigKeys = map[string]TsigKey{
		"real-key.": {Secret: []byte("secret"), TenantID: ""},
	}

	req := packet.NewDNSPacket()
	req.Header.ID = 1234
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "tsig.test.", QType: packet.AXFR})

	buf := packet.NewBytePacketBuffer()
	_ = req.Write(buf)
	// Sign with wrong secret
	_ = req.SignTSIG(buf, "real-key.", []byte("wrong-secret"))

	// Tamper with buffer to cause verify failure
	buf.Buf[0] ^= 0xFF

	conn := &mockTCPConn{}
	srv.handleAXFR(context.Background(), conn, req, buf.Buf[:buf.Position()], nil)

	if len(conn.captured) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(conn.captured))
	}

	res := packet.NewDNSPacket()
	pb := packet.NewBytePacketBuffer()
	pb.Load(conn.captured[0])
	_ = res.FromBuffer(pb)
	if res.Header.ResCode != packet.RcodeRefused {
		t.Errorf("Expected REFUSED (5), got %d", res.Header.ResCode)
	}
}

func TestHandleAXFR_TenantMismatch(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "tsig.test.", TenantID: "tenant-a"}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "tsig.test.", Type: domain.TypeSOA, Content: "ns1. ns2. 1 2 3 4 5"},
		},
	}
	srv := NewServer(":0", repo, nil)
	srv.TsigKeys = map[string]TsigKey{
		"real-key.": {Secret: []byte("secret"), TenantID: "tenant-b"}, // different tenant
	}

	req := packet.NewDNSPacket()
	req.Header.ID = 1234
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "tsig.test.", QType: packet.AXFR})

	buf := packet.NewBytePacketBuffer()
	_ = req.Write(buf)
	_ = req.SignTSIG(buf, "real-key.", []byte("secret"))

	conn := &mockTCPConn{}
	srv.handleAXFR(context.Background(), conn, req, buf.Buf[:buf.Position()], nil)

	if len(conn.captured) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(conn.captured))
	}

	res := packet.NewDNSPacket()
	pb := packet.NewBytePacketBuffer()
	pb.Load(conn.captured[0])
	_ = res.FromBuffer(pb)
	if res.Header.ResCode != packet.RcodeRefused {
		t.Errorf("Expected Refused (5), got %d", res.Header.ResCode)
	}
}

func TestServer_Run_NonBlockingOnTCPDoTFailure(t *testing.T) {
	t.Setenv("DOH_PORT", "10443")
	// Bind to a port first to force TCP error in Run
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	addr := l.Addr().String()

	srv := NewServer(addr, nil, nil)
	// Intentional minimal TLS config to exercise DoT path in tests only
	srv.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Context that expires quickly
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Should not block indefinitely even if listeners fail to bind (e.g. port already in use)
	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Run(ctx)
	}()

	select {
	case err := <-errChan:
		if err != nil {
			t.Logf("Run returned expected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("srv.Run blocked for too long")
	}
}

func TestHandleIXFR_TSIGUnknownKey(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "ixfr-tsig.test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "ixfr-tsig.test.", Type: domain.TypeSOA, Content: "ns1. ns2. 1 2 3 4 5"},
		},
	}
	srv := NewServer(":0", repo, nil)
	srv.TsigKeys = map[string]TsigKey{
		"real-key.": {Secret: []byte("secret"), TenantID: ""},
	}

	req := packet.NewDNSPacket()
	req.Header.ID = 5678
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "ixfr-tsig.test.", QType: packet.IXFR})
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name:   "ixfr-tsig.test.",
		Type:   packet.SOA,
		Serial: 1,
	})

	buf := packet.NewBytePacketBuffer()
	_ = req.Write(buf)
	_ = req.SignTSIG(buf, "unknown-key.", []byte("any"))

	conn := &mockTCPConn{}
	srv.handleIXFR(context.Background(), conn, req, buf.Buf[:buf.Position()], nil)

	if len(conn.captured) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(conn.captured))
	}

	res := packet.NewDNSPacket()
	pb := packet.NewBytePacketBuffer()
	pb.Load(conn.captured[0])
	_ = res.FromBuffer(pb)
	if res.Header.ResCode != packet.RcodeRefused {
		t.Errorf("Expected NOTAUTH (5), got %d", res.Header.ResCode)
	}
}

func TestHandleIXFR_TSIGVerifyFailed(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "ixfr-tsig.test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "ixfr-tsig.test.", Type: domain.TypeSOA, Content: "ns1. ns2. 1 2 3 4 5"},
		},
	}
	srv := NewServer(":0", repo, nil)
	srv.TsigKeys = map[string]TsigKey{
		"real-key.": {Secret: []byte("secret"), TenantID: ""},
	}

	req := packet.NewDNSPacket()
	req.Header.ID = 5678
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "ixfr-tsig.test.", QType: packet.IXFR})
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name:   "ixfr-tsig.test.",
		Type:   packet.SOA,
		Serial: 1,
	})

	buf := packet.NewBytePacketBuffer()
	_ = req.Write(buf)
	// Sign with correct key name but wrong secret
	_ = req.SignTSIG(buf, "real-key.", []byte("wrong-secret"))

	// Tamper with buffer to cause verify failure
	buf.Buf[0] ^= 0xFF

	conn := &mockTCPConn{}
	srv.handleIXFR(context.Background(), conn, req, buf.Buf[:buf.Position()], nil)

	if len(conn.captured) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(conn.captured))
	}

	res := packet.NewDNSPacket()
	pb := packet.NewBytePacketBuffer()
	pb.Load(conn.captured[0])
	_ = res.FromBuffer(pb)
	if res.Header.ResCode != packet.RcodeRefused {
		t.Errorf("Expected NOTAUTH (5), got %d", res.Header.ResCode)
	}
}

func TestHandleIXFR_ChunkCountExceedsLimit(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "ixfr-limit.test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "ixfr-limit.test.", Type: domain.TypeSOA, Content: "ns1. ns2. 1 2 3 4 5"},
		},
	}

	// Build chunks exceeding MaxIXFRChunks
	tooManyChunks := make([]domain.IXFRChunk, MaxIXFRChunks+1)
	for i := range tooManyChunks {
		tooManyChunks[i] = domain.IXFRChunk{Serial: uint32(i + 1)}
	}
	repo.mockGetIXFRChain = func(ctx context.Context, zoneID string, fromSerial uint32, toSerial uint32) ([]domain.IXFRChunk, error) {
		return tooManyChunks, nil
	}

	srv := NewServer(":0", repo, nil)
	srv.TsigKeys = map[string]TsigKey{}

	req := packet.NewDNSPacket()
	req.Header.ID = 5679
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "ixfr-limit.test.", QType: packet.IXFR})
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name:   "ixfr-limit.test.",
		Type:   packet.SOA,
		Serial: uint32(len(tooManyChunks)),
	})

	buf := packet.NewBytePacketBuffer()
	_ = req.Write(buf)

	conn := &mockTCPConn{}
	srv.handleIXFR(context.Background(), conn, req, buf.Buf[:buf.Position()], nil)

	if len(conn.captured) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(conn.captured))
	}

	res := packet.NewDNSPacket()
	pb := packet.NewBytePacketBuffer()
	pb.Load(conn.captured[0])
	_ = res.FromBuffer(pb)
	if res.Header.ResCode != packet.RcodeServFail {
		t.Errorf("Expected SERVFAIL (2), got %d", res.Header.ResCode)
	}
}

func TestHandleIXFR_RecordsPerChunkExceedsLimit(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "ixfr-limit.test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "ixfr-limit.test.", Type: domain.TypeSOA, Content: "ns1. ns2. 1 2 3 4 5"},
		},
	}

	// Build chunks where Added exceeds MaxRecordsPerChunk
	tooManyRecords := make([]domain.Record, MaxRecordsPerChunk+1)
	for i := range tooManyRecords {
		tooManyRecords[i] = domain.Record{Name: "ixfr-limit.test.", Type: domain.TypeA, Content: "1.1.1.1"}
	}
	repo.mockGetIXFRChain = func(ctx context.Context, zoneID string, fromSerial uint32, toSerial uint32) ([]domain.IXFRChunk, error) {
		return []domain.IXFRChunk{
			{Serial: 1, Deleted: []domain.Record{}, Added: tooManyRecords},
		}, nil
	}

	srv := NewServer(":0", repo, nil)
	srv.TsigKeys = map[string]TsigKey{}

	req := packet.NewDNSPacket()
	req.Header.ID = 5680
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "ixfr-limit.test.", QType: packet.IXFR})
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name:   "ixfr-limit.test.",
		Type:   packet.SOA,
		Serial: 2,
	})

	buf := packet.NewBytePacketBuffer()
	_ = req.Write(buf)

	conn := &mockTCPConn{}
	srv.handleIXFR(context.Background(), conn, req, buf.Buf[:buf.Position()], nil)

	if len(conn.captured) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(conn.captured))
	}

	res := packet.NewDNSPacket()
	pb := packet.NewBytePacketBuffer()
	pb.Load(conn.captured[0])
	_ = res.FromBuffer(pb)
	if res.Header.ResCode != packet.RcodeServFail {
		t.Errorf("Expected SERVFAIL (2), got %d", res.Header.ResCode)
	}
}

func TestHandleAXFR_RecordCountExceedsLimit(t *testing.T) {
	// Build records exceeding MaxAXFRRecords
	tooManyRecords := make([]domain.Record, MaxAXFRRecords+1)
	for i := range tooManyRecords {
		tooManyRecords[i] = domain.Record{Name: "axfr-limit.test.", Type: domain.TypeA, Content: "1.1.1.1"}
	}
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "axfr-limit.test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "axfr-limit.test.", Type: domain.TypeSOA, Content: "ns1. ns2. 1 2 3 4 5"},
		},
	}
	repo.mockListRecordsForZoneStreaming = func(ctx context.Context, zoneID string, tenantID string) (ports.RecordIterator, error) {
		return &sliceRecordIterator{records: tooManyRecords, index: 0}, nil
	}

	srv := NewServer(":0", repo, nil)
	srv.TsigKeys = map[string]TsigKey{}

	req := packet.NewDNSPacket()
	req.Header.ID = 5681
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "axfr-limit.test.", QType: packet.AXFR})

	buf := packet.NewBytePacketBuffer()
	_ = req.Write(buf)

	conn := &mockTCPConn{}
	srv.handleAXFR(context.Background(), conn, req, buf.Buf[:buf.Position()], nil)

	if len(conn.captured) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(conn.captured))
	}

	res := packet.NewDNSPacket()
	pb := packet.NewBytePacketBuffer()
	pb.Load(conn.captured[0])
	_ = res.FromBuffer(pb)
	if res.Header.ResCode != packet.RcodeServFail {
		t.Errorf("Expected SERVFAIL (2), got %d", res.Header.ResCode)
	}
}

func TestDLQRetryWorker_Shutdown(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to run miniredis: %v", err)
	}
	defer mr.Close()

	redisCache := NewRedisCache(mr.Addr(), "", 0, RedisPoolConfig{})
	defer redisCache.Close()

	srv := &Server{
		Redis:  redisCache,
		Logger: slog.Default(),
		Cache:  nil,
	}

	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(1)
	done := make(chan struct{})
	go func() {
		defer wg.Done()
		srv.dlqRetryWorker(ctx, done)
	}()

	// Cancel immediately — worker should exit promptly, not after 5s
	cancel()

	wgDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(wgDone)
	}()

	select {
	case <-wgDone:
		// Pass — exited promptly after context cancel
	case <-time.After(500 * time.Millisecond):
		t.Fatal("dlqRetryWorker did not exit within 500ms after context cancel")
	}
}

func TestDLQRetryWorker_MalformedMessage(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()

	redisCache := NewRedisCache(mr.Addr(), "", 0, RedisPoolConfig{})
	defer redisCache.Close()

	srv := &Server{
		Redis:  redisCache,
		Logger: slog.Default(),
		Cache:  NewDNSCache(make(chan struct{}), nil),
	}

	// Push malformed messages (0 parts, 1 part, 4+ parts)
	redisCache.PushToDLQ(context.Background(), "no-colons-at-all")
	redisCache.PushToDLQ(context.Background(), "")
	redisCache.PushToDLQ(context.Background(), "a:b:c:d") // 4 parts

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	_ = cancel // Timeout is for worker exit, not explicit cancellation
	done := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.dlqRetryWorker(ctx, done)
	}()

	select {
	case <-ctx.Done():
		// Expected - worker processed messages and exited when context timed out
	case <-time.After(1 * time.Second):
		t.Fatal("Worker did not exit within expected time")
	}
	wg.Wait()
}

func TestDLQRetryWorker_DoneSignal(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()

	redisCache := NewRedisCache(mr.Addr(), "", 0, RedisPoolConfig{})
	defer redisCache.Close()

	srv := &Server{
		Redis:  redisCache,
		Logger: slog.Default(),
		Cache:  NewDNSCache(make(chan struct{}), nil),
	}

	ctx, cancel := context.WithCancel(context.Background())
	_ = cancel // Signal is via done channel, not context cancel
	done := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.dlqRetryWorker(ctx, done)
	}()

	time.Sleep(50 * time.Millisecond)

	// Close done - worker should exit promptly
	close(done)

	wgDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(wgDone)
	}()

	select {
	case <-wgDone:
		// Pass - exited via done signal
	case <-time.After(500 * time.Millisecond):
		t.Fatal("dlqRetryWorker did not exit within 500ms after done close")
	}
}

func TestDLQRetryWorker_EmptyMessage(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()

	redisCache := NewRedisCache(mr.Addr(), "", 0, RedisPoolConfig{})
	defer redisCache.Close()

	srv := &Server{
		Redis:  redisCache,
		Logger: slog.Default(),
		Cache:  NewDNSCache(make(chan struct{}), nil),
	}

	// Push empty message to DLQ
	redisCache.PushToDLQ(context.Background(), "")

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	done := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.dlqRetryWorker(ctx, done)
	}()

	// Wait for processing
	time.Sleep(200 * time.Millisecond)
	close(done)
	wg.Wait()

	// Test passes if no panic - empty message is logged and skipped
}

func TestStartInvalidationListener_ZoneLevelLegacy(t *testing.T) {
	// Test that legacy zone-level messages (without tenant prefix) work
	mr, _ := miniredis.Run()
	defer mr.Close()

	srv := &Server{
		Redis:  NewRedisCache(mr.Addr(), "", 0, RedisPoolConfig{}),
		Logger: slog.Default(),
		Cache:  NewDNSCache(make(chan struct{}), nil),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Prime cache
	srv.Cache.Set("example.com.:1", []byte("data1"), time.Hour)

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.startInvalidationListener(ctx, done)
	}()

	time.Sleep(100 * time.Millisecond)

	// Publish legacy zone-level (name without colons triggers zone-level flush)
	mr.Publish(InvalidationChannel, "example.com.")

	// Wait for invalidation
	time.Sleep(200 * time.Millisecond)

	// Key should be flushed (zone-level invalidation flushes entire L1)
	_, found := srv.Cache.Get("example.com.:1")
	if found {
		t.Error("Zone-level invalidation should flush L1 cache")
	}

	close(done)
	wg.Wait()
}

func TestSendCHAOSIdentity(t *testing.T) {
	srv := NewServer(":0", nil, slog.Default())
	srv.NodeID = "test-node-id"

	req := packet.NewDNSPacket()
	req.Header.ID = 123
	q := packet.DNSQuestion{Name: "hostname.bind.", QType: packet.TXT, QClass: ClassCHAOS}
	req.Questions = append(req.Questions, q)

	var captured []byte
	err := srv.sendCHAOSIdentity(req, q, func(data []byte) error {
		captured = data
		return nil
	}, "TXT", "udp")

	assert.NoError(t, err)
	assert.NotEmpty(t, captured)

	// Verify it's a valid DNS packet (at least header is correct)
	// Packet format: header (12 bytes) + question + answer
	assert.GreaterOrEqual(t, len(captured), 20)
}

func TestCheckCache_L2Hit(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to run miniredis: %v", err)
	}
	defer mr.Close()

	srv := NewServer(":0", nil, slog.Default())
	srv.Redis = NewRedisCache(mr.Addr(), "", 0, RedisPoolConfig{})

	// Set data in Redis (L2 cache) with a tenant-aware key
	cacheKey := "tenant1:example.com.:1"
	srv.Redis.Set(context.Background(), cacheKey, []byte("cached-response-data"), time.Hour)

	req := packet.NewDNSPacket()
	req.Header.ID = 0x1234

	var sent []byte
	result := srv.checkCache(context.Background(), req, cacheKey, "", "A", "udp", func(data []byte) error {
		sent = data
		return nil
	})

	assert.NotNil(t, result)
	// TX ID (0x1234) is written at offset 0, so sent = "\x12\x34" + "ched-response-data"
	assert.Equal(t, "\x12\x34ched-response-data", string(sent))
}

func TestSendServFail(t *testing.T) {
	srv := NewServer(":0", nil, slog.Default())
	req := packet.NewDNSPacket()
	req.Header.ID = 123

	var sent []byte
	err := srv.sendServFail(req, func(data []byte) error {
		sent = data
		return nil
	}, "A", "udp")

	if err != nil {
		t.Fatalf("sendServFail failed: %v", err)
	}
	if len(sent) == 0 {
		t.Error("Expected non-empty response")
	}

	// Verify response has SERVFAIL RCODE
	resp := packet.NewDNSPacket()
	buf := packet.NewBytePacketBuffer()
	buf.Load(sent)
	_ = resp.FromBuffer(buf)
	if resp.Header.ResCode != packet.RcodeServFail {
		t.Errorf("Expected SERVFAIL, got %d", resp.Header.ResCode)
	}
}

func TestIsAuthorizedNotifier(t *testing.T) {
	// Check if localhost resolves to 127.0.0.1 (skip hostname test if not)
	localHostIP, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	localhostResolvesTo127 := err == nil && localHostIP != nil

	tests := []struct {
		clientIP    string
		masterServer string
		want         bool
		skipIfNoLocalhost bool
	}{
		// IP match
		{"192.168.1.1", "192.168.1.1:53", true, false},
		{"192.168.1.1", "192.168.1.1", true, false},
		// IP mismatch
		{"192.168.1.1", "10.0.0.1:53", false, false},
		// Hostname resolution (may not work in all environments)
		{"127.0.0.1", "localhost:53", true, !localhostResolvesTo127},
		// Invalid
		{"invalid", "localhost:53", false, false},
	}

	for _, tt := range tests {
		if tt.skipIfNoLocalhost {
			t.Skip("localhost does not resolve to 127.0.0.1 in this environment")
		}
		got := isAuthorizedNotifier(tt.clientIP, tt.masterServer)
		if got != tt.want {
			t.Errorf("isAuthorizedNotifier(%q, %q) = %v, want %v", tt.clientIP, tt.masterServer, got, tt.want)
		}
	}
}
