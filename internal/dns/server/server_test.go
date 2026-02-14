package server

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

type mockServerRepo struct {
	mu      sync.RWMutex
	records []domain.Record
	zones   []domain.Zone
	changes []domain.ZoneChange
	keys    []domain.DNSSECKey
}

func (m *mockServerRepo) GetRecords(ctx context.Context, name string, qType domain.RecordType, clientIP string) ([]domain.Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []domain.Record
	for _, r := range m.records {
		if r.Name == name && (qType == "" || r.Type == qType) {
			res = append(res, r)
		}
	}
	return res, nil
}

func (m *mockServerRepo) GetIPsForName(ctx context.Context, name string, clientIP string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []string
	for _, r := range m.records {
		if r.Name == name && r.Type == domain.TypeA {
			res = append(res, r.Content)
		}
	}
	return res, nil
}

func (m *mockServerRepo) GetZone(ctx context.Context, name string) (*domain.Zone, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, z := range m.zones {
		if z.Name == name {
			return &z, nil
		}
	}
	return nil, nil
}

func (m *mockServerRepo) ListRecordsForZone(ctx context.Context, zoneID string) ([]domain.Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []domain.Record
	for _, r := range m.records {
		if r.ZoneID == zoneID {
			res = append(res, r)
		}
	}
	return res, nil
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

func (m *mockServerRepo) CreateRecord(ctx context.Context, record *domain.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, *record)
	return nil
}

func (m *mockServerRepo) ListZones(ctx context.Context, tenantID string) ([]domain.Zone, error) {
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
	return nil
}
func (m *mockServerRepo) DeleteRecord(ctx context.Context, recordID string, zoneID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var next []domain.Record
	for _, r := range m.records {
		if r.ID != recordID {
			next = append(next, r)
		}
	}
	m.records = next
	return nil
}

func (m *mockServerRepo) DeleteRecordsByNameAndType(ctx context.Context, zoneID string, name string, qType domain.RecordType) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var next []domain.Record
	for _, r := range m.records {
		if r.ZoneID == zoneID && r.Name == name && r.Type == qType {
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
	for _, r := range m.records {
		if r.ZoneID == zoneID && r.Name == name {
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
	var next []domain.Record
	for _, r := range m.records {
		if r.ZoneID == zoneID && r.Name == name && r.Type == qType && r.Content == content {
			continue
		}
		next = append(next, r)
	}
	m.records = next
	return nil
}

func (m *mockServerRepo) RecordZoneChange(ctx context.Context, change *domain.ZoneChange) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.changes = append(m.changes, *change)
	return nil
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

func (m *mockServerRepo) SaveAuditLog(ctx context.Context, log *domain.AuditLog) error {
	return nil
}

func (m *mockServerRepo) GetAuditLogs(ctx context.Context, tenantID string) ([]domain.AuditLog, error) {
	return nil, nil
}

func (m *mockServerRepo) CreateKey(ctx context.Context, key *domain.DNSSECKey) error {
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

func (m *mockServerRepo) Ping(ctx context.Context) error { return nil }

func TestHandlePacketLocalHit(t *testing.T) {
	repo := &mockServerRepo{
		records: []domain.Record{
			{Name: "local.test.", Type: domain.TypeA, Content: "1.1.1.1", TTL: 60},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDnsPacket()
	req.Header.ID = 123
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "local.test.", QType: packet.A})
	
	buffer := packet.NewBytePacketBuffer()
	req.Write(buffer)
	data := buffer.Buf[:buffer.Position()]

	var capturedResp []byte
	err := srv.handlePacket(data, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}, func(resp []byte) error {
		capturedResp = resp
		return nil
	})

	if err != nil {
		t.Fatalf("HandlePacket failed: %v", err)
	}

	resBuf := packet.NewBytePacketBuffer()
	copy(resBuf.Buf, capturedResp)
	resp := packet.NewDnsPacket()
	resp.FromBuffer(resBuf)

	if len(resp.Answers) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(resp.Answers))
	}
	if resp.Answers[0].IP.String() != "1.1.1.1" {
		t.Errorf("Expected 1.1.1.1, got %s", resp.Answers[0].IP.String())
	}
}

func TestHandlePacketCacheHit(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer("127.0.0.1:0", repo, nil)
	
	// Pre-populate cache
	cacheKey := "cached.test.:1" // A record
	cachedPacket := packet.NewDnsPacket()
	cachedPacket.Header.Response = true
	cachedPacket.Questions = append(cachedPacket.Questions, packet.DnsQuestion{Name: "cached.test.", QType: packet.A})
	cachedPacket.Answers = append(cachedPacket.Answers, packet.DnsRecord{
		Name: "cached.test.", Type: packet.A, IP: net.ParseIP("2.2.2.2"), TTL: 60, Class: 1,
	})
	buf := packet.NewBytePacketBuffer()
	cachedPacket.Write(buf)
	srv.Cache.Set(cacheKey, buf.Buf[:buf.Position()], 60*time.Second)

	// Query
	req := packet.NewDnsPacket()
	req.Header.ID = 999
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "cached.test.", QType: packet.A})
	reqBuf := packet.NewBytePacketBuffer()
	req.Write(reqBuf)

	var capturedResp []byte
	srv.handlePacket(reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}, func(resp []byte) error {
		capturedResp = resp
		return nil
	})

	resBuf := packet.NewBytePacketBuffer()
	copy(resBuf.Buf, capturedResp)
	resp := packet.NewDnsPacket()
	resp.FromBuffer(resBuf)

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

	req := packet.NewDnsPacket()
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "worker.test.", QType: packet.A})
	reqBuf := packet.NewBytePacketBuffer()
	req.Write(reqBuf)

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

	req := packet.NewDnsPacket()
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "missing.test.", QType: packet.A})
	reqBuf := packet.NewBytePacketBuffer()
	req.Write(reqBuf)

	var capturedResp []byte
	srv.handlePacket(reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}, func(resp []byte) error {
		capturedResp = resp
		return nil
	})

	resPacket := packet.NewDnsPacket()
	pBuf := packet.NewBytePacketBuffer()
	copy(pBuf.Buf, capturedResp)
	resPacket.FromBuffer(pBuf)

	if resPacket.Header.ResCode != 3 {
		t.Errorf("Expected NXDOMAIN (3), got %d", resPacket.Header.ResCode)
	}
}

func TestHandlePacketNoQuestions(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDnsPacket()
	reqBuf := packet.NewBytePacketBuffer()
	req.Write(reqBuf)

	var capturedResp []byte
	srv.handlePacket(reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}, func(resp []byte) error {
		capturedResp = resp
		return nil
	})

	resPacket := packet.NewDnsPacket()
	pBuf := packet.NewBytePacketBuffer()
	copy(pBuf.Buf, capturedResp)
	resPacket.FromBuffer(pBuf)

	if resPacket.Header.ResCode != 4 {
		t.Errorf("Expected FORMERR (4) for no questions, got %d", resPacket.Header.ResCode)
	}
}

func TestHandlePacketEDNS(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDnsPacket()
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "test.com.", QType: packet.A})
	// Add OPT record
	req.Resources = append(req.Resources, packet.DnsRecord{
		Type:           packet.OPT,
		UDPPayloadSize: 4096,
	})
	
	reqBuf := packet.NewBytePacketBuffer()
	req.Write(reqBuf)

	err := srv.handlePacket(reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}, func(resp []byte) error {
		return nil
	})
	
	if err != nil {
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

	req := packet.NewDnsPacket()
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "big.test.", QType: packet.A})
	// No OPT -> limit 512
	reqBuf := packet.NewBytePacketBuffer()
	req.Write(reqBuf)

	err := srv.handlePacket(reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}, func(resp []byte) error {
		resPacket := packet.NewDnsPacket()
		resBuffer := packet.NewBytePacketBuffer()
		copy(resBuffer.Buf, resp)
		resPacket.FromBuffer(resBuffer)

		if !resPacket.Header.TruncatedMessage {
			t.Errorf("Expected TC bit to be set")
		}
		if len(resPacket.Answers) > 0 {
			t.Errorf("Expected answers to be cleared in truncated response, got %d", len(resPacket.Answers))
		}
		return nil
	})
	if err != nil {
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

	req := packet.NewDnsPacket()
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "doh.test.", QType: packet.A})
	reqBuf := packet.NewBytePacketBuffer()
	req.Write(reqBuf)

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
	
	p := packet.NewDnsPacket()
	pBuf := packet.NewBytePacketBuffer()
	pBuf.Load(conn.captured[0])
	p.FromBuffer(pBuf)

	if p.Header.ResCode != 4 || p.Header.ID != 1234 {
		t.Errorf("Invalid TCP error response")
	}
}

type mockResponseWriter struct {
	http.ResponseWriter
	code   int
	header http.Header
	body   []byte
}

func (m *mockResponseWriter) Header() http.Header {
	if m.header == nil { m.header = make(http.Header) }
	return m.header
}
func (m *mockResponseWriter) Write(b []byte) (int, error) {
	m.body = append(m.body, b...)
	return len(b), nil
}
func (m *mockResponseWriter) WriteHeader(statusCode int) { m.code = statusCode }
