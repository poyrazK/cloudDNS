package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

type mockServerRepo struct {
	records []domain.Record
	zones   []domain.Zone
}

func (m *mockServerRepo) GetRecords(ctx context.Context, name string, qType domain.RecordType, clientIP string) ([]domain.Record, error) {
	var res []domain.Record
	for _, r := range m.records {
		if r.Name == name && (qType == "" || r.Type == qType) {
			res = append(res, r)
		}
	}
	return res, nil
}

func (m *mockServerRepo) CreateZone(ctx context.Context, zone *domain.Zone) error {
	m.zones = append(m.zones, *zone)
	return nil
}

func (m *mockServerRepo) CreateZoneWithRecords(ctx context.Context, zone *domain.Zone, records []domain.Record) error {
	m.zones = append(m.zones, *zone)
	m.records = append(m.records, records...)
	return nil
}

func (m *mockServerRepo) CreateRecord(ctx context.Context, record *domain.Record) error {
	m.records = append(m.records, *record)
	return nil
}

func (m *mockServerRepo) ListZones(ctx context.Context, tenantID string) ([]domain.Zone, error) {
	var res []domain.Zone
	for _, z := range m.zones {
		if z.TenantID == tenantID {
			res = append(res, z)
		}
	}
	return res, nil
}
func (m *mockServerRepo) DeleteZone(ctx context.Context, zoneID string, tenantID string) error {
	return nil
}
func (m *mockServerRepo) DeleteRecord(ctx context.Context, recordID string, zoneID string) error {
	return nil
}

func TestHandlePacketLocalHit(t *testing.T) {
	repo := &mockServerRepo{
		records: []domain.Record{
			{Name: "local.test", Type: domain.TypeA, Content: "1.1.1.1", TTL: 60},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDnsPacket()
	req.Header.ID = 123
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "local.test", QType: packet.A})
	
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
		t.Errorf("Expected 1 answer, got %d", len(resp.Answers))
	}
	if resp.Answers[0].IP.String() != "1.1.1.1" {
		t.Errorf("Expected 1.1.1.1, got %s", resp.Answers[0].IP.String())
	}
}

func TestHandlePacketCacheHit(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer("127.0.0.1:0", repo, nil)
	
	// Pre-populate cache
	cacheKey := "cached.test:1" // A record
	cachedPacket := packet.NewDnsPacket()
	cachedPacket.Header.Response = true
	cachedPacket.Answers = append(cachedPacket.Answers, packet.DnsRecord{
		Name: "cached.test", Type: packet.A, IP: net.ParseIP("2.2.2.2"), TTL: 60,
	})
	buf := packet.NewBytePacketBuffer()
	cachedPacket.Write(buf)
	srv.Cache.Set(cacheKey, buf.Buf[:buf.Position()], 60*time.Second)

	// Query
	req := packet.NewDnsPacket()
	req.Header.ID = 999
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "cached.test", QType: packet.A})
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
			{Name: "worker.test", Type: domain.TypeA, Content: "3.3.3.3", TTL: 60},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)
	srv.WorkerCount = 1
	
	// Start one worker
	go srv.udpWorker()

	req := packet.NewDnsPacket()
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "worker.test", QType: packet.A})
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
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "missing.test", QType: packet.A})
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
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "test.com", QType: packet.A})
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
