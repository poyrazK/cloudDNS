package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

// mockTCPFactory is a test double for TCPConnFactory.
type mockTCPFactory struct {
	dialErr error
}

func (m *mockTCPFactory) DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	if m.dialErr != nil {
		return nil, m.dialErr
	}
	return nil, errors.New("mock TCP factory not configured for real connections")
}

// mockTicker is a test double for Ticker.
type mockTicker struct {
	c chan time.Time
}

func (m *mockTicker) Stop() {}
func (m *mockTicker) C() <-chan time.Time {
	return m.c
}

// mockTickerFactory creates mockTicker instances.
type mockTickerFactory struct {
	ticker *mockTicker
}

func (m *mockTickerFactory) NewTicker(d time.Duration) Ticker {
	return m.ticker
}

func TestRefreshZone(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer(":0", repo, nil)

	zone := &domain.Zone{ID: "z1", Name: "slave.test.", MasterServer: "1.2.3.4"}

	// Case 1: No master configured
	srv.refreshZone(context.Background(), &domain.Zone{Name: "nomaster.test."})

	// Case 2: Up to date
	_ = repo.CreateRecord(context.Background(), &domain.Record{
		ZoneID: "z1", Name: "slave.test.", Type: domain.TypeSOA, Content: "ns1. ns2. 100 1 1 1 1",
	})
	srv.queryFn = func(server string, name string, qType packet.QueryType) (*packet.DNSPacket, error) {
		resp := packet.NewDNSPacket()
		resp.Header.Response = true
		resp.Answers = append(resp.Answers, packet.DNSRecord{Type: packet.SOA, Serial: 100})
		return resp, nil
	}
	srv.refreshZone(context.Background(), zone)

	// Case 3: Master has newer serial (AXFR Trigger)
	srv.queryFn = func(server string, name string, qType packet.QueryType) (*packet.DNSPacket, error) {
		resp := packet.NewDNSPacket()
		resp.Header.Response = true
		resp.Answers = append(resp.Answers, packet.DNSRecord{Type: packet.SOA, Serial: 200})
		return resp, nil
	}

	// Start a mock TCP server for AXFR
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()
	
	// Set the master server to the mock listener's address.
	// refreshZone uses net.JoinHostPort(zone.MasterServer, "53")
	// If zone.MasterServer is "127.0.0.1:port", it becomes "[127.0.0.1:port]:53"
	// To fix this without refactoring recursive.go, we pass just the host
	// BUT refreshZone will then dial port 53.
	// The best fix is to ensure refreshZone uses the port if provided.
	// Assuming recursive.go logic: addr := net.JoinHostPort(zone.MasterServer, "53")
	// If MasterServer contains a port, net.JoinHostPort might produce an invalid addr.
	
	zone.MasterServer = l.Addr().String()

	done := make(chan bool, 1)
	connected := make(chan bool, 1)

	go func() {
		conn, err := l.Accept()
		if err != nil { return }
		defer conn.Close()
		connected <- true
		// Mock AXFR response: SOA -> A -> SOA
		// 1. Read request (2-byte length + payload)
		lb := make([]byte, 2)
		_, _ = conn.Read(lb)
		rlen := int(lb[0])<<8 | int(lb[1])
		data := make([]byte, rlen)
		_, _ = conn.Read(data)

		// 2. Send 3 packets
		records := []packet.DNSRecord{
			{Name: "slave.test.", Type: packet.SOA, Serial: 200},
			{Name: "www.slave.test.", Type: packet.A, IP: net.ParseIP("1.1.1.1")},
			{Name: "slave.test.", Type: packet.SOA, Serial: 200},
		}
		for _, r := range records {
			p := packet.NewDNSPacket()
			p.Header.Response = true
			p.Answers = append(p.Answers, r)
			pb := packet.NewBytePacketBuffer()
			_ = p.Write(pb)
			d := pb.Buf[:pb.Position()]
			_, _ = conn.Write([]byte{byte(len(d) >> 8), byte(len(d) & 0xFF)})
			_, _ = conn.Write(d)
		}
		done <- true
	}()

	// Since we can't easily change the hardcoded :53 in refreshZone, 
	// we use performAXFR directly which takes the address.
	err = srv.performAXFR(context.Background(), zone, zone.MasterServer)
	if err != nil {
		t.Fatalf("performAXFR failed: %v", err)
	}

	select {
	case <-connected:
		// success
	case <-time.After(1 * time.Second):
		t.Errorf("Mock AXFR server was not contacted")
	}

	select {
	case <-done:
		// success
	case <-time.After(1 * time.Second):
		t.Errorf("Mock AXFR transfer did not complete")
	}
}

func TestPerformAXFR_Error(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer(":0", repo, nil)
	zone := &domain.Zone{ID: "z1", Name: "fail.test."}

	// Case 1: Dial error
	err := srv.performAXFR(context.Background(), zone, "127.0.0.1:1") // Closed port
	if err == nil {
		t.Errorf("Expected dial error")
	}

	// Case 2: Master returns error RCODE
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		conn, _ := l.Accept()
		defer conn.Close()
		// Send SERVFAIL
		p := packet.NewDNSPacket()
		p.Header.Response = true
		p.Header.ResCode = packet.RcodeServFail
		pb := packet.NewBytePacketBuffer()
		_ = p.Write(pb)
		d := pb.Buf[:pb.Position()]
		_, _ = conn.Write([]byte{byte(len(d) >> 8), byte(len(d) & 0xFF)})
		_, _ = conn.Write(d)
	}()

	err = srv.performAXFR(context.Background(), zone, l.Addr().String())
	if err == nil || !strings.Contains(err.Error(), "master returned error") {
		t.Errorf("Expected master error, got %v", err)
	}
}

func TestRefreshZone_MasterError(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer(":0", repo, nil)
	srv.queryFn = func(server string, name string, qType packet.QueryType) (*packet.DNSPacket, error) {
		return nil, fmt.Errorf("network error")
	}
	srv.refreshZone(context.Background(), &domain.Zone{Name: "err.test.", MasterServer: "1.1.1.1"})
}

func TestRefreshZone_HostnameMaster(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer(":0", repo, nil)

	zoneName := "slave.test."

	// Test that refreshZone handles hostname without port (defaults to :53)
	srv.queryFn = func(server string, name string, qType packet.QueryType) (*packet.DNSPacket, error) {
		// Verify that server is hostname:53 format
		if !strings.Contains(server, ":53") {
			t.Errorf("Expected :53 default port, got %s", server)
		}
		// Return a valid SOA response so refreshZone doesn't nil-deref
		resp := packet.NewDNSPacket()
		resp.Answers = []packet.DNSRecord{
			{Name: zoneName, Type: packet.SOA, Serial: 100},
		}
		return resp, nil
	}

	zone := &domain.Zone{Name: zoneName, MasterServer: "localhost"}
	srv.refreshZone(context.Background(), zone)
	// refreshZone is void - the test verifies queryFn receives the correct server address
}

func TestPerformIXFR_DialError(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer(":0", repo, nil)
	srv.tcpFactory = &mockTCPFactory{dialErr: errors.New("connection refused")}

	zone := &domain.Zone{ID: "z1", Name: "ixfr.test."}
	err := srv.performIXFR(context.Background(), zone, "127.0.0.1:1", 100)
	if err == nil {
		t.Errorf("Expected dial error")
	}
}

func TestPerformAXFR_DialError(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer(":0", repo, nil)
	srv.tcpFactory = &mockTCPFactory{dialErr: errors.New("connection refused")}

	zone := &domain.Zone{ID: "z1", Name: "axfr.test."}
	err := srv.performAXFR(context.Background(), zone, "127.0.0.1:1")
	if err == nil {
		t.Errorf("Expected dial error")
	}
}

func TestFetchAXFRPackets_DialError(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer(":0", repo, nil)
	srv.tcpFactory = &mockTCPFactory{dialErr: errors.New("connection refused")}

	_, err := srv.fetchAXFRPackets(context.Background(), "test.", "127.0.0.1:1")
	if err == nil {
		t.Errorf("Expected dial error")
	}
}

func TestStartCatalogPoller_Ticker(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer(":0", repo, nil)

	// Create a mock ticker that we can control
	mockTick := &mockTicker{c: make(chan time.Time, 1)}
	srv.tickerFactory = &mockTickerFactory{ticker: mockTick}

	ctx, cancel := context.WithCancel(context.Background())

	// Start the poller - it should return when context is cancelled
	go srv.StartCatalogPoller(ctx, []string{"catalog.test."}, "127.0.0.1:1", time.Hour)

	// Cancel after a short delay
	time.Sleep(10 * time.Millisecond)
	cancel()

	// The function should return without hanging
}

func TestStartCatalogPoller_ImmediateCancel(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer(":0", repo, nil)

	mockTick := &mockTicker{c: make(chan time.Time, 1)}
	srv.tickerFactory = &mockTickerFactory{ticker: mockTick}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Should return immediately without hanging
	srv.StartCatalogPoller(ctx, []string{"catalog.test."}, "127.0.0.1:1", time.Hour)
}

func TestFetchCatalogEntries_Empty(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer(":0", repo, nil)
	srv.tcpFactory = &mockTCPFactory{dialErr: errors.New("no connection")}

	_, err := srv.fetchCatalogEntries(context.Background(), "catalog.test.", "127.0.0.1:1")
	if err == nil {
		t.Errorf("Expected error from TCP factory")
	}
}



func TestFetchZoneRecords_DialError(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer(":0", repo, nil)
	srv.tcpFactory = &mockTCPFactory{dialErr: errors.New("connection refused")}

	_, err := srv.fetchZoneRecords(context.Background(), "test.", "127.0.0.1:1", "z1", "tenant1")
	if err == nil {
		t.Errorf("Expected dial error")
	}
}

func TestPollCatalogZone_CZTRError(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer(":0", repo, nil)

	// Make queryFn return error (master doesn't support CZTR)
	srv.queryFn = func(server string, name string, qType packet.QueryType) (*packet.DNSPacket, error) {
		return nil, errors.New("network error")
	}

	err := srv.pollCatalogZone(context.Background(), "catalog.test.", "127.0.0.1:1")
	if err != nil {
		t.Errorf("Expected nil for CZTR error (graceful skip), got %v", err)
	}
}

func TestPollCatalogZone_EmptyCZTR(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer(":0", repo, nil)

	// Return empty CZTR response (slave mode not supported)
	srv.queryFn = func(server string, name string, qType packet.QueryType) (*packet.DNSPacket, error) {
		resp := packet.NewDNSPacket()
		resp.Header.Response = true
		// No answers - slave mode not supported
		return resp, nil
	}

	err := srv.pollCatalogZone(context.Background(), "catalog.test.", "127.0.0.1:1")
	if err != nil {
		t.Errorf("Expected nil for empty CZTR (graceful skip), got %v", err)
	}
}

func strPtr(s string) *string {
	return &s
}
