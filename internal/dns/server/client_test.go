package server

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestRefreshZone(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer(":0", repo, nil)

	zone := &domain.Zone{ID: "z1", Name: "slave.test.", MasterServer: "1.2.3.4"}

	// Case 1: No master configured
	srv.refreshZone(&domain.Zone{Name: "nomaster.test."})

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
	srv.refreshZone(zone)

	// Case 3: Master has newer serial (AXFR Trigger)
	srv.queryFn = func(server string, name string, qType packet.QueryType) (*packet.DNSPacket, error) {
		resp := packet.NewDNSPacket()
		resp.Header.Response = true
		resp.Answers = append(resp.Answers, packet.DNSRecord{Type: packet.SOA, Serial: 200})
		return resp, nil
	}

	// Start a mock TCP server for AXFR
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	zone.MasterServer, _, _ = net.SplitHostPort(l.Addr().String())

	go func() {
		conn, err := l.Accept()
		if err != nil { return }
		defer conn.Close()
		// Mock AXFR response: SOA -> A -> SOA
		// 1. Read request
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
	}()

	srv.refreshZone(zone)
}

func TestPerformAXFR_Error(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer(":0", repo, nil)
	zone := &domain.Zone{ID: "z1", Name: "fail.test."}

	// Case 1: Dial error
	err := srv.performAXFR(zone, "127.0.0.1:1") // Closed port
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

	err = srv.performAXFR(zone, l.Addr().String())
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
	srv.refreshZone(&domain.Zone{Name: "err.test.", MasterServer: "1.1.1.1"})
}
