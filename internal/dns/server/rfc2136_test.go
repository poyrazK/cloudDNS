package server

import (
	"context"
	"net"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

// TestHandleUpdateAddRecord verifies that a standard DNS UPDATE (RFC 2136)
// can successfully add a new A record to an authoritative zone.
func TestHandleUpdateAddRecord(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{
			{ID: "zone-1", Name: "example.test."},
		},
		records: []domain.Record{
			{ID: "soa1", ZoneID: "zone-1", Name: "example.test.", Type: domain.TypeSOA, Content: "ns1.example.test. host. 1 3600 600 604800 300"},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDnsPacket()
	req.Header.ID = 100
	req.Header.Opcode = packet.OPCODE_UPDATE
	// Zone Section: Specifies the zone being updated
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "example.test.", QType: packet.SOA})
	// Update Section: The record to be added (Class IN)
	req.Authorities = append(req.Authorities, packet.DnsRecord{
		Name: "new.example.test.",
		Type: packet.A,
		Class: 1, // IN -> Add
		TTL: 3600,
		IP: net.ParseIP("192.168.1.10"),
	})

	buffer := packet.NewBytePacketBuffer()
	req.Write(buffer)
	data := buffer.Buf[:buffer.Position()]

	var capturedResp []byte
	err := srv.handlePacket(data, "127.0.0.1:12345", func(resp []byte) error {
		capturedResp = resp
		return nil
	})

	if err != nil {
		t.Fatalf("HandlePacket failed: %v", err)
	}

	resPacket := packet.NewDnsPacket()
	pBuf := packet.NewBytePacketBuffer()
	copy(pBuf.Buf, capturedResp)
	resPacket.FromBuffer(pBuf)

	if resPacket.Header.ResCode != packet.RCODE_NOERROR {
		t.Errorf("Expected NOERROR, got %d", resPacket.Header.ResCode)
	}

	// Verify record was actually persisted to the repository
	found := false
	for _, r := range repo.records {
		if r.Name == "new.example.test." && r.Content == "192.168.1.10" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Record was not added to repo")
	}
}

// TestHandleUpdateDeleteRRSet verifies the deletion of an entire RRset (Class ANY)
// as defined in RFC 2136 Section 2.5.2.
func TestHandleUpdateDeleteRRSet(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{
			{ID: "zone-1", Name: "example.test."},
		},
		records: []domain.Record{
			{ZoneID: "zone-1", Name: "del.example.test.", Type: domain.TypeA, Content: "1.1.1.1"},
			{ZoneID: "zone-1", Name: "del.example.test.", Type: domain.TypeA, Content: "2.2.2.2"},
			{ZoneID: "zone-1", Name: "del.example.test.", Type: domain.TypeTXT, Content: "keep me"},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDnsPacket()
	req.Header.Opcode = packet.OPCODE_UPDATE
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "example.test.", QType: packet.SOA})
	// Delete RRSet: Class ANY (255), Type A
	req.Authorities = append(req.Authorities, packet.DnsRecord{
		Name: "del.example.test.",
		Type: packet.A,
		Class: 255, // ANY -> Delete RRset
	})

	buffer := packet.NewBytePacketBuffer()
	req.Write(buffer)
	data := buffer.Buf[:buffer.Position()]

	srv.handlePacket(data, "127.0.0.1:12345", func(resp []byte) error { return nil })

	// Verify all A records are gone but the TXT record remains
	for _, r := range repo.records {
		if r.Name == "del.example.test." && r.Type == domain.TypeA {
			t.Errorf("A record was not deleted")
		}
	}
	foundTXT := false
	for _, r := range repo.records {
		if r.Name == "del.example.test." && r.Type == domain.TypeTXT {
			foundTXT = true
		}
	}
	if !foundTXT {
		t.Errorf("TXT record was accidentally deleted")
	}
}

// TestHandleUpdatePrerequisiteFail verifies that an update fails with NXDOMAIN
// if a "Name is in use" prerequisite is not met.
func TestHandleUpdatePrerequisiteFail(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{
			{ID: "zone-1", Name: "example.test."},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDnsPacket()
	req.Header.Opcode = packet.OPCODE_UPDATE
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "example.test.", QType: packet.SOA})
	// Prerequisite: Name is in use (Class ANY, Type ANY)
	req.Answers = append(req.Answers, packet.DnsRecord{
		Name: "missing.example.test.",
		Type: 255, // ANY
		Class: 255, // ANY
	})

	buffer := packet.NewBytePacketBuffer()
	req.Write(buffer)
	data := buffer.Buf[:buffer.Position()]

	var capturedResp []byte
	srv.handlePacket(data, "127.0.0.1:12345", func(resp []byte) error {
		capturedResp = resp
		return nil
	})

	resPacket := packet.NewDnsPacket()
	pBuf := packet.NewBytePacketBuffer()
	copy(pBuf.Buf, capturedResp)
	resPacket.FromBuffer(pBuf)

	if resPacket.Header.ResCode != packet.RCODE_NXDOMAIN {
		t.Errorf("Expected NXDOMAIN (3) for failed prerequisite, got %d", resPacket.Header.ResCode)
	}
}

// TestHandleUpdateMorePrereqs tests complex prerequisite scenarios including 
// "Name NOT in use" (Class NONE).
func TestHandleUpdateMorePrereqs(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "test.test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "exists.test.", Type: domain.TypeA, Content: "1.1.1.1"},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	// 1. Success case: Prerequisite check
	req := packet.NewDnsPacket()
	req.Header.Opcode = packet.OPCODE_UPDATE
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "test.test.", QType: packet.SOA})
	req.Answers = append(req.Answers, packet.DnsRecord{
		Name: "exists.test.", Type: packet.A, Class: 255,
	})
	
	buf := packet.NewBytePacketBuffer()
	req.Write(buf)
	srv.handlePacket(buf.Buf[:buf.Position()], "127.0.0.1:1", func(resp []byte) error {
		return nil
	})

	// 2. Failure case: "Name NOT in use" but name exists
	req2 := packet.NewDnsPacket()
	req2.Header.Opcode = packet.OPCODE_UPDATE
	req2.Questions = append(req2.Questions, packet.DnsQuestion{Name: "test.test.", QType: packet.SOA})
	req2.Answers = append(req2.Answers, packet.DnsRecord{
		Name: "exists.test.", Type: 255, Class: 254, // NONE/ANY -> YXDOMAIN if name in use
	})
	buf2 := packet.NewBytePacketBuffer()
	req2.Write(buf2)
	srv.handlePacket(buf2.Buf[:buf2.Position()], "127.0.0.1:1", func(resp []byte) error {
		p := packet.NewDnsPacket()
		pb := packet.NewBytePacketBuffer()
		pb.Load(resp)
		p.FromBuffer(pb)
		if p.Header.ResCode != packet.RCODE_YXDOMAIN {
			t.Errorf("Expected YXDOMAIN for existing name check, got %d", p.Header.ResCode)
		}
		return nil
	})
}

// TestHandleUpdateDeleteSpecific verifies the deletion of a single RR from an RRset
// (Class NONE) as defined in RFC 2136 Section 2.5.4.
func TestHandleUpdateDeleteSpecific(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "test.test."}},
		records: []domain.Record{
			{ID: "r1", ZoneID: "z1", Name: "www.test.", Type: domain.TypeA, Content: "1.1.1.1"},
			{ID: "r2", ZoneID: "z1", Name: "www.test.", Type: domain.TypeA, Content: "2.2.2.2"},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDnsPacket()
	req.Header.Opcode = packet.OPCODE_UPDATE
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "test.test.", QType: packet.SOA})
	// Delete specific record: Class NONE (254), Type A, matching IP 1.1.1.1
	req.Authorities = append(req.Authorities, packet.DnsRecord{
		Name: "www.test.", Type: packet.A, Class: 254, IP: net.ParseIP("1.1.1.1"),
	})

	buf := packet.NewBytePacketBuffer()
	req.Write(buf)
	srv.handlePacket(buf.Buf[:buf.Position()], "127.0.0.1:1", func(resp []byte) error { return nil })

	// Verify only 2.2.2.2 remains
	count := 0
	for _, r := range repo.records {
		if r.Name == "www.test." && r.Type == domain.TypeA { count++ }
	}
	if count != 1 {
		t.Errorf("Expected 1 record to remain, got %d", count)
	}
}

// TestHandleUpdateTSIG verifies that Dynamic Updates are correctly authenticated
// using TSIG signatures (RFC 2845).
func TestHandleUpdateTSIG(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{
			{ID: "zone-1", Name: "tsig.test."},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)
	srv.TsigKeys["testkey."] = []byte("secret123")

	req := packet.NewDnsPacket()
	req.Header.Opcode = packet.OPCODE_UPDATE
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "tsig.test.", QType: packet.SOA})
	req.Authorities = append(req.Authorities, packet.DnsRecord{
		Name: "auth.tsig.test.",
		Type: packet.A,
		Class: 1,
		TTL: 300,
		IP: net.ParseIP("1.2.3.4"),
	})

	buffer := packet.NewBytePacketBuffer()
	req.Write(buffer)
	
	// Sign the packet with TSIG
	err := req.SignTSIG(buffer, "testkey.", []byte("secret123"))
	if err != nil {
		t.Fatalf("Failed to sign TSIG: %v", err)
	}
	
	data := buffer.Buf[:buffer.Position()]
	
	parsedReq := packet.NewDnsPacket()
	pBuf := packet.NewBytePacketBuffer()
	pBuf.Load(data)
	parsedReq.FromBuffer(pBuf)

	err = srv.handlePacket(data, "127.0.0.1:12345", func(resp []byte) error {
		resPacket := packet.NewDnsPacket()
		resBuf := packet.NewBytePacketBuffer()
		resBuf.Load(resp)
		resPacket.FromBuffer(resBuf)
		if resPacket.Header.ResCode != packet.RCODE_NOERROR {
			t.Errorf("Expected NOERROR for valid TSIG, got %d", resPacket.Header.ResCode)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("handlePacket failed: %v", err)
	}

	found := false
	for _, r := range repo.records {
		if r.Name == "auth.tsig.test." {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Record was not added after authenticated update")
	}
}

func TestHandleUpdate_ErrorCases(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "error.test."}},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)
	srv.TsigKeys["key1"] = []byte("secret")

	// 1. Invalid ZOCOUNT != 1
	req := packet.NewDnsPacket()
	req.Header.Opcode = packet.OPCODE_UPDATE
	// 0 questions
	buf := packet.NewBytePacketBuffer()
	req.Write(buf)
	srv.handlePacket(buf.Buf[:buf.Position()], "127.0.0.1:1", func(resp []byte) error {
		p := packet.NewDnsPacket()
		pb := packet.NewBytePacketBuffer()
		pb.Load(resp)
		p.FromBuffer(pb)
		if p.Header.ResCode != packet.RCODE_FORMERR {
			t.Errorf("Expected FORMERR for ZOCOUNT=0, got %d", p.Header.ResCode)
		}
		return nil
	})

	// 2. Unknown TSIG key
	req2 := packet.NewDnsPacket()
	req2.Header.Opcode = packet.OPCODE_UPDATE
	req2.Questions = append(req2.Questions, packet.DnsQuestion{Name: "error.test.", QType: packet.SOA})
	buf2 := packet.NewBytePacketBuffer()
	req2.Write(buf2)
	req2.SignTSIG(buf2, "unknown.", []byte("any"))
	srv.handlePacket(buf2.Buf[:buf2.Position()], "127.0.0.1:1", func(resp []byte) error {
		p := packet.NewDnsPacket()
		pb := packet.NewBytePacketBuffer()
		pb.Load(resp)
		p.FromBuffer(pb)
		if p.Header.ResCode != packet.RCODE_NOTAUTH {
			t.Errorf("Expected NOTAUTH for unknown TSIG, got %d", p.Header.ResCode)
		}
		return nil
	})

	// 3. Not authoritative zone
	req3 := packet.NewDnsPacket()
	req3.Header.Opcode = packet.OPCODE_UPDATE
	req3.Questions = append(req3.Questions, packet.DnsQuestion{Name: "notauth.test.", QType: packet.SOA})
	buf3 := packet.NewBytePacketBuffer()
	req3.Write(buf3)
	srv.handlePacket(buf3.Buf[:buf3.Position()], "127.0.0.1:1", func(resp []byte) error {
		p := packet.NewDnsPacket()
		pb := packet.NewBytePacketBuffer()
		pb.Load(resp)
		p.FromBuffer(pb)
		if p.Header.ResCode != packet.RCODE_NOTAUTH {
			t.Errorf("Expected NOTAUTH for non-existent zone, got %d", p.Header.ResCode)
		}
		return nil
	})
}

func TestCheckPrerequisite_RRset(t *testing.T) {
	repo := &mockServerRepo{
		records: []domain.Record{
			{Name: "exists.test.", Type: domain.TypeA, Content: "1.1.1.1"},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)
	ctx := context.Background()
	zone := &domain.Zone{ID: "z1"}

	// 1. RRset exists (value independent) - SUCCESS
	err := srv.checkPrerequisite(ctx, zone, packet.DnsRecord{Name: "exists.test.", Type: packet.A, Class: 255})
	if err != nil { t.Errorf("Expected success, got %v", err) }

	// 2. RRset exists - FAILURE (doesn't exist)
	err = srv.checkPrerequisite(ctx, zone, packet.DnsRecord{Name: "missing.test.", Type: packet.A, Class: 255})
	if err == nil { t.Errorf("Expected error for missing RRset") }

	// 3. RRset does NOT exist - SUCCESS
	err = srv.checkPrerequisite(ctx, zone, packet.DnsRecord{Name: "missing.test.", Type: packet.A, Class: 254})
	if err != nil { t.Errorf("Expected success, got %v", err) }

	// 4. RRset does NOT exist - FAILURE (it exists)
	err = srv.checkPrerequisite(ctx, zone, packet.DnsRecord{Name: "exists.test.", Type: packet.A, Class: 254})
	if err == nil { t.Errorf("Expected error for existing RRset check") }
}
