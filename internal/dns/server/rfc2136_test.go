package server

import (
	"context"
	"errors"
	"net"
	"strings"
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

	req := packet.NewDNSPacket()
	req.Header.ID = 100
	req.Header.Opcode = packet.OpcodeUpdate
	// Zone Section: Specifies the zone being updated
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "example.test.", QType: packet.SOA})
	// Update Section: The record to be added (Class IN)
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name:  "new.example.test.",
		Type:  packet.A,
		Class: 1, // IN -> Add
		TTL:   3600,
		IP:    net.ParseIP("192.168.1.10"),
	})

	buffer := packet.NewBytePacketBuffer()
	_ = req.Write(buffer)
	data := buffer.Buf[:buffer.Position()]

	var capturedResp []byte
	err := srv.handlePacket(data, "127.0.0.1:12345", func(resp []byte) error {
		capturedResp = resp
		return nil
	}, "udp")

	if err != nil {
		t.Fatalf("HandlePacket failed: %v", err)
	}

	resPacket := packet.NewDNSPacket()
	pBuf := packet.NewBytePacketBuffer()
	pBuf.Load(capturedResp)
	_ = resPacket.FromBuffer(pBuf)

	if resPacket.Header.ResCode != packet.RcodeNoError {
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
			{ID: "soa1", ZoneID: "zone-1", Name: "example.test.", Type: domain.TypeSOA, Content: "ns1. ns2. 1 3600 600 604800 300"},
			{ZoneID: "zone-1", Name: "del.example.test.", Type: domain.TypeA, Content: "1.1.1.1"},
			{ZoneID: "zone-1", Name: "del.example.test.", Type: domain.TypeA, Content: "2.2.2.2"},
			{ZoneID: "zone-1", Name: "del.example.test.", Type: domain.TypeTXT, Content: "keep me"},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDNSPacket()
	req.Header.Opcode = packet.OpcodeUpdate
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "example.test.", QType: packet.SOA})
	// Delete RRSet: Class ANY (255), Type A
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name:  "del.example.test.",
		Type:  packet.A,
		Class: 255, // ANY -> Delete RRset
	})

	buffer := packet.NewBytePacketBuffer()
	_ = req.Write(buffer)
	data := buffer.Buf[:buffer.Position()]

	if err := srv.handlePacket(data, "127.0.0.1:12345", func(_ []byte) error { return nil }, "udp"); err != nil {
		t.Errorf("handlePacket failed: %v", err)
	}

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

	req := packet.NewDNSPacket()
	req.Header.Opcode = packet.OpcodeUpdate
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "example.test.", QType: packet.SOA})
	// Prerequisite: Name is in use (Class ANY, Type ANY)
	req.Answers = append(req.Answers, packet.DNSRecord{
		Name:  "missing.example.test.",
		Type:  255, // ANY
		Class: 255, // ANY
	})

	buffer := packet.NewBytePacketBuffer()
	_ = req.Write(buffer)
	data := buffer.Buf[:buffer.Position()]

	var capturedResp []byte
	err := srv.handlePacket(data, "127.0.0.1:12345", func(resp []byte) error {
		capturedResp = resp
		return nil
	}, "udp")
	if err != nil {
		t.Fatalf("handlePacket failed: %v", err)
	}

	resPacket := packet.NewDNSPacket()
	pBuf := packet.NewBytePacketBuffer()
	pBuf.Load(capturedResp)
	_ = resPacket.FromBuffer(pBuf)

	if resPacket.Header.ResCode != packet.RcodeNxDomain {
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
	req := packet.NewDNSPacket()
	req.Header.Opcode = packet.OpcodeUpdate
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "test.test.", QType: packet.SOA})
	req.Answers = append(req.Answers, packet.DNSRecord{
		Name: "exists.test.", Type: packet.A, Class: 255,
	})

	buf := packet.NewBytePacketBuffer()
	_ = req.Write(buf)
	if err := srv.handlePacket(buf.Buf[:buf.Position()], "127.0.0.1:1", func(_ []byte) error {
		return nil
	}, "udp"); err != nil {
		t.Errorf("handlePacket failed: %v", err)
	}

	// 2. Failure case: "Name NOT in use" but name exists
	req2 := packet.NewDNSPacket()
	req2.Header.Opcode = packet.OpcodeUpdate
	req2.Questions = append(req2.Questions, packet.DNSQuestion{Name: "test.test.", QType: packet.SOA})
	req2.Answers = append(req2.Answers, packet.DNSRecord{
		Name: "exists.test.", Type: 255, Class: 254, // NONE/ANY -> YXDOMAIN if name in use
	})
	buf2 := packet.NewBytePacketBuffer()
	_ = req2.Write(buf2)
	if err := srv.handlePacket(buf2.Buf[:buf2.Position()], "127.0.0.1:1", func(resp []byte) error {
		p := packet.NewDNSPacket()
		pb := packet.NewBytePacketBuffer()
		pb.Load(resp)
		_ = p.FromBuffer(pb)
		if p.Header.ResCode != packet.RcodeYxDomain {
			t.Errorf("Expected YXDOMAIN for existing name check, got %d", p.Header.ResCode)
		}
		return nil
	}, "udp"); err != nil {
		t.Errorf("handlePacket failed: %v", err)
	}
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

	req := packet.NewDNSPacket()
	req.Header.Opcode = packet.OpcodeUpdate
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "test.test.", QType: packet.SOA})
	// Delete specific record: Class NONE (254), Type A, matching IP 1.1.1.1
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name: "www.test.", Type: packet.A, Class: 254, IP: net.ParseIP("1.1.1.1"),
	})

	buf := packet.NewBytePacketBuffer()
	_ = req.Write(buf)
	if err := srv.handlePacket(buf.Buf[:buf.Position()], "127.0.0.1:1", func(_ []byte) error { return nil }, "udp"); err != nil {
		t.Errorf("handlePacket failed: %v", err)
	}

	// Verify only 2.2.2.2 remains
	count := 0
	for _, r := range repo.records {
		if strings.TrimSuffix(r.Name, ".") == "www.test" && r.Type == domain.TypeA {
			count++
		}
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

	req := packet.NewDNSPacket()
	req.Header.Opcode = packet.OpcodeUpdate
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "tsig.test.", QType: packet.SOA})
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name:  "auth.tsig.test.",
		Type:  packet.A,
		Class: 1,
		TTL:   300,
		IP:    net.ParseIP("1.2.3.4"),
	})

	buffer := packet.NewBytePacketBuffer()
	_ = req.Write(buffer)

	// Sign the packet with TSIG
	err := req.SignTSIG(buffer, "testkey.", []byte("secret123"))
	if err != nil {
		t.Fatalf("Failed to sign TSIG: %v", err)
	}

	data := buffer.Buf[:buffer.Position()]

	parsedReq := packet.NewDNSPacket()
	pBuf := packet.NewBytePacketBuffer()
	pBuf.Load(data)
	_ = parsedReq.FromBuffer(pBuf)

	if err := srv.handlePacket(data, "127.0.0.1:12345", func(resp []byte) error {
		resPacket := packet.NewDNSPacket()
		resBuf := packet.NewBytePacketBuffer()
		resBuf.Load(resp)
		_ = resPacket.FromBuffer(resBuf)
		if resPacket.Header.ResCode != packet.RcodeNoError {
			t.Errorf("Expected NOERROR for valid TSIG, got %d", resPacket.Header.ResCode)
		}
		return nil
	}, "udp"); err != nil {
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
	req := packet.NewDNSPacket()
	req.Header.Opcode = packet.OpcodeUpdate
	// 0 questions
	buf := packet.NewBytePacketBuffer()
	_ = req.Write(buf)
	if err := srv.handlePacket(buf.Buf[:buf.Position()], "127.0.0.1:1", func(resp []byte) error {
		p := packet.NewDNSPacket()
		pb := packet.NewBytePacketBuffer()
		pb.Load(resp)
		_ = p.FromBuffer(pb)
		if p.Header.ResCode != packet.RcodeFormErr {
			t.Errorf("Expected FORMERR for ZOCOUNT=0, got %d", p.Header.ResCode)
		}
		return nil
	}, "udp"); err != nil {
		t.Errorf("handlePacket failed: %v", err)
	}

	// 2. Unknown TSIG key
	req2 := packet.NewDNSPacket()
	req2.Header.Opcode = packet.OpcodeUpdate
	req2.Questions = append(req2.Questions, packet.DNSQuestion{Name: "error.test.", QType: packet.SOA})
	buf2 := packet.NewBytePacketBuffer()
	_ = req2.Write(buf2)
	_ = req2.SignTSIG(buf2, "unknown.", []byte("any"))
	if err := srv.handlePacket(buf2.Buf[:buf2.Position()], "127.0.0.1:1", func(resp []byte) error {
		p := packet.NewDNSPacket()
		pb := packet.NewBytePacketBuffer()
		pb.Load(resp)
		_ = p.FromBuffer(pb)
		if p.Header.ResCode != packet.RcodeNotAuth {
			t.Errorf("Expected NOTAUTH for unknown TSIG, got %d", p.Header.ResCode)
		}
		return nil
	}, "udp"); err != nil {
		t.Errorf("handlePacket failed: %v", err)
	}

	// 3. Not authoritative zone
	req3 := packet.NewDNSPacket()
	req3.Header.Opcode = packet.OpcodeUpdate
	req3.Questions = append(req3.Questions, packet.DNSQuestion{Name: "notauth.test.", QType: packet.SOA})
	buf3 := packet.NewBytePacketBuffer()
	_ = req3.Write(buf3)
	if err := srv.handlePacket(buf3.Buf[:buf3.Position()], "127.0.0.1:1", func(resp []byte) error {
		p := packet.NewDNSPacket()
		pb := packet.NewBytePacketBuffer()
		pb.Load(resp)
		_ = p.FromBuffer(pb)
		if p.Header.ResCode != packet.RcodeNotAuth {
			t.Errorf("Expected NOTAUTH for non-existent zone, got %d", p.Header.ResCode)
		}
		return nil
	}, "udp"); err != nil {
		t.Errorf("handlePacket failed: %v", err)
	}
}

func TestCheckPrerequisite_GetRecordsError(t *testing.T) {
	repo := &mockServerRepo{
		zones:          []domain.Zone{{ID: "z1", Name: "update.test."}},
		failGetRecords: true,
	}
	srv := NewServer(":0", repo, nil)

	req := packet.NewDNSPacket()
	req.Header.ID = 9999
	req.Header.Opcode = packet.OpcodeUpdate
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "update.test.", QType: packet.SOA})
	req.Answers = append(req.Answers, packet.DNSRecord{
		Name: "any.update.test.", Type: packet.A, Class: 255,
	})

	_ = srv.handleUpdate(req, nil, "127.0.0.1", func(resp []byte) error {
		res := packet.NewDNSPacket()
		pb := packet.NewBytePacketBuffer()
		pb.Load(resp)
		_ = res.FromBuffer(pb)
		if res.Header.ResCode != packet.RcodeServFail {
			t.Errorf("Expected SERVFAIL for repo error, got %d", res.Header.ResCode)
		}
		return nil
	})
}

// TestCheckPrerequisite_MoreBranches covers missing branches in checkPrerequisite.
func TestCheckPrerequisite_MoreBranches(t *testing.T) {
	repo := &mockServerRepo{
		records: []domain.Record{
			{Name: "exists.test.", Type: domain.TypeA, Content: "1.1.1.1"},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)
	ctx := context.Background()

	assertRcode := func(err error, expectedRcode int) {
		t.Helper()
		var uErr updateError
		if !errors.As(err, &uErr) {
			t.Fatalf("Expected updateError, got %v", err)
		}
		if uErr.rcode != expectedRcode {
			t.Errorf("Expected rcode %d, got %d", expectedRcode, uErr.rcode)
		}
	}

	// 1. Class ANY (255), Type ANY (255), exists -> Success
	err := srv.checkPrerequisite(ctx, packet.DNSRecord{Name: "exists.test.", Type: 255, Class: 255})
	if err != nil {
		t.Errorf("Expected success, got %v", err)
	}

	// 2. Class ANY (255), Type A, exists -> Success
	err = srv.checkPrerequisite(ctx, packet.DNSRecord{Name: "exists.test.", Type: packet.A, Class: 255})
	if err != nil {
		t.Errorf("Expected success, got %v", err)
	}

	// 3. Class NONE (254), Type ANY (255), exists -> YXDOMAIN
	err = srv.checkPrerequisite(ctx, packet.DNSRecord{Name: "exists.test.", Type: 255, Class: 254})
	assertRcode(err, int(packet.RcodeYxDomain))

	// 4. Class NONE (254), Type A, exists -> YXRRSET
	err = srv.checkPrerequisite(ctx, packet.DNSRecord{Name: "exists.test.", Type: packet.A, Class: 254})
	assertRcode(err, int(packet.RcodeYxRRSet))

	// 5. Class IN (1), Type A, missing -> NXRRSET
	err = srv.checkPrerequisite(ctx, packet.DNSRecord{Name: "missing.test.", Type: packet.A, Class: 1})
	assertRcode(err, int(packet.RcodeNxRRSet))
}

// TestApplyUpdate_TransactionRollback verifies that if a database failure occurs
// mid-update, the entire transaction is rolled back and no partial updates remain.
func TestApplyUpdate_TransactionRollback(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "rollback.test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "rollback.test.", Type: domain.TypeSOA, Content: "ns1. ns2. 1 2 3 4 5"},
		},
	}
	srv := NewServer(":0", repo, nil)

	req := packet.NewDNSPacket()
	req.Header.Opcode = packet.OpcodeUpdate
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "rollback.test.", QType: packet.SOA})

	// Two updates:
	// 1. Add valid A record
	// 2. Add another A record, but we'll trigger a failure here
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name: "a1.rollback.test.", Type: packet.A, Class: 1, TTL: 60, IP: net.ParseIP("1.1.1.1"),
	})
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name: "fail.rollback.test.", Type: packet.A, Class: 1, TTL: 60, IP: net.ParseIP("9.9.9.9"),
	})

	// Inject deterministic failure for the second record
	repo.failOnRecordName = "fail.rollback.test."

	_ = srv.handleUpdate(req, nil, "127.0.0.1", func(resp []byte) error {
		res := packet.NewDNSPacket()
		pb := packet.NewBytePacketBuffer()
		pb.Load(resp)
		_ = res.FromBuffer(pb)
		if res.Header.ResCode != packet.RcodeServFail {
			t.Errorf("Expected SERVFAIL on transaction failure, got %d", res.Header.ResCode)
		}
		return nil
	})

	// Verify NO records were added (atomicity)
	// Original state: 1 SOA record
	if len(repo.records) != 1 {
		t.Errorf("Expected 1 record after rollback, got %d", len(repo.records))
	}
	if repo.records[0].Type != domain.TypeSOA {
		t.Errorf("Expected only SOA record to remain")
	}
}

// TestPrepareUpdate_ConvertErrorNone verifies that prepareUpdate returns an error
// if record conversion fails during a Class NONE (delete specific) update.
func TestPrepareUpdate_ConvertErrorNone(t *testing.T) {
	srv := NewServer(":0", &mockServerRepo{}, nil)
	up := packet.DNSRecord{
		Name:  "test.com.",
		Type:  999, // Unsupported
		Class: 254, // NONE
	}
	_, _, err := srv.prepareUpdate("z1", up)
	if err == nil {
		t.Errorf("Expected error for unsupported type in Class NONE update")
	}
}

// TestHandleUpdateDeleteRRSetSpecific verifies the deletion of an entire RRset of a specific type.
func TestHandleUpdateDeleteRRSetSpecific(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "spec.test."}},
		records: []domain.Record{
			{ID: "soa1", ZoneID: "z1", Name: "spec.test.", Type: domain.TypeSOA, Content: "ns1. ns2. 1 3600 600 604800 300"},
			{ZoneID: "z1", Name: "www.spec.test.", Type: domain.TypeA, Content: "1.1.1.1"},
			{ZoneID: "z1", Name: "www.spec.test.", Type: domain.TypeTXT, Content: "keep me"},
		},
	}
	srv := NewServer(":0", repo, nil)

	req := packet.NewDNSPacket()
	req.Header.Opcode = packet.OpcodeUpdate
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "spec.test.", QType: packet.SOA})
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name: "www.spec.test.", Type: packet.A, Class: 255,
	})

	err := srv.handleUpdate(req, nil, "127.0.0.1", func(resp []byte) error {
		res := packet.NewDNSPacket()
		pb := packet.NewBytePacketBuffer()
		pb.Load(resp)
		_ = res.FromBuffer(pb)
		if res.Header.ResCode != packet.RcodeNoError {
			t.Errorf("Expected NOERROR for RRSet delete update, got %d", res.Header.ResCode)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("handleUpdate failed: %v", err)
	}

	for _, r := range repo.records {
		if r.Name == "www.spec.test." && r.Type == domain.TypeA {
			t.Errorf("A record should have been deleted")
		}
	}
}

func TestHandleUpdate_SOAFetchError(t *testing.T) {
	repo := &mockServerRepo{
		zones:          []domain.Zone{{ID: "z1", Name: "soaerr.test."}},
		failGetRecords: true, // Fail fetching SOA
	}
	srv := NewServer(":0", repo, nil)

	req := packet.NewDNSPacket()
	req.Header.ID = 0
	req.Header.Opcode = packet.OpcodeUpdate
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "soaerr.test.", QType: packet.SOA})
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name: "new.soaerr.test.", Type: packet.A, Class: 1, TTL: 60, IP: net.ParseIP("1.1.1.1"),
	})

	_ = srv.handleUpdate(req, nil, "127.0.0.1", func(resp []byte) error {
		p := packet.NewDNSPacket()
		pb := packet.NewBytePacketBuffer()
		pb.Load(resp)
		_ = p.FromBuffer(pb)
		if p.Header.ResCode != packet.RcodeServFail {
			t.Errorf("Expected SERVFAIL, got %d", p.Header.ResCode)
		}
		return nil
	})
}

func TestHandleUpdate_SOADeleteError(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "soadel.test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "soadel.test.", Type: domain.TypeSOA, Content: "ns1. ns2. 1 2 3 4 5"},
		},
		failDeleteSOA: true,
	}
	srv := NewServer(":0", repo, nil)

	req := packet.NewDNSPacket()
	req.Header.ID = 0
	req.Header.Opcode = packet.OpcodeUpdate
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "soadel.test.", QType: packet.SOA})
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name: "new.soadel.test.", Type: packet.A, Class: 1, TTL: 60, IP: net.ParseIP("1.1.1.1"),
	})

	_ = srv.handleUpdate(req, nil, "127.0.0.1", func(resp []byte) error {
		p := packet.NewDNSPacket()
		pb := packet.NewBytePacketBuffer()
		pb.Load(resp)
		_ = p.FromBuffer(pb)
		if p.Header.ResCode != packet.RcodeServFail {
			t.Errorf("Expected SERVFAIL, got %d", p.Header.ResCode)
		}
		return nil
	})
}

func TestHandleUpdate_SOACreateError(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "soacrt.test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "soacrt.test.", Type: domain.TypeSOA, Content: "ns1. ns2. 1 2 3 4 5"},
		},
		failCreateSOA: true, // Only fail when creating SOA
	}
	srv := NewServer(":0", repo, nil)

	req := packet.NewDNSPacket()
	req.Header.ID = 0
	req.Header.Opcode = packet.OpcodeUpdate
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "soacrt.test.", QType: packet.SOA})
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name: "new.soacrt.test.", Type: packet.A, Class: 1, TTL: 60, IP: net.ParseIP("1.1.1.1"),
	})

	_ = srv.handleUpdate(req, nil, "127.0.0.1", func(resp []byte) error {
		p := packet.NewDNSPacket()
		pb := packet.NewBytePacketBuffer()
		pb.Load(resp)
		_ = p.FromBuffer(pb)
		if p.Header.ResCode != packet.RcodeServFail {
			t.Errorf("Expected SERVFAIL, got %d", p.Header.ResCode)
		}
		return nil
	})
}

func TestHandleUpdate_ZoneNotFound(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer(":0", repo, nil)

	req := packet.NewDNSPacket()
	req.Header.Opcode = packet.OpcodeUpdate
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "nonexistent.test.", QType: packet.SOA})

	_ = srv.handleUpdate(req, nil, "127.0.0.1", func(resp []byte) error {
		res := packet.NewDNSPacket()
		pb := packet.NewBytePacketBuffer()
		pb.Load(resp)
		_ = res.FromBuffer(pb)
		if res.Header.ResCode != packet.RcodeNotAuth {
			t.Errorf("Expected NOTAUTH for unknown zone, got %d", res.Header.ResCode)
		}
		return nil
	})
}
