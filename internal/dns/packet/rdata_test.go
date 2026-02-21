package packet

import (
	"net"
	"strings"
	"testing"
)

// TestDNSQuestion_WriteError verifies that invalid label lengths correctly trigger errors.
func TestDNSQuestion_WriteError(t *testing.T) {
	// Label too long (> 63 chars) - invalid per RFC 1035
	longLabel := strings.Repeat("a", 64)
	q := NewDNSQuestion(longLabel+".com.", A)
	buf := NewBytePacketBuffer()
	if err := q.Write(buf); err == nil {
		t.Errorf("Expected error for too long label")
	}
}

// TestDNSRecord_AllTypesRoundTrip performs comprehensive serialization/deserialization 
// checks for all supported DNS record types.
func TestDNSRecord_AllTypesRoundTrip(t *testing.T) {
	testCases := []DNSRecord{
		{Name: "a.test.", Type: A, Class: 1, TTL: 60, IP: net.ParseIP("1.2.3.4")},
		{Name: "aaaa.test.", Type: AAAA, Class: 1, TTL: 60, IP: net.ParseIP("2001:db8::1")},
		{Name: "ns.test.", Type: NS, Class: 1, TTL: 60, Host: "ns1.test."},
		{Name: "md.test.", Type: MD, Class: 1, TTL: 60, Host: "md.test."},
		{Name: "mf.test.", Type: MF, Class: 1, TTL: 60, Host: "mf.test."},
		{Name: "mb.test.", Type: MB, Class: 1, TTL: 60, Host: "mb.test."},
		{Name: "mg.test.", Type: MG, Class: 1, TTL: 60, Host: "mg.test."},
		{Name: "mr.test.", Type: MR, Class: 1, TTL: 60, Host: "mr.test."},
		{Name: "cname.test.", Type: CNAME, Class: 1, TTL: 60, Host: "real.test."},
		{Name: "ptr.test.", Type: PTR, Class: 1, TTL: 60, Host: "target.test."},
		{Name: "mx.test.", Type: MX, Class: 1, TTL: 60, Priority: 10, Host: "mail.test."},
		{Name: "txt.test.", Type: TXT, Class: 1, TTL: 60, Txt: "hello world"},
		{Name: "soa.test.", Type: SOA, Class: 1, TTL: 60, MName: "ns.test.", RName: "admin.test.", Serial: 1, Refresh: 2, Retry: 3, Expire: 4, Minimum: 5},
		{Name: "hinfo.test.", Type: HINFO, Class: 1, TTL: 60, CPU: "ARM", OS: "LINUX"},
		{Name: "minfo.test.", Type: MINFO, Class: 1, TTL: 60, RMailBX: "rm.test.", EMailBX: "em.test."},
		{Name: "nsec.test.", Type: NSEC, Class: 1, TTL: 60, NextName: "next.test.", TypeBitMap: []byte{0, 1, 2}},
		{Name: "dnskey.test.", Type: DNSKEY, Class: 1, TTL: 60, Flags: 256, Algorithm: 13, PublicKey: []byte{1, 2, 3, 4}},
		{Name: "rrsig.test.", Type: RRSIG, Class: 1, TTL: 60, TypeCovered: 1, Algorithm: 13, Labels: 2, OrigTTL: 60, Expiration: 100, Inception: 50, KeyTag: 123, SignerName: "test.", Signature: []byte{5, 6, 7, 8}},
		{Name: "nsec3.test.", Type: NSEC3, Class: 1, TTL: 60, HashAlg: 1, Iterations: 10, Salt: []byte{1, 2}, NextHash: []byte{3, 4, 5}, TypeBitMap: []byte{6, 7}},
		{Name: "nsec3p.test.", Type: NSEC3PARAM, Class: 1, TTL: 60, HashAlg: 1, Iterations: 10, Salt: []byte{1, 2}},
		{Name: "ds.test.", Type: DS, Class: 1, TTL: 60, KeyTag: 123, Algorithm: 13, DigestType: 2, Digest: []byte{1, 2, 3, 4}},
		{Name: "opt.test.", Type: OPT, Class: 4096, TTL: 0x01020304}, // EDNS(0)
		{Name: "tsig.test.", Type: TSIG, Class: 0, TTL: 0, AlgorithmName: "hmac-sha256.", TimeSigned: 123456, Fudge: 300, MAC: []byte{1, 2, 3}, OriginalID: 1, Error: 0, Other: []byte{4}},
	}

	for _, tc := range testCases {
		t.Run(tc.Type.String(), func(t *testing.T) {
			buf := NewBytePacketBuffer()
			_, errWrite := tc.Write(buf)
			if errWrite != nil {
				t.Fatalf("Write failed: %v", errWrite)
			}

			// Simulate network transfer by loading the data into a fresh buffer
			data := make([]byte, buf.Position())
			copy(data, buf.Buf[:buf.Position()])
			
			readBuf := NewBytePacketBuffer()
			readBuf.Load(data)
			
			var parsed DNSRecord
			errRead := parsed.Read(readBuf)
			if errRead != nil {
				t.Fatalf("Read failed: %v", errRead)
			}

			if parsed.Type != tc.Type {
				t.Errorf("Type mismatch: got %v, want %v", parsed.Type, tc.Type)
			}
			
			// Specific content verification for common types
			switch tc.Type {
			case A, AAAA:
				if parsed.IP.String() != tc.IP.String() { t.Errorf("IP mismatch") }
			case NS, CNAME, PTR:
				if parsed.Host != tc.Host { t.Errorf("Host mismatch") }
			case MX:
				if parsed.Priority != tc.Priority || parsed.Host != tc.Host { t.Errorf("MX mismatch") }
			case TXT:
				if parsed.Txt != tc.Txt { t.Errorf("TXT mismatch") }
			}
		})
	}
}

// TestDNSRecord_OPTOptions verifies EDNS(0) option serialization (RFC 6891).
func TestDNSRecord_OPTOptions(t *testing.T) {
	rec := DNSRecord{
		Name: ".", Type: OPT, Class: 4096, TTL: 0,
	}
	rec.AddEDE(EdeBlocked, "Blocked") // Extended DNS Error (RFC 8914)
	rec.Options = append(rec.Options, EdnsOption{Code: 10, Data: []byte{1, 2, 3}})

	buf := NewBytePacketBuffer()
	_, err := rec.Write(buf)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	data := buf.Buf[:buf.Position()]
	readBuf := NewBytePacketBuffer()
	readBuf.Load(data)
	
	var parsed DNSRecord
	if err := parsed.Read(readBuf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if len(parsed.Options) != 2 {
		t.Errorf("Expected 2 options, got %d", len(parsed.Options))
	}
}

// TestDNSRecord_TSIGFields ensures TSIG records (RFC 2845) are correctly round-tripped.
func TestDNSRecord_TSIGFields(t *testing.T) {
	rec := DNSRecord{
		Name: "key.", Type: TSIG, Class: 0, TTL: 0,
		AlgorithmName: "hmac-sha256.",
		TimeSigned:    1234567890,
		Fudge:         300,
		MAC:           []byte{1, 2, 3, 4, 5, 6, 7, 8},
		OriginalID:    1234,
		Error:         0,
		Other:         []byte{0xDE, 0xAD},
	}

	buf := NewBytePacketBuffer()
	_, err := rec.Write(buf)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	data := buf.Buf[:buf.Position()]
	readBuf := NewBytePacketBuffer()
	readBuf.Load(data)
	
	var parsed DNSRecord
	if err := parsed.Read(readBuf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if parsed.TimeSigned != rec.TimeSigned || string(parsed.MAC) != string(rec.MAC) || string(parsed.Other) != string(rec.Other) {
		t.Errorf("TSIG fields mismatch: %+v", parsed)
	}
}

// TestDNSPacket_FromBufferError verifies error handling for truncated headers.
func TestDNSPacket_FromBufferError(t *testing.T) {
	buf := NewBytePacketBuffer()
	buf.Load([]byte{1, 2, 3}) // Header is 12 bytes, so this is truncated
	p := NewDNSPacket()
	if err := p.FromBuffer(buf); err == nil {
		t.Errorf("Expected error for truncated header")
	}
}

// TestRFC2136_Classes verifies the special Class ANY and NONE handling 
// required for DNS Dynamic Updates.
func TestRFC2136_Classes(t *testing.T) {
	// Class ANY (255) - used for RRset deletion (RFC 2136 Section 2.5.2)
	// The RDLENGTH MUST be 0.
	anyRec := DNSRecord{
		Name: "test.", Type: A, Class: 255, TTL: 0,
	}
	buf := NewBytePacketBuffer()
	_, _ = anyRec.Write(buf)
	
	readBuf := NewBytePacketBuffer()
	readBuf.Load(buf.Buf[:buf.Position()])
	var parsedAny DNSRecord
	_ = parsedAny.Read(readBuf)
	if parsedAny.Class != 255 {
		t.Errorf("Expected Class ANY (255), got %d", parsedAny.Class)
	}

	// Class NONE (254) - used for specific RR deletion (RFC 2136 Section 2.5.4)
	// This class MUST include RDATA to identify the record to delete.
	noneRec := DNSRecord{
		Name: "test.", Type: A, Class: 254, TTL: 0, IP: net.ParseIP("1.1.1.1"),
	}
	buf2 := NewBytePacketBuffer()
	_, _ = noneRec.Write(buf2)
	
	readBuf2 := NewBytePacketBuffer()
	readBuf2.Load(buf2.Buf[:buf2.Position()])
	var parsedNone DNSRecord
	_ = parsedNone.Read(readBuf2)
	if parsedNone.IP.String() != "1.1.1.1" {
		t.Errorf("Expected IP 1.1.1.1 for Class NONE, got %s", parsedNone.IP.String())
	}
}
