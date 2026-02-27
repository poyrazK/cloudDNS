package packet

import (
	"net"
	"testing"
)

// TestPacketCoverage_WriteErrorExhaustive tests every single byte boundary failure
// in the DNSRecord.Write method to cover all error branches.
func TestPacketCoverage_WriteErrorExhaustive(t *testing.T) {
	records := []DNSRecord{
		{Name: "a.test.", Type: A, Class: 1, TTL: 60, IP: net.ParseIP("1.1.1.1").To4()},
		{Name: "aaaa.test.", Type: AAAA, Class: 1, TTL: 60, IP: net.ParseIP("2001:db8::1")},
		{Name: "ns.test.", Type: NS, Class: 1, Host: "ns1.test."},
		{Name: "cname.test.", Type: CNAME, Class: 1, Host: "target.test."},
		{Name: "mx.test.", Type: MX, Class: 1, Priority: 10, Host: "mail.test."},
		{Name: "soa.test.", Type: SOA, Class: 1, MName: "m.test.", RName: "r.test.", Serial: 1, Refresh: 2, Retry: 3, Expire: 4, Minimum: 5},
		{Name: "txt.test.", Type: TXT, Class: 1, Txt: "hello world"},
		{Name: "srv.test.", Type: SRV, Class: 1, Priority: 1, Weight: 2, Port: 80, Host: "srv.test."},
		{Name: "opt.test.", Type: OPT, Class: 4096, Options: []EdnsOption{{Code: 15, Data: []byte{1, 2, 3}}}},
		{Name: "hinfo.test.", Type: HINFO, Class: 1, CPU: "intel", OS: "linux"},
		{Name: "minfo.test.", Type: MINFO, Class: 1, RMailBX: "r.test.", EMailBX: "e.test."},
		{Name: "dnskey.test.", Type: DNSKEY, Class: 1, Flags: 256, Algorithm: 13, PublicKey: []byte{1, 2, 3, 4}},
		{Name: "ds.test.", Type: DS, Class: 1, KeyTag: 123, Algorithm: 13, DigestType: 1, Digest: []byte{1, 2}},
		{Name: "rrsig.test.", Type: RRSIG, Class: 1, TypeCovered: uint16(A), Algorithm: 13, Labels: 2, OrigTTL: 300, Expiration: 1000, Inception: 500, KeyTag: 123, SignerName: "test.", Signature: []byte{1, 2, 3}},
		{Name: "nsec.test.", Type: NSEC, Class: 1, NextName: "z.test.", TypeBitMap: []byte{1, 2}},
		{Name: "nsec3.test.", Type: NSEC3, Class: 1, HashAlg: 1, Flags: 0, Iterations: 10, Salt: []byte{1}, NextHash: []byte{2}, TypeBitMap: []byte{3}},
		{Name: "nsec3param.test.", Type: NSEC3PARAM, Class: 1, HashAlg: 1, Flags: 0, Iterations: 10, Salt: []byte{1}},
		{Name: "tsig.test.", Type: TSIG, Class: 255, AlgorithmName: "hmac.", TimeSigned: 123, Fudge: 300, MAC: []byte{1}, OriginalID: 1, Error: 0, Other: []byte{1}},
		{Type: A, Class: 255}, // ANY class deletion
	}

	for _, r := range records {
		t.Run(r.Type.String(), func(t *testing.T) {
			buf := NewBytePacketBuffer()
			written, err := r.Write(buf)
			if err != nil {
				t.Fatalf("Failed to do baseline write for type %v: %v", r.Type, err)
			}
			totalBytes := written

			// Now, for every byte from 1 to totalBytes-1, we simulate a buffer boundary
			// by setting Pos so that it hits MaxPacketSize exactly at that relative offset.
			for limit := 1; limit < totalBytes; limit++ {
				failBuf := NewBytePacketBuffer()
				// Adjust starting Pos so we only have 'limit' bytes available to write
				failBuf.Pos = MaxPacketSize - limit
				_, err := r.Write(failBuf)
				if err == nil {
					t.Errorf("Expected write to fail at limit %d/%d for type %v", limit, totalBytes, r.Type)
				}
			}
		})
	}
}

// TestPacketCoverage_ReadErrorExhaustive tests every single byte boundary failure
// in the DNSRecord.Read method to cover all error branches.
func TestPacketCoverage_ReadErrorExhaustive(t *testing.T) {
	records := []DNSRecord{
		{Name: "a.test.", Type: A, Class: 1, TTL: 60, IP: net.ParseIP("1.1.1.1").To4()},
		{Name: "aaaa.test.", Type: AAAA, Class: 1, TTL: 60, IP: net.ParseIP("2001:db8::1")},
		{Name: "ns.test.", Type: NS, Class: 1, Host: "ns1.test."},
		{Name: "mx.test.", Type: MX, Class: 1, Priority: 10, Host: "mail.test."},
		{Name: "soa.test.", Type: SOA, Class: 1, MName: "m.test.", RName: "r.test.", Serial: 1, Refresh: 2, Retry: 3, Expire: 4, Minimum: 5},
		{Name: "txt.test.", Type: TXT, Class: 1, Txt: "hello world"},
		{Name: "srv.test.", Type: SRV, Class: 1, Priority: 1, Weight: 2, Port: 80, Host: "srv.test."},
		{Name: "opt.test.", Type: OPT, Class: 4096, Options: []EdnsOption{{Code: 15, Data: []byte{1, 2, 3}}}},
		{Name: "hinfo.test.", Type: HINFO, Class: 1, CPU: "intel", OS: "linux"},
		{Name: "minfo.test.", Type: MINFO, Class: 1, RMailBX: "r.test.", EMailBX: "e.test."},
		{Name: "dnskey.test.", Type: DNSKEY, Class: 1, Flags: 256, Algorithm: 13, PublicKey: []byte{1, 2, 3, 4}},
		{Name: "ds.test.", Type: DS, Class: 1, KeyTag: 123, Algorithm: 13, DigestType: 1, Digest: []byte{1, 2}},
		{Name: "rrsig.test.", Type: RRSIG, Class: 1, TypeCovered: uint16(A), Algorithm: 13, Labels: 2, OrigTTL: 300, Expiration: 1000, Inception: 500, KeyTag: 123, SignerName: "test.", Signature: []byte{1, 2, 3}},
		{Name: "nsec.test.", Type: NSEC, Class: 1, NextName: "z.test.", TypeBitMap: []byte{1, 2}},
		{Name: "nsec3.test.", Type: NSEC3, Class: 1, HashAlg: 1, Flags: 0, Iterations: 10, Salt: []byte{1}, NextHash: []byte{2}, TypeBitMap: []byte{3}},
		{Name: "nsec3param.test.", Type: NSEC3PARAM, Class: 1, HashAlg: 1, Flags: 0, Iterations: 10, Salt: []byte{1}},
		{Name: "tsig.test.", Type: TSIG, Class: 255, AlgorithmName: "hmac.", TimeSigned: 123, Fudge: 300, MAC: []byte{1}, OriginalID: 1, Error: 0, Other: []byte{1}},
	}

	for _, r := range records {
		t.Run(r.Type.String(), func(t *testing.T) {
			buf := NewBytePacketBuffer()
			_, err := r.Write(buf)
			if err != nil {
				t.Fatalf("Failed to do baseline write for type %v: %v", r.Type, err)
			}

			totalBytes := buf.Position()

			for truncateLimit := 1; truncateLimit < totalBytes; truncateLimit++ {
				failBuf := NewBytePacketBuffer()
				failBuf.Load(buf.Buf[:truncateLimit])

				var parsed DNSRecord
				err := parsed.Read(failBuf)
				if err == nil {
					t.Errorf("Expected read to fail at truncation %d/%d for type %v", truncateLimit, totalBytes, r.Type)
				}
			}
		})
	}
}
