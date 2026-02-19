package packet

import (
	"net"
	"testing"
)

func TestDNSRecord_RoundTrip_AllTypes(t *testing.T) {
	testCases := []struct {
		name string
		rec  DNSRecord
	}{
		{
			name: "A",
			rec:  DNSRecord{Name: "a.test.", Type: A, Class: 1, TTL: 60, IP: net.ParseIP("1.2.3.4")},
		},
		{
			name: "AAAA",
			rec:  DNSRecord{Name: "aaaa.test.", Type: AAAA, Class: 1, TTL: 60, IP: net.ParseIP("2001:db8::1")},
		},
		{
			name: "NS",
			rec:  DNSRecord{Name: "ns.test.", Type: NS, Class: 1, TTL: 60, Host: "ns1.test."},
		},
		{
			name: "CNAME",
			rec:  DNSRecord{Name: "cname.test.", Type: CNAME, Class: 1, TTL: 60, Host: "real.test."},
		},
		{
			name: "MX",
			rec:  DNSRecord{Name: "mx.test.", Type: MX, Class: 1, TTL: 60, Priority: 10, Host: "mail.test."},
		},
		{
			name: "TXT",
			rec:  DNSRecord{Name: "txt.test.", Type: TXT, Class: 1, TTL: 60, Txt: "hello world"},
		},
		{
			name: "SOA",
			rec:  DNSRecord{Name: "soa.test.", Type: SOA, Class: 1, TTL: 60, MName: "ns1.test.", RName: "admin.test.", Serial: 1, Refresh: 2, Retry: 3, Expire: 4, Minimum: 5},
		},
		{
			name: "HINFO",
			rec:  DNSRecord{Name: "hinfo.test.", Type: HINFO, Class: 1, TTL: 60, CPU: "ARM64", OS: "LINUX"},
		},
		{
			name: "MINFO",
			rec:  DNSRecord{Name: "minfo.test.", Type: MINFO, Class: 1, TTL: 60, RMailBX: "a.test.", EMailBX: "b.test."},
		},
		{
			name: "NSEC",
			rec:  DNSRecord{Name: "nsec.test.", Type: NSEC, Class: 1, TTL: 60, NextName: "z.test.", TypeBitMap: []byte{0, 1, 2}},
		},
		{
			name: "DNSKEY",
			rec:  DNSRecord{Name: "dnskey.test.", Type: DNSKEY, Class: 1, TTL: 60, Flags: 256, Algorithm: 13, PublicKey: []byte{1, 2, 3, 4}},
		},
		{
			name: "RRSIG",
			rec:  DNSRecord{Name: "rrsig.test.", Type: RRSIG, Class: 1, TTL: 60, TypeCovered: uint16(A), Algorithm: 13, Labels: 2, OrigTTL: 60, Expiration: 100, Inception: 50, KeyTag: 123, SignerName: "test.", Signature: []byte{1, 2, 3, 4}},
		},
		{
			name: "NSEC3",
			rec:  DNSRecord{Name: "nsec3.test.", Type: NSEC3, Class: 1, TTL: 60, HashAlg: 1, Flags: 1, Iterations: 10, Salt: []byte{1, 2}, NextHash: []byte{3, 4, 5}, TypeBitMap: []byte{6, 7}},
		},
		{
			name: "NSEC3PARAM",
			rec:  DNSRecord{Name: "nsec3param.test.", Type: NSEC3PARAM, Class: 1, TTL: 60, HashAlg: 1, Flags: 0, Iterations: 10, Salt: []byte{1, 2, 3}},
		},
		{
			name: "DS",
			rec:  DNSRecord{Name: "ds.test.", Type: DS, Class: 1, TTL: 60, KeyTag: 123, Algorithm: 13, DigestType: 2, Digest: []byte{1, 2, 3, 4}},
		},
		{
			name: "OPT",
			rec:  DNSRecord{Name: ".", Type: OPT, Class: 4096, UDPPayloadSize: 4096, ExtendedRcode: 1, EDNSVersion: 0, Z: 0, Options: []EdnsOption{{Code: 1, Data: []byte{1, 2}}}},
		},
		{
			name: "TSIG",
			rec:  DNSRecord{Name: "key.test.", Type: TSIG, Class: 255, TTL: 0, AlgorithmName: "hmac-sha256.", TimeSigned: 123, Fudge: 300, MAC: []byte{1, 2, 3}, OriginalID: 456, Error: 0, Other: []byte{7, 8}},
		},
		{
			name: "MD",
			rec:  DNSRecord{Name: "md.test.", Type: MD, Class: 1, TTL: 60, Host: "target.test."},
		},
		{
			name: "MF",
			rec:  DNSRecord{Name: "mf.test.", Type: MF, Class: 1, TTL: 60, Host: "target.test."},
		},
		{
			name: "MB",
			rec:  DNSRecord{Name: "mb.test.", Type: MB, Class: 1, TTL: 60, Host: "target.test."},
		},
		{
			name: "MG",
			rec:  DNSRecord{Name: "mg.test.", Type: MG, Class: 1, TTL: 60, Host: "target.test."},
		},
		{
			name: "MR",
			rec:  DNSRecord{Name: "mr.test.", Type: MR, Class: 1, TTL: 60, Host: "target.test."},
		},
		{
			name: "PTR",
			rec:  DNSRecord{Name: "ptr.test.", Type: PTR, Class: 1, TTL: 60, Host: "target.test."},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := NewBytePacketBuffer()
			_, err := tc.rec.Write(buf)
			if err != nil {
				t.Fatalf("Write failed: %v", err)
			}

			buf.Len = buf.Pos
			_ = buf.Seek(0)
			
			var parsed DNSRecord
			err = parsed.Read(buf)
			if err != nil {
				t.Fatalf("Read failed: %v", err)
			}

			// Basic validation
			if parsed.Type != tc.rec.Type {
				t.Errorf("Type mismatch: got %v, want %v", parsed.Type, tc.rec.Type)
			}
			
			if parsed.Name != tc.rec.Name && !(tc.rec.Name == "" && parsed.Name == ".") {
				t.Errorf("Name mismatch: got %s, want %s", parsed.Name, tc.rec.Name)
			}
		})
	}
}
