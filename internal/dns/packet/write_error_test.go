package packet

import (
	"net"
	"testing"
)

func TestDNSHeader_WriteError(t *testing.T) {
	h := NewDNSHeader()
	buf := NewBytePacketBuffer()
	buf.Pos = MaxPacketSize - 1
	if err := h.Write(buf); err == nil {
		t.Errorf("Expected error for header write at end of buffer")
	}
}

func TestDNSQuestion_WriteErrorPath(t *testing.T) {
	q := NewDNSQuestion("test.com.", A)
	buf := NewBytePacketBuffer()
	buf.Pos = MaxPacketSize - 1
	if err := q.Write(buf); err == nil {
		t.Errorf("Expected error for question write at end of buffer")
	}
}

func TestDNSRecord_WriteErrorPaths(t *testing.T) {
	buf := NewBytePacketBuffer()
	buf.Pos = MaxPacketSize - 1

	records := []DNSRecord{
		{Name: "a.test.", Type: A, Class: 1, IP: net.ParseIP("1.1.1.1")},
		{Name: "ns.test.", Type: NS, Class: 1, Host: "ns1.test."},
		{Name: "mx.test.", Type: MX, Class: 1, Priority: 10, Host: "mail.test."},
		{Name: "soa.test.", Type: SOA, Class: 1, MName: "n.test.", RName: "a.test."},
		{Name: "opt.test.", Type: OPT, Class: 4096},
		{Name: "tsig.test.", Type: TSIG},
	}

	for _, r := range records {
		t.Run(r.Type.String(), func(t *testing.T) {
			buf.Pos = MaxPacketSize - 1
			if _, err := r.Write(buf); err == nil {
				t.Errorf("Expected error for %v record write at end of buffer", r.Type)
			}
		})
	}
}

func TestDNSRecord_WriteErrorPaths_ObsoleteTypes(t *testing.T) {
	buf := NewBytePacketBuffer()
	records := []DNSRecord{
		{Name: "md.test.", Type: MD, Class: 1, Host: "md.test."},
		{Name: "mf.test.", Type: MF, Class: 1, Host: "mf.test."},
		{Name: "mb.test.", Type: MB, Class: 1, Host: "mb.test."},
		{Name: "mg.test.", Type: MG, Class: 1, Host: "mg.test."},
		{Name: "mr.test.", Type: MR, Class: 1, Host: "mr.test."},
	}

	for _, r := range records {
		t.Run(r.Type.String(), func(t *testing.T) {
			buf.Reset()
			buf.Pos = MaxPacketSize - 1
			if _, err := r.Write(buf); err == nil {
				t.Errorf("Expected error for %v record write at end of buffer", r.Type)
			}
		})
	}
}

func TestDNSRecord_WriteNameError(t *testing.T) {
	buf := NewBytePacketBuffer()
	longLabel := "abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcd" // 64 chars
	r := DNSRecord{Name: longLabel + ".com.", Type: A, Class: 1, IP: net.ParseIP("1.1.1.1")}
	if _, err := r.Write(buf); err == nil {
		t.Errorf("Expected error for too long label in record name")
	}
}

func TestDNSRecord_WriteHostError(t *testing.T) {
	buf := NewBytePacketBuffer()
	longLabel := "abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcd"
	r := DNSRecord{Name: "a.test.", Type: NS, Class: 1, Host: longLabel + ".test."}
	if _, err := r.Write(buf); err == nil {
		t.Errorf("Expected error for too long label in host field")
	}
}


func TestDNSPacket_WriteErrorPaths_Resources(t *testing.T) {
	p := NewDNSPacket()
	// Add enough items to make header valid but fail later
	p.Resources = append(p.Resources, DNSRecord{Name: "res.", Type: A, Class: 1, IP: net.ParseIP("3.3.3.3")})

	buf := NewBytePacketBuffer()
	
	// Fail at Resources
	buf.Pos = MaxPacketSize - 12
	if err := p.Write(buf); err == nil {
		t.Errorf("Expected error at Resources write")
	}
}

func TestDNSRecord_WriteErrorPaths_ComplexTypes(t *testing.T) {
	buf := NewBytePacketBuffer()
	
	// RRSIG
	rrsig := DNSRecord{
		Name: "rrsig.test.", Type: RRSIG, Class: 1, 
		SignerName: "test.", Signature: []byte{1, 2, 3},
	}
	
	// Fail at start
	buf.Reset()
	buf.Pos = MaxPacketSize - 1
	if _, err := rrsig.Write(buf); err == nil {
		t.Errorf("Expected error for RRSIG write at start")
	}

	// DNSKEY
	dnskey := DNSRecord{
		Name: "dnskey.test.", Type: DNSKEY, Class: 1, PublicKey: []byte{1, 2, 3},
	}
	buf.Reset()
	buf.Pos = MaxPacketSize - 1
	if _, err := dnskey.Write(buf); err == nil {
		t.Errorf("Expected error for DNSKEY write at start")
	}

	// NSEC3
	nsec3 := DNSRecord{
		Name: "nsec3.test.", Type: NSEC3, Class: 1, Salt: []byte{1}, NextHash: []byte{2}, TypeBitMap: []byte{0},
	}
	buf.Reset()
	buf.Pos = MaxPacketSize - 1
	if _, err := nsec3.Write(buf); err == nil {
		t.Errorf("Expected error for NSEC3 write at start")
	}

	// DS
	ds := DNSRecord{
		Name: "ds.test.", Type: DS, Class: 1, Digest: []byte{1, 2, 3},
	}
	buf.Reset()
	buf.Pos = MaxPacketSize - 1
	if _, err := ds.Write(buf); err == nil {
		t.Errorf("Expected error for DS write at start")
	}
}

func TestDNSRecord_ReadErrorPaths(t *testing.T) {
	testCases := []struct {
		name string
		typ  QueryType
		data []byte
		rdLen uint16
		err  bool
	}{
		{"Truncated A", A, []byte{1, 2, 3}, 4, true},
		{"Truncated AAAA", AAAA, []byte{1, 2, 3, 4, 5, 6, 7, 8}, 16, true},
		{"Truncated MX", MX, []byte{0, 10}, 5, true}, // Priority ok, missing Host
		{"Truncated SOA", SOA, []byte{0}, 20, true},
		{"Truncated TXT", TXT, []byte{5, 'a', 'b'}, 6, true}, // claims 5 but only 2
		{"Truncated HINFO", HINFO, []byte{3, 'a', 'b'}, 10, true}, // CPU len ok, missing CPU
		{"Truncated MINFO", MINFO, []byte{0}, 10, true}, // RMailBX ok, missing EMailBX
		{"Truncated NSEC", NSEC, []byte{0}, 10, true}, // NextName ok, missing BitMap
		{"Truncated DNSKEY", DNSKEY, []byte{0, 0, 3}, 10, true}, // Flags, Proto ok, missing Alg
		{"Truncated RRSIG", RRSIG, []byte{0, 1, 13}, 20, true}, // TypeCovered ok, Alg ok, missing Labels
		{"Truncated NSEC3", NSEC3, []byte{1, 0, 0, 10}, 20, true}, // HashAlg, Flags, Iterations ok, missing SaltLen
		{"Truncated DS", DS, []byte{0, 0, 13}, 10, true}, // KeyTag ok, Alg ok, missing DigestType
		{"Truncated TSIG", TSIG, []byte{0}, 20, true}, // AlgoName ok, missing TimeSigned
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := NewBytePacketBuffer()
			_ = buf.Write(0) // Name .
			_ = buf.Writeu16(uint16(tc.typ))
			_ = buf.Writeu16(1) // Class
			_ = buf.Writeu32(60) // TTL
			_ = buf.Writeu16(tc.rdLen)
			
			for _, b := range tc.data {
				_ = buf.Write(b)
			}
			
			// We MUST set buf.Len to exactly what we wrote to simulate truncation
			buf.Len = buf.Pos
			_ = buf.Seek(0)
			var r DNSRecord
			err := r.Read(buf)
			if tc.err && err == nil {
				t.Errorf("Expected error for %s", tc.name)
			}
		})
	}
}
