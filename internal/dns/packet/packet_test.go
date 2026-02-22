package packet

import (
	"net"
	"strings"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

func TestHeaderSerialization(t *testing.T) {
	header := DNSHeader{
		ID:                  1234,
		Response:            true,
		AuthoritativeAnswer: true,
		Questions:           1,
	}

	buffer := NewBytePacketBuffer()
	err := header.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write header: %v", err)
	}

	if buffer.Position() != 12 {
		t.Errorf("Header should be 12 bytes, got %d", buffer.Position())
	}

	_ = buffer.Seek(0)
	readHeader := DNSHeader{}
	err = readHeader.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read header: %v", err)
	}

	if readHeader.ID != 1234 {
		t.Errorf("Expected ID 1234, got %d", readHeader.ID)
	}
	if !readHeader.Response {
		t.Errorf("Expected Response bit to be set")
	}
	if !readHeader.AuthoritativeAnswer {
		t.Errorf("Expected AuthoritativeAnswer bit to be set")
	}
}

func TestNameSerialization(t *testing.T) {
	buffer := NewBytePacketBuffer()
	name := "google.com."
	
	err := buffer.WriteName(name)
	if err != nil {
		t.Fatalf("Failed to write name: %v", err)
	}

	_ = buffer.Seek(0)
	readName, err := buffer.ReadName()
	if err != nil {
		t.Fatalf("Failed to read name: %v", err)
	}

	if readName != name {
		t.Errorf("Expected %s, got %s", name, readName)
	}
}

func TestFullPacket(t *testing.T) {
	packet := NewDNSPacket()
	packet.Header.ID = 666
	packet.Header.Response = true
	packet.Questions = append(packet.Questions, DNSQuestion{
		Name:  "test.com.",
		QType: A,
	})
	packet.Answers = append(packet.Answers, DNSRecord{
		Name:  "test.com.",
		Type:  A,
		Class: 1,
		TTL:   3600,
		IP:    net.ParseIP("127.0.0.1"),
	})

	buffer := NewBytePacketBuffer()
	err := packet.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write packet: %v", err)
	}

	_ = buffer.Seek(0)
	parsedPacket := NewDNSPacket()
	err = parsedPacket.FromBuffer(buffer)
	if err != nil {
		t.Fatalf("Failed to parse packet: %v", err)
	}

	if parsedPacket.Header.ID != 666 {
		t.Errorf("Expected ID 666, got %d", parsedPacket.Header.ID)
	}
	if len(parsedPacket.Questions) != 1 || parsedPacket.Questions[0].Name != "test.com." {
		t.Errorf("Question mismatch: expected test.com., got %s", parsedPacket.Questions[0].Name)
	}
	if len(parsedPacket.Answers) != 1 || parsedPacket.Answers[0].IP.String() != "127.0.0.1" {
		t.Errorf("Answer mismatch")
	}
}

func TestTXTRecordSerialization(t *testing.T) {
	record := DNSRecord{
		Name: "test.com.",
		Type: TXT,
		TTL:  300,
		Txt:  "v=spf1 include:_spf.google.com ~all",
	}

	buffer := NewBytePacketBuffer()
	_, err := record.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write TXT record: %v", err)
	}

	_ = buffer.Seek(0)
	parsed := DNSRecord{}
	err = parsed.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read record: %v", err)
	}
	if parsed.Txt != record.Txt {
		t.Errorf("TXT mismatch")
	}
}

func TestSOARecordSerialization(t *testing.T) {
	record := DNSRecord{
		Name:    "example.com.",
		Type:    SOA,
		TTL:     3600,
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
		Serial:  2023101001,
		Refresh: 3600,
		Retry:   600,
		Expire:  1209600,
		Minimum: 3600,
	}

	buffer := NewBytePacketBuffer()
	_, err := record.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write SOA record: %v", err)
	}

	_ = buffer.Seek(0)
	parsed := DNSRecord{}
	err = parsed.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read SOA record: %v", err)
	}
	if parsed.Serial != record.Serial {
		t.Errorf("SOA Serial mismatch")
	}
}

func TestBufferOverflow(t *testing.T) {
	buffer := NewBytePacketBuffer()
	buffer.Pos = MaxPacketSize - 1
	err := buffer.Write(1)
	if err != nil {
		t.Errorf("Should be able to write at MaxPacketSize - 1")
	}
	err = buffer.Write(2)
	if err == nil {
		t.Errorf("Should have failed to write at MaxPacketSize")
	}
}

func TestReadWriteU32(t *testing.T) {
	buffer := NewBytePacketBuffer()
	val := uint32(0x12345678)
	err := buffer.Writeu32(val)
	if err != nil {
		t.Fatalf("Writeu32 failed: %v", err)
	}

	_ = buffer.Seek(0)
	read, err := buffer.Readu32()
	if err != nil {
		t.Fatalf("Readu32 failed: %v", err)
	}

	if read != val {
		t.Errorf("Expected %x, got %x", val, read)
	}
}

func TestLabelLengthLimit(t *testing.T) {
	buffer := NewBytePacketBuffer()
	// 63 characters is the limit for a single label
	longLabel := "abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabc"
	err := buffer.WriteName(longLabel + ".com.")
	if err != nil {
		t.Fatalf("Should allow 63 char label: %v", err)
	}

	tooLongLabel := longLabel + "d"
	err = buffer.WriteName(tooLongLabel + ".com.")
	if err == nil {
		t.Errorf("Should NOT allow 64 char label")
	}
}

func TestEmptyName(t *testing.T) {
	buffer := NewBytePacketBuffer()
	err := buffer.WriteName("")
	if err != nil {
		t.Fatalf("Failed to write empty name")
	}
	// Position should be 1 (just the null terminator)
	if buffer.Position() != 1 {
		t.Errorf("Expected pos 1 for empty name, got %d", buffer.Position())
	}

	_ = buffer.Seek(0)
	name, _ := buffer.ReadName()
	if name != "." {
		t.Errorf("Expected root dot, got %s", name)
	}
}

func TestMXRecordSerialization(t *testing.T) {
	record := DNSRecord{
		Name:     "test.com.",
		Type:     MX,
		TTL:      300,
		Priority: 10,
		Host:     "mail.test.com.",
	}

	buffer := NewBytePacketBuffer()
	_, err := record.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write MX record: %v", err)
	}

	_ = buffer.Seek(0)
	parsed := DNSRecord{}
	err = parsed.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read MX record: %v", err)
	}

	if parsed.Priority != 10 {
		t.Errorf("Expected priority 10, got %d", parsed.Priority)
	}
	if parsed.Host != "mail.test.com." {
		t.Errorf("Expected mail.test.com., got %s", parsed.Host)
	}
}

func TestCNAMERecordSerialization(t *testing.T) {
	record := DNSRecord{
		Name: "alias.test.com.",
		Type: CNAME,
		TTL:  300,
		Host: "real.test.com.",
	}

	buffer := NewBytePacketBuffer()
	_, err := record.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write CNAME record: %v", err)
	}

	_ = buffer.Seek(0)
	parsed := DNSRecord{}
	err = parsed.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read CNAME record: %v", err)
	}

	if parsed.Host != "real.test.com." {
		t.Errorf("Expected real.test.com., got %s", parsed.Host)
	}
}

func TestReadWriteAllTypes(t *testing.T) {
	records := []DNSRecord{
		{Name: "a.test.", Type: A, TTL: 300, IP: net.ParseIP("1.2.3.4")},
		{Name: "aaaa.test.", Type: AAAA, TTL: 300, IP: net.ParseIP("2001:db8::1")},
		{Name: "ns.test.", Type: NS, TTL: 300, Host: "ns1.test."},
		{Name: "cname.test.", Type: CNAME, TTL: 300, Host: "real.test."},
		{Name: "mx.test.", Type: MX, TTL: 300, Priority: 10, Host: "mail.test."},
		{Name: "", Type: OPT, Class: 4096, UDPPayloadSize: 4096, TTL: 0}, // EDNS
		{Name: "hinfo.test.", Type: HINFO, CPU: "ARM64", OS: "LINUX", TTL: 300},
		{Name: "minfo.test.", Type: MINFO, RMailBX: "a.test.", EMailBX: "b.test.", TTL: 300},
		{Name: "dnskey.test.", Type: DNSKEY, Flags: 256, Algorithm: 13, PublicKey: []byte{1, 2, 3, 4}, TTL: 300},
		{Name: "ds.test.", Type: DS, KeyTag: 123, Algorithm: 13, DigestType: 2, Digest: []byte{1, 2, 3, 4}, TTL: 300},
		{Name: "nsec.test.", Type: NSEC, NextName: "next.test.", TypeBitMap: []byte{0, 1, 2}, TTL: 300},
		{Name: "nsec3param.test.", Type: NSEC3PARAM, HashAlg: 1, Iterations: 10, Salt: []byte{1, 2}, TTL: 300},
		{Name: "srv.test.", Type: SRV, Priority: 10, Class: 1, TTL: 300},
	}

	for _, rec := range records {
		buffer := NewBytePacketBuffer()
		_, err := rec.Write(buffer)
		if err != nil {
			t.Errorf("Failed to write %v: %v", rec.Type, err)
			continue
		}

		_ = buffer.Seek(0)
		parsed := DNSRecord{}
		err = parsed.Read(buffer)
		if err != nil {
			t.Errorf("Failed to read %v: %v", rec.Type, err)
			continue
		}

		expectedName := rec.Name
		if expectedName == "" { expectedName = "." }
		if parsed.Name != expectedName {
			t.Errorf("%v: Name mismatch: %s vs %s", rec.Type, parsed.Name, expectedName)
		}
		
		switch rec.Type {
		case A, AAAA:
			if parsed.IP.String() != rec.IP.String() {
				t.Errorf("%v: IP mismatch: %s vs %s", rec.Type, parsed.IP, rec.IP)
			}
		case NS, CNAME:
			if parsed.Host != rec.Host {
				t.Errorf("%v: Host mismatch: %s vs %s", rec.Type, parsed.Host, rec.Host)
			}
		case MX:
			if parsed.Priority != rec.Priority || parsed.Host != rec.Host {
				t.Errorf("%v: MX mismatch", rec.Type)
			}
		case OPT:
			if parsed.UDPPayloadSize != 4096 {
				t.Errorf("OPT: Expected size 4096, got %d", parsed.UDPPayloadSize)
			}
		case HINFO:
			if parsed.CPU != rec.CPU || parsed.OS != rec.OS {
				t.Errorf("HINFO mismatch")
			}
		case MINFO:
			if parsed.RMailBX != rec.RMailBX || parsed.EMailBX != rec.EMailBX {
				t.Errorf("MINFO mismatch")
			}
		}
	}
}

func TestReadName_InfiniteLoop(t *testing.T) {
	buffer := NewBytePacketBuffer()
	// Create a pointer that points to itself
	_ = buffer.Write(0xC0)
	_ = buffer.Write(0x00)
	
	_ = buffer.Seek(0)
	_, err := buffer.ReadName()
	if err == nil {
		t.Errorf("Should have failed with infinite loop error")
	}
}

func TestDNSKEYRecordSerialization(t *testing.T) {
	record := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		TTL:       3600,
		Flags:     256,
		Algorithm: 13,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04},
	}

	buffer := NewBytePacketBuffer()
	_, err := record.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write DNSKEY record: %v", err)
	}

	_ = buffer.Seek(0)
	parsed := DNSRecord{}
	err = parsed.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read DNSKEY record: %v", err)
	}

	if parsed.Flags != record.Flags || parsed.Algorithm != record.Algorithm {
		t.Errorf("DNSKEY metadata mismatch")
	}
	if string(parsed.PublicKey) != string(record.PublicKey) {
		t.Errorf("PublicKey mismatch")
	}
}

func TestRRSIGRecordSerialization(t *testing.T) {
	record := DNSRecord{
		Name:        "example.com.",
		Type:        RRSIG,
		TTL:         3600,
		TypeCovered: uint16(A),
		Algorithm:   13,
		Labels:      2,
		OrigTTL:     3600,
		Expiration:  1700000000,
		Inception:   1600000000,
		KeyTag:      12345,
		SignerName:  "example.com.",
		Signature:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}

	buffer := NewBytePacketBuffer()
	_, err := record.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write RRSIG record: %v", err)
	}

	_ = buffer.Seek(0)
	parsed := DNSRecord{}
	err = parsed.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read RRSIG record: %v", err)
	}

	if parsed.TypeCovered != record.TypeCovered || parsed.KeyTag != record.KeyTag {
		t.Errorf("RRSIG metadata mismatch")
	}
	if parsed.SignerName != record.SignerName {
		t.Errorf("SignerName mismatch: expected %s, got %s", record.SignerName, parsed.SignerName)
	}
}

func TestNSECRecordSerialization(t *testing.T) {
	record := DNSRecord{
		Name:       "a.example.com.",
		Type:       NSEC,
		TTL:        3600,
		NextName:   "z.example.com.",
		TypeBitMap: []byte{0x00, 0x06, 0x40, 0x01},
	}

	buffer := NewBytePacketBuffer()
	_, err := record.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write NSEC record: %v", err)
	}

	_ = buffer.Seek(0)
	parsed := DNSRecord{}
	err = parsed.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read NSEC record: %v", err)
	}

	if parsed.NextName != record.NextName {
		t.Errorf("NextName mismatch: expected %s, got %s", record.NextName, parsed.NextName)
	}
}

func TestHINFORecordSerialization(t *testing.T) {
	record := DNSRecord{
		Name: "host.test.",
		Type: HINFO,
		TTL:  300,
		CPU:  "INTEL-I7",
		OS:   "LINUX",
	}

	buffer := NewBytePacketBuffer()
	_, err := record.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write HINFO record: %v", err)
	}

	_ = buffer.Seek(0)
	parsed := DNSRecord{}
	err = parsed.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read HINFO record: %v", err)
	}

	if parsed.CPU != record.CPU || parsed.OS != record.OS {
		t.Errorf("HINFO mismatch")
	}
}

func TestMINFORecordSerialization(t *testing.T) {
	record := DNSRecord{
		Name:    "mail.test.",
		Type:    MINFO,
		TTL:     300,
		RMailBX: "admin.test.",
		EMailBX: "errors.test.",
	}

	buffer := NewBytePacketBuffer()
	_, err := record.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write MINFO record: %v", err)
	}

	_ = buffer.Seek(0)
	parsed := DNSRecord{}
	err = parsed.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read MINFO record: %v", err)
	}

	if parsed.RMailBX != record.RMailBX || parsed.EMailBX != record.EMailBX {
		t.Errorf("MINFO mismatch")
	}
}

func TestNSEC3RecordSerialization(t *testing.T) {
	record := DNSRecord{
		Name:       "example.com.",
		Type:       NSEC3,
		TTL:        300,
		HashAlg:    1,
		Flags:      1,
		Iterations: 10,
		Salt:       []byte{0xAB, 0xCD},
		NextHash:   []byte{0x01, 0x02, 0x03, 0x04},
		TypeBitMap: []byte{0x00, 0x02, 0x40},
	}

	buffer := NewBytePacketBuffer()
	_, err := record.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write NSEC3 record: %v", err)
	}

	_ = buffer.Seek(0)
	parsed := DNSRecord{}
	err = parsed.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read NSEC3 record: %v", err)
	}

	if parsed.HashAlg != record.HashAlg || parsed.Iterations != record.Iterations {
		t.Errorf("NSEC3 metadata mismatch")
	}
	if string(parsed.Salt) != string(record.Salt) || string(parsed.NextHash) != string(record.NextHash) {
		t.Errorf("NSEC3 hash/salt mismatch")
	}
}

func TestNSEC3PARAMRecordSerialization(t *testing.T) {
	record := DNSRecord{
		Name:       "example.com.",
		Type:       NSEC3PARAM,
		TTL:        300,
		HashAlg:    1,
		Flags:      0,
		Iterations: 10,
		Salt:       []byte{0xDE, 0xAD},
	}

	buffer := NewBytePacketBuffer()
	_, err := record.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write NSEC3PARAM record: %v", err)
	}

	_ = buffer.Seek(0)
	parsed := DNSRecord{}
	err = parsed.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read NSEC3PARAM record: %v", err)
	}

	if parsed.HashAlg != record.HashAlg || parsed.Iterations != record.Iterations {
		t.Errorf("NSEC3PARAM metadata mismatch")
	}
	if string(parsed.Salt) != string(record.Salt) {
		t.Errorf("NSEC3PARAM salt mismatch")
	}
}

func TestDSRecordSerialization(t *testing.T) {
	record := DNSRecord{
		Name:       "example.com.",
		Type:       DS,
		TTL:        3600,
		KeyTag:     1234,
		Algorithm:  13,
		DigestType: 2,
		Digest:     []byte{0x01, 0x02, 0x03, 0x04},
	}

	buffer := NewBytePacketBuffer()
	_, err := record.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write DS record: %v", err)
	}

	_ = buffer.Seek(0)
	parsed := DNSRecord{}
	err = parsed.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read DS record: %v", err)
	}

	if parsed.KeyTag != record.KeyTag || parsed.Algorithm != record.Algorithm || parsed.DigestType != record.DigestType {
		t.Errorf("DS metadata mismatch")
	}
	if string(parsed.Digest) != string(record.Digest) {
		t.Errorf("DS digest mismatch")
	}
}

func TestEDERecordSerialization(t *testing.T) {
	record := DNSRecord{
		Name:           ".",
		Type:           OPT,
		UDPPayloadSize: 4096,
	}
	record.AddEDE(EdeBlocked, "Privacy policy violation")

	buffer := NewBytePacketBuffer()
	_, err := record.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write OPT with EDE: %v", err)
	}

	_ = buffer.Seek(0)
	parsed := DNSRecord{}
	err = parsed.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read record: %v", err)
	}

	if len(parsed.Options) != 1 {
		t.Fatalf("Expected 1 EDNS option, got %d", len(parsed.Options))
	}
	opt := parsed.Options[0]
	if opt.Code != 15 {
		t.Errorf("Expected EDE option (15), got %d", opt.Code)
	}
	
	infoCode := uint16(opt.Data[0])<<8 | uint16(opt.Data[1])
	if infoCode != EdeBlocked {
		t.Errorf("Expected EdeBlocked (%d), got %d", EdeBlocked, infoCode)
	}
	extraText := string(opt.Data[2:])
	if extraText != "Privacy policy violation" {
		t.Errorf("Expected extra text mismatch, got %s", extraText)
	}
}

func TestBufferPool(t *testing.T) {
	buf := GetBuffer()
	if buf.Position() != 0 {
		t.Errorf("Expected reset buffer from pool")
	}
	_ = buf.Write(1)
	PutBuffer(buf)
	
	buf2 := GetBuffer()
	if buf2.Position() != 0 {
		t.Errorf("Expected reused buffer to be reset")
	}
}

func TestBufferRandomAccess(t *testing.T) {
	buf := NewBytePacketBuffer()
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	_ = buf.WriteRange(10, data)
	
	if val, _ := buf.Get(10); val != 0xDE {
		t.Errorf("Get(10) failed")
	}
	
	got, _ := buf.GetRange(10, 4)
	if string(got) != string(data) {
		t.Errorf("GetRange mismatch")
	}
}

func TestNameCompression(t *testing.T) {
	buf := NewBytePacketBuffer()
	buf.HasNames = true
	
	// Write name first time
	_ = buf.WriteName("example.com.")
	pos1 := 0 // should be at 0
	
	// Write same name again
	_ = buf.WriteName("example.com.")
	
	// Buffer should now contain:
	// [7] 'e' 'x' 'a' 'm' 'p' 'l' 'e' [3] 'c' 'o' 'm' [0] [0xC0, 0x00]
	// Total 13 bytes for first name, then 2 byte pointer
	if buf.Position() != 15 {
		t.Errorf("Expected 15 bytes total, got %d", buf.Position())
	}
	
	// Verify pointer
	if buf.Buf[13] != 0xC0 || buf.Buf[14] != byte(pos1) {
		t.Errorf("Invalid compression pointer: %x %x", buf.Buf[13], buf.Buf[14])
	}
}

func TestReadName_MaxJumps(t *testing.T) {
	buf := NewBytePacketBuffer()
	// Create a loop of pointers
	buf.Buf[0] = 0xC0
	buf.Buf[1] = 0x02
	buf.Buf[2] = 0xC0
	buf.Buf[3] = 0x00
	buf.Len = 4
	buf.parsing = true
	
	_ = buf.Seek(0)
	_, err := buf.ReadName()
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("Expected jump limit error, got %v", err)
	}
}

func TestQueryType_String(t *testing.T) {
	tests := []struct {
		qt   QueryType
		want string
	}{
		{A, "A"},
		{NS, "NS"},
		{CNAME, "CNAME"},
		{SOA, "SOA"},
		{MX, "MX"},
		{TXT, "TXT"},
		{AAAA, "AAAA"},
		{SRV, "SRV"},
		{DS, "DS"},
		{RRSIG, "RRSIG"},
		{NSEC, "NSEC"},
		{DNSKEY, "DNSKEY"},
		{NSEC3, "NSEC3"},
		{NSEC3PARAM, "NSEC3PARAM"},
		{AXFR, "AXFR"},
		{IXFR, "IXFR"},
		{ANY, "ANY"},
		{OPT, "OPT"},
		{TSIG, "TSIG"},
		{PTR, "PTR"},
		{QueryType(999), "TYPE999"},
	}
	for _, tt := range tests {
		if got := tt.qt.String(); got != tt.want {
			t.Errorf("QueryType(%d).String() = %v, want %v", tt.qt, got, tt.want)
		}
	}
}

func TestDNSHeader_NewAndWrite(t *testing.T) {
	h := NewDNSHeader()
	h.ID = 1234
	h.Response = true
	h.Opcode = 0
	h.AuthoritativeAnswer = true
	h.TruncatedMessage = false
	h.RecursionDesired = true
	h.RecursionAvailable = true
	h.Z = false
	h.AuthedData = true
	h.CheckingDisabled = false
	h.ResCode = 0
	h.Questions = 1
	h.Answers = 0
	h.AuthoritativeEntries = 0
	h.ResourceEntries = 0

	buf := NewBytePacketBuffer()
	if err := h.Write(buf); err != nil {
		t.Fatalf("Header.Write failed: %v", err)
	}

	if buf.Position() != 12 {
		t.Errorf("Expected 12 bytes, got %d", buf.Position())
	}
}

func TestDNSQuestion_NewAndWrite(t *testing.T) {
	q := NewDNSQuestion("example.com.", A)
	buf := NewBytePacketBuffer()
	if err := q.Write(buf); err != nil {
		t.Fatalf("Question.Write failed: %v", err)
	}

	_ = buf.Seek(0)
	parsed := DNSQuestion{}
	if err := parsed.Read(buf); err != nil {
		t.Fatalf("Question.Read failed: %v", err)
	}

	if parsed.Name != "example.com." || parsed.QType != A {
		t.Errorf("Question mismatch: %+v", parsed)
	}
}

func TestRecordTypeToQueryType(t *testing.T) {
	tests := []struct {
		rt   domain.RecordType
		want QueryType
	}{
		{domain.TypeA, A},
		{domain.TypeNS, NS},
		{domain.TypeCNAME, CNAME},
		{domain.TypeSOA, SOA},
		{domain.TypeMX, MX},
		{domain.TypeTXT, TXT},
		{domain.TypeAAAA, AAAA},
		{domain.TypePTR, PTR},
		{"UNKNOWN", UNKNOWN},
	}
	for _, tt := range tests {
		if got := RecordTypeToQueryType(tt.rt); got != tt.want {
			t.Errorf("RecordTypeToQueryType(%v) = %v, want %v", tt.rt, got, tt.want)
		}
	}
}

func TestBufferLoad(t *testing.T) {
	buf := NewBytePacketBuffer()
	data := []byte{1, 2, 3}
	buf.Load(data)
	if val, _ := buf.Read(); val != 1 {
		t.Errorf("Buffer Load failed")
	}
}

func TestBuffer_EdgeCases(t *testing.T) {
	buf := NewBytePacketBuffer()
	
	// 1. Step and Seek
	_ = buf.Step(10)
	if buf.Position() != 10 {
		t.Errorf("Step(10) failed")
	}
	_ = buf.Seek(5)
	if buf.Position() != 5 {
		t.Errorf("Seek(5) failed")
	}

	// 2. Nested Name Compression
	buf.Reset()
	buf.HasNames = true
	
	// Write "a.b.test.com."
	_ = buf.WriteName("a.b.test.com.")
	// Write "b.test.com." (should reuse suffix)
	_ = buf.WriteName("b.test.com.")
	
	if buf.Position() >= 30 { // Total should be less than naive sum
		t.Errorf("Compression not working effectively")
	}
}

func TestDNSPacket_WriteAllSections(t *testing.T) {
	p := NewDNSPacket()
	p.Header.ID = 1
	p.Questions = append(p.Questions, DNSQuestion{Name: "q.test.", QType: A})
	p.Answers = append(p.Answers, DNSRecord{Name: "q.test.", Type: A, IP: net.ParseIP("1.1.1.1"), TTL: 60, Class: 1})
	p.Authorities = append(p.Authorities, DNSRecord{Name: "q.test.", Type: NS, Host: "ns.test.", TTL: 60, Class: 1})
	p.Resources = append(p.Resources, DNSRecord{Name: "ns.test.", Type: A, IP: net.ParseIP("2.2.2.2"), TTL: 60, Class: 1})

	buf := NewBytePacketBuffer()
	if err := p.Write(buf); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if p.Header.Questions != 1 || p.Header.Answers != 1 || p.Header.AuthoritativeEntries != 1 || p.Header.ResourceEntries != 1 {
		t.Errorf("Header counts not updated correctly: %+v", p.Header)
	}

	if err := buf.Seek(0); err != nil {
		t.Fatalf("Seek failed: %v", err)
	}
	parsed := NewDNSPacket()
	if err := parsed.FromBuffer(buf); err != nil {
		t.Fatalf("FromBuffer failed: %v", err)
	}

	if len(parsed.Questions) != 1 || len(parsed.Answers) != 1 || len(parsed.Authorities) != 1 || len(parsed.Resources) != 1 {
		t.Errorf("Parsed sections length mismatch: Q:%d A:%d Auth:%d Add:%d",
			len(parsed.Questions), len(parsed.Answers), len(parsed.Authorities), len(parsed.Resources))
	}
}

func TestDNSRecord_ExtraTypes(t *testing.T) {
	records := []DNSRecord{
		{Name: "null.test.", Type: NULL, Data: []byte{1, 2, 3, 4}, TTL: 60, Class: 1},
		{Name: "unknown.test.", Type: QueryType(999), Data: []byte{5, 6}, TTL: 60, Class: 1},
		{Name: "nsec3.test.", Type: NSEC3, HashAlg: 1, Iterations: 5, Salt: []byte{0xAB}, NextHash: []byte{1, 2, 3}, TypeBitMap: []byte{0, 1, 2}, TTL: 60, Class: 1},
		{Name: "ds.test.", Type: DS, KeyTag: 1234, Algorithm: 13, DigestType: 2, Digest: []byte{0xDE, 0xAD}, TTL: 60, Class: 1},
		{Name: "nsec.test.", Type: NSEC, NextName: "z.test.", TypeBitMap: []byte{0, 1}, TTL: 60, Class: 1},
		{Name: "dnskey.test.", Type: DNSKEY, Flags: 256, Algorithm: 13, PublicKey: []byte{1, 2, 3}, TTL: 60, Class: 1},
		{Name: "rrsig.test.", Type: RRSIG, TypeCovered: uint16(A), Algorithm: 13, Labels: 2, OrigTTL: 3600, Expiration: 1000, Inception: 500, KeyTag: 1, SignerName: "test.", Signature: []byte{1, 2}, TTL: 60, Class: 1},
	}

	for _, rec := range records {
		buf := NewBytePacketBuffer()
		_, err := rec.Write(buf)
		if err != nil {
			t.Errorf("Write failed for %v: %v", rec.Type, err)
			continue
		}

		if err := buf.Seek(0); err != nil {
			t.Errorf("Seek failed: %v", err)
			continue
		}
		parsed := DNSRecord{}
		if err := parsed.Read(buf); err != nil {
			t.Errorf("Read failed for %v: %v", rec.Type, err)
			continue
		}

		if parsed.Type != rec.Type {
			t.Errorf("Type mismatch for %v: got %v", rec.Type, parsed.Type)
		}
		
		switch rec.Type {
		case DS:
			if parsed.KeyTag != rec.KeyTag || string(parsed.Digest) != string(rec.Digest) {
				t.Errorf("DS mismatch")
			}
		case NSEC:
			if parsed.NextName != rec.NextName {
				t.Errorf("NSEC mismatch")
			}
		case DNSKEY:
			if parsed.Flags != rec.Flags || string(parsed.PublicKey) != string(rec.PublicKey) {
				t.Errorf("DNSKEY mismatch")
			}
		}
	}
}

func TestDNSRecord_ReadTruncated(t *testing.T) {
	// Create a valid A record buffer then truncate it
	rec := DNSRecord{Name: "a.", Type: A, Class: 1, TTL: 60, IP: net.ParseIP("1.1.1.1")}
	buf := NewBytePacketBuffer()
	_, _ = rec.Write(buf)
	data := buf.Buf[:buf.Position()-1] // Truncate last byte of IP
	
	truncatedBuf := NewBytePacketBuffer()
	truncatedBuf.Load(data)
	
	parsed := DNSRecord{}
	err := parsed.Read(truncatedBuf)
	if err == nil {
		t.Errorf("Expected error when reading truncated record")
	}
}

func TestDNSQuestion_QClass(t *testing.T) {
	tests := []struct {
		name   string
		qclass uint16
		want   uint16
	}{
		{"Default Class", 0, 1}, // Should default to IN (1)
		{"CH Class", 3, 3},
		{"IN Class", 1, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := NewDNSQuestion("test.com.", A)
			q.QClass = tt.qclass
			buf := NewBytePacketBuffer()
			if err := q.Write(buf); err != nil {
				t.Fatalf("Write failed: %v", err)
			}

			_ = buf.Seek(0)
			parsed := DNSQuestion{}
			if err := parsed.Read(buf); err != nil {
				t.Fatalf("Read failed: %v", err)
			}

			if parsed.QClass != tt.want {
				t.Errorf("QClass = %d, want %d", parsed.QClass, tt.want)
			}
		})
	}
}

func TestTSIG_SignVerify(t *testing.T) {
	// 1. Create a standard DNS query
	p := NewDNSPacket()
	p.Header.ID = 1234
	p.Questions = append(p.Questions, DNSQuestion{Name: "test.com.", QType: A})
	
	buf := NewBytePacketBuffer()
	secret := []byte("secret")
	
	// 2. Proactively write the packet to the buffer (WITHOUT TSIG yet)
	if err := p.Write(buf); err != nil {
		t.Fatalf("Failed to write packet: %v", err)
	}
	
	// 3. Append the TSIG signature to the message
	if err := p.SignTSIG(buf, "key.", secret); err != nil {
		t.Fatalf("SignTSIG failed: %v", err)
	}
	
	// 4. Capture the final signed data and parse it back into a new packet
	data := buf.Buf[:buf.Position()]
	parsed := NewDNSPacket()
	pBuf := NewBytePacketBuffer()
	pBuf.Load(data)
	if err := parsed.FromBuffer(pBuf); err != nil {
		t.Fatalf("FromBuffer failed: %v", err)
	}
	
	// 5. Verify successful verification
	if err := parsed.VerifyTSIG(data, parsed.TSIGStart, secret); err != nil {
		t.Errorf("VerifyTSIG validation failed: %v", err)
	}

	// 6. Test MAC mismatch
	if err := parsed.VerifyTSIG(data, parsed.TSIGStart, []byte("wrong")); err == nil {
		t.Errorf("VerifyTSIG should have failed with wrong secret")
	}

	// 7. Test time drift
	tsigRec := &parsed.Resources[len(parsed.Resources)-1]
	originalTime := tsigRec.TimeSigned
	tsigRec.TimeSigned -= 1000 // 1000 seconds drift (Fudge is 300)
	if err := parsed.VerifyTSIG(data, parsed.TSIGStart, secret); err == nil || !strings.Contains(err.Error(), "drift") {
		t.Errorf("Expected time drift error, got %v", err)
	}
	tsigRec.TimeSigned = originalTime
}

func TestBuffer_ReadRange_Error(t *testing.T) {
	buf := NewBytePacketBuffer()
	_, err := buf.ReadRange(MaxPacketSize - 1, 10)
	if err == nil {
		t.Error("expected error when reading out of bounds range")
	}
}

func TestDNSHeader_Read_Error(t *testing.T) {
	buf := NewBytePacketBuffer()
	h := DNSHeader{}
	err := h.Read(buf) // Buffer empty
	if err == nil {
		t.Error("expected error when reading header from empty buffer")
	}
}

func TestDNSPacket_FromBuffer_Error(t *testing.T) {
	buf := NewBytePacketBuffer()
	p := NewDNSPacket()
	err := p.FromBuffer(buf)
	if err == nil {
		t.Error("expected error when parsing packet from empty buffer")
	}
}
