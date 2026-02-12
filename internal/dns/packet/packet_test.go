package packet

import (
	"net"
	"testing"
)

func TestHeaderSerialization(t *testing.T) {
	header := DnsHeader{
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

	buffer.Seek(0)
	readHeader := DnsHeader{}
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

	buffer.Seek(0)
	readName, err := buffer.ReadName()
	if err != nil {
		t.Fatalf("Failed to read name: %v", err)
	}

	if readName != name {
		t.Errorf("Expected %s, got %s", name, readName)
	}
}

func TestFullPacket(t *testing.T) {
	packet := NewDnsPacket()
	packet.Header.ID = 666
	packet.Header.Response = true
	packet.Questions = append(packet.Questions, DnsQuestion{
		Name:  "test.com.",
		QType: A,
	})
	packet.Answers = append(packet.Answers, DnsRecord{
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

	buffer.Seek(0)
	parsedPacket := NewDnsPacket()
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
	record := DnsRecord{
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

	buffer.Seek(0)
	parsed := DnsRecord{}
	err = parsed.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read record: %v", err)
	}
	if parsed.Txt != record.Txt {
		t.Errorf("TXT mismatch")
	}
}

func TestSOARecordSerialization(t *testing.T) {
	record := DnsRecord{
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

	buffer.Seek(0)
	parsed := DnsRecord{}
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

	buffer.Seek(0)
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

	buffer.Seek(0)
	name, _ := buffer.ReadName()
	if name != "." {
		t.Errorf("Expected root dot, got %s", name)
	}
}

func TestMXRecordSerialization(t *testing.T) {
	record := DnsRecord{
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

	buffer.Seek(0)
	parsed := DnsRecord{}
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
	record := DnsRecord{
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

	buffer.Seek(0)
	parsed := DnsRecord{}
	err = parsed.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read CNAME record: %v", err)
	}

	if parsed.Host != "real.test.com." {
		t.Errorf("Expected real.test.com., got %s", parsed.Host)
	}
}

func TestReadWriteAllTypes(t *testing.T) {
	records := []DnsRecord{
		{Name: "a.test.", Type: A, TTL: 300, IP: net.ParseIP("1.2.3.4")},
		{Name: "aaaa.test.", Type: AAAA, TTL: 300, IP: net.ParseIP("2001:db8::1")},
		{Name: "ns.test.", Type: NS, TTL: 300, Host: "ns1.test."},
		{Name: "cname.test.", Type: CNAME, TTL: 300, Host: "real.test."},
		{Name: "mx.test.", Type: MX, TTL: 300, Priority: 10, Host: "mail.test."},
		{Name: "", Type: OPT, UDPPayloadSize: 4096, TTL: 0}, // EDNS
	}

	for _, rec := range records {
		buffer := NewBytePacketBuffer()
		_, err := rec.Write(buffer)
		if err != nil {
			t.Errorf("Failed to write %v: %v", rec.Type, err)
			continue
		}

		buffer.Seek(0)
		parsed := DnsRecord{}
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
		}
	}
}

func TestReadName_InfiniteLoop(t *testing.T) {
	buffer := NewBytePacketBuffer()
	
	// Create a pointer that points to itself
	buffer.Write(0xC0)
	buffer.Write(0x00)
	
	buffer.Seek(0)
	_, err := buffer.ReadName()
	if err == nil {
		t.Errorf("Should have failed with infinite loop error")
	}
}

func TestDNSKEYRecordSerialization(t *testing.T) {

	record := DnsRecord{

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



	buffer.Seek(0)

	parsed := DnsRecord{}

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

	record := DnsRecord{

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



	buffer.Seek(0)

	parsed := DnsRecord{}

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

	record := DnsRecord{

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



	buffer.Seek(0)

	parsed := DnsRecord{}

	err = parsed.Read(buffer)

	if err != nil {

		t.Fatalf("Failed to read NSEC record: %v", err)

	}



	if parsed.NextName != record.NextName {

		t.Errorf("NextName mismatch: expected %s, got %s", record.NextName, parsed.NextName)

	}

}



func TestHINFORecordSerialization(t *testing.T) {

	record := DnsRecord{

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



	buffer.Seek(0)

	parsed := DnsRecord{}

	err = parsed.Read(buffer)

	if err != nil {

		t.Fatalf("Failed to read HINFO record: %v", err)

	}



	if parsed.CPU != record.CPU || parsed.OS != record.OS {

		t.Errorf("HINFO mismatch")

	}

}



func TestMINFORecordSerialization(t *testing.T) {

	record := DnsRecord{

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



	buffer.Seek(0)

	parsed := DnsRecord{}

	err = parsed.Read(buffer)

	if err != nil {

		t.Fatalf("Failed to read MINFO record: %v", err)

	}



	if parsed.RMailBX != record.RMailBX || parsed.EMailBX != record.EMailBX {

		t.Errorf("MINFO mismatch")

	}

}


