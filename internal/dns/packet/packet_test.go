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
	name := "google.com"
	
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
		Name:  "test.com",
		QType: A,
	})
	packet.Answers = append(packet.Answers, DnsRecord{
		Name:  "test.com",
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
	if len(parsedPacket.Questions) != 1 || parsedPacket.Questions[0].Name != "test.com" {
		t.Errorf("Question mismatch")
	}
	if len(parsedPacket.Answers) != 1 || parsedPacket.Answers[0].IP.String() != "127.0.0.1" {
		t.Errorf("Answer mismatch")
	}
}

func TestTXTRecordSerialization(t *testing.T) {
	record := DnsRecord{
		Name: "test.com",
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
	// Note: Read currently skips complex RDATA for types other than A/AAAA in our scratch version.
	// However, we can check the written length and general structure.
	if err != nil {
		t.Fatalf("Failed to read record header: %v", err)
	}
}

func TestSOARecordSerialization(t *testing.T) {
	record := DnsRecord{
		Name:    "example.com",
		Type:    SOA,
		TTL:     3600,
		MName:   "ns1.example.com",
		RName:   "admin.example.com",
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

	// Verify that we can jump back and forth in buffer during length calculation
	if buffer.Position() <= 12 {
		t.Errorf("SOA record should be significantly larger than 12 bytes")
	}
}

func TestBufferOverflow(t *testing.T) {
	buffer := NewBytePacketBuffer()
	buffer.Pos = 511
	err := buffer.Write(1)
	if err != nil {
		t.Errorf("Should be able to write at 511")
	}
	err = buffer.Write(2)
	if err == nil {
		t.Errorf("Should have failed to write at 512")
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
	err := buffer.WriteName(longLabel + ".com")
	if err != nil {
		t.Fatalf("Should allow 63 char label: %v", err)
	}

	tooLongLabel := longLabel + "d"
	err = buffer.WriteName(tooLongLabel + ".com")
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
	if name != "" {
		t.Errorf("Expected empty string, got %s", name)
	}
}

func TestMalformedPacketRead(t *testing.T) {
	// A real DNS header is 12 bytes. If we only have 2 bytes, it should fail.
	buffer := NewBytePacketBuffer()
	buffer.Write(1)
	buffer.Write(2)
	// We need a way to tell the buffer that its "logical" end is at index 2
	// For now, let's just seek to a position where Readu16 will hit 512
	buffer.Seek(511)

	p := NewDnsPacket()
	err := p.FromBuffer(buffer)
	if err == nil {
		t.Errorf("Should have failed to read header from end of buffer")
	}
}

func TestInvalidQueryType(t *testing.T) {
	buffer := NewBytePacketBuffer()
	q := DnsQuestion{Name: "test.com", QType: 9999}
	err := q.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write question with unknown type: %v", err)
	}

	buffer.Seek(0)
	parsed := DnsQuestion{}
	parsed.Read(buffer)
	if parsed.QType != 9999 {
		t.Errorf("Expected QType 9999, got %d", parsed.QType)
	}
}
