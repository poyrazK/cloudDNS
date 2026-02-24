package packet

import (
	"net"
	"testing"
)

func TestDNSRecord_ReadWrite_SRV(t *testing.T) {
	record := DNSRecord{
		Name:     "srv.test.",
		Type:     SRV,
		TTL:      300,
		Priority: 10,
		Weight:   5,
		Port:     5060,
		Host:     "sip.test.",
	}

	buffer := NewBytePacketBuffer()
	_, err := record.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write SRV record: %v", err)
	}

	_ = buffer.Seek(0)
	parsed := DNSRecord{}
	err = parsed.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read SRV record: %v", err)
	}

	if parsed.Priority != 10 || parsed.Weight != 5 || parsed.Port != 5060 || parsed.Host != "sip.test." {
		t.Errorf("SRV record data mismatch: %+v", parsed)
	}
}

func TestDNSRecord_ReadWrite_AAAA(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	record := DNSRecord{
		Name: "aaaa.test.",
		Type: AAAA,
		TTL:  300,
		IP:   ip,
	}

	buffer := NewBytePacketBuffer()
	_, err := record.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write AAAA record: %v", err)
	}

	_ = buffer.Seek(0)
	parsed := DNSRecord{}
	err = parsed.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read AAAA record: %v", err)
	}

	if parsed.IP.String() != ip.String() {
		t.Errorf("AAAA IP mismatch: expected %s, got %s", ip, parsed.IP)
	}
}

func TestDNSRecord_Write_SpecialClasses(t *testing.T) {
	// Class ANY (255) for Dynamic Updates (RFC 2136)
	record := DNSRecord{
		Name:  "delete.test.",
		Type:  A,
		Class: 255,
		TTL:   0,
	}

	buffer := NewBytePacketBuffer()
	_, err := record.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write Class ANY record: %v", err)
	}

	// Class ANY should have 0 RDLENGTH
	_ = buffer.Seek(buffer.Position() - 2)
	rdLen, _ := buffer.Readu16()
	if rdLen != 0 {
		t.Errorf("Class ANY record should have 0 RDLENGTH, got %d", rdLen)
	}
}

func TestBytePacketBuffer_Writeu32_Error(t *testing.T) {
	buffer := NewBytePacketBuffer()
	buffer.Pos = MaxPacketSize - 2
	err := buffer.Writeu32(0x12345678)
	if err == nil {
		t.Error("expected error when writing u32 out of bounds")
	}
}

func TestBytePacketBuffer_Writeu16_Error(t *testing.T) {
	buffer := NewBytePacketBuffer()
	buffer.Pos = MaxPacketSize - 1
	err := buffer.Writeu16(0x1234)
	if err == nil {
		t.Error("expected error when writing u16 out of bounds")
	}
}

func TestBytePacketBuffer_Seek_Error(t *testing.T) {
	buffer := NewBytePacketBuffer()
	err := buffer.Seek(MaxPacketSize + 1)
	if err == nil {
		t.Error("expected error when seeking out of bounds")
	}
}

func TestDNSHeader_ReadWrite_Error(t *testing.T) {
	buffer := NewBytePacketBuffer()
	h := DNSHeader{ID: 1}
	
	// Truncate buffer to fail during read
	_ = h.Write(buffer)
	data := buffer.Buf[:5] // Header is 12 bytes
	
	failBuf := NewBytePacketBuffer()
	failBuf.Load(data)
	
	parsed := DNSHeader{}
	if err := parsed.Read(failBuf); err == nil {
		t.Error("expected error when reading truncated header")
	}
}

func TestDNSRecord_Read_HINFO(t *testing.T) {
	record := DNSRecord{
		Name: "h.test.",
		Type: HINFO,
		TTL:  300,
		CPU:  "ARM",
		OS:   "OSX",
	}
	buf := NewBytePacketBuffer()
	_, _ = record.Write(buf)
	
	_ = buf.Seek(0)
	parsed := DNSRecord{}
	if err := parsed.Read(buf); err != nil {
		t.Fatalf("Read HINFO failed: %v", err)
	}
	if parsed.CPU != "ARM" || parsed.OS != "OSX" {
		t.Errorf("HINFO data mismatch")
	}
}
