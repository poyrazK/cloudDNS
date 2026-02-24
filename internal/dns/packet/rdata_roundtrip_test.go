package packet

import (
	"testing"
)

func TestDNSRecord_ReadWrite_MINFO(t *testing.T) {
	record := DNSRecord{
		Name:    "minfo.test.",
		Type:    MINFO,
		TTL:     300,
		RMailBX: "r.test.",
		EMailBX: "e.test.",
	}

	buffer := NewBytePacketBuffer()
	_, _ = record.Write(buffer)
	_ = buffer.Seek(0)
	
	parsed := DNSRecord{}
	_ = parsed.Read(buffer)
	
	if parsed.RMailBX != "r.test." || parsed.EMailBX != "e.test." {
		t.Errorf("MINFO mismatch: %+v", parsed)
	}
}

func TestDNSRecord_ReadWrite_PTR(t *testing.T) {
	record := DNSRecord{
		Name: "1.1.1.1.in-addr.arpa.",
		Type: PTR,
		TTL:  300,
		Host: "host.test.",
	}

	buffer := NewBytePacketBuffer()
	_, _ = record.Write(buffer)
	_ = buffer.Seek(0)
	
	parsed := DNSRecord{}
	_ = parsed.Read(buffer)
	
	if parsed.Host != "host.test." {
		t.Errorf("PTR mismatch: %+v", parsed)
	}
}

func TestDNSRecord_ReadWrite_MX(t *testing.T) {
	record := DNSRecord{
		Name:     "mx.test.",
		Type:     MX,
		TTL:      300,
		Priority: 10,
		Host:     "mail.test.",
	}

	buffer := NewBytePacketBuffer()
	_, _ = record.Write(buffer)
	_ = buffer.Seek(0)
	
	parsed := DNSRecord{}
	_ = parsed.Read(buffer)
	
	if parsed.Priority != 10 || parsed.Host != "mail.test." {
		t.Errorf("MX mismatch: %+v", parsed)
	}
}

func TestDNSRecord_Write_Generic(t *testing.T) {
	// Test the default case in Write
	record := DNSRecord{
		Name: "generic.test.",
		Type: UNKNOWN,
		Data: []byte{1, 2, 3},
		TTL:  300,
	}
	buf := NewBytePacketBuffer()
	_, err := record.Write(buf)
	if err != nil {
		t.Errorf("Generic write failed: %v", err)
	}
}

func TestDNSRecord_Write_NONE(t *testing.T) {
	// RFC 2136 Class NONE (254)
	record := DNSRecord{
		Name:  "none.test.",
		Type:  A,
		Class: 254,
		TTL:   0,
		Data:  nil,
	}
	buf := NewBytePacketBuffer()
	_, err := record.Write(buf)
	if err != nil {
		t.Errorf("Class NONE write failed: %v", err)
	}
}
