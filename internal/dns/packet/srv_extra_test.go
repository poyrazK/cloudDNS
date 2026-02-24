package packet

import (
	"testing"
)

func TestDNSRecord_ReadWrite_SRV_Comprehensive(t *testing.T) {
	record := DNSRecord{
		Name:     "_sip._tcp.example.com.",
		Type:     SRV,
		TTL:      300,
		Priority: 10,
		Weight:   20,
		Port:     5060,
		Host:     "pbx.example.com.",
	}

	buffer := NewBytePacketBuffer()
	_, err := record.Write(buffer)
	if err != nil {
		t.Fatalf("SRV Write failed: %v", err)
	}

	_ = buffer.Seek(0)
	parsed := DNSRecord{}
	err = parsed.Read(buffer)
	if err != nil {
		t.Fatalf("SRV Read failed: %v", err)
	}

	if parsed.Priority != 10 || parsed.Weight != 20 || parsed.Port != 5060 || parsed.Host != "pbx.example.com." {
		t.Errorf("SRV mismatch: %+v", parsed)
	}
}
