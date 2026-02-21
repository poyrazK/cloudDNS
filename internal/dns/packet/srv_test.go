package packet

import (
	"testing"
)

func TestSRVRecord_ReadWrite(t *testing.T) {
	buffer := NewBytePacketBuffer()
	
	original := DNSRecord{
		Name:     "service.example.com.",
		Type:     SRV,
		Class:    1,
		TTL:      3600,
		Priority: 10,
		Weight:   5,
		Port:     5060,
		Host:     "sipserver.example.com.",
	}

	// Write original record
	_, err := original.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write SRV record: %v", err)
	}

	// Read back into a new record
	buffer.Pos = 0
	decoded := DNSRecord{}
	err = decoded.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read SRV record: %v", err)
	}

	// Validate fields
	if decoded.Name != original.Name {
		t.Errorf("Name mismatch: got %s, want %s", decoded.Name, original.Name)
	}
	if decoded.Type != original.Type {
		t.Errorf("Type mismatch: got %v, want %v", decoded.Type, original.Type)
	}
	if decoded.Priority != original.Priority {
		t.Errorf("Priority mismatch: got %d, want %d", decoded.Priority, original.Priority)
	}
	if decoded.Weight != original.Weight {
		t.Errorf("Weight mismatch: got %d, want %d", decoded.Weight, original.Weight)
	}
	if decoded.Port != original.Port {
		t.Errorf("Port mismatch: got %d, want %d", decoded.Port, original.Port)
	}
	if decoded.Host != original.Host {
		t.Errorf("Host mismatch: got %s, want %s", decoded.Host, original.Host)
	}
}
