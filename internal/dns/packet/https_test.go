package packet

import (
	"net"
	"testing"
)

func TestHTTPSRecord_ReadWrite(t *testing.T) {
	buffer := NewBytePacketBuffer()

	original := DNSRecord{
		Name:  "www.example.com.",
		Type:  HTTPS,
		Class: 1,
		TTL:   300,
		HTTPSPriority:  1,
		HTTPSTarget:    "service.example.com.",
		HTTPSAlpn:      []string{"h3", "h2"},
		HTTPSPort:      8443, // non-default port so it's written
		HTTPSIpv4Hint:  []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")},
		HTTPSIpv6Hint:  []net.IP{net.ParseIP("2001:db8::1")},
		HTTPSEchConfig: []byte{0x00, 0x01, 0x02, 0x03},
	}

	// Write original record
	_, err := original.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write HTTPS record: %v", err)
	}

	// Read back into a new record
	buffer.Pos = 0
	decoded := DNSRecord{}
	err = decoded.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read HTTPS record: %v", err)
	}

	// Validate fields
	if decoded.Name != original.Name {
		t.Errorf("Name mismatch: got %s, want %s", decoded.Name, original.Name)
	}
	if decoded.Type != original.Type {
		t.Errorf("Type mismatch: got %v, want %v", decoded.Type, original.Type)
	}
	if decoded.HTTPSPriority != original.HTTPSPriority {
		t.Errorf("HTTPSPriority mismatch: got %d, want %d", decoded.HTTPSPriority, original.HTTPSPriority)
	}
	if decoded.HTTPSTarget != original.HTTPSTarget {
		t.Errorf("HTTPSTarget mismatch: got %s, want %s", decoded.HTTPSTarget, original.HTTPSTarget)
	}
	if len(decoded.HTTPSAlpn) != len(original.HTTPSAlpn) {
		t.Errorf("HTTPSAlpn length mismatch: got %d, want %d", len(decoded.HTTPSAlpn), len(original.HTTPSAlpn))
	}
	for i, alpn := range decoded.HTTPSAlpn {
		if alpn != original.HTTPSAlpn[i] {
			t.Errorf("HTTPSAlpn[%d] mismatch: got %s, want %s", i, alpn, original.HTTPSAlpn[i])
		}
	}
	if decoded.HTTPSPort != original.HTTPSPort {
		t.Errorf("HTTPSPort mismatch: got %d, want %d", decoded.HTTPSPort, original.HTTPSPort)
	}
	if len(decoded.HTTPSIpv4Hint) != len(original.HTTPSIpv4Hint) {
		t.Errorf("HTTPSIpv4Hint length mismatch: got %d, want %d", len(decoded.HTTPSIpv4Hint), len(original.HTTPSIpv4Hint))
	}
	for i, ip := range decoded.HTTPSIpv4Hint {
		if !ip.Equal(original.HTTPSIpv4Hint[i]) {
			t.Errorf("HTTPSIpv4Hint[%d] mismatch: got %s, want %s", i, ip, original.HTTPSIpv4Hint[i])
		}
	}
	if len(decoded.HTTPSIpv6Hint) != len(original.HTTPSIpv6Hint) {
		t.Errorf("HTTPSIpv6Hint length mismatch: got %d, want %d", len(decoded.HTTPSIpv6Hint), len(original.HTTPSIpv6Hint))
	}
	for i, ip := range decoded.HTTPSIpv6Hint {
		if !ip.Equal(original.HTTPSIpv6Hint[i]) {
			t.Errorf("HTTPSIpv6Hint[%d] mismatch: got %s, want %s", i, ip, original.HTTPSIpv6Hint[i])
		}
	}
	if string(decoded.HTTPSEchConfig) != string(original.HTTPSEchConfig) {
		t.Errorf("HTTPSEchConfig mismatch: got %v, want %v", decoded.HTTPSEchConfig, original.HTTPSEchConfig)
	}
}

func TestHTTPSRecord_AliasMode(t *testing.T) {
	buffer := NewBytePacketBuffer()

	// Priority 0 = AliasMode (no SVCB params)
	original := DNSRecord{
		Name:           "example.com.",
		Type:           HTTPS,
		Class:          1,
		TTL:            300,
		HTTPSPriority: 0,
		HTTPSTarget:    "www.example.com.",
	}

	_, err := original.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write HTTPS AliasMode record: %v", err)
	}

	buffer.Pos = 0
	decoded := DNSRecord{}
	err = decoded.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read HTTPS AliasMode record: %v", err)
	}

	if decoded.HTTPSPriority != 0 {
		t.Errorf("HTTPSPriority mismatch: got %d, want 0 (AliasMode)", decoded.HTTPSPriority)
	}
	if decoded.HTTPSTarget != original.HTTPSTarget {
		t.Errorf("HTTPSTarget mismatch: got %s, want %s", decoded.HTTPSTarget, original.HTTPSTarget)
	}
	// AliasMode should have no params
	if len(decoded.HTTPSAlpn) != 0 {
		t.Errorf("HTTPSAlpn should be empty for AliasMode, got %d", len(decoded.HTTPSAlpn))
	}
}

func TestHTTPSRecord_NoDefault(t *testing.T) {
	buffer := NewBytePacketBuffer()

	original := DNSRecord{
		Name:           "https-only.example.com.",
		Type:           HTTPS,
		Class:          1,
		TTL:            300,
		HTTPSPriority:  1,
		HTTPSTarget:    "service.example.com.",
		HTTPSNoDefault: true,
		HTTPSAlpn:      []string{"h3"},
	}

	_, err := original.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write HTTPS record with no-default: %v", err)
	}

	buffer.Pos = 0
	decoded := DNSRecord{}
	err = decoded.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read HTTPS record with no-default: %v", err)
	}

	if !decoded.HTTPSNoDefault {
		t.Errorf("HTTPSNoDefault should be true")
	}
}

func TestHTTPSRecord_DefaultPort(t *testing.T) {
	buffer := NewBytePacketBuffer()

	// Port 443 is default and should not be written
	original := DNSRecord{
		Name:           "www.example.com.",
		Type:           HTTPS,
		Class:          1,
		TTL:            300,
		HTTPSPriority:  1,
		HTTPSTarget:    "service.example.com.",
		HTTPSPort:      443, // default
		HTTPSAlpn:      []string{"h3"},
	}

	_, err := original.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write HTTPS record: %v", err)
	}

	// Read back and verify port is not present (defaults to 0)
	buffer.Pos = 0
	decoded := DNSRecord{}
	err = decoded.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read HTTPS record: %v", err)
	}

	// Port 443 is default, so it should be 0 when read back (not written)
	if decoded.HTTPSPort != 0 {
		t.Errorf("HTTPSPort should be 0 (default) when 443 is not written, got %d", decoded.HTTPSPort)
	}
}

func TestHTTPSRecord_Write_OnlyAlpn(t *testing.T) {
	buffer := NewBytePacketBuffer()

	original := DNSRecord{
		Name:           "www.example.com.",
		Type:           HTTPS,
		Class:          1,
		TTL:            300,
		HTTPSPriority:  1,
		HTTPSTarget:    "service.example.com.",
		HTTPSAlpn:      []string{"h3", "h2"},
		// No port, no echconfig, no hints
	}

	_, err := original.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write HTTPS record: %v", err)
	}

	buffer.Pos = 0
	decoded := DNSRecord{}
	err = decoded.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read HTTPS record: %v", err)
	}

	if len(decoded.HTTPSAlpn) != 2 {
		t.Errorf("HTTPSAlpn length mismatch: got %d, want 2", len(decoded.HTTPSAlpn))
	}
	if decoded.HTTPSPort != 0 {
		t.Errorf("HTTPSPort should be 0, got %d", decoded.HTTPSPort)
	}
}

func TestHTTPSRecord_Write_OnlyEchConfig(t *testing.T) {
	buffer := NewBytePacketBuffer()

	original := DNSRecord{
		Name:           "www.example.com.",
		Type:           HTTPS,
		Class:          1,
		TTL:            300,
		HTTPSPriority:  1,
		HTTPSTarget:    "service.example.com.",
		HTTPSEchConfig: []byte{0x00, 0x01, 0x02, 0x03, 0x04},
	}

	_, err := original.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write HTTPS record: %v", err)
	}

	buffer.Pos = 0
	decoded := DNSRecord{}
	err = decoded.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read HTTPS record: %v", err)
	}

	if string(decoded.HTTPSEchConfig) != string(original.HTTPSEchConfig) {
		t.Errorf("HTTPSEchConfig mismatch: got %v, want %v", decoded.HTTPSEchConfig, original.HTTPSEchConfig)
	}
}

func TestHTTPSRecord_Write_OnlyIpv4Hint(t *testing.T) {
	buffer := NewBytePacketBuffer()

	original := DNSRecord{
		Name:           "www.example.com.",
		Type:           HTTPS,
		Class:          1,
		TTL:            300,
		HTTPSPriority:  1,
		HTTPSTarget:    "service.example.com.",
		HTTPSIpv4Hint:  []net.IP{net.ParseIP("192.0.2.1")},
	}

	_, err := original.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write HTTPS record: %v", err)
	}

	buffer.Pos = 0
	decoded := DNSRecord{}
	err = decoded.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read HTTPS record: %v", err)
	}

	if len(decoded.HTTPSIpv4Hint) != 1 {
		t.Errorf("HTTPSIpv4Hint length mismatch: got %d, want 1", len(decoded.HTTPSIpv4Hint))
	}
	if !decoded.HTTPSIpv4Hint[0].Equal(original.HTTPSIpv4Hint[0]) {
		t.Errorf("HTTPSIpv4Hint mismatch: got %v, want %v", decoded.HTTPSIpv4Hint[0], original.HTTPSIpv4Hint[0])
	}
}

func TestHTTPSRecord_Write_OnlyIpv6Hint(t *testing.T) {
	buffer := NewBytePacketBuffer()

	original := DNSRecord{
		Name:           "www.example.com.",
		Type:           HTTPS,
		Class:          1,
		TTL:            300,
		HTTPSPriority:  1,
		HTTPSTarget:    "service.example.com.",
		HTTPSIpv6Hint:  []net.IP{net.ParseIP("2001:db8::1")},
	}

	_, err := original.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write HTTPS record: %v", err)
	}

	buffer.Pos = 0
	decoded := DNSRecord{}
	err = decoded.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read HTTPS record: %v", err)
	}

	if len(decoded.HTTPSIpv6Hint) != 1 {
		t.Errorf("HTTPSIpv6Hint length mismatch: got %d, want 1", len(decoded.HTTPSIpv6Hint))
	}
	if !decoded.HTTPSIpv6Hint[0].Equal(original.HTTPSIpv6Hint[0]) {
		t.Errorf("HTTPSIpv6Hint mismatch: got %v, want %v", decoded.HTTPSIpv6Hint[0], original.HTTPSIpv6Hint[0])
	}
}

func TestHTTPSRecord_ReadWrite_RoundTrip(t *testing.T) {
	// Test with multiple ALPN values
	buffer := NewBytePacketBuffer()

	original := DNSRecord{
		Name:           "multi-alpn.example.com.",
		Type:           HTTPS,
		Class:          1,
		TTL:            600,
		HTTPSPriority:  1,
		HTTPSTarget:    "target.example.com.",
		HTTPSAlpn:      []string{"h3", "h2", "http/1.1"},
		HTTPSPort:      443,
	}

	_, err := original.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	buffer.Pos = 0
	decoded := DNSRecord{}
	err = decoded.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	if len(decoded.HTTPSAlpn) != 3 {
		t.Errorf("ALPN count mismatch: got %d, want 3", len(decoded.HTTPSAlpn))
	}
	for i, alpn := range []string{"h3", "h2", "http/1.1"} {
		if decoded.HTTPSAlpn[i] != alpn {
			t.Errorf("ALPN[%d] mismatch: got %s, want %s", i, decoded.HTTPSAlpn[i], alpn)
		}
	}
}

func TestHTTPSRecord_Read_AllParams(t *testing.T) {
	// Test reading a record with all possible SVCB params
	buffer := NewBytePacketBuffer()

	original := DNSRecord{
		Name:           "full.example.com.",
		Type:           HTTPS,
		Class:          1,
		TTL:            300,
		HTTPSPriority:  1,
		HTTPSTarget:    "service.example.com.",
		HTTPSAlpn:      []string{"h3"},
		HTTPSPort:      8443,
		HTTPSIpv4Hint:  []net.IP{net.ParseIP("192.0.2.1")},
		HTTPSIpv6Hint:  []net.IP{net.ParseIP("2001:db8::1")},
		HTTPSEchConfig: []byte{0x01, 0x02},
		HTTPSNoDefault: true,
	}

	_, err := original.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	buffer.Pos = 0
	decoded := DNSRecord{}
	err = decoded.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	if decoded.HTTPSNoDefault != true {
		t.Errorf("HTTPSNoDefault should be true")
	}
	if decoded.HTTPSPort != 8443 {
		t.Errorf("HTTPSPort mismatch: got %d, want 8443", decoded.HTTPSPort)
	}
}

func TestHTTPSRecord_Read_TruncatedKey(t *testing.T) {
	// Construct wire format: priority(2) + target name + 2 bytes of param (not enough for key+len=3)
	buffer := NewBytePacketBuffer()

	// Write a valid HTTPS record but with insufficient bytes for SVCB param parsing
	// RDLENGTH = 2 (priority) + target len + 2 (truncated param area)
	// The key byte is written but not the 2-byte length that follows
	rdlength := uint16(2 + 3 + 2) // priority(2) + target(".") + 2 bytes (truncated param)
	buffer.Writeu16(rdlength) // RDLENGTH
	buffer.Writeu16(1)        // Priority = 1
	buffer.WriteName("service.example.com.")
	// Write just a key byte without the length bytes
	buffer.Write(6)           // ipv4hint key
	buffer.Pos = 0
	buffer.Len = buffer.Pos

	decoded := DNSRecord{}
	err := decoded.Read(buffer)
	if err == nil {
		t.Fatalf("Expected error for truncated param, got nil")
	}
}

func TestHTTPSRecord_Write_AliasModeWithParams(t *testing.T) {
	// Priority 0 (AliasMode) must not have SVCB params
	buffer := NewBytePacketBuffer()

	original := DNSRecord{
		Name:           "example.com.",
		Type:           HTTPS,
		Class:          1,
		TTL:            300,
		HTTPSPriority:  0, // AliasMode
		HTTPSTarget:    "www.example.com.",
		HTTPSAlpn:      []string{"h3"}, // Should cause error
	}

	_, err := original.Write(buffer)
	if err == nil {
		t.Fatalf("Expected error when AliasMode has SVCB params, got nil")
	}
}

func TestHTTPSRecord_ReadWrite_AllFieldsSet(t *testing.T) {
	// Test with every HTTPS field populated
	buffer := NewBytePacketBuffer()

	original := DNSRecord{
		Name:            "full.example.com.",
		Type:            HTTPS,
		Class:           1,
		TTL:             600,
		HTTPSPriority:   1,
		HTTPSTarget:     "target.example.com.",
		HTTPSAlpn:       []string{"h3", "h2", "http/1.1"},
		HTTPSPort:       8443,
		HTTPSIpv4Hint:   []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")},
		HTTPSIpv6Hint:   []net.IP{net.ParseIP("2001:db8::1")},
		HTTPSEchConfig:  []byte{0x00, 0x01, 0x02, 0x03, 0x04},
		HTTPSNoDefault:   true,
	}

	_, err := original.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	buffer.Pos = 0
	decoded := DNSRecord{}
	err = decoded.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	// Verify all fields
	if decoded.HTTPSPriority != original.HTTPSPriority {
		t.Errorf("HTTPSPriority mismatch")
	}
	if decoded.HTTPSTarget != original.HTTPSTarget {
		t.Errorf("HTTPSTarget mismatch")
	}
	if len(decoded.HTTPSAlpn) != 3 {
		t.Errorf("HTTPSAlpn count: got %d, want 3", len(decoded.HTTPSAlpn))
	}
	if decoded.HTTPSPort != 8443 {
		t.Errorf("HTTPSPort mismatch: got %d, want 8443", decoded.HTTPSPort)
	}
	if len(decoded.HTTPSIpv4Hint) != 2 {
		t.Errorf("HTTPSIpv4Hint count: got %d, want 2", len(decoded.HTTPSIpv4Hint))
	}
	if len(decoded.HTTPSIpv6Hint) != 1 {
		t.Errorf("HTTPSIpv6Hint count: got %d, want 1", len(decoded.HTTPSIpv6Hint))
	}
	if len(decoded.HTTPSEchConfig) != 5 {
		t.Errorf("HTTPSEchConfig length: got %d, want 5", len(decoded.HTTPSEchConfig))
	}
	if !decoded.HTTPSNoDefault {
		t.Errorf("HTTPSNoDefault should be true")
	}
}

func TestHTTPSRecord_Write_OnlyIpv4HintExtra(t *testing.T) {
	// Only ipv4hint set, no other params
	buffer := NewBytePacketBuffer()

	original := DNSRecord{
		Name:           "www.example.com.",
		Type:           HTTPS,
		Class:          1,
		TTL:            300,
		HTTPSPriority:   1,
		HTTPSTarget:    "service.example.com.",
		HTTPSIpv4Hint:  []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")},
	}

	_, err := original.Write(buffer)
	if err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	buffer.Pos = 0
	decoded := DNSRecord{}
	err = decoded.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	if len(decoded.HTTPSIpv4Hint) != 2 {
		t.Errorf("HTTPSIpv4Hint count: got %d, want 2", len(decoded.HTTPSIpv4Hint))
	}
	if len(decoded.HTTPSAlpn) != 0 {
		t.Errorf("HTTPSAlpn should be empty, got %d", len(decoded.HTTPSAlpn))
	}
	if decoded.HTTPSPort != 0 {
		t.Errorf("HTTPSPort should be 0, got %d", decoded.HTTPSPort)
	}
}