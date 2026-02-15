package packet

import (
	"bytes"
	"testing"
)

func TestNSEC3_HashAndEncode(t *testing.T) {
	name := "example.com."
	salt := []byte{0xab, 0xcd}
	iterations := uint16(1)

	// 1. Hash it
	hash := HashName(name, 1, iterations, salt)
	if len(hash) != 20 { // SHA-1 is 20 bytes
		t.Errorf("Expected 20 byte hash, got %d", len(hash))
	}

	// 2. Encode it
	encoded := Base32Encode(hash)
	if len(encoded) == 0 {
		t.Errorf("Encoded string should not be empty")
	}

	// 3. Test with 0 iterations
	hash0 := HashName(name, 1, 0, salt)
	if bytes.Equal(hash, hash0) {
		t.Errorf("Different iteration counts should produce different hashes")
	}
}

func TestHashName_Root(t *testing.T) {
	h1 := HashName(".", 1, 0, nil)
	h2 := HashName("", 1, 0, nil)
	if !bytes.Equal(h1, h2) {
		t.Errorf("Root dot and empty string should produce same hash")
	}
}

func TestBase32Encode_Small(t *testing.T) {
	// Test data that doesn't align perfectly with 5-bit boundaries
	data := []byte{0xFF} // 1111 1111 -> 11111 11100 -> 'v' 's'
	got := Base32Encode(data)
	if got != "vs" {
		t.Errorf("Expected vs, got %s", got)
	}
}
