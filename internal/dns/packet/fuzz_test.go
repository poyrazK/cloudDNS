package packet

import (
	"testing"
)

// FuzzDNSPacketParse tests the robustness of the DNS packet parser against arbitrary byte slices.
// It ensures that malformed, truncated, or malicious payloads return an error rather than panicking or causing an infinite loop.
func FuzzDNSPacketParse(f *testing.F) {
	// Add seed corpus to guide the fuzzer

	// Seed 1: A valid, simple A record query for "example.com."
	validQuery := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags (Standard query)
		0x00, 0x01, // QDCOUNT (1)
		0x00, 0x00, // ANCOUNT (0)
		0x00, 0x00, // NSCOUNT (0)
		0x00, 0x00, // ARCOUNT (0)
		// Question
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, // Name
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
	}
	f.Add(validQuery)

	// Seed 2: Empty packet
	f.Add([]byte{})

	// Seed 3: Truncated header
	f.Add([]byte{0x12, 0x34, 0x01})

	// Seed 4: Malformed pointer (pointer loop / out of bounds)
	f.Add([]byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xC0, 0x0C, // Pointer pointing to itself
		0x00, 0x01, 0x00, 0x01,
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		buf := NewBytePacketBuffer()
		buf.Load(data)

		pkt := NewDNSPacket()

		// The sole requirement of this fuzz test is that it does not panic, hang, or leak.
		// Returning an error on garbage data is the expected and correct behavior.
		_ = pkt.FromBuffer(buf)
	})
}

// FuzzDNSPacketRoundTrip tests that any successfully parsed packet can be serialized
// back to bytes and parsed again into an identical packet.
func FuzzDNSPacketRoundTrip(f *testing.F) {
	// Add seed corpus
	validQuery := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags
		0x00, 0x01, // QDCOUNT
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
	}
	f.Add(validQuery)

	f.Fuzz(func(t *testing.T, data []byte) {
		buf1 := NewBytePacketBuffer()
		buf1.Load(data)
		pkt1 := NewDNSPacket()
		if err := pkt1.FromBuffer(buf1); err != nil {
			return // Ignore invalid packets
		}

		// Serialize the packet
		buf2 := NewBytePacketBuffer()
		buf2.HasNames = true // Enable compression for realistic conditions
		if err := pkt1.Write(buf2); err != nil {
			t.Fatalf("Failed to serialize successfully parsed packet: %v", err)
		}

		// Parse it again
		serializedData := buf2.Buf[:buf2.Position()]
		buf3 := NewBytePacketBuffer()
		buf3.Load(serializedData)
		pkt2 := NewDNSPacket()
		if err := pkt2.FromBuffer(buf3); err != nil {
			t.Fatalf("Failed to parse serialized packet: %v", err)
		}

		// Deep check core properties to ensure data loss didn't occur
		if pkt1.Header.ID != pkt2.Header.ID {
			t.Errorf("Header ID mismatch: %v != %v", pkt1.Header.ID, pkt2.Header.ID)
		}
		if len(pkt1.Questions) != len(pkt2.Questions) {
			t.Errorf("Question count mismatch: %d != %d", len(pkt1.Questions), len(pkt2.Questions))
		}
		if len(pkt1.Answers) != len(pkt2.Answers) {
			t.Errorf("Answer count mismatch: %d != %d", len(pkt1.Answers), len(pkt2.Answers))
		}
	})
}

