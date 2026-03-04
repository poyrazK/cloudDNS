package packet

import (
	"testing"
)

// FuzzNSEC3Parse targets the NSEC3 record parsing logic.
func FuzzNSEC3Parse(f *testing.F) {
	// Seed 1: Valid NSEC3 record RDATA
	// Alg(1), Flags(1), Iter(2), SaltLen(1), Salt, HashLen(1), Hash, BitMap
	validNSEC3 := []byte{1, 0, 0, 10, 2, 0xAA, 0xBB, 2, 0xCC, 0xDD, 0, 1, 2}

	f.Add(validNSEC3)
	f.Add([]byte{}) // Empty
	f.Add([]byte{1, 0, 0, 10}) // Truncated before salt len

	f.Fuzz(func(t *testing.T, data []byte) {
		buf := NewBytePacketBuffer()
		_ = buf.WriteName("nsec3.test.")
		_ = buf.Writeu16(uint16(NSEC3))
		_ = buf.Writeu16(1) // Class IN
		_ = buf.Writeu32(300) // TTL
		_ = buf.Writeu16(uint16(len(data))) // RDLENGTH
		_ = buf.WriteRange(buf.Position(), data)

		buf.Len = buf.Pos
		buf.parsing = true
		_ = buf.Seek(0)

		parsed := DNSRecord{}
		_ = parsed.Read(buf) // Should not panic
	})
}

// FuzzRRSIGParse targets the RRSIG record parsing logic.
func FuzzRRSIGParse(f *testing.F) {
	// Type(2), Alg(1), Labels(1), TTL(4), Exp(4), Inc(4), Tag(2), Name, Sig
	validRRSIG := []byte{0x00, 0x01, 0x0D, 0x02, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x7B, 0x04, 't', 'e', 's', 't', 0x00, 0xDE, 0xAD}
	
	f.Add(validRRSIG)
	f.Add([]byte{})
	
	f.Fuzz(func(t *testing.T, data []byte) {
		buf := NewBytePacketBuffer()
		_ = buf.WriteName("rrsig.test.")
		_ = buf.Writeu16(uint16(RRSIG))
		_ = buf.Writeu16(1) // Class IN
		_ = buf.Writeu32(300) // TTL
		_ = buf.Writeu16(uint16(len(data))) // RDLENGTH
		_ = buf.WriteRange(buf.Position(), data)

		buf.Len = buf.Pos
		buf.parsing = true
		_ = buf.Seek(0)

		parsed := DNSRecord{}
		_ = parsed.Read(buf) // Should not panic
	})
}
