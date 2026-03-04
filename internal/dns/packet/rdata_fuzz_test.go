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

// FuzzSRVParse targets the SRV record parsing logic.
func FuzzSRVParse(f *testing.F) {
	// Priority(2), Weight(2), Port(2), TargetName
	validSRV := []byte{0x00, 0x0A, 0x00, 0x14, 0x1F, 0x90, 0x06, 't', 'a', 'r', 'g', 'e', 't', 0x00}
	f.Add(validSRV)
	
	f.Fuzz(func(t *testing.T, data []byte) {
		buf := NewBytePacketBuffer()
		_ = buf.WriteName("_sip._tcp.example.com.")
		_ = buf.Writeu16(uint16(SRV))
		_ = buf.Writeu16(1)
		_ = buf.Writeu32(300)
		_ = buf.Writeu16(uint16(len(data)))
		_ = buf.WriteRange(buf.Position(), data)

		buf.Len = buf.Pos
		buf.parsing = true
		_ = buf.Seek(0)

		parsed := DNSRecord{}
		_ = parsed.Read(buf)
	})
}

// FuzzSOAParse targets the SOA record parsing logic.
func FuzzSOAParse(f *testing.F) {
	// MName, RName, Serial(4), Refresh(4), Retry(4), Expire(4), Minimum(4)
	validSOA := []byte{
		0x03, 'n', 's', '1', 0x00, 
		0x05, 'a', 'd', 'm', 'i', 'n', 0x00,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x0E, 0x10,
		0x00, 0x00, 0x02, 0x58,
		0x00, 0x09, 0x3A, 0x80,
		0x00, 0x00, 0x01, 0x2C,
	}
	f.Add(validSOA)

	f.Fuzz(func(t *testing.T, data []byte) {
		buf := NewBytePacketBuffer()
		_ = buf.WriteName("example.com.")
		_ = buf.Writeu16(uint16(SOA))
		_ = buf.Writeu16(1)
		_ = buf.Writeu32(300)
		_ = buf.Writeu16(uint16(len(data)))
		_ = buf.WriteRange(buf.Position(), data)

		buf.Len = buf.Pos
		buf.parsing = true
		_ = buf.Seek(0)

		parsed := DNSRecord{}
		_ = parsed.Read(buf)
	})
}
