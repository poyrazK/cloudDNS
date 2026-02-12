package packet

import (
	"crypto/sha1"
	"strings"
)

// RFC 5155: NSEC3 Hashing
func HashName(name string, alg uint8, iterations uint16, salt []byte) []byte {
	// 1. Canonicalize name (lowercase and wire format)
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	// Manual wire format conversion for hashing (simplified)
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	var wire []byte
	for _, l := range labels {
		wire = append(wire, byte(len(l)))
		wire = append(wire, []byte(l)...)
	}
	wire = append(wire, 0) // Null terminator

	// 2. Initial Hash: H(name | salt)
	h := sha1.New()
	h.Write(wire)
	h.Write(salt)
	res := h.Sum(nil)

	// 3. Iterative Hash: H(prev | salt)
	for i := uint16(0); i < iterations; i++ {
		h.Reset()
		h.Write(res)
		h.Write(salt)
		res = h.Sum(nil)
	}

	return res
}

// RFC 5155 Section 3.3: Base32 Encoding for NSEC3
// Note: This is NOT standard RFC 4648 Base32. It uses a specific character set.
const nsec3Base32Map = "0123456789abcdefghijklmnopqrstuv"

func Base32Encode(data []byte) string {
	var res strings.Builder
	// Process bits in 5-bit chunks
	var val uint32
	var bits uint8
	for _, b := range data {
		val = (val << 8) | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			res.WriteByte(nsec3Base32Map[(val>>bits)&0x1F])
		}
	}
	if bits > 0 {
		res.WriteByte(nsec3Base32Map[(val<<(5-bits))&0x1F])
	}
	return res.String()
}
