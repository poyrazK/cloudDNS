package packet

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"strings"
)

// RFC 4034 Appendix B: Key Tag Calculation
func (r *DnsRecord) ComputeKeyTag() uint16 {
	if r.Type != DNSKEY {
		return 0
	}

	buf := NewBytePacketBuffer()
	buf.Writeu16(r.Flags)
	buf.Write(3) // Protocol
	buf.Write(r.Algorithm)
	for _, b := range r.PublicKey {
		buf.Write(b)
	}

	data := buf.Buf[:buf.Position()]
	var ac uint32
	for i, b := range data {
		if i%2 == 0 {
			ac += uint32(b) << 8
		} else {
			ac += uint32(b)
		}
	}
	ac += (ac >> 16) & 0xFFFF
	return uint16(ac & 0xFFFF)
}

// RFC 4034 Section 5.2: DS RDATA Calculation
func (r *DnsRecord) ComputeDS(digestType uint8) (DnsRecord, error) {
	if r.Type != DNSKEY {
		return DnsRecord{}, nil
	}

	// 1. Prepare Buffer: owner name | RDATA
	buf := NewBytePacketBuffer()
	buf.WriteName(strings.ToLower(r.Name))
	buf.Writeu16(r.Flags)
	buf.Write(3) // Protocol
	buf.Write(r.Algorithm)
	for _, b := range r.PublicKey {
		buf.Write(b)
	}

	// 2. Hash it
	var digest []byte
	switch digestType {
	case 2: // SHA-256
		hashed := sha256.Sum256(buf.Buf[:buf.Position()])
		digest = hashed[:]
	default:
		// Unsupported or fallback
		return DnsRecord{}, nil
	}

	return DnsRecord{
		Name:       r.Name,
		Type:       DS,
		Class:      1,
		TTL:        r.TTL,
		KeyTag:     r.ComputeKeyTag(),
		Algorithm:  r.Algorithm,
		DigestType: digestType,
		Digest:     digest,
	}, nil
}

// SignRRSet generates an RRSIG for a set of records
// Simplified implementation for ECDSA P-256 (Algorithm 13)
func SignRRSet(records []DnsRecord, privKey *ecdsa.PrivateKey, signerName string, keyTag uint16, inception, expiration uint32) (DnsRecord, error) {
	if len(records) == 0 {
		return DnsRecord{}, nil
	}

	sig := DnsRecord{
		Name:        records[0].Name,
		Type:        RRSIG,
		Class:       1,
		TTL:         records[0].TTL,
		TypeCovered: uint16(records[0].Type),
		Algorithm:   13, // ECDSAP256SHA256
		Labels:      uint8(countLabels(records[0].Name)),
		OrigTTL:     records[0].TTL,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      keyTag,
		SignerName:  signerName,
	}

	buf := NewBytePacketBuffer()
	buf.Writeu16(sig.TypeCovered)
	buf.Write(sig.Algorithm)
	buf.Write(sig.Labels)
	buf.Writeu32(sig.OrigTTL)
	buf.Writeu32(sig.Expiration)
	buf.Writeu32(sig.Inception)
	buf.Writeu16(sig.KeyTag)
	buf.WriteName(sig.SignerName)

	for _, r := range records {
		buf.WriteName(strings.ToLower(r.Name))
		buf.Writeu16(uint16(r.Type))
		buf.Writeu16(uint16(1)) // Class IN
		buf.Writeu32(r.TTL)
		// Simplified: Real DNSSEC requires canonical RDATA serialization here
	}

	hashed := crypto.SHA256.New()
	hashed.Write(buf.Buf[:buf.Position()])
	h := hashed.Sum(nil)

	rb, sb, err := ecdsa.Sign(rand.Reader, privKey, h)
	if err != nil {
		return DnsRecord{}, err
	}

	rBytes := rb.Bytes()
	sBytes := sb.Bytes()
	sigData := make([]byte, 64)
	copy(sigData[32-len(rBytes):], rBytes)
	copy(sigData[64-len(sBytes):], sBytes)
	
	sig.Signature = sigData
	return sig, nil
}

func countLabels(name string) int {
	name = strings.TrimSuffix(name, ".")
	if name == "" { return 0 }
	return len(strings.Split(name, "."))
}
