package packet

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- SHA-1 required for DNSSEC DS records (RFC 4034)
	"crypto/sha256"
	"strings"
)

// DNSSEC Algorithm numbers per RFC 8624
const (
	AlgorithmRSASHA256 uint8 = 8
	AlgorithmECDSAP256 uint8 = 13
	AlgorithmED25519   uint8 = 15
)

// ComputeKeyTag calculates the key tag for a DNSKEY record according to RFC 4034 Appendix B.
// This is used to quickly identify which DNSKEY a signature refers to.
func (r *DNSRecord) ComputeKeyTag() uint16 {
	if r.Type != DNSKEY {
		return 0
	}

	buf := NewBytePacketBuffer()
	if err := buf.Writeu16(r.Flags); err != nil {
		return 0
	}
	if err := buf.Write(3); err != nil {
		return 0
	} // Protocol: MUST be 3 (RFC 4034 Section 2.1.2)
	if err := buf.Write(r.Algorithm); err != nil {
		return 0
	}
	for _, b := range r.PublicKey {
		if err := buf.Write(b); err != nil {
			return 0
		}
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
	return uint16(ac & 0xFFFF) // #nosec G115
}

// ComputeDS generates a Delegation Signer (DS) record from a DNSKEY record (RFC 4034 Section 5.2).
// Supported digest types:
//   - 1: SHA-1
//   - 2: SHA-256
func (r *DNSRecord) ComputeDS(digestType uint8) (DNSRecord, error) {
	if r.Type != DNSKEY {
		return DNSRecord{}, nil
	}

	// 1. Prepare Buffer: The digest is calculated over [owner name | DNSKEY RDATA]
	// Owner name MUST be in its canonical wire format (lowercase, no compression).
	buf := NewBytePacketBuffer()
	if err := buf.WriteName(strings.ToLower(r.Name)); err != nil {
		return DNSRecord{}, err
	}
	if err := buf.Writeu16(r.Flags); err != nil {
		return DNSRecord{}, err
	}
	if err := buf.Write(3); err != nil {
		return DNSRecord{}, err
	} // Protocol: MUST be 3 per RFC 4034
	if err := buf.Write(r.Algorithm); err != nil {
		return DNSRecord{}, err
	}
	for _, b := range r.PublicKey {
		if err := buf.Write(b); err != nil {
			return DNSRecord{}, err
		}
	}

	// 2. Calculate the cryptographic digest
	var digest []byte
	switch digestType {
	case 1: // SHA-1
		hashed := sha1.Sum(buf.Buf[:buf.Position()]) // #nosec G401
		digest = hashed[:]
	case 2: // SHA-256
		hashed := sha256.Sum256(buf.Buf[:buf.Position()])
		digest = hashed[:]
	default:
		// Unsupported digest type - return empty record per RFC 4034 expectations in some contexts
		return DNSRecord{}, nil
	}

	return DNSRecord{
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

// SignRRSet generates an RRSIG for a set of records.
// Supports ECDSA P-256 (Algorithm 13), RSA SHA-256 (Algorithm 8), and Ed25519 (Algorithm 15).
func SignRRSet(records []DNSRecord, privKey any, algorithm uint8, signerName string, keyTag uint16, inception, expiration uint32) (DNSRecord, error) {
	if len(records) == 0 {
		return DNSRecord{}, nil
	}

	sig := DNSRecord{
		Name:        records[0].Name,
		Type:        RRSIG,
		Class:       1,
		TTL:         records[0].TTL,
		TypeCovered: uint16(records[0].Type),
		Algorithm:   algorithm,
		Labels:      uint8(countLabels(records[0].Name)), // #nosec G115
		OrigTTL:     records[0].TTL,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      keyTag,
		SignerName:  signerName,
	}

	buf := NewBytePacketBuffer()

	// Prepend RRSIG RDATA fields (excluding Signature) per RFC 4034 Section 8.1
	if err := buf.Writeu16(sig.TypeCovered); err != nil {
		return DNSRecord{}, err
	}
	if err := buf.Write(sig.Algorithm); err != nil {
		return DNSRecord{}, err
	}
	if err := buf.Write(sig.Labels); err != nil {
		return DNSRecord{}, err
	}
	if err := buf.Writeu32(sig.OrigTTL); err != nil {
		return DNSRecord{}, err
	}
	if err := buf.Writeu32(sig.Expiration); err != nil {
		return DNSRecord{}, err
	}
	if err := buf.Writeu32(sig.Inception); err != nil {
		return DNSRecord{}, err
	}
	if err := buf.Writeu16(sig.KeyTag); err != nil {
		return DNSRecord{}, err
	}
	if err := buf.WriteName(strings.ToLower(sig.SignerName)); err != nil {
		return DNSRecord{}, err
	}

	// Write canonical RRset per RFC 4034: owner|type|class|Original TTL|RDLENGTH|RDATA
	for _, r := range records {
		if err := buf.WriteName(strings.ToLower(r.Name)); err != nil {
			return DNSRecord{}, err
		}
		if err := buf.Writeu16(uint16(r.Type)); err != nil {
			return DNSRecord{}, err
		}
		if err := buf.Writeu16(1); err != nil {
			return DNSRecord{}, err
		} // Class IN
		if err := buf.Writeu32(sig.OrigTTL); err != nil {
			return DNSRecord{}, err
		}
		// Write RDATA in canonical form
		if err := writeSignCanonicalRData(&r, buf); err != nil {
			return DNSRecord{}, err
		}
	}

	hashed := crypto.SHA256.New()
	hashed.Write(buf.Buf[:buf.Position()])
	h := hashed.Sum(nil)

	var sigData []byte
	switch algorithm {
	case AlgorithmECDSAP256:
		ecdsaPriv, ok := privKey.(*ecdsa.PrivateKey)
		if !ok {
			return DNSRecord{}, ErrInvalidSignature
		}
		rb, sb, err := ecdsa.Sign(rand.Reader, ecdsaPriv, h)
		if err != nil {
			return DNSRecord{}, err
		}
		rBytes := rb.FillBytes(make([]byte, 32))
		sBytes := sb.FillBytes(make([]byte, 32))
		sigData = make([]byte, 64)
		copy(sigData[0:32], rBytes)
		copy(sigData[32:64], sBytes)

	case AlgorithmRSASHA256:
		rsaPriv, ok := privKey.(*rsa.PrivateKey)
		if !ok {
			return DNSRecord{}, ErrInvalidSignature
		}
		var err error
		sigData, err = rsa.SignPKCS1v15(rand.Reader, rsaPriv, crypto.SHA256, h)
		if err != nil {
			return DNSRecord{}, err
		}

	case AlgorithmED25519:
		ed25519Priv, ok := privKey.([ed25519.PrivateKeySize]byte)
		if !ok {
			return DNSRecord{}, ErrInvalidSignature
		}
		sigData = ed25519.Sign(ed25519Priv[:], buf.Buf[:buf.Position()])

	default:
		return DNSRecord{}, ErrUnsupportedAlgorithm
	}

	sig.Signature = sigData
	return sig, nil
}

// countLabels returns the number of DNS name labels (e.g., "www.example.com." has 3).
func countLabels(name string) int {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return 0
	}
	return len(strings.Split(name, "."))
}

// writeSignCanonicalRData writes the RDATA portion of a record in canonical form for signing.
// Handles all record types per RFC 4034 canonical wire format.
func writeSignCanonicalRData(r *DNSRecord, buf *BytePacketBuffer) error {
	switch r.Type {
	case A:
		ip4 := r.IP.To4()
		if ip4 == nil {
			break
		}
		if err := buf.Writeu16(4); err != nil {
			return err
		}
		for _, b := range ip4 {
			if err := buf.Write(b); err != nil {
				return err
			}
		}
		return nil
	case AAAA:
		if err := buf.Writeu16(16); err != nil {
			return err
		}
		return writeBytes(buf, r.IP.To16())
	case CNAME, NS, PTR:
		return buf.WriteName(strings.ToLower(r.Host))
	case MX:
		if err := buf.Writeu16(r.Priority); err != nil {
			return err
		}
		return buf.WriteName(strings.ToLower(r.Host))
	case TXT:
		for _, chunk := range stringsToChunks(r.Txt) {
			if err := buf.WriteUint8(len(chunk)); err != nil {
				return err
			}
			if err := writeBytes(buf, []byte(chunk)); err != nil {
				return err
			}
		}
		return nil
	case SOA:
		if err := buf.WriteName(strings.ToLower(r.MName)); err != nil {
			return err
		}
		if err := buf.WriteName(strings.ToLower(r.RName)); err != nil {
			return err
		}
		if err := buf.Writeu32(r.Serial); err != nil {
			return err
		}
		if err := buf.Writeu32(r.Refresh); err != nil {
			return err
		}
		if err := buf.Writeu32(r.Retry); err != nil {
			return err
		}
		if err := buf.Writeu32(r.Expire); err != nil {
			return err
		}
		return buf.Writeu32(r.Minimum)
	case SRV:
		if err := buf.Writeu16(r.Priority); err != nil {
			return err
		}
		if err := buf.Writeu16(r.Weight); err != nil {
			return err
		}
		if err := buf.Writeu16(r.Port); err != nil {
			return err
		}
		return buf.WriteName(strings.ToLower(r.Host))
	case DNSKEY:
		if err := buf.Writeu16(r.Flags); err != nil {
			return err
		}
		if err := buf.Write(3); err != nil {
			return err
		}
		if err := buf.Write(r.Algorithm); err != nil {
			return err
		}
		return writeBytes(buf, r.PublicKey)
	case DS:
		if err := buf.Writeu16(r.KeyTag); err != nil {
			return err
		}
		if err := buf.Write(r.Algorithm); err != nil {
			return err
		}
		if err := buf.Write(r.DigestType); err != nil {
			return err
		}
		return writeBytes(buf, r.Digest)
	case NSEC:
		if err := buf.WriteName(strings.ToLower(r.NextName)); err != nil {
			return err
		}
		return writeBytes(buf, r.TypeBitMap)
	default:
		if len(r.Data) > 0 {
			return writeBytes(buf, r.Data)
		}
	}
	return nil
}
