package packet

import (
	"crypto/hmac"
	"crypto/md5"
	"errors"
	"time"
)

// VerifyTSIG checks if the TSIG record in the packet matches the provided key
func (p *DnsPacket) VerifyTSIG(rawBuffer []byte, keyName string, secret []byte) error {
	// 1. Find TSIG record (must be the last record in additional)
	if len(p.Resources) == 0 {
		return errors.New("no records in additional section")
	}
	tsig := p.Resources[len(p.Resources)-1]
	if tsig.Type != TSIG {
		return errors.New("last record is not TSIG")
	}

	// 2. Check key name
	if tsig.Name != keyName {
		return errors.New("TSIG key name mismatch")
	}

	// 3. Check time drift (Fudge)
	now := uint64(time.Now().Unix())
	drift := uint64(0)
	if now > tsig.TimeSigned {
		drift = now - tsig.TimeSigned
	} else {
		drift = tsig.TimeSigned - now
	}
	if drift > uint64(tsig.Fudge) {
		return errors.New("TSIG time drift exceeded")
	}

	// 4. Reconstruct original packet without TSIG for HMAC
	// The HMAC is over: [original packet without TSIG] + [TSIG variables]
	// According to RFC 2845, we need to strip the TSIG record and adjust ARCOUNT
	
	// Implementation Note: Since we have the rawBuffer, we can find where TSIG starts
	// and take everything before it.
	
	// 5. Compute HMAC
	h := hmac.New(md5.New, secret)
	
	// Add original data (we would need to adjust the ARCOUNT in the header byte 11)
	// For simplicity in this scratch version, we assume the caller provides the correct buffer
	h.Write(rawBuffer)
	
	// Add TSIG variables (RFC 2845 Section 3.4.1)
	// [Name] [Class] [TTL] [Algorithm] [Time] [Fudge] [Error] [Other]
	// (Note: Name and Algorithm are in wire format)
	
	// Verification logic...
	return nil // Skeleton for now
}

func (p *DnsPacket) SignTSIG(buffer *BytePacketBuffer, keyName string, secret []byte) error {
	// 1. Prepare TSIG Record (without MAC yet)
	tsig := DnsRecord{
		Name:          keyName,
		Type:          TSIG,
		Class:         255, // ANY
		TTL:           0,
		AlgorithmName: "hmac-md5.sig-alg.reg.int.",
		TimeSigned:    uint64(time.Now().Unix()),
		Fudge:         300,
		OriginalID:    p.Header.ID,
	}

	// 2. Compute MAC
	h := hmac.New(md5.New, secret)
	// Write current buffer content (packet without TSIG)
	h.Write(buffer.Buf[:buffer.Position()])
	
	// Add TSIG variables to HMAC...
	
	tsig.MAC = h.Sum(nil)

	// 3. Write TSIG record to buffer
	_, err := tsig.Write(buffer)
	return err
}
