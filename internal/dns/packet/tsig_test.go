package packet

import (
	"testing"
	"time"
)

// TestVerifyTSIG_ErrorPaths validates the negative security and validation paths 
// for TSIG (RFC 2845).
func TestVerifyTSIG_ErrorPaths(t *testing.T) {
	keyName := "key."
	secret := []byte("secret")

	// 1. Missing TSIG record in Additional section.
	p := NewDNSPacket()
	buf := NewBytePacketBuffer()
	_ = p.Header.Write(buf)
	err := p.VerifyTSIG(buf.Buf, 0, secret)
	if err == nil || err.Error() != "no records in additional section" {
		t.Errorf("Expected 'no records in additional section', got %v", err)
	}

	// 2. Additional section exists, but the final record is not TSIG.
	p.Resources = append(p.Resources, DNSRecord{Name: "a.", Type: A, Class: 1, IP: nil})
	err = p.VerifyTSIG(buf.Buf, 0, secret)
	if err == nil || err.Error() != "last record is not TSIG" {
		t.Errorf("Expected 'last record is not TSIG', got %v", err)
	}

	// 3. Time drift validation: Ensure TSIG fails if Time Signed is outside the fudge window.
	p.Resources = []DNSRecord{} 
	tsig := DNSRecord{
		Name:       keyName,
		Type:       TSIG,
		Class:      255,
		TTL:        0,
		AlgorithmName: "hmac-md5.sig-alg.reg.int.",
		TimeSigned: uint64(time.Now().Add(-10 * time.Minute).Unix()), // #nosec G115
		Fudge:      300, // 5 min window
		MAC:        []byte{1,2,3},
	}
	p.Resources = append(p.Resources, tsig)
	
	// Reconstruct buffer to include the fake TSIG record.
	buf.Reset()
	_ = p.Write(buf)
	
	err = p.VerifyTSIG(buf.Buf, 0, secret) 
	if err == nil || err.Error() != "TSIG time drift exceeded" {
		t.Errorf("Expected 'TSIG time drift exceeded', got %v", err)
	}

	// 4. MAC Mismatch: Ensure TSIG fails if the packet content has been tampered with.
	pClean := NewDNSPacket()
	pClean.Header.ID = 1234
	bufClean := NewBytePacketBuffer()
	_ = pClean.Header.Write(bufClean)
	
	// Correctly sign the packet first.
	_ = pClean.SignTSIG(bufClean, keyName, secret)
	
	// Tamper with the raw buffer (change the first byte of the header).
	bufClean.Buf[0] = 0xFF 
	
	err = pClean.VerifyTSIG(bufClean.Buf[:bufClean.Position()], pClean.TSIGStart, secret)
	if err == nil || err.Error() != "TSIG MAC mismatch" {
		t.Errorf("Expected 'TSIG MAC mismatch', got %v", err)
	}
}
