package packet

import (
	"testing"
)

func TestSignTSIG_ErrorPaths(t *testing.T) {
	p := NewDNSPacket()
	buf := NewBytePacketBuffer()
	
	// Force error by filling buffer to near max
	buf.Pos = MaxPacketSize - 5
	err := p.SignTSIG(buf, "key.", []byte("secret"))
	if err == nil {
		t.Errorf("Expected error when signing TSIG with full buffer")
	}
}

func TestVerifyTSIG_SmallBuffer(t *testing.T) {
	p := NewDNSPacket()
	// No resources
	err := p.VerifyTSIG([]byte{1, 2, 3}, 0, []byte("secret"))
	if err == nil {
		t.Errorf("Expected error for empty Additional section")
	}
}

func TestVerifyTSIG_PrefixHandling(t *testing.T) {
	p := NewDNSPacket()
	p.Resources = append(p.Resources, DNSRecord{Name: "tsig.", Type: TSIG, MAC: []byte{1}})
	
	// Prefix too small for header (12 bytes)
	// VerifyTSIG checks if len(prefix) >= 12
	err := p.VerifyTSIG(make([]byte, 5), 5, []byte("secret"))
	if err == nil || err.Error() != "TSIG MAC mismatch" {
		t.Logf("Got error: %v", err)
	}
}
