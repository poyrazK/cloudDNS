package packet

import (
	"testing"
	"time"
)

func TestSignAndVerifyTSIG(t *testing.T) {
	pkg := NewDNSPacket()
	pkg.Header.ID = 1234
	pkg.Questions = append(pkg.Questions, DNSQuestion{Name: "test.auth.", QType: A, QClass: 1})

	buffer := NewBytePacketBuffer()
	if err := pkg.Write(buffer); err != nil {
		t.Fatalf("Failed to write packet: %v", err)
	}

	secret := []byte("my-secret-key")
	keyName := "tsig-key."

	// Test SignTSIG
	if err := pkg.SignTSIG(buffer, keyName, secret); err != nil {
		t.Fatalf("Failed to sign TSIG: %v", err)
	}

	// Read packet back to verify
	_ = buffer.Seek(0)
	parsedPkg := NewDNSPacket()
	if err := parsedPkg.FromBuffer(buffer); err != nil {
		t.Fatalf("Failed to parse signed packet: %v", err)
	}

	if len(parsedPkg.Resources) != 1 || parsedPkg.Resources[0].Type != TSIG {
		t.Fatalf("Expected TSIG record in additional resources")
	}

	// Test VerifyTSIG
	// Note: We need the raw buffer to verify because TSIG verifies the original binary payload
	if err := parsedPkg.VerifyTSIG(buffer.Buf, parsedPkg.TSIGStart, secret); err != nil {
		t.Errorf("Failed to verify TSIG: %v", err)
	}

	// Test VerifyTSIG Failure (Wrong Secret)
	if err := parsedPkg.VerifyTSIG(buffer.Buf, parsedPkg.TSIGStart, []byte("wrong-key")); err == nil {
		t.Errorf("VerifyTSIG should fail with wrong secret")
	}

	// Test VerifyTSIG Failure (No TSIG Record)
	emptyPkg := NewDNSPacket()
	if err := emptyPkg.VerifyTSIG(buffer.Buf, 0, secret); err == nil {
		t.Errorf("VerifyTSIG should fail on packet without TSIG")
	}

	// Test Time Drift
	parsedPkg.Resources[0].TimeSigned = uint64(time.Now().Unix() - 1000)
	if err := parsedPkg.VerifyTSIG(buffer.Buf, parsedPkg.TSIGStart, secret); err == nil {
		t.Errorf("VerifyTSIG should fail with huge time drift")
	}
}
