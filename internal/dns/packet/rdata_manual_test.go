package packet

import (
	"testing"
)

func TestDNSRecord_Read_WKS_Manual(t *testing.T) {
	// Manual buffer for WKS: IP(4) + Proto(1) + BitMap
	buf := NewBytePacketBuffer()
	_ = buf.Writeu16(0) // rdlen placeholder
	start := buf.Position()
	_ = buf.WriteRange(buf.Position(), []byte{127, 0, 0, 1, 6, 0x80})
	curr := buf.Position()
	_ = buf.Seek(start - 2)
	_ = buf.Writeu16(uint16(curr - start))
	_ = buf.Seek(curr)
	
	// Prepend name, type, class, ttl
	finalBuf := NewBytePacketBuffer()
	_ = finalBuf.WriteName("wks.test.")
	_ = finalBuf.Writeu16(uint16(WKS))
	_ = finalBuf.Writeu16(1)
	_ = finalBuf.Writeu32(300)
	_ = finalBuf.WriteRange(finalBuf.Position(), buf.Buf[:buf.Position()])
	
	finalBuf.Len = finalBuf.Pos
	finalBuf.parsing = true
	_ = finalBuf.Seek(0)
	
	parsed := DNSRecord{}
	err := parsed.Read(finalBuf)
	if err != nil {
		t.Fatalf("Read WKS failed: %v", err)
	}
}

func TestDNSRecord_Read_MINFO_Manual(t *testing.T) {
	buf := NewBytePacketBuffer()
	_ = buf.WriteName("r.test.")
	_ = buf.WriteName("e.test.")
	data := buf.Buf[:buf.Position()]
	
	finalBuf := NewBytePacketBuffer()
	_ = finalBuf.WriteName("minfo.test.")
	_ = finalBuf.Writeu16(uint16(MINFO))
	_ = finalBuf.Writeu16(1)
	_ = finalBuf.Writeu32(300)
	_ = finalBuf.Writeu16(uint16(len(data)))
	_ = finalBuf.WriteRange(finalBuf.Position(), data)
	
	finalBuf.Len = finalBuf.Pos
	finalBuf.parsing = true
	_ = finalBuf.Seek(0)
	
	parsed := DNSRecord{}
	_ = parsed.Read(finalBuf)
	if parsed.RMailBX != "r.test." {
		t.Errorf("expected r.test.")
	}
}

func TestDNSRecord_Read_DNSKEY_Manual(t *testing.T) {
	data := []byte{0x01, 0x00, 0x03, 0x0D, 0xAA, 0xBB} // Flags(2), Proto(1), Alg(1), Key
	
	finalBuf := NewBytePacketBuffer()
	_ = finalBuf.WriteName("dnskey.test.")
	_ = finalBuf.Writeu16(uint16(DNSKEY))
	_ = finalBuf.Writeu16(1)
	_ = finalBuf.Writeu32(300)
	_ = finalBuf.Writeu16(uint16(len(data)))
	_ = finalBuf.WriteRange(finalBuf.Position(), data)
	
	finalBuf.Len = finalBuf.Pos
	finalBuf.parsing = true
	_ = finalBuf.Seek(0)
	
	parsed := DNSRecord{}
	_ = parsed.Read(finalBuf)
	if parsed.Flags != 0x0100 || parsed.Algorithm != 0x0D {
		t.Errorf("DNSKEY mismatch")
	}
}

func TestDNSRecord_Read_RRSIG_Manual(t *testing.T) {
	// Type(2), Alg(1), Labels(1), TTL(4), Exp(4), Inc(4), Tag(2), Name, Sig
	data := []byte{0x00, 0x01, 0x0D, 0x02, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x7B}
	buf := NewBytePacketBuffer()
	_ = buf.WriteRange(0, data)
	_ = buf.Seek(len(data))
	_ = buf.WriteName("signer.test.")
	_ = buf.WriteRange(buf.Position(), []byte{0xDE, 0xAD})
	payload := buf.Buf[:buf.Position()]

	finalBuf := NewBytePacketBuffer()
	_ = finalBuf.WriteName("rrsig.test.")
	_ = finalBuf.Writeu16(uint16(RRSIG))
	_ = finalBuf.Writeu16(1)
	_ = finalBuf.Writeu32(300)
	_ = finalBuf.Writeu16(uint16(len(payload)))
	_ = finalBuf.WriteRange(finalBuf.Position(), payload)
	
	finalBuf.Len = finalBuf.Pos
	finalBuf.parsing = true
	_ = finalBuf.Seek(0)
	
	parsed := DNSRecord{}
	_ = parsed.Read(finalBuf)
	if parsed.TypeCovered != 1 || parsed.KeyTag != 123 || parsed.SignerName != "signer.test." {
		t.Errorf("RRSIG mismatch: %+v", parsed)
	}
}

func TestDNSRecord_Read_NSEC_Manual(t *testing.T) {
	buf := NewBytePacketBuffer()
	_ = buf.WriteName("next.test.")
	_ = buf.WriteRange(buf.Position(), []byte{0, 1, 2})
	payload := buf.Buf[:buf.Position()]

	finalBuf := NewBytePacketBuffer()
	_ = finalBuf.WriteName("nsec.test.")
	_ = finalBuf.Writeu16(uint16(NSEC))
	_ = finalBuf.Writeu16(1)
	_ = finalBuf.Writeu32(300)
	_ = finalBuf.Writeu16(uint16(len(payload)))
	_ = finalBuf.WriteRange(finalBuf.Position(), payload)
	
	finalBuf.Len = finalBuf.Pos
	finalBuf.parsing = true
	_ = finalBuf.Seek(0)
	
	parsed := DNSRecord{}
	_ = parsed.Read(finalBuf)
	if parsed.NextName != "next.test." {
		t.Errorf("NSEC mismatch")
	}
}

func TestDNSRecord_Read_NSEC3_Manual(t *testing.T) {
	// Alg(1), Flags(1), Iter(2), SaltLen(1), Salt, HashLen(1), Hash, BitMap
	data := []byte{1, 0, 0, 10, 2, 0xAA, 0xBB, 2, 0xCC, 0xDD, 0, 1, 2}
	
	finalBuf := NewBytePacketBuffer()
	_ = finalBuf.WriteName("nsec3.test.")
	_ = finalBuf.Writeu16(uint16(NSEC3))
	_ = finalBuf.Writeu16(1)
	_ = finalBuf.Writeu32(300)
	_ = finalBuf.Writeu16(uint16(len(data)))
	_ = finalBuf.WriteRange(finalBuf.Position(), data)
	
	finalBuf.Len = finalBuf.Pos
	finalBuf.parsing = true
	_ = finalBuf.Seek(0)
	
	parsed := DNSRecord{}
	_ = parsed.Read(finalBuf)
	if parsed.HashAlg != 1 || parsed.Iterations != 10 {
		t.Errorf("NSEC3 mismatch")
	}
}

func TestDNSRecord_Read_NSEC3PARAM_Manual(t *testing.T) {
	data := []byte{1, 0, 0, 10, 2, 0xDE, 0xAD}
	
	finalBuf := NewBytePacketBuffer()
	_ = finalBuf.WriteName("nsec3p.test.")
	_ = finalBuf.Writeu16(uint16(NSEC3PARAM))
	_ = finalBuf.Writeu16(1)
	_ = finalBuf.Writeu32(300)
	_ = finalBuf.Writeu16(uint16(len(data)))
	_ = finalBuf.WriteRange(finalBuf.Position(), data)
	
	finalBuf.Len = finalBuf.Pos
	finalBuf.parsing = true
	_ = finalBuf.Seek(0)
	
	parsed := DNSRecord{}
	_ = parsed.Read(finalBuf)
	if parsed.HashAlg != 1 || parsed.Iterations != 10 {
		t.Errorf("NSEC3PARAM mismatch")
	}
}
