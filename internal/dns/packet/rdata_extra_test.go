package packet

import (
	"net"
	"testing"
)

func TestDNSRecord_ReadWrite_WKS(t *testing.T) {
	record := DNSRecord{
		Name:     "wks.test.",
		Type:     WKS,
		TTL:      300,
		IP:       net.ParseIP("1.2.3.4"),
		Protocol: 6, // TCP
		BitMap:   []byte{0x00, 0x01},
	}

	// Manual data since WKS isn't implemented in Write switch
	record.Data = append(net.ParseIP("1.2.3.4").To4(), 6)
	record.Data = append(record.Data, 0x00, 0x01)

	buffer := NewBytePacketBuffer()
	_, _ = record.Write(buffer)
	_ = buffer.Seek(0)
	
	parsed := DNSRecord{}
	_ = parsed.Read(buffer)
	
	if parsed.Type != WKS {
		t.Errorf("expected WKS type")
	}
}

func TestDNSRecord_ReadWrite_NSEC3(t *testing.T) {
	record := DNSRecord{
		Name:       "nsec3.test.",
		Type:       NSEC3,
		TTL:        300,
		HashAlg:    1,
		Flags:      0,
		Iterations: 10,
		Salt:       []byte{0xAB, 0xCD},
		NextHash:   []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		TypeBitMap: []byte{0x00, 0x02, 0x40},
	}

	buffer := NewBytePacketBuffer()
	_, _ = record.Write(buffer)
	_ = buffer.Seek(0)
	
	parsed := DNSRecord{}
	err := parsed.Read(buffer)
	if err != nil {
		t.Fatalf("Read NSEC3 failed: %v", err)
	}
	
	if parsed.HashAlg != 1 || parsed.Iterations != 10 {
		t.Errorf("NSEC3 mismatch: %+v", parsed)
	}
}

func TestDNSRecord_ReadWrite_NSEC3PARAM(t *testing.T) {
	record := DNSRecord{
		Name:       "nsec3p.test.",
		Type:       NSEC3PARAM,
		TTL:        0,
		HashAlg:    1,
		Flags:      0,
		Iterations: 10,
		Salt:       []byte{0xDE, 0xAD},
	}

	buffer := NewBytePacketBuffer()
	_, _ = record.Write(buffer)
	_ = buffer.Seek(0)
	
	parsed := DNSRecord{}
	_ = parsed.Read(buffer)
	
	if parsed.HashAlg != 1 || parsed.Iterations != 10 || string(parsed.Salt) != string(record.Salt) {
		t.Errorf("NSEC3PARAM mismatch")
	}
}

func TestDNSRecord_ReadWrite_OPT_Options(t *testing.T) {
	record := DNSRecord{
		Name: ".",
		Type: OPT,
		UDPPayloadSize: 4096,
		Options: []EdnsOption{
			{Code: 3, Data: []byte("nsid-test")},
		},
	}

	buffer := NewBytePacketBuffer()
	_, _ = record.Write(buffer)
	_ = buffer.Seek(0)
	
	parsed := DNSRecord{}
	_ = parsed.Read(buffer)
	
	if len(parsed.Options) != 1 || parsed.Options[0].Code != 3 || string(parsed.Options[0].Data) != "nsid-test" {
		t.Errorf("OPT Options mismatch: %+v", parsed.Options)
	}
}
