package packet

import (
	"testing"
)

func TestDNSRecord_Read_NULL_Manual(t *testing.T) {
	data := []byte{1, 2, 3, 4}
	
	finalBuf := NewBytePacketBuffer()
	_ = finalBuf.WriteName("null.test.")
	_ = finalBuf.Writeu16(uint16(NULL))
	_ = finalBuf.Writeu16(1)
	_ = finalBuf.Writeu32(300)
	_ = finalBuf.Writeu16(uint16(len(data)))
	_ = finalBuf.WriteRange(finalBuf.Position(), data)
	
	finalBuf.Len = finalBuf.Pos
	finalBuf.parsing = true
	_ = finalBuf.Seek(0)
	
	parsed := DNSRecord{}
	_ = parsed.Read(finalBuf)
	if parsed.Type != NULL {
		t.Errorf("expected NULL type")
	}
}

func TestDNSRecord_AddEDE_More(t *testing.T) {
	record := DNSRecord{
		Name: ".",
		Type: OPT,
	}
	record.AddEDE(EdeOther, "") // No text
	if len(record.Options) != 1 {
		t.Errorf("expected 1 option")
	}
	if len(record.Options[0].Data) != 2 {
		t.Errorf("expected 2 bytes for EDE with no text")
	}
}
