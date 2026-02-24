package packet

import (
	"strings"
	"testing"
)

func TestBytePacketBuffer_ReadName_Errors(t *testing.T) {
	// 1. Invalid label length (out of bounds)
	buf := NewBytePacketBuffer()
	buf.Buf[0] = 5
	buf.Buf[1] = 'a'
	buf.Len = 2
	buf.parsing = true
	_ = buf.Seek(0)
	_, err := buf.ReadName()
	if err == nil {
		t.Error("expected error for truncated label")
	}

	// 2. Invalid compression pointer (out of bounds)
	buf.Reset()
	buf.Buf[0] = 0xC0
	buf.Buf[1] = 0xFF // Offset 255, but buffer only 2 bytes
	buf.Len = 2
	buf.parsing = true
	_ = buf.Seek(0)
	_, err = buf.ReadName()
	if err == nil {
		t.Error("expected error for out of bounds pointer")
	}

	// 3. Compression pointer points to itself
	buf.Reset()
	buf.Buf[0] = 0xC0
	buf.Buf[1] = 0x00
	buf.Len = 2
	buf.parsing = true
	_ = buf.Seek(0)
	_, err = buf.ReadName()
	if err == nil {
		t.Error("expected error for infinite loop pointer")
	}
}

func TestBytePacketBuffer_WriteName_Errors(t *testing.T) {
	buf := NewBytePacketBuffer()
	
	// 1. Label too long
	longLabel := strings.Repeat("a", 64)
	err := buf.WriteName(longLabel + ".com.")
	if err == nil || !strings.Contains(err.Error(), "label too long") {
		t.Error("expected error for too long label")
	}

	// 2. Buffer overflow during write
	buf.Reset()
	buf.Pos = MaxPacketSize - 5
	err = buf.WriteName("very.long.name.that.exceeds.buffer.limit.com.")
	if err == nil {
		t.Error("expected error for buffer overflow")
	}
}

func TestBytePacketBuffer_BoundsChecks(t *testing.T) {
	buf := NewBytePacketBuffer()
	
	// 1. Step out of MaxPacketSize
	err := buf.Step(MaxPacketSize + 1)
	if err == nil {
		t.Error("expected error for step > MaxPacketSize")
	}
	
	// 2. Seek out of MaxPacketSize
	err = buf.Seek(MaxPacketSize + 1)
	if err == nil {
		t.Error("expected error for seek > MaxPacketSize")
	}
	
	// 3. Parsing mode checks
	buf.Reset()
	buf.Load([]byte{1, 2, 3})
	// Pos is 0, Len is 3, parsing is true
	err = buf.Step(4)
	if err == nil {
		t.Error("expected error for step > Len in parsing mode")
	}
	err = buf.Seek(4)
	if err == nil {
		t.Error("expected error for seek > Len in parsing mode")
	}
}
