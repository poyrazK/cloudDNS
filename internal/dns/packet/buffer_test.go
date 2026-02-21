package packet

import "testing"

func TestBufferGetters(t *testing.T) {
	buf := NewBytePacketBuffer()
	data := []byte{1, 2, 3, 4, 5}
	copy(buf.Buf, data)

	// Test Get
	val, err := buf.Get(2)
	if err != nil || val != 3 {
		t.Errorf("Get(2) failed: val=%d, err=%v", val, err)
	}

	// Test GetRange
	rangeData, err := buf.GetRange(1, 3)
	if err != nil || len(rangeData) != 3 || rangeData[0] != 2 || rangeData[2] != 4 {
		t.Errorf("GetRange(1, 3) failed: got=%v, err=%v", rangeData, err)
	}

	// Test Out of bounds
	_, err = buf.Get(MaxPacketSize + 1)
	if err == nil {
		t.Errorf("Get out of bounds should fail")
	}

	_, err = buf.GetRange(MaxPacketSize-1, 10)
	if err == nil {
		t.Errorf("GetRange out of bounds should fail")
	}
}

func TestBufferMutators(t *testing.T) {
	buf := NewBytePacketBuffer()
	
	// Test WriteRange
	_ = buf.WriteRange(20, []byte{0xAA, 0xBB})
	got, _ := buf.GetRange(20, 2)
	if got[0] != 0xAA || got[1] != 0xBB {
		t.Errorf("WriteRange failed")
	}

	// Test Step and Seek
	_ = buf.Step(10)
	_ = buf.Seek(5)

	// Test Error paths for other methods
	if err := buf.WriteRange(MaxPacketSize, []byte{1}); err == nil {
		t.Errorf("WriteRange out of bounds should fail")
	}
}

func TestBuffer_ReadErrors(t *testing.T) {
	buf := NewBytePacketBuffer()
	buf.Pos = MaxPacketSize

	if _, err := buf.Read(); err == nil {
		t.Errorf("Read at end of buffer should fail")
	}
	if _, err := buf.Readu16(); err == nil {
		t.Errorf("Readu16 at end of buffer should fail")
	}
	if _, err := buf.Readu32(); err == nil {
		t.Errorf("Readu32 at end of buffer should fail")
	}
	if _, err := buf.ReadRange(MaxPacketSize-1, 5); err == nil {
		t.Errorf("ReadRange out of bounds should fail")
	}
}
