package utils

import "testing"

func TestGetCurrentTimeUint32(t *testing.T) {
	ts := GetCurrentTimeUint32()
	if ts == 0 {
		t.Errorf("expected non-zero timestamp, got 0")
	}
}
