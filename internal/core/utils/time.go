// Package utils provides helper functions for DNS operations.
package utils

import "time"

// GetCurrentTimeUint32 returns the current Unix timestamp as uint32.
// Unix timestamps are always positive (1970–2106), so this conversion is safe.
// Includes bounds check to satisfy gosec G115.
func GetCurrentTimeUint32() uint32 {
	ts := time.Now().Unix()
	if ts < 0 {
		return 0
	}
	if ts > 0xFFFFFFFF {
		return 0xFFFFFFFF
	}
	return uint32(ts)
}