package utils

// serialLessThanRFC1982 returns true if a < b per RFC 1982 serial number arithmetic.
// Handles uint32 wrap-around by treating serials as circular (mod 2^32).
func serialLessThanRFC1982(a, b uint32) bool {
	if a == b {
		return false
	}
	diff := b - a
	// a < b if the difference is less than 2^31 (unsigned comparison wraps)
	return diff < 2147483648 // 2^31
}

// serialWrapped returns true if the serial space has wrapped between from and to.
// This occurs when fromSerial > toSerial (unsigned comparison).
func serialWrapped(fromSerial, toSerial uint32) bool {
	return fromSerial > toSerial
}
