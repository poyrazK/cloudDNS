//go:build windows

package server

// setReusePort is a no-op on Windows (SO_REUSEPORT is not supported).
func setReusePort(fd uintptr) error {
	return nil
}
