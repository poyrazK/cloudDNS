//go:build windows

package server

func setReusePort(fd uintptr) error {
	return nil
}
