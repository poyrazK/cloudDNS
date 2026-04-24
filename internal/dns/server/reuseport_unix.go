//go:build !windows

package server

import (
	"errors"
	"golang.org/x/sys/unix"
)

// setReusePort enables SO_REUSEPORT on a socket file descriptor.
// Unix file descriptors are non-negative small integers, so the int
// cast below is safe. We validate the range to satisfy G115.
func setReusePort(fd uintptr) error {
	if fd > 0x7FFFFFFF {
		return errors.New("file descriptor out of valid range")
	}
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}
