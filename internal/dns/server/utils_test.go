package server

import (
	"fmt"
	"net"
)

func GetFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func GetFreeUDPPort() (int, error) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenUDP("udp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.LocalAddr().(*net.UDPAddr).Port, nil
}

// GetFreePortStr returns a free port as a string ":port"
func GetFreePortStr() string {
	p, err := GetFreePort()
	if err != nil {
		return ":0"
	}
	return fmt.Sprintf(":%d", p)
}

// GetFreeAddr returns a free 127.0.0.1 address with port
func GetFreeAddr() string {
	p, err := GetFreePort()
	if err != nil {
		return "127.0.0.1:0"
	}
	return fmt.Sprintf("127.0.0.1:%d", p)
}
