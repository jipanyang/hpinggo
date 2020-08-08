// Package utilities provides common utility functions
package utilities

import (
	"fmt"
	"golang.org/x/sys/unix"
)

func OpenRawSocket(family int) (int, error) {
	fd, err := unix.Socket(family, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return fd, err
	}
	err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
	if err != nil {
		unix.Close(fd)
		return -1, err
	}

	switch family {
	case unix.AF_INET6:
		err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1)
	case unix.AF_INET:
		err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
	default:
		return -1, fmt.Errorf("invalid address family: %v", family)
	}

	if err != nil {
		unix.Close(fd)
		return -1, err
	}

	return fd, nil
}
