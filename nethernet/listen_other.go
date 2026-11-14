//go:build !linux

package nethernet

import (
	"errors"
	"net"
)

// ListenUDP binds one UDP socket to port. SO_REUSEPORT groups are Linux only
// here, so n > 1 is refused and n <= 0 means one.
func ListenUDP(port, n int) ([]*net.UDPConn, error) {
	if n > 1 {
		return nil, errors.New("nethernet: more than one relay socket needs Linux (SO_REUSEPORT)")
	}
	c, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		return nil, err
	}
	return []*net.UDPConn{c}, nil
}
