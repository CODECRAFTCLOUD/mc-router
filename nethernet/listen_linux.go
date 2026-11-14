//go:build linux

package nethernet

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// ListenUDP binds n UDP sockets to port in one SO_REUSEPORT group, so the
// kernel spreads client datagrams over them by flow, as nginx's reuseport does
// for its workers. n <= 0 means one per core the Go runtime runs on
// (GOMAXPROCS, which follows the container's CPU limit). Port 0 binds the first
// socket to a free port and the rest to the same one.
func ListenUDP(port, n int) ([]*net.UDPConn, error) {
	if n <= 0 {
		n = runtime.GOMAXPROCS(0)
	}
	var lc net.ListenConfig
	if n > 1 { // one socket binds as before, so another process can never share its port
		lc.Control = func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}); err != nil {
				return err
			}
			return serr
		}
	}
	socks := make([]*net.UDPConn, 0, n)
	for range n {
		pc, err := lc.ListenPacket(context.Background(), "udp", fmt.Sprintf(":%d", port))
		if err != nil {
			for _, c := range socks {
				_ = c.Close()
			}
			return nil, err
		}
		c := pc.(*net.UDPConn)
		port = c.LocalAddr().(*net.UDPAddr).Port
		socks = append(socks, c)
	}
	return socks, nil
}
