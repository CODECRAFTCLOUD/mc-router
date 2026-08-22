package server

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/itzg/mc-router/mcproto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoutesWakeConfig(t *testing.T) {
	r := NewRoutes(t.Context())
	r.CreateMapping("a.com", "backend:25565", nil, nil, nil, "", "")
	r.SetWakeConfig("a.com", "wake up!", []string{"steve", "alex"})

	assert.Equal(t, "wake up!", r.GetWakeMessage("a.com"))
	assert.Equal(t, []string{"steve", "alex"}, r.GetWakeAllowlist("a.com"))

	// Unknown server → zero values (no message; nil allowlist = allow-all).
	assert.Equal(t, "", r.GetWakeMessage("other.com"))
	assert.Nil(t, r.GetWakeAllowlist("other.com"))

	// Default route (serverAddress == "").
	r.SetDefaultRoute("d:25565", nil, nil, nil, "", "")
	r.SetWakeConfig("", "default wake", nil)
	assert.Equal(t, "default wake", r.GetWakeMessage(""))
}

// readLoginDisconnect reads one frame from r and, if it is a login-state
// Disconnect (packet 0x00), returns its JSON body. Any other outcome
// (timeout, EOF, different packet) returns ("", false) — i.e. "not kicked".
func readLoginDisconnect(r net.Conn) (string, bool) {
	br := bufio.NewReader(r)
	frame, err := mcproto.ReadFrame(br, &net.TCPAddr{})
	if err != nil {
		return "", false
	}
	pr := bytes.NewReader(frame.Payload)
	id, err := mcproto.ReadVarInt(pr)
	if err != nil || id != mcproto.PacketIdLoginDisconnect {
		return "", false
	}
	s, _ := mcproto.ReadString(pr)
	return s, true
}

func TestFindAndConnectBackendWakeKick(t *testing.T) {
	newConn := func(routes IRoutes) *Connector {
		return NewConnector(t.Context(), routes, NewDownScaler(false, 5*time.Second),
			discardMetricsBuilder{}.BuildConnectorMetrics(), false, false, nil)
	}
	// A login to an autoScaleUp service, driven straight through
	// findAndConnectBackend (which receives the already-parsed playerInfo).
	drive := func(c *Connector, playerName string) net.Conn {
		frontend, tr := net.Pipe()
		go c.findAndConnectBackend(frontend, &net.TCPAddr{IP: net.IPv4(1, 2, 3, 4)},
			bytes.NewReader(nil), 0, "mc.example.com", &PlayerInfo{Name: playerName},
			mcproto.StateLogin, false, 758)
		return tr
	}

	t.Run("asleep+allowed: kicked with wake message, wake fired", func(t *testing.T) {
		routes := NewRoutes(t.Context())
		routes.WithDownScaler(NewDownScaler(false, 5*time.Second))
		woke := make(chan struct{}, 1)
		waker := func(ctx context.Context) (string, error) { woke <- struct{}{}; return "", nil }
		// 127.0.0.1:1 refuses instantly → probe fails → treated as asleep.
		routes.CreateMapping("mc.example.com", "127.0.0.1:1", nil, waker, nil, "", "")

		tr := drive(newConn(routes), "steve")
		defer tr.Close()
		_ = tr.SetReadDeadline(time.Now().Add(3 * time.Second))

		msg, kicked := readLoginDisconnect(tr)
		require.True(t, kicked, "asleep server should kick the joiner")
		assert.Contains(t, msg, defaultWakeMessage)
		select {
		case <-woke:
		case <-time.After(2 * time.Second):
			t.Fatal("waker was not fired for an allowed player")
		}
	})

	t.Run("asleep+denied: kicked with deny message, wake NOT fired", func(t *testing.T) {
		routes := NewRoutes(t.Context())
		routes.WithDownScaler(NewDownScaler(false, 5*time.Second))
		woke := make(chan struct{}, 1)
		waker := func(ctx context.Context) (string, error) { woke <- struct{}{}; return "", nil }
		routes.CreateMapping("mc.example.com", "127.0.0.1:1", nil, waker, nil, "", "")
		routes.SetWakeConfig("mc.example.com", "", []string{"alice"}) // steve excluded

		tr := drive(newConn(routes), "steve")
		defer tr.Close()
		_ = tr.SetReadDeadline(time.Now().Add(3 * time.Second))

		msg, kicked := readLoginDisconnect(tr)
		require.True(t, kicked, "denied player should be kicked")
		assert.Contains(t, msg, wakeDenyMessage)
		select {
		case <-woke:
			t.Fatal("waker fired for a denied player (would wake + bill)")
		case <-time.After(500 * time.Millisecond):
		}
	})

	// The invariant: a genuinely-reachable (awake) backend is NEVER kicked, so
	// the rejoin can connect and there is no infinite kick loop.
	t.Run("awake: NOT kicked (infinite-loop guard)", func(t *testing.T) {
		backendLn, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer backendLn.Close()
		go func() {
			for {
				conn, err := backendLn.Accept()
				if err != nil {
					return
				}
				go func() { _, _ = io.Copy(io.Discard, conn); _ = conn.Close() }()
			}
		}()

		routes := NewRoutes(t.Context())
		routes.WithDownScaler(NewDownScaler(false, 5*time.Second))
		waker := func(ctx context.Context) (string, error) { return backendLn.Addr().String(), nil }
		routes.CreateMapping("mc.example.com", backendLn.Addr().String(), nil, waker, nil, "", "")

		tr := drive(newConn(routes), "steve")
		defer tr.Close()
		_ = tr.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))

		_, kicked := readLoginDisconnect(tr)
		assert.False(t, kicked, "an awake server must NOT kick the player (infinite-loop guard)")
	})
}
