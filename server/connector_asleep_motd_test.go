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

// statusPingForMOTD drives one real status handshake against a route and reports
// the status JSON the client received, or ok=false when the connector closed the
// connection without sending anything.
//
// The backend address is deliberately unreachable so the dial fails, which is the
// state a scaled-to-zero server's Service is in (no endpoints).
func statusPingForMOTD(t *testing.T, waker WakerFunc, routeMOTD string, globalMOTD string) (string, bool) {
	t.Helper()

	routes := NewRoutes(t.Context())
	downScaler := NewDownScaler(false, 5*time.Second)
	routes.WithDownScaler(downScaler)

	// Port 0 never accepts, so the dial fails the way an endpoint-less ClusterIP does.
	backendAddress := "127.0.0.1:0"
	scalingTarget := TestingScalingTarget(backendAddress)

	routes.CreateMapping("mc.example.com", backendAddress, scalingTarget, waker, nil, routeMOTD, "")

	metricsBuilder := discardMetricsBuilder{}
	c := NewConnector(t.Context(), routes, downScaler, metricsBuilder.BuildConnectorMetrics(), false, false, nil)
	c.UseAsleepMOTD(globalMOTD)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go c.acceptConnections(ln, 0)

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer clientConn.Close()

	// Handshake, nextState=1 (status)
	err = writeTestPacket(clientConn, 0x00, func(w io.Writer) {
		_ = mcproto.WriteVarInt(w, 758)
		_ = mcproto.WriteString(w, "mc.example.com")
		w.Write([]byte{0x63, 0xdd})
		_ = mcproto.WriteVarInt(w, 1)
	})
	require.NoError(t, err)

	// Status Request
	err = writeTestPacket(clientConn, 0x00, nil)
	require.NoError(t, err)

	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	frame, err := mcproto.ReadFrame(bufio.NewReader(clientConn), clientConn.RemoteAddr())
	if err != nil {
		// Connection closed with no status response.
		return "", false
	}

	packetReader := bytes.NewReader(frame.Payload)
	packetID, err := mcproto.ReadVarInt(packetReader)
	require.NoError(t, err)
	require.Equal(t, 0x00, packetID)

	jsonStr, err := mcproto.ReadString(packetReader)
	require.NoError(t, err)
	return jsonStr, true
}

func noopWaker(_ context.Context) (string, error) { return "127.0.0.1:0", nil }

// A server that cannot be woken (apps/api patches autoScaleUp="false" when the owner
// stops it, when billing gates it, or when it fails to boot) still carries a per-server
// MOTD explaining WHY. That message must reach the player's server list.
func TestAsleepMOTD_PerRouteMOTDServedWithoutWaker(t *testing.T) {
	jsonStr, ok := statusPingForMOTD(t, nil, "stopped by owner", "join to wake me")
	require.True(t, ok, "a route with a per-route MOTD must answer the status ping even with no waker")
	assert.Contains(t, jsonStr, "stopped by owner")
	assert.NotContains(t, jsonStr, "join to wake me", "the global wake MOTD must not override the per-route message")
}

// The global --auto-scale-asleep-motd invites the player to join to wake the server.
// For a route that cannot wake, that invitation is a lie, so nothing must be served.
func TestAsleepMOTD_GlobalMOTDNotServedWithoutWaker(t *testing.T) {
	_, ok := statusPingForMOTD(t, nil, "", "join to wake me")
	assert.False(t, ok, "the global wake MOTD must not be served for a route that cannot wake")
}

// A wakeable route with no per-route message still falls back to the global one.
func TestAsleepMOTD_GlobalMOTDServedWhenWakeable(t *testing.T) {
	jsonStr, ok := statusPingForMOTD(t, noopWaker, "", "join to wake me")
	require.True(t, ok, "a wakeable route must serve the global asleep MOTD")
	assert.Contains(t, jsonStr, "join to wake me")
}

// A per-route MOTD outranks the global one even when the route CAN wake. This is a
// real state, not a hypothetical: the reconciler re-arms wake on a server that failed
// to boot (autoScaleUp back to "true") while the API leaves the boot-failure message on
// it, and that message is the one the owner needs to see. Pinning it from this side too
// stops a later "simplification" that checks the global MOTD first.
func TestAsleepMOTD_PerRouteMOTDOutranksGlobalWhenWakeable(t *testing.T) {
	jsonStr, ok := statusPingForMOTD(t, noopWaker, "failed to boot", "join to wake me")
	require.True(t, ok, "a wakeable route with a per-route MOTD must answer")
	assert.Contains(t, jsonStr, "failed to boot")
	assert.NotContains(t, jsonStr, "join to wake me", "the per-route message is authoritative")
}
