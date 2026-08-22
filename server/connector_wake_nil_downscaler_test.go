package server

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// A login to an asleep backend must not panic when the down-scaler is disabled.
//
// Production runs with --auto-scale-up but without --auto-scale-down, so
// NewConnector receives a nil IDownScaler. The wake path used to call
// c.downScaler.Cancel() guarded only by "scalingTarget != nil", which killed the
// whole router on every wake attempt.
func TestWakePathWithNilDownScaler(t *testing.T) {
	routes := NewRoutes(t.Context())

	// Port 1 is closed: the probe dial fails, i.e. the backend reads as asleep.
	backendAddress := "127.0.0.1:1"
	scalingTarget := TestingScalingTarget(backendAddress)
	waker := func(ctx context.Context) (string, error) { return backendAddress, nil }
	routes.CreateMapping("mc.example.com", backendAddress, scalingTarget, waker, nil, "asleep", "loading")

	metricsBuilder := discardMetricsBuilder{}
	// nil down-scaler — exactly what server.go builds without --auto-scale-down.
	c := NewConnector(t.Context(), routes, nil, metricsBuilder.BuildConnectorMetrics(), false, false, nil)
	c.UseBackendDialTimeout(50 * time.Millisecond)

	client, frontend := net.Pipe()
	defer client.Close()
	defer frontend.Close()
	// Drain the kick packet so WriteLoginDisconnect does not block on the pipe.
	go func() { _, _ = io.Copy(io.Discard, client) }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.findAndConnectBackend(frontend, frontend.RemoteAddr(), nil, 0,
			"mc.example.com", nil, 2 /* StateLogin */, false, 758)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("findAndConnectBackend hung on the wake path")
	}
}
