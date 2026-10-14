package nethernet

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMetricsRegistersOnTheGivenRegistry(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	m.SignalingRequests.WithLabelValues("tls", "ok").Inc()
	m.TLSHandshakes.WithLabelValues("ok").Inc()
	m.WakeHolds.WithLabelValues("ready").Inc()
	m.Sessions.WithLabelValues("srv-1", "bound").Set(1)
	m.UDPDropped.WithLabelValues("unknown_peer").Inc()
	m.RegistryErrors.Inc()
	m.RegistryQueueFull.Inc()
	m.LookupsDropped.WithLabelValues("s").Inc()
	m.Renominations.WithLabelValues("sent").Inc()
	m.AnswerRetries.WithLabelValues("recovered").Inc()

	families, err := reg.Gather()
	require.NoError(t, err)
	var names []string
	for _, f := range families {
		names = append(names, f.GetName())
	}
	assert.ElementsMatch(t, []string{
		"nethernet_signaling_requests_total", "nethernet_tls_handshakes_total", "nethernet_wake_holds_total",
		"nethernet_sessions", "nethernet_udp_dropped_total", "nethernet_registry_errors_total",
		"nethernet_registry_queue_full_total", "nethernet_registry_lookups_dropped_total",
		"nethernet_renominations_total", "nethernet_answer_retries_total",
	}, names)
	assert.Equal(t, 1.0, testutil.ToFloat64(m.UDPDropped.WithLabelValues("unknown_peer")))
}

func TestNilMetricsIsANoOp(t *testing.T) {
	var m *Metrics
	assert.NotPanics(t, func() {
		m.dropped("unknown_peer")
		m.registryError()
		m.queueFull()
		m.lookupDropped("s")
		m.renomination("sent")
		m.answerRetry("recovered")
		m.session("srv-1", "bound", 1)
	})
}
