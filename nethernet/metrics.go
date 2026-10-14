package nethernet

import "github.com/prometheus/client_golang/prometheus"

// Metrics are the router's own series. They register on the registerer given to
// NewMetrics, never on the default registry the Java mc-router metrics use.
// A nil *Metrics is valid and records nothing.
type Metrics struct {
	SignalingRequests *prometheus.CounterVec // transport (tls, http; "" when refused before a byte is read), result
	TLSHandshakes     *prometheus.CounterVec // outcome
	WakeHolds         *prometheus.CounterVec // outcome
	Sessions          *prometheus.GaugeVec   // server, state (signaled, bound)
	UDPDropped        *prometheus.CounterVec // reason
	RegistryErrors    prometheus.Counter
	RegistryQueueFull prometheus.Counter
	LookupsDropped    *prometheus.CounterVec // kind (s, c)
	Renominations     *prometheus.CounterVec // outcome (sent, confirmed)
	AnswerRetries     *prometheus.CounterVec // outcome (recovered, exhausted)
}

func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		SignalingRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nethernet_signaling_requests_total", Help: "NetherNet signaling requests by transport (tls, http) and result.",
		}, []string{"transport", "result"}),
		TLSHandshakes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nethernet_tls_handshakes_total", Help: "TLS handshakes on the signaling port by outcome.",
		}, []string{"outcome"}),
		WakeHolds: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nethernet_wake_holds_total", Help: "Signaling requests held for a wake, by outcome.",
		}, []string{"outcome"}),
		Sessions: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "nethernet_sessions", Help: "Relay sessions by server and state (signaled, bound).",
		}, []string{"server", "state"}),
		UDPDropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nethernet_udp_dropped_total", Help: "UDP datagrams the relay dropped, by reason.",
		}, []string{"reason"}),
		RegistryErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "nethernet_registry_errors_total", Help: "Errors from the shared session registry.",
		}),
		RegistryQueueFull: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "nethernet_registry_queue_full_total",
			Help: "Shared-registry writes skipped because the worker queue was full; the datagram is still forwarded.",
		}),
		LookupsDropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nethernet_registry_lookups_dropped_total",
			Help: "Shared-registry lookups skipped because their budget or queue was full, by kind (s: session by STUN username, c: client by address); the client's retransmit retries.",
		}, []string{"kind"}),
		Renominations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nethernet_renominations_total",
			Help: "Client checks of an adopted session forwarded with USE-CANDIDATE added (sent), and server success responses that ended a session's re-nomination (confirmed).",
		}, []string{"outcome"}),
		AnswerRetries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nethernet_answer_retries_total",
			Help: "Joins whose answer had no candidate at the pod address, by how the re-forwards of the offer ended: an answer that named the pod (recovered), or a 502 (exhausted).",
		}, []string{"outcome"}),
	}
	reg.MustRegister(m.SignalingRequests, m.TLSHandshakes, m.WakeHolds, m.Sessions, m.UDPDropped, m.RegistryErrors, m.RegistryQueueFull, m.LookupsDropped, m.Renominations, m.AnswerRetries)
	return m
}

func (m *Metrics) dropped(reason string) {
	if m != nil {
		m.UDPDropped.WithLabelValues(reason).Inc()
	}
}

func (m *Metrics) registryError() {
	if m != nil {
		m.RegistryErrors.Inc()
	}
}

func (m *Metrics) session(server, state string, delta float64) {
	if m != nil {
		m.Sessions.WithLabelValues(server, state).Add(delta)
	}
}

func (m *Metrics) queueFull() {
	if m != nil {
		m.RegistryQueueFull.Inc()
	}
}

func (m *Metrics) lookupDropped(kind string) {
	if m != nil {
		m.LookupsDropped.WithLabelValues(kind).Inc()
	}
}

func (m *Metrics) signal(transport, result string) {
	if m != nil {
		m.SignalingRequests.WithLabelValues(transport, result).Inc()
	}
}

func (m *Metrics) tlsHandshake(outcome string) {
	if m != nil {
		m.TLSHandshakes.WithLabelValues(outcome).Inc()
	}
}

func (m *Metrics) wakeHold(outcome string) {
	if m != nil {
		m.WakeHolds.WithLabelValues(outcome).Inc()
	}
}

func (m *Metrics) renomination(outcome string) {
	if m != nil {
		m.Renominations.WithLabelValues(outcome).Inc()
	}
}

func (m *Metrics) answerRetry(outcome string) {
	if m != nil {
		m.AnswerRetries.WithLabelValues(outcome).Inc()
	}
}
