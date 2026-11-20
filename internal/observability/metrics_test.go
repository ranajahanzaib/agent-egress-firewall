package observability

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestMetricsRegistration(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	if m == nil {
		t.Fatal("expected non-nil Metrics instance")
	}

	m.RequestsTotal.WithLabelValues("openai", "allow").Inc()
	m.DetectionsTotal.WithLabelValues("EMAIL", "pattern").Inc()
	m.ActiveRequests.Set(3)
	m.InferenceDurationSeconds.Observe(0.025)
	m.ProxyDurationSeconds.Observe(0.045)
	m.VaultOperationsTotal.WithLabelValues("store", "success").Inc()

	logger := SetupLogger()
	if logger == nil {
		t.Error("expected non-nil logger")
	}
}
