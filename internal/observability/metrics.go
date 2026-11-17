package observability

import (
	"log/slog"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Metrics struct {
	RequestsTotal            *prometheus.CounterVec
	DetectionsTotal          *prometheus.CounterVec
	InferenceDurationSeconds prometheus.Histogram
	ProxyDurationSeconds     prometheus.Histogram
	ActiveRequests           prometheus.Gauge
	VaultOperationsTotal     *prometheus.CounterVec
}

func NewMetrics(reg prometheus.Registerer) *Metrics {
	factory := promauto.With(reg)
	return &Metrics{
		RequestsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegf_requests_total",
				Help: "Total outbound HTTP requests inspected by route and decision",
			},
			[]string{"route", "decision"},
		),
		DetectionsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegf_detections_total",
				Help: "Total sensitive entities detected by category and source",
			},
			[]string{"category", "source"},
		),
		InferenceDurationSeconds: factory.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "aegf_inference_duration_seconds",
				Help:    "Time spent communicating with and executing in the Rust inference engine",
				Buckets: prometheus.DefBuckets,
			},
		),
		ProxyDurationSeconds: factory.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "aegf_proxy_duration_seconds",
				Help:    "Total time spent processing outbound proxy request",
				Buckets: prometheus.DefBuckets,
			},
		),
		ActiveRequests: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "aegf_active_requests",
				Help: "Number of active outbound requests currently being processed",
			},
		),
		VaultOperationsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegf_vault_operations_total",
				Help: "Total vault operations by operation type and status",
			},
			[]string{"operation", "status"},
		),
	}
}

func SetupLogger() *slog.Logger {
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	handler := slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(handler)
	slog.SetDefault(logger)
	return logger
}
