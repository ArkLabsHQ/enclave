package sdk

import (
	"fmt"
	"strings"
	"sync/atomic"
)

// Metrics tracks operational counters for the enclave.
// All fields are safe for concurrent use.
type Metrics struct {
	HTTPRequests    atomic.Int64
	HTTPErrors      atomic.Int64 // 4xx + 5xx responses
	KMSOperations   atomic.Int64
	KMSErrors       atomic.Int64
	StorageReads    atomic.Int64
	StorageWrites   atomic.Int64
	StorageDeletes  atomic.Int64
	StorageErrors   atomic.Int64
	SecretReads     atomic.Int64
	SecretWrites    atomic.Int64
	SecretDeletes   atomic.Int64
}

// enclaveMetrics is the global metrics instance.
var enclaveMetrics Metrics

// GetMetrics returns the global metrics instance.
func GetMetrics() *Metrics {
	return &enclaveMetrics
}

// Snapshot returns a point-in-time copy of all counters.
func (m *Metrics) Snapshot() map[string]int64 {
	return map[string]int64{
		"http_requests":   m.HTTPRequests.Load(),
		"http_errors":     m.HTTPErrors.Load(),
		"kms_operations":  m.KMSOperations.Load(),
		"kms_errors":      m.KMSErrors.Load(),
		"storage_reads":   m.StorageReads.Load(),
		"storage_writes":  m.StorageWrites.Load(),
		"storage_deletes": m.StorageDeletes.Load(),
		"storage_errors":  m.StorageErrors.Load(),
		"secret_reads":    m.SecretReads.Load(),
		"secret_writes":   m.SecretWrites.Load(),
		"secret_deletes":  m.SecretDeletes.Load(),
	}
}

// prometheusMetric defines a single metric for Prometheus exposition.
type prometheusMetric struct {
	name string
	help string
	typ  string // "counter" or "gauge"
	val  func() int64
}

// PrometheusText returns all metrics in Prometheus text exposition format.
func (m *Metrics) PrometheusText() string {
	metrics := []prometheusMetric{
		{"enclave_http_requests_total", "Total HTTP requests handled by the enclave supervisor.", "counter", m.HTTPRequests.Load},
		{"enclave_http_errors_total", "Total HTTP responses with status 4xx or 5xx.", "counter", m.HTTPErrors.Load},
		{"enclave_kms_operations_total", "Total KMS Decrypt operations attempted.", "counter", m.KMSOperations.Load},
		{"enclave_kms_errors_total", "Total failed KMS operations.", "counter", m.KMSErrors.Load},
		{"enclave_storage_reads_total", "Total encrypted storage read operations.", "counter", m.StorageReads.Load},
		{"enclave_storage_writes_total", "Total encrypted storage write operations.", "counter", m.StorageWrites.Load},
		{"enclave_storage_deletes_total", "Total encrypted storage delete operations.", "counter", m.StorageDeletes.Load},
		{"enclave_storage_errors_total", "Total failed storage operations.", "counter", m.StorageErrors.Load},
		{"enclave_secret_reads_total", "Total dynamic secret read operations.", "counter", m.SecretReads.Load},
		{"enclave_secret_writes_total", "Total dynamic secret write operations.", "counter", m.SecretWrites.Load},
		{"enclave_secret_deletes_total", "Total dynamic secret delete operations.", "counter", m.SecretDeletes.Load},
	}

	var b strings.Builder
	for _, met := range metrics {
		fmt.Fprintf(&b, "# HELP %s %s\n", met.name, met.help)
		fmt.Fprintf(&b, "# TYPE %s %s\n", met.name, met.typ)
		fmt.Fprintf(&b, "%s %d\n", met.name, met.val())
	}
	return b.String()
}
