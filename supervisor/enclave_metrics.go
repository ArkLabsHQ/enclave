package supervisor

import (
	"io"
	"net/http"
	"net/url"
)

// handleEnclaveMetrics proxies the metric snapshot from the enclave supervisor.
// GET /enclave-metrics
func (s *server) handleEnclaveMetrics(w http.ResponseWriter, r *http.Request) {
	enclaveURL := envOrDefault("ENCLAVE_URL", "https://127.0.0.1:443")
	u, err := url.Parse(enclaveURL + "/v1/enclave-metrics")
	if err != nil {
		http.Error(w, `{"error":"bad enclave URL"}`, http.StatusInternalServerError)
		return
	}
	u.RawQuery = r.URL.RawQuery

	resp, err := enclaveMetricsClient.Get(u.String())
	if err != nil {
		http.Error(w, `{"error":"enclave unreachable"}`, http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}
