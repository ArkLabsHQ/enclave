package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

// handleTraces proxies trace spans from the enclave supervisor (live),
// or queries CloudWatch Logs for historical spans when ?history=true.
// GET /enclave-traces?since=RFC3339&limit=100&service=app|supervisor&history=true
func (s *server) handleTraces(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("history") == "true" {
		s.handleTracesHistory(w, r)
		return
	}

	enclaveURL := envOrDefault("ENCLAVE_URL", "https://127.0.0.1:443")
	u, err := url.Parse(enclaveURL + "/v1/enclave-traces")
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

// handleTracesHistory queries CloudWatch Logs for historical span entries.
func (s *server) handleTracesHistory(w http.ResponseWriter, r *http.Request) {
	logGroup := fmt.Sprintf("/enclave/%s/%s/traces", s.deployment, s.appName)

	var startTime *int64
	if since := r.URL.Query().Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339Nano, since); err == nil {
			startTime = aws.Int64(t.UnixMilli())
		} else if t, err := time.Parse(time.RFC3339, since); err == nil {
			startTime = aws.Int64(t.UnixMilli())
		}
	}

	limit := int32(100)
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 10000 {
			limit = int32(n)
		}
	}

	service := strings.ToLower(r.URL.Query().Get("service"))

	var filterPattern *string
	if service != "" {
		pattern := fmt.Sprintf(`{ $.source = %q }`, service)
		filterPattern = aws.String(pattern)
	}

	input := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName: aws.String(logGroup),
		Limit:        aws.Int32(limit),
	}
	if startTime != nil {
		input.StartTime = startTime
	}
	if filterPattern != nil {
		input.FilterPattern = filterPattern
	}

	result, err := s.cwlClient.FilterLogEvents(r.Context(), input)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"cloudwatch query failed: %s"}`, err), http.StatusInternalServerError)
		return
	}

	entries := make([]json.RawMessage, 0, len(result.Events))
	for _, event := range result.Events {
		if event.Message != nil {
			entries = append(entries, json.RawMessage(*event.Message))
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entries)
}
