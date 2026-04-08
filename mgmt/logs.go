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

// handleLogs proxies log entries from the enclave supervisor (live),
// or queries CloudWatch Logs for historical logs when ?history=true.
// GET /logs?since=RFC3339&level=info&limit=100&history=true
func (s *server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("history") == "true" {
		s.handleLogsHistory(w, r)
		return
	}

	// Live pull from enclave supervisor (existing behavior).
	enclaveURL := envOrDefault("ENCLAVE_URL", "https://127.0.0.1:443")
	u, err := url.Parse(enclaveURL + "/v1/logs")
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// handleLogsHistory queries CloudWatch Logs for historical log entries.
func (s *server) handleLogsHistory(w http.ResponseWriter, r *http.Request) {
	logGroup := fmt.Sprintf("/enclave/%s/%s/logs", s.deployment, s.appName)

	// Parse query params.
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

	level := strings.ToLower(r.URL.Query().Get("level"))

	// Build filter pattern for level if specified.
	var filterPattern *string
	if level != "" {
		// CloudWatch JSON filter: match level field.
		// For severity filtering, we include all levels >= requested.
		levels := levelAndAbove(level)
		if len(levels) > 0 {
			parts := make([]string, len(levels))
			for i, l := range levels {
				parts[i] = fmt.Sprintf(`$.level = %q`, l)
			}
			pattern := "{ " + strings.Join(parts, " || ") + " }"
			filterPattern = aws.String(pattern)
		}
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

	// Parse log events back into LogEntry format.
	entries := make([]json.RawMessage, 0, len(result.Events))
	for _, event := range result.Events {
		if event.Message != nil {
			entries = append(entries, json.RawMessage(*event.Message))
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entries)
}

// levelAndAbove returns the given level and all levels above it.
func levelAndAbove(level string) []string {
	order := []string{"debug", "info", "warn", "error"}
	idx := -1
	for i, l := range order {
		if l == level {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil
	}
	return order[idx:]
}
