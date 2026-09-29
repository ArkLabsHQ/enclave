package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type otlpRecord struct {
	Signal  string          `json:"signal"`
	Service string          `json:"service"`
	Group   string          `json:"group,omitempty"`
	Stream  string          `json:"stream,omitempty"`
	Body    json.RawMessage `json:"body"`
}

var authorizationPattern = regexp.MustCompile(
	`^AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/\d{8}/us-east-1/(logs|xray|monitoring)/aws4_request, ` +
		`SignedHeaders=([a-z0-9;-]+), Signature=[0-9a-f]{64}$`)

type otlpStore struct {
	mu      sync.Mutex
	records []otlpRecord
}

func (s *otlpStore) add(r otlpRecord) {
	s.mu.Lock()
	s.records = append(s.records, r)
	s.mu.Unlock()
}

func (s *otlpStore) list(signal string) []otlpRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []otlpRecord{}
	for _, r := range s.records {
		if r.Signal == signal {
			out = append(out, r)
		}
	}
	return out
}

func runOTLPReceiver(listenAddr string, upstreamLogs *url.URL) error {
	store := &otlpStore{}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("POST /v1/logs", otlpIngest(store, "logs", "logs", func() proto.Message {
		return &collogspb.ExportLogsServiceRequest{}
	}))
	mux.HandleFunc("POST /v1/traces", otlpIngest(store, "traces", "xray", func() proto.Message {
		return &coltracepb.ExportTraceServiceRequest{}
	}))
	mux.HandleFunc("POST /v1/metrics", otlpIngest(store, "metrics", "monitoring", func() proto.Message {
		return &colmetricspb.ExportMetricsServiceRequest{}
	}))
	mux.HandleFunc("GET /_otlp/{signal}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(store.list(r.PathValue("signal")))
	})
	mux.Handle("/", httputil.NewSingleHostReverseProxy(upstreamLogs))

	log.Printf("otlp receiver listening on %s, proxying the Logs API to %s", listenAddr, upstreamLogs)
	return http.ListenAndServe(listenAddr, mux)
}

func otlpIngest(store *otlpStore, signal, service string, newRequest func() proto.Message) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		match := authorizationPattern.FindStringSubmatch(r.Header.Get("Authorization"))
		if match == nil {
			http.Error(w, "missing or malformed SigV4 Authorization", http.StatusUnauthorized)
			return
		}
		if match[1] != service {
			http.Error(w, fmt.Sprintf("signed for %s, this endpoint is %s", match[1], service), http.StatusForbidden)
			return
		}
		if r.Header.Get("X-Amz-Date") == "" {
			http.Error(w, "missing X-Amz-Date", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("X-Amz-Security-Token") != "mock-session-token" {
			http.Error(w, "missing or unknown X-Amz-Security-Token", http.StatusUnauthorized)
			return
		}
		signedHeaders := ";" + match[2] + ";"
		group, stream := r.Header.Get("x-aws-log-group"), r.Header.Get("x-aws-log-stream")
		if service == "logs" {
			if group == "" || stream == "" {
				http.Error(w, "x-aws-log-group and x-aws-log-stream are required", http.StatusBadRequest)
				return
			}
			for _, h := range []string{"x-aws-log-group", "x-aws-log-stream"} {
				if !strings.Contains(signedHeaders, ";"+h+";") {
					http.Error(w, h+" must be a signed header", http.StatusBadRequest)
					return
				}
			}
		}

		var body io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				http.Error(w, "bad gzip: "+err.Error(), http.StatusBadRequest)
				return
			}
			defer func() { _ = gz.Close() }()
			body = gz
		}
		raw, err := io.ReadAll(body)
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}

		msg := newRequest()
		contentType := r.Header.Get("Content-Type")
		switch {
		case strings.HasPrefix(contentType, "application/x-protobuf"):
			err = proto.Unmarshal(raw, msg)
		case strings.HasPrefix(contentType, "application/json"):
			err = protojson.Unmarshal(raw, msg)
		default:
			http.Error(w, "unsupported Content-Type "+contentType, http.StatusUnsupportedMediaType)
			return
		}
		if err != nil {
			http.Error(w, "decode OTLP "+signal+": "+err.Error(), http.StatusBadRequest)
			return
		}
		decoded, err := protojson.Marshal(msg)
		if err != nil {
			http.Error(w, "encode OTLP "+signal+": "+err.Error(), http.StatusInternalServerError)
			return
		}
		store.add(otlpRecord{Signal: signal, Service: service, Group: group, Stream: stream, Body: decoded})

		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		if strings.HasPrefix(contentType, "application/json") {
			_, _ = w.Write([]byte("{}"))
		}
	}
}
