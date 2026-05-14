package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otellog "go.opentelemetry.io/otel/log"
	otelmetric "go.opentelemetry.io/otel/metric"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	otelTrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

// attestationPayload is the CBOR structure inside a COSE Sign1 attestation document.
type attestationPayload struct {
	PCRs     map[uint][]byte `cbor:"pcrs"`
	UserData []byte          `cbor:"user_data"`
	Nonce    []byte          `cbor:"nonce"`
}

// supervisorURL is the internal URL of the runtime.
// The test app calls back to it for storage/secrets management.
var supervisorURL string

// appRequestCounter is an OTEL counter incremented on each request.
var appRequestCounter otelmetric.Int64Counter

func main() {
	port := os.Getenv("ENCLAVE_APP_PORT")
	if port == "" {
		port = "7074"
	}

	proxyPort := os.Getenv("ENCLAVE_PROXY_PORT")
	if proxyPort == "" {
		proxyPort = "7073"
	}
	supervisorURL = "http://127.0.0.1:" + proxyPort

	// Set up OTEL tracing + metrics: export to the supervisor's endpoints.
	token := os.Getenv("ENCLAVE_RUNTIME_TOKEN")
	if token != "" {
		ctx := context.Background()
		headers := map[string]string{"Authorization": "Bearer " + token}

		// Tracing exporter.
		traceExporter, err := otlptracehttp.New(ctx,
			otlptracehttp.WithEndpoint("127.0.0.1:"+proxyPort),
			otlptracehttp.WithURLPath("/v1/enclave-traces"),
			otlptracehttp.WithInsecure(),
			otlptracehttp.WithHeaders(headers),
		)
		if err == nil {
			tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(traceExporter))
			otel.SetTracerProvider(tp)
			defer func() { _ = tp.Shutdown(ctx) }()
			log.Printf("OTEL tracing enabled")
		}

		// Metrics exporter.
		metricExporter, err := otlpmetrichttp.New(ctx,
			otlpmetrichttp.WithEndpoint("127.0.0.1:"+proxyPort),
			otlpmetrichttp.WithURLPath("/v1/enclave-metrics"),
			otlpmetrichttp.WithInsecure(),
			otlpmetrichttp.WithHeaders(headers),
		)
		if err == nil {
			mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(
				sdkmetric.NewPeriodicReader(metricExporter, sdkmetric.WithInterval(5*time.Second)),
			))
			otel.SetMeterProvider(mp)
			defer func() { _ = mp.Shutdown(ctx) }()

			meter := mp.Meter("test-app")
			appRequestCounter, _ = meter.Int64Counter("test_app_requests_total",
				otelmetric.WithDescription("Total requests handled by the test app"),
			)
			log.Printf("OTEL metrics enabled")
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", handleRoot)
	mux.HandleFunc("GET /test/secrets", handleTestSecrets)
	mux.HandleFunc("GET /test/storage", handleTestStorage)
	mux.HandleFunc("GET /test/storage-persistence", handleTestStoragePersistence)
	mux.HandleFunc("GET /test/attestation", handleTestAttestation)
	mux.HandleFunc("GET /test/attestation-document", handleTestAttestationDocument)
	mux.HandleFunc("GET /test/dynamic-secrets", handleTestDynamicSecrets)
	mux.HandleFunc("GET /test/dynamic-secret-persistence", handleTestDynamicSecretPersistence)
	mux.HandleFunc("GET /test/pcr-secrets", handleTestPCRSecrets)
	mux.HandleFunc("GET /test/attestation-persistence", handleTestAttestationPersistence)
	mux.HandleFunc("GET /test/attestation-binding", handleTestAttestationBinding)
	mux.HandleFunc("GET /test/logs", handleTestLogs)
	mux.HandleFunc("GET /test/env-override", handleTestEnvOverride)

	// Wrap mux with otelhttp — every incoming request creates a span automatically.
	otelHandler := otelhttp.NewHandler(mux, "test-app",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method + " " + r.URL.Path
		}),
	)

	// gRPC server: registers grpc.health.v1.Health which gives us both a unary
	// (Check) and a server-streaming (Watch) RPC for end-to-end protocol tests
	// without dragging in protobuf codegen.
	grpcSrv := grpc.NewServer()
	healthSrv := health.NewServer()
	healthSrv.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcSrv, healthSrv)
	reflection.Register(grpcSrv)

	// Unified handler: HTTP/2 gRPC requests go to the gRPC server; everything
	// else stays on the existing REST mux. Wrapped in h2c.NewHandler so the
	// listener accepts HTTP/2 cleartext from the runtime proxy upstream.
	unified := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(
			r.Header.Get("Content-Type"), "application/grpc") {
			grpcSrv.ServeHTTP(w, r)
			return
		}
		otelHandler.ServeHTTP(w, r)
	})
	handler := h2c.NewHandler(unified, &http2.Server{})

	log.Printf("listening on :%s", port)
	srv := &http.Server{Addr: ":" + port, Handler: handler}
	log.Fatal(srv.ListenAndServe())
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	// Create a child span to simulate app-level work.
	tracer := otel.Tracer("test-app")
	_, span := tracer.Start(r.Context(), "handleRoot.work",
		otelTrace.WithAttributes(attribute.String("app", "test-enclave-app")),
	)
	defer span.End()

	// Increment app metric counter.
	if appRequestCounter != nil {
		appRequestCounter.Add(r.Context(), 1)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":     "ok",
		"app":        "test-enclave-app",
		"request_id": uuid.NewString(),
	})
}

// handleTestAttestation verifies BIP-340 Schnorr response signatures.
// Calls the supervisor's /v1/enclave-info, then verifies the
// X-Attestation-Signature header against the response body.
func handleTestAttestation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	results := map[string]any{}

	// Fetch enclave-info from the supervisor (which signs all responses).
	resp, err := http.Get(supervisorURL + "/v1/enclave-info")
	if err != nil {
		results["error"] = fmt.Sprintf("fetch enclave-info: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	sigHex := resp.Header.Get("X-Attestation-Signature")
	pubkeyHex := resp.Header.Get("X-Attestation-Pubkey")

	results["signature_present"] = sigHex != ""
	results["pubkey_present"] = pubkeyHex != ""

	if sigHex == "" || pubkeyHex == "" {
		results["error"] = "attestation headers missing"
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}

	// Parse compressed public key (33 bytes).
	pubkeyBytes, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		results["error"] = fmt.Sprintf("decode pubkey hex: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	pubkey, err := btcec.ParsePubKey(pubkeyBytes)
	if err != nil {
		results["error"] = fmt.Sprintf("parse pubkey: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	results["pubkey"] = pubkeyHex

	// Parse BIP-340 Schnorr signature (64 bytes).
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		results["error"] = fmt.Sprintf("decode signature hex: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		results["error"] = fmt.Sprintf("parse schnorr signature: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}

	// Verify: sha256(body) signed with attestation key.
	msgHash := sha256.Sum256(body)
	valid := sig.Verify(msgHash[:], pubkey)
	results["signature_valid"] = valid

	if valid {
		results["status"] = "ok"
	} else {
		results["error"] = "signature verification failed"
		results["body_length"] = len(body)
		w.WriteHeader(http.StatusInternalServerError)
	}

	json.NewEncoder(w).Encode(results)
}

// handleTestSecrets verifies that KMS secrets were loaded into env vars.
func handleTestSecrets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	results := map[string]any{}

	// Check SIGNING_KEY (configured in enclave.yaml as a KMS secret).
	signingKey := os.Getenv("SIGNING_KEY")
	if signingKey != "" {
		results["signing_key"] = map[string]any{
			"present": true,
			"length":  len(signingKey),
		}
	} else {
		results["signing_key"] = map[string]any{
			"present": false,
		}
	}

	// Overall status.
	allPresent := signingKey != ""
	if allPresent {
		results["status"] = "ok"
	} else {
		results["status"] = "missing_secrets"
		w.WriteHeader(http.StatusInternalServerError)
	}

	json.NewEncoder(w).Encode(results)
}

// handleTestStorage exercises the storage API: put, get, verify, delete.
func handleTestStorage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	token := os.Getenv("ENCLAVE_RUNTIME_TOKEN")
	if token == "" {
		http.Error(w, `{"error":"ENCLAVE_RUNTIME_TOKEN not set"}`, http.StatusInternalServerError)
		return
	}

	testKey := fmt.Sprintf("test/%s", uuid.NewString())
	testValue := fmt.Sprintf("test-data-%d", time.Now().UnixNano())

	results := map[string]any{
		"key": testKey,
	}

	// PUT: store test data.
	putReq, _ := http.NewRequest("PUT", supervisorURL+"/v1/storage/"+testKey, bytes.NewReader([]byte(testValue)))
	putReq.Header.Set("Authorization", "Bearer "+token)
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		results["error"] = fmt.Sprintf("put request failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusCreated {
		results["error"] = fmt.Sprintf("put returned %d", putResp.StatusCode)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	results["put"] = "ok"

	// GET: read it back.
	getReq, _ := http.NewRequest("GET", supervisorURL+"/v1/storage/"+testKey, nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		results["error"] = fmt.Sprintf("get request failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	body, _ := io.ReadAll(getResp.Body)
	getResp.Body.Close()

	if string(body) != testValue {
		results["error"] = fmt.Sprintf("value mismatch: got %q, want %q", string(body), testValue)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	results["get"] = "ok"
	results["roundtrip"] = true

	// DELETE: clean up.
	delReq, _ := http.NewRequest("DELETE", supervisorURL+"/v1/storage/"+testKey, nil)
	delReq.Header.Set("Authorization", "Bearer "+token)
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		results["error"] = fmt.Sprintf("delete request failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	delResp.Body.Close()
	results["delete"] = "ok"

	results["status"] = "ok"
	json.NewEncoder(w).Encode(results)
}

// handleTestStoragePersistence writes a well-known key to storage (or reads it back).
// First call (key doesn't exist): writes "persistent-test-value" → returns {"phase":"write"}.
// Second call (key exists): reads it back and verifies → returns {"phase":"verify","roundtrip":true}.
// This lets the test suite verify storage survives across migration/restart.
func handleTestStoragePersistence(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	token := os.Getenv("ENCLAVE_RUNTIME_TOKEN")
	if token == "" {
		http.Error(w, `{"error":"ENCLAVE_RUNTIME_TOKEN not set"}`, http.StatusInternalServerError)
		return
	}

	const persistKey = "test/persistence-check"
	const persistValue = "persistent-test-value"
	results := map[string]any{"key": persistKey}

	// Try to GET first — if it exists, we're in verify phase.
	getReq, _ := http.NewRequest("GET", supervisorURL+"/v1/storage/"+persistKey, nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		results["error"] = fmt.Sprintf("get failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	body, _ := io.ReadAll(getResp.Body)
	getResp.Body.Close()

	if getResp.StatusCode == http.StatusOK && len(body) > 0 {
		// Verify phase: key existed, check value matches.
		results["phase"] = "verify"
		if string(body) == persistValue {
			results["roundtrip"] = true
			results["status"] = "ok"
		} else {
			results["error"] = fmt.Sprintf("value mismatch: got %q, want %q", string(body), persistValue)
			w.WriteHeader(http.StatusInternalServerError)
		}
		json.NewEncoder(w).Encode(results)
		return
	}

	// Write phase: key doesn't exist yet, create it.
	putReq, _ := http.NewRequest("PUT", supervisorURL+"/v1/storage/"+persistKey, bytes.NewReader([]byte(persistValue)))
	putReq.Header.Set("Authorization", "Bearer "+token)
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		results["error"] = fmt.Sprintf("put failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusCreated {
		results["error"] = fmt.Sprintf("put returned %d", putResp.StatusCode)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	results["phase"] = "write"
	results["status"] = "ok"
	json.NewEncoder(w).Encode(results)
}

// handleTestDynamicSecrets exercises the dynamic secrets API:
// PUT → GET → verify → list → DELETE.
func handleTestDynamicSecrets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	token := os.Getenv("ENCLAVE_RUNTIME_TOKEN")
	if token == "" {
		http.Error(w, `{"error":"ENCLAVE_RUNTIME_TOKEN not set"}`, http.StatusInternalServerError)
		return
	}

	secretName := fmt.Sprintf("test-secret-%s", uuid.NewString()[:8])
	secretValue := fmt.Sprintf("value-%d", time.Now().UnixNano())
	results := map[string]any{"name": secretName}

	// PUT: create dynamic secret.
	putBody, _ := json.Marshal(map[string]string{
		"value":   secretValue,
		"env_var": "TEST_DYNAMIC_" + fmt.Sprintf("%d", time.Now().UnixNano()%10000),
	})
	putReq, _ := http.NewRequest("PUT", supervisorURL+"/v1/secrets/"+secretName, bytes.NewReader(putBody))
	putReq.Header.Set("Authorization", "Bearer "+token)
	putReq.Header.Set("Content-Type", "application/json")
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		results["error"] = fmt.Sprintf("put secret failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusCreated {
		results["error"] = fmt.Sprintf("put secret returned %d", putResp.StatusCode)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	results["put"] = "ok"

	// GET: read it back.
	getReq, _ := http.NewRequest("GET", supervisorURL+"/v1/secrets/"+secretName, nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		results["error"] = fmt.Sprintf("get secret failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	getBody, _ := io.ReadAll(getResp.Body)
	getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		results["error"] = fmt.Sprintf("get secret returned %d: %s", getResp.StatusCode, string(getBody))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}

	var secretResp struct {
		Value string `json:"value"`
	}
	json.Unmarshal(getBody, &secretResp)
	if secretResp.Value != secretValue {
		results["error"] = fmt.Sprintf("value mismatch: got %q, want %q", secretResp.Value, secretValue)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	results["get"] = "ok"
	results["roundtrip"] = true

	// LIST: verify it appears.
	listReq, _ := http.NewRequest("GET", supervisorURL+"/v1/secrets", nil)
	listReq.Header.Set("Authorization", "Bearer "+token)
	listResp, err := http.DefaultClient.Do(listReq)
	if err == nil {
		listBody, _ := io.ReadAll(listResp.Body)
		listResp.Body.Close()
		var listResult struct {
			Secrets []struct{ Name string } `json:"secrets"`
		}
		json.Unmarshal(listBody, &listResult)
		found := false
		for _, s := range listResult.Secrets {
			if s.Name == secretName {
				found = true
				break
			}
		}
		results["listed"] = found
	}

	// DELETE: clean up.
	delReq, _ := http.NewRequest("DELETE", supervisorURL+"/v1/secrets/"+secretName, nil)
	delReq.Header.Set("Authorization", "Bearer "+token)
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		results["error"] = fmt.Sprintf("delete secret failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	delResp.Body.Close()
	results["delete"] = "ok"

	results["status"] = "ok"
	json.NewEncoder(w).Encode(results)
}

// handleTestDynamicSecretPersistence creates or verifies a well-known dynamic secret.
// First call (secret doesn't exist): creates "migration-persist-secret" → returns {"phase":"write"}.
// Second call (secret exists): reads it back and verifies → returns {"phase":"verify","roundtrip":true}.
// This lets the test suite verify dynamic secrets survive across migration/restart.
func handleTestDynamicSecretPersistence(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	token := os.Getenv("ENCLAVE_RUNTIME_TOKEN")
	if token == "" {
		http.Error(w, `{"error":"ENCLAVE_RUNTIME_TOKEN not set"}`, http.StatusInternalServerError)
		return
	}

	const persistName = "migration-persist-secret"
	const persistValue = "pre-migration-value"
	const persistEnvVar = "TEST_PERSIST_SECRET"
	results := map[string]any{"name": persistName}

	// Try GET first — if it exists, we're in verify phase.
	getReq, _ := http.NewRequest("GET", supervisorURL+"/v1/secrets/"+persistName, nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		results["error"] = fmt.Sprintf("get failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	getBody, _ := io.ReadAll(getResp.Body)
	getResp.Body.Close()

	if getResp.StatusCode == http.StatusOK && len(getBody) > 0 {
		var secretResp struct {
			Value string `json:"value"`
		}
		json.Unmarshal(getBody, &secretResp)
		results["phase"] = "verify"
		if secretResp.Value == persistValue {
			results["roundtrip"] = true
			results["status"] = "ok"
		} else {
			results["error"] = fmt.Sprintf("value mismatch: got %q, want %q", secretResp.Value, persistValue)
			w.WriteHeader(http.StatusInternalServerError)
		}
		json.NewEncoder(w).Encode(results)
		return
	}

	// Write phase: secret doesn't exist yet, create it.
	putBody, _ := json.Marshal(map[string]string{
		"value":   persistValue,
		"env_var": persistEnvVar,
	})
	putReq, _ := http.NewRequest("PUT", supervisorURL+"/v1/secrets/"+persistName, bytes.NewReader(putBody))
	putReq.Header.Set("Authorization", "Bearer "+token)
	putReq.Header.Set("Content-Type", "application/json")
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		results["error"] = fmt.Sprintf("put failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusCreated {
		results["error"] = fmt.Sprintf("put returned %d", putResp.StatusCode)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	results["phase"] = "write"
	results["status"] = "ok"
	json.NewEncoder(w).Encode(results)
}

// handleTestPCRSecrets verifies secret-to-PCR derivation math and that the
// NSM returns a valid attestation document with PCR16 matching the expected value.
// PCR16 is extended with SHA256(compressed_pubkey) and then locked by the SDK,
// so QEMU's NSM includes it in the attestation document (locked PCRs are included).
func handleTestPCRSecrets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	results := map[string]any{}

	// Get the signing key (static secret loaded by SDK).
	signingKeyHex := os.Getenv("SIGNING_KEY")
	if signingKeyHex == "" {
		results["error"] = "SIGNING_KEY not set"
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}

	// Derive the compressed public key from the secret (same as SDK does).
	secretBytes, err := hex.DecodeString(signingKeyHex)
	if err != nil || len(secretBytes) != 32 {
		results["error"] = fmt.Sprintf("SIGNING_KEY not valid 32-byte hex: %v (len=%d)", err, len(secretBytes))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}

	// secp256k1 private key → compressed public key → SHA256 hash (extension data).
	privKey, _ := btcec.PrivKeyFromBytes(secretBytes)
	compressedPubkey := privKey.PubKey().SerializeCompressed()
	extensionData := sha256.Sum256(compressedPubkey)

	results["pcr_index"] = 16
	results["extension_data"] = hex.EncodeToString(extensionData[:])
	results["pubkey"] = hex.EncodeToString(compressedPubkey)
	results["derivation_valid"] = len(compressedPubkey) == 33

	// Compute expected PCR16 value: SHA384(zeros_48 || extension_data).
	// Nitro PCRs 16-31 start as 48 zero bytes. ExtendPCR computes SHA384(old || data).
	var zeros48 [48]byte
	extendInput := append(zeros48[:], extensionData[:]...)
	expectedPCR16 := sha512.Sum384(extendInput)
	results["expected_pcr16"] = hex.EncodeToString(expectedPCR16[:])

	// Fetch the real attestation document from nitriding to verify NSM works.
	// PCR16 is now locked by the SDK after extension, so QEMU includes it.
	doc, err := fetchAttestationDoc()
	if err != nil {
		results["error"] = fmt.Sprintf("fetch attestation: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}

	results["pcr_count"] = len(doc.PCRs)
	results["attestation_doc_valid"] = true

	// Verify PCR16 from the attestation document matches expected value.
	if pcr16, ok := doc.PCRs[16]; ok {
		actualPCR16 := hex.EncodeToString(pcr16)
		results["actual_pcr16"] = actualPCR16
		results["pcr16_present"] = true
		results["pcr16_verified"] = actualPCR16 == hex.EncodeToString(expectedPCR16[:])
	} else {
		results["pcr16_present"] = false
		results["pcr16_verified"] = false
	}

	results["status"] = "ok"
	json.NewEncoder(w).Encode(results)
}

// handleTestAttestationDocument fetches a raw attestation document from nitriding,
// parses the COSE Sign1 structure, and returns the PCR values. This verifies that
// QEMU's NSM emulation produces real attestation documents with valid PCR state.
func handleTestAttestationDocument(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	results := map[string]any{}

	doc, err := fetchAttestationDoc()
	if err != nil {
		results["error"] = fmt.Sprintf("fetch attestation: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}

	results["pcr_count"] = len(doc.PCRs)

	// Report all PCR values.
	pcrMap := map[string]string{}
	for idx, val := range doc.PCRs {
		pcrMap[fmt.Sprintf("pcr%d", idx)] = hex.EncodeToString(val)
	}
	results["pcrs"] = pcrMap

	// PCR0 must be present and non-zero. QEMU computes real PCR0 from the EIF
	// (SHA384 of kernel + ramdisks + cmdline) at boot.
	if pcr0, ok := doc.PCRs[0]; ok {
		results["pcr0"] = hex.EncodeToString(pcr0)
		results["pcr0_present"] = true
		allZero := true
		for _, b := range pcr0 {
			if b != 0 {
				allZero = false
				break
			}
		}
		results["pcr0_nonzero"] = !allZero
		if allZero {
			results["error"] = "PCR0 is all zeros — EIF hash not computed by QEMU"
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(results)
			return
		}
	} else {
		results["error"] = "PCR0 missing from attestation document"
		results["pcr0_present"] = false
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}

	// Verify PCR16 is present and matches expected value (locked after extension).
	signingKeyHex := os.Getenv("SIGNING_KEY")
	if signingKeyHex != "" {
		secretBytes, err := hex.DecodeString(signingKeyHex)
		if err == nil && len(secretBytes) == 32 {
			privKey, _ := btcec.PrivKeyFromBytes(secretBytes)
			compressedPubkey := privKey.PubKey().SerializeCompressed()
			extensionData := sha256.Sum256(compressedPubkey)
			var zeros48 [48]byte
			extendInput := append(zeros48[:], extensionData[:]...)
			expectedPCR16 := sha512.Sum384(extendInput)

			if pcr16, ok := doc.PCRs[16]; ok {
				actualPCR16 := hex.EncodeToString(pcr16)
				results["pcr16"] = actualPCR16
				results["pcr16_verified"] = actualPCR16 == hex.EncodeToString(expectedPCR16[:])
			} else {
				results["pcr16_verified"] = false
			}
		}
	}

	results["status"] = "ok"
	json.NewEncoder(w).Encode(results)
}

// handleTestAttestationBinding verifies the full attestation chain of trust:
// 1. Fetch a signed response from the supervisor (get X-Attestation-Pubkey header)
// 2. Fetch the attestation document from nitriding (get UserData field)
// 3. Verify SHA256(X-Attestation-Pubkey) == UserData
// This proves the signing key is bound to the NSM attestation document.
func handleTestAttestationBinding(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	results := map[string]any{}

	// Step 1: Get the attestation pubkey from a signed response.
	resp, err := http.Get(supervisorURL + "/v1/enclave-info")
	if err != nil {
		results["error"] = fmt.Sprintf("fetch enclave-info: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	pubkeyHex := resp.Header.Get("X-Attestation-Pubkey")
	sigHex := resp.Header.Get("X-Attestation-Signature")
	if pubkeyHex == "" || sigHex == "" {
		results["error"] = "attestation headers missing from response"
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}

	// Verify the Schnorr signature on the response body.
	pubkeyBytes, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		results["error"] = fmt.Sprintf("decode pubkey: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	pubkey, err := btcec.ParsePubKey(pubkeyBytes)
	if err != nil {
		results["error"] = fmt.Sprintf("parse pubkey: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	sigBytes, _ := hex.DecodeString(sigHex)
	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		results["error"] = fmt.Sprintf("parse signature: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	msgHash := sha256.Sum256(body)
	results["signature_valid"] = sig.Verify(msgHash[:], pubkey)

	// Step 2: Compute SHA256(compressed_pubkey) — this is what the SDK registered
	// with nitriding via POST /enclave/hash during Init.
	pubkeyHash := sha256.Sum256(pubkeyBytes)
	results["pubkey_hash"] = hex.EncodeToString(pubkeyHash[:])

	// Step 3: Fetch attestation document and extract UserData.
	doc, err := fetchAttestationDoc()
	if err != nil {
		results["error"] = fmt.Sprintf("fetch attestation doc: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}

	// UserData format (nitriding v1.4.2):
	//   "sha256:" ++ tlsKeyHash(32) ++ ";" ++ "sha256:" ++ appKeyHash(32)
	// Total 79 bytes. appKeyHash at bytes 47:79.
	results["user_data"] = hex.EncodeToString(doc.UserData)
	results["user_data_length"] = len(doc.UserData)

	const (
		hashPrefix = "sha256:"
		hashSep    = ";"
		tlsStart   = len(hashPrefix)
		tlsEnd     = tlsStart + 32
		sepStart   = tlsEnd
		appPrefix  = sepStart + len(hashSep)
		appStart   = appPrefix + len(hashPrefix)
		appEnd     = appStart + 32
	)

	if len(doc.UserData) < appEnd {
		results["error"] = fmt.Sprintf("UserData too short: %d bytes (need %d)", len(doc.UserData), appEnd)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	if !bytes.Equal(doc.UserData[:tlsStart], []byte(hashPrefix)) {
		results["error"] = fmt.Sprintf("UserData missing %q prefix at offset 0 (got %q)", hashPrefix, string(doc.UserData[:tlsStart]))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	if string(doc.UserData[sepStart:appPrefix]) != hashSep {
		results["error"] = fmt.Sprintf("UserData missing %q separator at offset %d (got %q)", hashSep, sepStart, string(doc.UserData[sepStart:appPrefix]))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	if !bytes.Equal(doc.UserData[appPrefix:appStart], []byte(hashPrefix)) {
		results["error"] = fmt.Sprintf("UserData missing %q prefix at offset %d (got %q)", hashPrefix, appPrefix, string(doc.UserData[appPrefix:appStart]))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}

	appKeyHash := doc.UserData[appStart:appEnd]
	results["app_key_hash"] = hex.EncodeToString(appKeyHash)

	// Step 4: Verify binding — SHA256(attestation_pubkey) must equal appKeyHash.
	bindingValid := bytes.Equal(pubkeyHash[:], appKeyHash)
	results["binding_valid"] = bindingValid

	if bindingValid {
		results["status"] = "ok"
	} else {
		results["error"] = fmt.Sprintf("binding mismatch: SHA256(pubkey)=%s, appKeyHash=%s",
			hex.EncodeToString(pubkeyHash[:]), hex.EncodeToString(appKeyHash))
		w.WriteHeader(http.StatusInternalServerError)
	}

	json.NewEncoder(w).Encode(results)
}

// fetchAttestationDoc fetches a raw attestation document from nitriding's
// external HTTPS /enclave/attestation endpoint, parses the COSE Sign1 CBOR
// structure, and returns the full attestation payload (PCRs, UserData, Nonce).
// Note: uses nitriding's HTTPS port (443) because /enclave/attestation is only
// served on the external listener, not the internal HTTP port.
func fetchAttestationDoc() (*attestationPayload, error) {
	tlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	nonceBytes := make([]byte, 20)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)
	resp, err := tlsClient.Get("https://localhost:443/enclave/attestation?nonce=" + nonce)
	if err != nil {
		return nil, fmt.Errorf("GET /enclave/attestation: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("attestation returned %d: %s", resp.StatusCode, string(body))
	}

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	// nitriding returns base64-encoded attestation doc (may be raw or JSON-wrapped).
	docB64 := strings.TrimSpace(string(payload))
	if strings.HasPrefix(docB64, "{") {
		var parsed struct {
			Document string `json:"document"`
		}
		if err := json.Unmarshal(payload, &parsed); err == nil && parsed.Document != "" {
			docB64 = parsed.Document
		}
	}

	docBytes, err := base64.StdEncoding.DecodeString(docB64)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}

	// Parse COSE Sign1: CBOR array [protected, unprotected, payload, signature].
	var coseSign1 []cbor.RawMessage
	if err := cbor.Unmarshal(docBytes, &coseSign1); err != nil {
		return nil, fmt.Errorf("unmarshal COSE Sign1: %w", err)
	}
	if len(coseSign1) < 3 {
		return nil, fmt.Errorf("invalid COSE Sign1 structure (got %d elements)", len(coseSign1))
	}

	// Element [2] is the payload (CBOR bstr containing the attestation document).
	var payloadBytes []byte
	if err := cbor.Unmarshal(coseSign1[2], &payloadBytes); err != nil {
		return nil, fmt.Errorf("unmarshal COSE payload: %w", err)
	}

	var doc attestationPayload
	if err := cbor.Unmarshal(payloadBytes, &doc); err != nil {
		return nil, fmt.Errorf("unmarshal attestation document: %w", err)
	}

	if len(doc.PCRs) == 0 {
		return nil, fmt.Errorf("attestation document has no PCRs")
	}

	return &doc, nil
}

// handleTestAttestationPersistence verifies that the attestation pubkey and
// PCR16 extension hash survive migration. Uses the write/verify pattern:
//
// First call (pre-migration): derives pubkey + PCR16 hash from SIGNING_KEY,
// fetches attestation_pubkey from supervisor, stores all three values to
// encrypted storage → returns {"phase":"write"}.
//
// Second call (post-migration): reads stored values, re-derives current values,
// compares → returns {"phase":"verify","pubkey_match":true,"pcr16_match":true}.
func handleTestAttestationPersistence(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	token := os.Getenv("ENCLAVE_RUNTIME_TOKEN")
	if token == "" {
		http.Error(w, `{"error":"ENCLAVE_RUNTIME_TOKEN not set"}`, http.StatusInternalServerError)
		return
	}

	results := map[string]any{}

	// Derive current attestation values from SIGNING_KEY.
	signingKeyHex := os.Getenv("SIGNING_KEY")
	if signingKeyHex == "" {
		results["error"] = "SIGNING_KEY not set"
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	secretBytes, err := hex.DecodeString(signingKeyHex)
	if err != nil || len(secretBytes) != 32 {
		results["error"] = fmt.Sprintf("SIGNING_KEY invalid: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	privKey, _ := btcec.PrivKeyFromBytes(secretBytes)
	compressedPubkey := privKey.PubKey().SerializeCompressed()
	extensionData := sha256.Sum256(compressedPubkey)
	// Compute actual PCR16: SHA384(zeros_48 || SHA256(compressed_pubkey)).
	// Nitro PCRs 16-31 start as 48 zero bytes, ExtendPCR computes SHA384(old || data).
	var zeros48 [48]byte
	extendInput := append(zeros48[:], extensionData[:]...)
	actualPCR16 := sha512.Sum384(extendInput)
	currentPCR16 := hex.EncodeToString(actualPCR16[:])
	currentPubkey := hex.EncodeToString(compressedPubkey)

	// Fetch attestation_pubkey from supervisor (the ephemeral key used for signing).
	infoResp, err := http.Get(supervisorURL + "/v1/enclave-info")
	if err != nil {
		results["error"] = fmt.Sprintf("fetch enclave-info: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	infoBody, _ := io.ReadAll(infoResp.Body)
	infoResp.Body.Close()
	var info struct {
		AttestationPubkey string `json:"attestation_pubkey"`
	}
	json.Unmarshal(infoBody, &info)
	currentAttestPubkey := info.AttestationPubkey

	const storageKey = "test/attestation-persistence"

	// Try GET — if stored data exists, we're in verify phase.
	getReq, _ := http.NewRequest("GET", supervisorURL+"/v1/storage/"+storageKey, nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		results["error"] = fmt.Sprintf("storage get: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	storedBody, _ := io.ReadAll(getResp.Body)
	getResp.Body.Close()

	if getResp.StatusCode == http.StatusOK && len(storedBody) > 0 {
		// Verify phase: compare stored pre-migration values with current.
		var stored struct {
			Pubkey string `json:"pubkey"`
			PCR16  string `json:"pcr16"`
		}
		json.Unmarshal(storedBody, &stored)

		results["phase"] = "verify"
		results["pre_migration_pubkey"] = stored.Pubkey
		results["post_migration_pubkey"] = currentPubkey
		results["pubkey_match"] = stored.Pubkey == currentPubkey
		results["pre_migration_pcr16"] = stored.PCR16
		results["post_migration_pcr16"] = currentPCR16
		results["pcr16_match"] = stored.PCR16 == currentPCR16

		if stored.Pubkey == currentPubkey && stored.PCR16 == currentPCR16 {
			results["status"] = "ok"
		} else {
			results["error"] = "attestation values changed after migration"
			w.WriteHeader(http.StatusInternalServerError)
		}
		json.NewEncoder(w).Encode(results)
		return
	}

	// Write phase: store current values for post-migration comparison.
	storeData, _ := json.Marshal(map[string]string{
		"pubkey":        currentPubkey,
		"pcr16":         currentPCR16,
		"attest_pubkey": currentAttestPubkey,
	})
	putReq, _ := http.NewRequest("PUT", supervisorURL+"/v1/storage/"+storageKey, bytes.NewReader(storeData))
	putReq.Header.Set("Authorization", "Bearer "+token)
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		results["error"] = fmt.Sprintf("storage put: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusCreated {
		results["error"] = fmt.Sprintf("storage put returned %d", putResp.StatusCode)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}

	results["phase"] = "write"
	results["pubkey"] = currentPubkey
	results["pcr16"] = currentPCR16
	results["attest_pubkey"] = currentAttestPubkey
	results["status"] = "ok"
	json.NewEncoder(w).Encode(results)
}

// handleTestLogs tests the log round-trip via OTEL SDK (OTLP/HTTP protobuf)
// and verifies auth enforcement.
func handleTestLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	token := os.Getenv("ENCLAVE_RUNTIME_TOKEN")
	if token == "" {
		http.Error(w, `{"error":"ENCLAVE_RUNTIME_TOKEN not set"}`, http.StatusInternalServerError)
		return
	}

	results := map[string]any{}
	ctx := r.Context()

	// Create OTEL exporter pointing at the supervisor's /v1/logs endpoint.
	exporter, err := otlploghttp.New(ctx,
		otlploghttp.WithEndpoint(strings.TrimPrefix(supervisorURL, "http://")),
		otlploghttp.WithInsecure(),
		otlploghttp.WithHeaders(map[string]string{
			"Authorization": "Bearer " + token,
		}),
	)
	if err != nil {
		results["error"] = fmt.Sprintf("create OTEL exporter: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}

	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(exporter)))
	logger := provider.Logger("integration-test")

	// Emit 3 log entries at different severity levels.
	var r1 otellog.Record
	r1.SetTimestamp(time.Now())
	r1.SetSeverity(otellog.SeverityInfo)
	r1.SetBody(otellog.StringValue("integration test log"))
	r1.AddAttributes(otellog.String("test", "otel"))
	logger.Emit(ctx, r1)

	var r2 otellog.Record
	r2.SetTimestamp(time.Now())
	r2.SetSeverity(otellog.SeverityWarn)
	r2.SetBody(otellog.StringValue("batch entry 1"))
	logger.Emit(ctx, r2)

	var r3 otellog.Record
	r3.SetTimestamp(time.Now())
	r3.SetSeverity(otellog.SeverityError)
	r3.SetBody(otellog.StringValue("batch entry 2"))
	logger.Emit(ctx, r3)

	if err := provider.Shutdown(ctx); err != nil {
		results["error"] = fmt.Sprintf("OTEL shutdown: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	results["post"] = "ok"
	results["post_batch"] = "ok"

	// Verify auth enforcement: check the log buffer does NOT contain
	// the "should be rejected" message (we send it without auth token).
	noAuthExporter, err := otlploghttp.New(ctx,
		otlploghttp.WithEndpoint(strings.TrimPrefix(supervisorURL, "http://")),
		otlploghttp.WithInsecure(),
	)
	if err == nil {
		noAuthProvider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(noAuthExporter)))
		noAuthLogger := noAuthProvider.Logger("no-auth-test")
		var nr otellog.Record
		nr.SetSeverity(otellog.SeverityInfo)
		nr.SetBody(otellog.StringValue("should be rejected"))
		noAuthLogger.Emit(ctx, nr)
		_ = noAuthProvider.Shutdown(ctx)

		// Check the buffer — "should be rejected" must NOT appear.
		getResp, getErr := http.Get(supervisorURL + "/v1/enclave-logs")
		if getErr == nil {
			getBody, _ := io.ReadAll(getResp.Body)
			getResp.Body.Close()
			results["auth_enforced"] = !strings.Contains(string(getBody), "should be rejected")
		}
	}

	results["status"] = "ok"
	json.NewEncoder(w).Encode(results)
}

// handleTestEnvOverride exposes the TEST_RUNTIME_OVERRIDE* keys so the
// integration test can assert tofu's deploy-time overrides (supplied via
// env_values.auto.tfvars.json) flowed through SSM into the child app.
func handleTestEnvOverride(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":                        "ok",
		"test_runtime_override":         os.Getenv("TEST_RUNTIME_OVERRIDE"),
		"test_runtime_override_envfile": os.Getenv("TEST_RUNTIME_OVERRIDE_ENVFILE"),
	})
}
