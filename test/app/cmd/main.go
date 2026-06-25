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
	"errors"
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
	"github.com/redis/go-redis/v9"
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
		proxyPort = "8080"
	}
	supervisorURL = "http://127.0.0.1:" + proxyPort

	// Set up OTEL tracing + metrics: export to the supervisor's endpoints.
	token := os.Getenv("ENCLAVE_RUNTIME_TOKEN")
	if token != "" {
		ctx := context.Background()
		headers := map[string]string{"Authorization": "Bearer " + token}

		// Tracing exporter — uses OTLP/HTTP default path /v1/traces.
		traceExporter, err := otlptracehttp.New(ctx,
			otlptracehttp.WithEndpoint("127.0.0.1:"+proxyPort),
			otlptracehttp.WithInsecure(),
			otlptracehttp.WithHeaders(headers),
		)
		if err == nil {
			tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(traceExporter))
			otel.SetTracerProvider(tp)
			defer func() { _ = tp.Shutdown(ctx) }()
			log.Printf("OTEL tracing enabled")
		}

		// Metrics exporter — uses OTLP/HTTP default path /v1/metrics.
		metricExporter, err := otlpmetrichttp.New(ctx,
			otlpmetrichttp.WithEndpoint("127.0.0.1:"+proxyPort),
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
	mux.HandleFunc("GET /test/redis-types", handleTestRedisTypes)
	mux.HandleFunc("POST /test/storage-persistence", handleTestStoragePersistenceWrite)
	mux.HandleFunc("GET /test/storage-persistence", handleTestStoragePersistenceVerify)
	mux.HandleFunc("GET /test/attestation", handleTestAttestation)
	mux.HandleFunc("GET /test/attestation-document", handleTestAttestationDocument)
	mux.HandleFunc("GET /test/pcr-secrets", handleTestPCRSecrets)
	mux.HandleFunc("POST /test/attestation-persistence", handleTestAttestationPersistenceWrite)
	mux.HandleFunc("GET /test/attestation-persistence", handleTestAttestationPersistenceVerify)
	mux.HandleFunc("GET /test/attestation-binding", handleTestAttestationBinding)
	mux.HandleFunc("GET /test/logs", handleTestLogs)
	mux.HandleFunc("GET /test/env-override", handleTestEnvOverride)
	mux.HandleFunc("POST /test/crash", handleTestCrash)

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

// handleTestStorage exercises the K/V store with a real Redis client over the
// enclave's RESP listener: SET, GET, verify, DEL.
func handleTestStorage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rdb, err := redisClient()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	defer rdb.Close()
	ctx := r.Context()

	testKey := fmt.Sprintf("test/%s", uuid.NewString())
	testValue := fmt.Sprintf("test-data-%d", time.Now().UnixNano())
	results := map[string]any{"key": testKey}

	if err := rdb.Set(ctx, testKey, testValue, 0).Err(); err != nil {
		results["error"] = fmt.Sprintf("SET failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	results["put"] = "ok"

	got, err := rdb.Get(ctx, testKey).Result()
	if err != nil {
		results["error"] = fmt.Sprintf("GET failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	if got != testValue {
		results["error"] = fmt.Sprintf("value mismatch: got %q, want %q", got, testValue)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	results["get"] = "ok"
	results["roundtrip"] = true

	if err := rdb.Del(ctx, testKey).Err(); err != nil {
		results["error"] = fmt.Sprintf("DEL failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	results["delete"] = "ok"

	results["status"] = "ok"
	json.NewEncoder(w).Encode(results)
}

const (
	storagePersistKey   = "test/persistence-check"
	storagePersistValue = "persistent-test-value"
)

// handleTestStoragePersistenceWrite (POST) writes the well-known key+value,
// deleting any stale value first so re-runs don't carry over old data.
func handleTestStoragePersistenceWrite(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	rdb, err := redisClient()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	defer rdb.Close()
	ctx := r.Context()

	if err := rdb.Del(ctx, storagePersistKey).Err(); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"DEL failed: %v"}`, err), http.StatusInternalServerError)
		return
	}
	if err := rdb.Set(ctx, storagePersistKey, storagePersistValue, 0).Err(); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"SET failed: %v"}`, err), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "key": storagePersistKey})
}

// handleTestStoragePersistenceVerify (GET) reads the well-known key and compares
// it to the expected value. 404 if the key is missing (data lost during
// migration), 500 if the value is wrong, 200 if it matches exactly.
func handleTestStoragePersistenceVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	rdb, err := redisClient()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	defer rdb.Close()

	got, err := rdb.Get(r.Context(), storagePersistKey).Result()
	if errors.Is(err, redis.Nil) {
		http.Error(w, `{"error":"key not found — data lost during migration"}`, http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"GET failed: %v"}`, err), http.StatusInternalServerError)
		return
	}
	if got != storagePersistValue {
		http.Error(w, fmt.Sprintf(`{"error":"value mismatch: got %q, want %q"}`, got, storagePersistValue), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "key": storagePersistKey})
}

// redisClient builds a go-redis client for the enclave's RESP listener over
// loopback TLS, authenticating with the runtime token. The listener serves the
// attestation-bound cert (issued for the FQDN), so loopback dials skip
// verification — same trust domain, inside the enclave.
func redisClient() (*redis.Client, error) {
	token := os.Getenv("ENCLAVE_RUNTIME_TOKEN")
	if token == "" {
		return nil, errors.New("ENCLAVE_RUNTIME_TOKEN not set")
	}
	port := os.Getenv("ENCLAVE_KV_RESP_PORT")
	if port == "" {
		port = "6379"
	}
	return redis.NewClient(&redis.Options{
		Addr:      "127.0.0.1:" + port,
		Password:  token,
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	}), nil
}

// handleTestRedisTypes exercises the full Redis surface — hashes, lists, sets,
// sorted sets, streams, MULTI/EXEC transactions, SCAN, and pub/sub — through the
// real go-redis client, proving the enclave speaks them end to end.
func handleTestRedisTypes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	rdb, err := redisClient()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	defer rdb.Close()
	ctx := r.Context()
	p := fmt.Sprintf("itest:%d:", time.Now().UnixNano()) // unique per run
	results := map[string]any{}

	if err := rdb.HSet(ctx, p+"h", "f1", "v1", "f2", "v2").Err(); err == nil {
		hm, e := rdb.HGetAll(ctx, p+"h").Result()
		results["hash"] = e == nil && hm["f1"] == "v1" && hm["f2"] == "v2"
	}

	rdb.RPush(ctx, p+"l", "a", "b", "c")
	lr, e := rdb.LRange(ctx, p+"l", 0, -1).Result()
	results["list"] = e == nil && strings.Join(lr, ",") == "a,b,c"

	rdb.SAdd(ctx, p+"s", "x", "y", "x")
	sc, e := rdb.SCard(ctx, p+"s").Result()
	results["set"] = e == nil && sc == 2

	rdb.ZAdd(ctx, p+"z", redis.Z{Score: 2, Member: "b"}, redis.Z{Score: 1, Member: "a"})
	zr, e := rdb.ZRange(ctx, p+"z", 0, -1).Result()
	results["zset"] = e == nil && strings.Join(zr, ",") == "a,b"

	id, e := rdb.XAdd(ctx, &redis.XAddArgs{Stream: p + "st", Values: map[string]any{"f": "v"}}).Result()
	xl, _ := rdb.XLen(ctx, p+"st").Result()
	results["stream"] = e == nil && id != "" && xl == 1

	// MULTI/EXEC: SET then INCR commit atomically; INCR returns 2.
	pipe := rdb.TxPipeline()
	pipe.Set(ctx, p+"tx", "1", 0)
	incr := pipe.Incr(ctx, p+"tx")
	_, e = pipe.Exec(ctx)
	results["transaction"] = e == nil && incr.Val() == 2

	// SCAN finds the keys created above (6 data keys under the prefix).
	found := 0
	iter := rdb.Scan(ctx, 0, p+"*", 10).Iterator()
	for iter.Next(ctx) {
		found++
	}
	results["scan"] = iter.Err() == nil && found >= 6

	results["pubsub"] = testPubSub(ctx, rdb, p+"chan")

	ok := true
	for _, v := range results {
		if b, _ := v.(bool); !b {
			ok = false
		}
	}
	results["ok"] = ok
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(results)
}

// testPubSub subscribes, publishes, and confirms delivery on one channel.
func testPubSub(ctx context.Context, rdb *redis.Client, channel string) bool {
	sub := rdb.Subscribe(ctx, channel)
	defer sub.Close()
	if _, err := sub.Receive(ctx); err != nil { // subscribe confirmation
		return false
	}
	if err := rdb.Publish(ctx, channel, "hello").Err(); err != nil {
		return false
	}
	mctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	msg, err := sub.ReceiveMessage(mctx)
	return err == nil && msg.Payload == "hello"
}

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

	// Verify PCR30 (persistent identity key) == SHA384(0⁴⁸ ‖ sha256(identity pubkey)).
	// The identity pubkey is the same key that signs responses (X-Attestation-Pubkey).
	if infoResp, err := http.Get(supervisorURL + "/v1/enclave-info"); err == nil {
		identityPubkey := infoResp.Header.Get("X-Attestation-Pubkey")
		infoResp.Body.Close()
		results["identity_pubkey"] = identityPubkey
		if pubkeyBytes, err := hex.DecodeString(identityPubkey); err == nil && len(pubkeyBytes) > 0 {
			h := sha256.Sum256(pubkeyBytes)
			var zeros48 [48]byte
			expectedPCR30 := sha512.Sum384(append(zeros48[:], h[:]...))
			if pcr30, ok := doc.PCRs[30]; ok {
				results["pcr30"] = hex.EncodeToString(pcr30)
				results["pcr30_verified"] = hex.EncodeToString(pcr30) == hex.EncodeToString(expectedPCR30[:])
			} else {
				results["pcr30_verified"] = false
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

const attestPersistStorageKey = "test/attestation-persistence"

// deriveAttestationValues computes the current pubkey and PCR16 from SIGNING_KEY.
func deriveAttestationValues() (pubkey, pcr16 string, err error) {
	signingKeyHex := os.Getenv("SIGNING_KEY")
	if signingKeyHex == "" {
		return "", "", fmt.Errorf("SIGNING_KEY not set")
	}
	secretBytes, decErr := hex.DecodeString(signingKeyHex)
	if decErr != nil || len(secretBytes) != 32 {
		return "", "", fmt.Errorf("SIGNING_KEY invalid: %v", decErr)
	}
	privKey, _ := btcec.PrivKeyFromBytes(secretBytes)
	compressedPubkey := privKey.PubKey().SerializeCompressed()
	extensionData := sha256.Sum256(compressedPubkey)
	var zeros48 [48]byte
	extendInput := append(zeros48[:], extensionData[:]...)
	actualPCR16 := sha512.Sum384(extendInput)
	return hex.EncodeToString(compressedPubkey), hex.EncodeToString(actualPCR16[:]), nil
}

// handleTestAttestationPersistenceWrite (POST) derives pubkey + PCR16 from the
// current SIGNING_KEY, fetches attestation_pubkey from the supervisor, and stores
// all three to encrypted storage. Deletes any stale value first.
func handleTestAttestationPersistenceWrite(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	pubkey, pcr16, err := deriveAttestationValues()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	infoResp, err := http.Get(supervisorURL + "/v1/enclave-info")
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"fetch enclave-info: %v"}`, err), http.StatusInternalServerError)
		return
	}
	infoBody, _ := io.ReadAll(infoResp.Body)
	infoResp.Body.Close()
	var info struct {
		AttestationPubkey string `json:"attestation_pubkey"`
	}
	json.Unmarshal(infoBody, &info)

	rdb, err := redisClient()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	defer rdb.Close()

	storeData, _ := json.Marshal(map[string]string{
		"pubkey":        pubkey,
		"pcr16":         pcr16,
		"attest_pubkey": info.AttestationPubkey,
	})
	if err := rdb.Set(r.Context(), attestPersistStorageKey, storeData, 0).Err(); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"SET failed: %v"}`, err), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "pubkey": pubkey, "pcr16": pcr16})
}

// handleTestAttestationPersistenceVerify (GET) reads the pre-migration values from
// storage and compares them to the current derived values. Returns 404 if the stored
// data is missing, 500 if pubkey or PCR16 changed, 200 if both match.
func handleTestAttestationPersistenceVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	currentPubkey, currentPCR16, err := deriveAttestationValues()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	rdb, err := redisClient()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	defer rdb.Close()

	storedBody, err := rdb.Get(r.Context(), attestPersistStorageKey).Bytes()
	if errors.Is(err, redis.Nil) {
		http.Error(w, `{"error":"attestation data not found — storage lost during migration"}`, http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"GET failed: %v"}`, err), http.StatusInternalServerError)
		return
	}
	var stored struct {
		Pubkey       string `json:"pubkey"`
		PCR16        string `json:"pcr16"`
		AttestPubkey string `json:"attest_pubkey"`
	}
	json.Unmarshal(storedBody, &stored)

	results := map[string]any{
		"pre_migration_pubkey":  stored.Pubkey,
		"post_migration_pubkey": currentPubkey,
		"pubkey_match":          stored.Pubkey == currentPubkey,
		"pre_migration_pcr16":   stored.PCR16,
		"post_migration_pcr16":  currentPCR16,
		"pcr16_match":           stored.PCR16 == currentPCR16,
	}

	// The framework identity key rotates per generation, so after a migration the
	// current attestation_pubkey must DIFFER from the stored (pre-migration) one.
	if infoResp, err := http.Get(supervisorURL + "/v1/enclave-info"); err == nil {
		var info struct {
			AttestationPubkey string `json:"attestation_pubkey"`
		}
		infoBody, _ := io.ReadAll(infoResp.Body)
		infoResp.Body.Close()
		json.Unmarshal(infoBody, &info)
		results["pre_migration_identity_pubkey"] = stored.AttestPubkey
		results["post_migration_identity_pubkey"] = info.AttestationPubkey
		results["identity_rotated"] = stored.AttestPubkey != "" && info.AttestationPubkey != "" && stored.AttestPubkey != info.AttestationPubkey
	}

	if stored.Pubkey != currentPubkey || stored.PCR16 != currentPCR16 {
		results["error"] = "attestation values changed after migration"
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}
	results["ok"] = true
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

// handleTestCrash simulates an upstream-app crash by exiting the process
// shortly after responding.
func handleTestCrash(w http.ResponseWriter, r *http.Request) {
	log.Println("[test] /test/crash invoked — exiting in 100ms")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"crashing"}` + "\n"))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		os.Exit(1)
	}()
}
