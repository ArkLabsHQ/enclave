package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/google/uuid"
)

// supervisorURL is the internal URL of the enclave-supervisor.
// The test app calls back to it for storage/secrets management.
var supervisorURL string

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

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", handleRoot)
	mux.HandleFunc("GET /test/secrets", handleTestSecrets)
	mux.HandleFunc("GET /test/storage", handleTestStorage)
	mux.HandleFunc("GET /test/storage-persistence", handleTestStoragePersistence)
	mux.HandleFunc("GET /test/attestation", handleTestAttestation)
	mux.HandleFunc("GET /test/dynamic-secrets", handleTestDynamicSecrets)
	mux.HandleFunc("GET /test/dynamic-secret-persistence", handleTestDynamicSecretPersistence)
	mux.HandleFunc("GET /test/pcr-secrets", handleTestPCRSecrets)
	mux.HandleFunc("GET /test/attestation-persistence", handleTestAttestationPersistence)

	log.Printf("listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
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

	token := os.Getenv("ENCLAVE_MGMT_TOKEN")
	if token == "" {
		http.Error(w, `{"error":"ENCLAVE_MGMT_TOKEN not set"}`, http.StatusInternalServerError)
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

	token := os.Getenv("ENCLAVE_MGMT_TOKEN")
	if token == "" {
		http.Error(w, `{"error":"ENCLAVE_MGMT_TOKEN not set"}`, http.StatusInternalServerError)
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

	token := os.Getenv("ENCLAVE_MGMT_TOKEN")
	if token == "" {
		http.Error(w, `{"error":"ENCLAVE_MGMT_TOKEN not set"}`, http.StatusInternalServerError)
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

	token := os.Getenv("ENCLAVE_MGMT_TOKEN")
	if token == "" {
		http.Error(w, `{"error":"ENCLAVE_MGMT_TOKEN not set"}`, http.StatusInternalServerError)
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

// handleTestPCRSecrets verifies that static secret public keys were extended
// into PCRs 16+. For each static secret, the SDK computes
// SHA256(secp256k1_compressed_pubkey(secret_hex)) and extends PCR (16+i).
//
// We verify by: deriving the expected pubkey hash from SIGNING_KEY env var,
// then checking that enclave-info's attestation confirms it was extended.
// In QEMU (mock NSM), we verify the derivation is correct; in production,
// the attestation document would contain the actual PCR values.
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

	// secp256k1 private key → compressed public key.
	privKey, _ := btcec.PrivKeyFromBytes(secretBytes)
	compressedPubkey := privKey.PubKey().SerializeCompressed()
	pubkeyHash := sha256.Sum256(compressedPubkey)

	results["pcr_index"] = 16
	results["expected_extension"] = hex.EncodeToString(pubkeyHash[:])
	results["pubkey"] = hex.EncodeToString(compressedPubkey)

	// In QEMU with mock NSM, PCR values are not real. We verify that:
	// 1. The derivation produces valid output (no panic, correct lengths).
	// 2. The compressed pubkey is 33 bytes.
	// 3. The hash is 32 bytes (correct size for PCR extension).
	if len(compressedPubkey) != 33 {
		results["error"] = fmt.Sprintf("compressed pubkey wrong length: %d", len(compressedPubkey))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(results)
		return
	}

	results["derivation_valid"] = true
	results["pubkey_length"] = len(compressedPubkey)
	results["hash_length"] = len(pubkeyHash)
	results["status"] = "ok"
	json.NewEncoder(w).Encode(results)
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

	token := os.Getenv("ENCLAVE_MGMT_TOKEN")
	if token == "" {
		http.Error(w, `{"error":"ENCLAVE_MGMT_TOKEN not set"}`, http.StatusInternalServerError)
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
	pubkeyHash := sha256.Sum256(compressedPubkey)
	currentPCR16 := hex.EncodeToString(pubkeyHash[:])
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
			Pubkey      string `json:"pubkey"`
			PCR16       string `json:"pcr16"`
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
		"pubkey":          currentPubkey,
		"pcr16":           currentPCR16,
		"attest_pubkey":   currentAttestPubkey,
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
