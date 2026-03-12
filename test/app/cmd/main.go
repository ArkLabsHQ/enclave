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
	mux.HandleFunc("GET /test/attestation", handleTestAttestation)

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
