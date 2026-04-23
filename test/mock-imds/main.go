package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

type imdsCredentials struct {
	Code            string `json:"Code"`
	LastUpdated     string `json:"LastUpdated"`
	Type            string `json:"Type"`
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
}

func main() {
	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":1338"
	}

	roleName := "test-enclave-role"

	mux := http.NewServeMux()

	// IMDSv2 token endpoint.
	mux.HandleFunc("PUT /latest/api/token", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("mock-imds-token"))
	})

	// Role name discovery.
	mux.HandleFunc("GET /latest/meta-data/iam/security-credentials/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(roleName))
	})

	// Credentials for the role.
	mux.HandleFunc("GET /latest/meta-data/iam/security-credentials/{role}", func(w http.ResponseWriter, r *http.Request) {
		creds := imdsCredentials{
			Code:            "Success",
			LastUpdated:     "2026-01-01T00:00:00Z",
			Type:            "AWS-HMAC",
			AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			Token:           "mock-session-token",
			Expiration:      "2099-12-31T23:59:59Z",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(creds)
	})

	log.Printf("Mock IMDS listening on %s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}
