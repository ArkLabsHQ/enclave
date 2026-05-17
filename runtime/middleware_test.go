package runtime

import (
	"net/http"
	"testing"
)

func TestIsGRPCRequest(t *testing.T) {
	tests := []struct {
		name        string
		protoMajor  int
		contentType string
		want        bool
	}{
		{"native grpc over h2", 2, "application/grpc", true},
		{"grpc with proto subtype", 2, "application/grpc+proto", true},
		{"grpc with charset", 2, "application/grpc; charset=utf-8", true},
		{"grpc-web over h2", 2, "application/grpc-web+proto", true},
		{"grpc-web over h1", 1, "application/grpc-web", true},
		{"grpc-web-text over h1", 1, "application/grpc-web-text", true},
		{"grpc-web binary over h1", 1, "application/grpc-web+proto", true},
		{"json over h2", 2, "application/json", false},
		{"grpc-shaped CT over h1", 1, "application/grpc", false},
		{"empty CT over h2", 2, "", false},
		{"text plain over h2", 2, "text/plain", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{
				ProtoMajor: tc.protoMajor,
				Header:     http.Header{},
			}
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}
			if got := isGRPCRequest(r); got != tc.want {
				t.Fatalf("isGRPCRequest(proto=%d, ct=%q): got %v, want %v",
					tc.protoMajor, tc.contentType, got, tc.want)
			}
		})
	}
}
