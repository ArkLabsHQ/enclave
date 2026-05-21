package runtime

import (
	"crypto/tls"
	"testing"
)

// A nameless ClientHello (the supervisor reaches the enclave by loopback IP,
// which sends no SNI) must resolve to the enclave's FQDN — autocert rejects a
// handshake with no server name. A handshake that does carry a server name is
// passed through untouched.
func TestCertForHello(t *testing.T) {
	want := &tls.Certificate{}
	for _, tc := range []struct {
		name, sni, wantSNI string
	}{
		{"nameless handshake resolves to FQDN", "", "enclave.test"},
		{"FQDN handshake passes through", "enclave.test", "enclave.test"},
		{"other server name is left untouched", "other.example", "other.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var delegated string
			e := &Runtime{
				cfg: &Config{FQDN: "enclave.test"},
				tlsGetCert: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
					delegated = h.ServerName
					return want, nil
				},
			}
			cert, err := e.certForHello(&tls.ClientHelloInfo{ServerName: tc.sni})
			if err != nil {
				t.Fatalf("certForHello: %v", err)
			}
			if cert != want {
				t.Errorf("cert = %v, want the delegated cert", cert)
			}
			if delegated != tc.wantSNI {
				t.Errorf("delegated ServerName = %q, want %q", delegated, tc.wantSNI)
			}
		})
	}
}
