package signing

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// This literal pins the wire contract the README documents.
func TestSignedRequestWireFormat(t *testing.T) {
	nonce, err := hex.DecodeString("00112233445566778899aabbccddeeff00112233")
	require.NoError(t, err)
	response := []byte{0x0a, 0x02, 'p', 'k'}
	respHash := sha256.Sum256(response)
	msg := ResponseMessage(
		http.MethodPost, "/signer.v1.SignerService/GetPubkey", nonce, nil, 0, response,
	)
	require.Equal(t,
		"enclave-signed-response\nPOST /signer.v1.SignerService/GetPubkey\n"+
			"00112233445566778899aabbccddeeff00112233\n"+
			// SHA-256 of the empty request.
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"+
			"0\n"+hex.EncodeToString(respHash[:]),
		string(msg))
}

func TestSignedRequestTarget(t *testing.T) {
	// Received requests: sign the target as sent, which browsers leave unescaped.
	for target, want := range map[string]string{
		"/items/a|b?q=x^y": "/items/a|b?q=x^y",
		"/a%7Cb":           "/a%7Cb",
		"/a?":              "/a",
		"/a?b?":            "/a?b?",
	} {
		raw := "GET " + target + " HTTP/1.1\r\nHost: api.example\r\n\r\n"
		req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
		require.NoError(t, err)
		require.Equal(t, want, RequestTarget(req), target)
	}

	// Client requests: sign what Go's transport sends, without an empty "?".
	req, err := http.NewRequest(http.MethodGet, "https://[fe80::1%25eth0]:8443/items/a|b?", nil)
	require.NoError(t, err)
	require.Equal(t, "/items/a%7Cb", RequestTarget(req))
}
