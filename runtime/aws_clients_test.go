package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/stretchr/testify/require"
)

// newTestIMDS serves the IMDSv2 token handshake and hands instance-id requests
// to the given handler.
func newTestIMDS(t *testing.T, instanceID http.HandlerFunc) *imds.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /latest/api/token", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("token"))
	})
	mux.HandleFunc("GET /latest/meta-data/instance-id", instanceID)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return imds.New(imds.Options{Endpoint: srv.URL, Retryer: aws.NopRetryer{}})
}

func TestResolveInstanceIDTrimsTheResponse(t *testing.T) {
	client := newTestIMDS(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("  i-0e2ce2ce2ce2ce2ce\n"))
	})

	id, err := resolveInstanceID(context.Background(), client)

	require.NoError(t, err)
	require.Equal(t, "i-0e2ce2ce2ce2ce2ce", id)
}

func TestResolveInstanceIDRejectsAnEmptyBody(t *testing.T) {
	client := newTestIMDS(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("  \n"))
	})

	_, err := resolveInstanceID(context.Background(), client)

	require.ErrorContains(t, err, "empty instance-id")
}

func TestResolveInstanceIDReportsTheIMDSFailure(t *testing.T) {
	client := newTestIMDS(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "metadata unavailable", http.StatusServiceUnavailable)
	})

	_, err := resolveInstanceID(context.Background(), client)

	require.Error(t, err)
	require.ErrorContains(t, err, "IMDS instance-id lookup")
	require.ErrorContains(t, err, "503")
}

// bodyIMDS answers every metadata request with the given body.
type bodyIMDS struct{ body io.Reader }

func (b bodyIMDS) GetMetadata(
	context.Context, *imds.GetMetadataInput, ...func(*imds.Options),
) (*imds.GetMetadataOutput, error) {
	return &imds.GetMetadataOutput{Content: io.NopCloser(b.body)}, nil
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestResolveInstanceIDReportsAReadFailure(t *testing.T) {
	cause := errors.New("connection reset")

	_, err := resolveInstanceID(context.Background(), bodyIMDS{body: failingReader{cause}})

	require.ErrorIs(t, err, cause)
	require.True(t, strings.HasPrefix(err.Error(), "read IMDS instance-id response"))
}

var testCredentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
	return aws.Credentials{
		AccessKeyID: "AKID", SecretAccessKey: "SECRET", SessionToken: "TOKEN",
	}, nil
})

func TestSigV4TransportSignsEveryAttempt(t *testing.T) {
	type captured struct {
		header http.Header
		body   []byte
	}
	var mu sync.Mutex
	var seen []captured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, captured{header: r.Header.Clone(), body: body})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{Transport: &sigv4Transport{
		creds: testCredentials, region: "eu-west-1", service: "logs",
		signer: v4.NewSigner(), next: http.DefaultTransport,
	}}
	payload := []byte("not really gzip, but signed as sent")
	for i := 0; i < 2; i++ {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/logs", bytes.NewReader(payload))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-protobuf")
		req.Header.Set("Content-Encoding", "gzip")
		req.Header.Set("x-aws-log-group", "/prod/enclave/logs/app")
		req.Header.Set("x-aws-log-stream", "i-0e2ce2ce2ce2ce2ce")

		resp, err := client.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Empty(t, req.Header.Get("Authorization"),
			"the caller's request must be left unsigned: a retry re-signs a clone")
	}

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, seen, 2)
	authorization := regexp.MustCompile(
		`^AWS4-HMAC-SHA256 Credential=AKID/\d{8}/eu-west-1/logs/aws4_request, ` +
			`SignedHeaders=([a-z0-9-]+;)*x-aws-log-group;x-aws-log-stream, Signature=[0-9a-f]{64}$`)
	for _, got := range seen {
		require.Regexp(t, authorization, got.header.Get("Authorization"))
		require.NotEmpty(t, got.header.Get("X-Amz-Date"))
		require.Equal(t, "TOKEN", got.header.Get("X-Amz-Security-Token"))
		require.Equal(t, "gzip", got.header.Get("Content-Encoding"))
		require.Equal(t, payload, got.body, "the body must arrive byte for byte")

		signedAt, err := time.Parse("20060102T150405Z", got.header.Get("X-Amz-Date"))
		require.NoError(t, err)
		again, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/logs", nil)
		require.NoError(t, err)
		again.ContentLength = int64(len(got.body)) // signed as a header when known
		for name, values := range got.header {
			switch strings.ToLower(name) {
			case "authorization", "x-amz-date", "x-amz-security-token",
				"accept-encoding", "content-length", "user-agent":
				continue
			}
			again.Header[name] = values
		}
		creds, err := testCredentials.Retrieve(context.Background())
		require.NoError(t, err)
		sum := sha256.Sum256(got.body)
		require.NoError(t, v4.NewSigner().SignHTTP(context.Background(), creds, again,
			hex.EncodeToString(sum[:]), "logs", "eu-west-1", signedAt))
		require.Equal(t, again.Header.Get("Authorization"), got.header.Get("Authorization"))
	}
}

func TestOTLPBaseURLUsesRegionAndOverrides(t *testing.T) {
	t.Setenv("AWS_ENDPOINT_URL_LOGS", "http://aws:4318/")
	t.Setenv("AWS_ENDPOINT_URL_XRAY", "http://aws:4319")
	t.Setenv("AWS_ENDPOINT_URL_MONITORING", "")
	up := newOTLPEndpoints(aws.Config{Region: "eu-central-1", Credentials: testCredentials})

	require.Equal(t, "http://aws:4318", up.Logs.base)
	require.Equal(t, "http://aws:4319", up.Traces.base)
	require.Equal(t, "https://monitoring.eu-central-1.amazonaws.com", up.Metrics.base)
	for service, u := range map[string]otlpClient{
		"logs": up.Logs, "xray": up.Traces, "monitoring": up.Metrics,
	} {
		transport, ok := u.client.Transport.(*sigv4Transport)
		require.True(t, ok, service)
		require.Equal(t, service, transport.service, "each client signs for its own service")
		require.Equal(t, "eu-central-1", transport.region)
	}
}
