package runtime

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
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
