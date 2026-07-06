package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/hf/nsm/response"
	"github.com/stretchr/testify/require"
)

func TestVerifyPredecessorCommitment_Genesis(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")
	t.Setenv("ENCLAVE_PREVIOUS_PCR0", "genesis")

	ctx := context.Background()

	t.Run("no predecessor", func(t *testing.T) {
		err := VerifyPredecessorCommitment(ctx, nil, NewSSM(&fakeSSM{}))
		require.NoError(t, err)
	})

	t.Run("rejects SSM predecessor", func(t *testing.T) {
		errs := VerifyPredecessorCommitment(ctx, nil, NewSSM(&fakeSSM{params: map[string]string{
			migrationPreviousPCR0Param(): "abc123",
		}}))
		require.Error(t, errs)
	})
}

func TestVerifyPredecessorCommitment_Predecessor(t *testing.T) {
	prevPCR0Bytes := bytes.Repeat([]byte{0xab}, 48)
	currentPCR0Bytes := bytes.Repeat([]byte{0xcd}, 48)
	prevPCR0 := hex.EncodeToString(prevPCR0Bytes)
	attestation := base64.StdEncoding.EncodeToString([]byte("predecessor attestation"))

	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")
	t.Setenv("ENCLAVE_PREVIOUS_PCR0", prevPCR0)

	ctx := context.Background()
	previousParam := migrationPreviousPCR0Param()
	attestationParam := migrationPreviousPCR0AttestationParam()

	t.Run("missing previous PCR0", func(t *testing.T) {
		err := VerifyPredecessorCommitment(ctx, nil, NewSSM(&fakeSSM{}))
		require.Error(t, err)
	})

	t.Run("mismatched previous PCR0", func(t *testing.T) {
		err := VerifyPredecessorCommitment(ctx, nil, NewSSM(&fakeSSM{params: map[string]string{
			previousParam: strings.Repeat("0", 96),
		}}))
		require.Error(t, err)
	})

	t.Run("requires attestation", func(t *testing.T) {
		cases := []struct {
			name   string
			params map[string]string
		}{
			{"missing", map[string]string{previousParam: prevPCR0}},
			{"unset", map[string]string{previousParam: prevPCR0, attestationParam: "UNSET"}},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				err := VerifyPredecessorCommitment(ctx, nil, NewSSM(&fakeSSM{params: tc.params}))
				require.Error(t, err)
			})
		}
	})

	t.Run("wrong PCR31", func(t *testing.T) {
		nsm := predecessorNSM(t, currentPCR0Bytes, map[uint][]byte{
			0:                 prevPCR0Bytes,
			migrationPCRIndex: bytes.Repeat([]byte{0xef}, 48),
		})

		err := VerifyPredecessorCommitment(ctx, nsm, NewSSM(&fakeSSM{params: map[string]string{
			previousParam:    prevPCR0,
			attestationParam: attestation,
		}}))

		require.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		nsm := predecessorNSM(t, currentPCR0Bytes, map[uint][]byte{
			0:                 prevPCR0Bytes,
			migrationPCRIndex: currentPCR0Bytes,
		})

		err := VerifyPredecessorCommitment(ctx, nsm, NewSSM(&fakeSSM{params: map[string]string{
			previousParam:    strings.ToUpper(prevPCR0),
			attestationParam: attestation,
		}}))

		require.NoError(t, err)
	})
}

func TestMigratorPreviousPCR0Info(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")

	ctx := context.Background()

	t.Run("genesis", func(t *testing.T) {
		info, err := NewMigrator(nil, nil, NewSSM(&fakeSSM{}), nil, nil, nil).PreviousPCR0Info(ctx)

		require.NoError(t, err)
		require.Equal(t, &PreviousPCR0Info{PCR0: "genesis"}, info)
	})

	t.Run("recorded predecessor", func(t *testing.T) {
		info, err := NewMigrator(nil, nil, NewSSM(&fakeSSM{params: map[string]string{
			migrationPreviousPCR0Param():            "abc123",
			migrationPreviousPCR0AttestationParam(): "attestation",
		}}), nil, nil, nil).PreviousPCR0Info(ctx)

		require.NoError(t, err)
		require.Equal(t, &PreviousPCR0Info{PCR0: "abc123", Attestation: "attestation"}, info)
	})
}

func TestMigratorCooldownStatus(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")
	t.Setenv("ENCLAVE_MIGRATION_COOLDOWN", "2m")

	ctx := context.Background()

	t.Run("none", func(t *testing.T) {
		status, err := NewMigrator(nil, nil, NewSSM(&fakeSSM{}), nil, nil, nil).CooldownStatus(ctx)

		require.NoError(t, err)
		require.Equal(t, &CooldownStatus{ConfiguredSeconds: 120}, status)
	})

	t.Run("pending", func(t *testing.T) {
		status, err := NewMigrator(nil, nil, NewSSM(&fakeSSM{params: map[string]string{
			migrationRequestedAtParam(): time.Now().UTC().Format(time.RFC3339),
		}}), nil, nil, nil).CooldownStatus(ctx)

		require.NoError(t, err)
		require.True(t, status.Pending)
		require.Equal(t, 120, status.ConfiguredSeconds)
		require.Greater(t, status.RemainingSeconds, 0)
		require.LessOrEqual(t, status.RemainingSeconds, 120)
	})

	t.Run("bad timestamp", func(t *testing.T) {
		_, err := NewMigrator(nil, nil, NewSSM(&fakeSSM{params: map[string]string{
			migrationRequestedAtParam(): "not-time",
		}}), nil, nil, nil).CooldownStatus(ctx)

		require.Error(t, err)
	})
}

func TestStartMigrationRequestValidate(t *testing.T) {
	validPCR0 := strings.Repeat("a", 96)

	for _, tc := range []struct {
		name    string
		request StartMigrationRequest
		wantErr bool
	}{
		{name: "missing", request: StartMigrationRequest{}, wantErr: true},
		{name: "short", request: StartMigrationRequest{NewPCR0: "abc"}, wantErr: true},
		{name: "bad hex", request: StartMigrationRequest{NewPCR0: strings.Repeat("z", 96)}, wantErr: true},
		{name: "valid", request: StartMigrationRequest{NewPCR0: validPCR0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.request.Validate()
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func predecessorNSM(t *testing.T, currentPCR0 []byte, predecessorPCRs map[uint][]byte) NSM {
	t.Helper()
	session := &fakeNSMSession{responses: []response.Response{
		attestationDocumentResponse(buildForgedAttestation(t, map[uint][]byte{0: currentPCR0})),
	}}
	return &nsmW{nsm: &fakeNSM{
		session:      session,
		verifyResult: attestationResult(predecessorPCRs, nil),
	}}
}
