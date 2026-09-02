package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/require"
)

func accessDenied() error {
	return &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied"}
}

func TestKeyStatusFromDescribeKey(t *testing.T) {
	deletionDate := time.Now().Add(30 * 24 * time.Hour).UTC()

	tests := []struct {
		name         string
		state        kmstypes.KeyState
		wantState    string
		wantDeletion bool
	}{
		{"enabled", kmstypes.KeyStateEnabled, keyStateExists, false},
		{"disabled", kmstypes.KeyStateDisabled, keyStateExists, false},
		{"creating", kmstypes.KeyStateCreating, keyStateExists, false},
		{"updating", kmstypes.KeyStateUpdating, keyStateExists, false},
		{"unavailable", kmstypes.KeyStateUnavailable, keyStateExists, false},
		{"pending import", kmstypes.KeyStatePendingImport, keyStateExists, false},
		{"pending deletion", kmstypes.KeyStatePendingDeletion, keyStatePendingDeletion, true},
		{
			"pending replica deletion",
			kmstypes.KeyStatePendingReplicaDeletion,
			keyStatePendingDeletion,
			true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeKMS()
			f.keyStates = map[string]*kmstypes.KeyMetadata{
				"key-1": {
					KeyId:        aws.String("key-1"),
					KeyState:     tc.state,
					DeletionDate: aws.Time(deletionDate),
				},
			}

			got := NewKeyAuditor(f).KeyStatus(context.Background(), "key-1")

			require.Equal(t, tc.wantState, got.State)
			require.Equal(t, checkedViaDescribeKey, got.CheckedVia)
			require.Zero(t, f.policyCalls, "a conclusive describe must not fall back")
			if tc.wantDeletion {
				require.NotNil(t, got.DeletionDate)
				require.Equal(t, deletionDate, got.DeletionDate.UTC())
			} else {
				require.Nil(t, got.DeletionDate)
			}
		})
	}
}

// deleted is the one state that proves a generation can no longer decrypt, so
// it must come only from a positive absence signal and must end the ladder.
func TestKeyStatusDeletedIsTerminal(t *testing.T) {
	f := newFakeKMS()

	got := NewKeyAuditor(f).KeyStatus(context.Background(), "gone")

	require.Equal(t, keyStateDeleted, got.State)
	require.Equal(t, checkedViaDescribeKey, got.CheckedVia)
	require.Equal(t, 1, f.describeCalls)
	require.Zero(t, f.policyCalls, "NotFound is conclusive; no fallback may run")
}

func TestKeyStatusMissingMetadataIsUnknown(t *testing.T) {
	f := newFakeKMS()
	f.putKey("key-1", "{}")
	f.describeNilMetadata = true

	got := NewKeyAuditor(f).KeyStatus(context.Background(), "key-1")

	require.Equal(t, keyStateUnknown, got.State)
	require.Equal(t, checkedViaDescribeKey, got.CheckedVia)
	require.Contains(t, got.Reason, "no key metadata")
	require.Zero(t, f.policyCalls, "a nil-metadata describe must not fall back")
}

// Locked keys minted before DescribeKey was in the key policy deny it. The
// GetKeyPolicy rung still tells present from gone.
func TestKeyStatusFallsBackWhenDescribeIsDenied(t *testing.T) {
	t.Run("policy readable means the key still exists", func(t *testing.T) {
		f := newFakeKMS()
		f.putKey("legacy", "{}")
		f.describeErr = accessDenied()

		got := NewKeyAuditor(f).KeyStatus(context.Background(), "legacy")

		require.Equal(t, keyStateExists, got.State)
		require.Equal(t, checkedViaGetKeyPolicy, got.CheckedVia)
		require.Equal(t, 1, f.policyCalls)
	})

	t.Run("policy not found proves deletion", func(t *testing.T) {
		f := newFakeKMS()
		f.describeErr = accessDenied()

		got := NewKeyAuditor(f).KeyStatus(context.Background(), "legacy")

		require.Equal(t, keyStateDeleted, got.State)
		require.Equal(t, checkedViaGetKeyPolicy, got.CheckedVia)
	})

	t.Run("both denied is unknown and names both errors", func(t *testing.T) {
		f := newFakeKMS()
		f.describeErr = accessDenied()
		f.putKey("legacy", "{}")
		f.getKeyPolicyErr = accessDenied()

		got := NewKeyAuditor(f).KeyStatus(context.Background(), "legacy")

		require.Equal(t, keyStateUnknown, got.State)
		require.Contains(t, got.Reason, "describe_key:")
		require.Contains(t, got.Reason, "get_key_policy:")
		require.Contains(t, got.Reason, "AccessDeniedException")
	})
}

// KMSInvalidStateException is what cryptographic operations return; if it ever
// reaches an audit read it means something unmodelled, never a deletion.
func TestKeyStatusInvalidStateIsUnknownNotDeleted(t *testing.T) {
	f := newFakeKMS()
	f.putKey("key-1", "{}")
	f.describeErr = &kmstypes.KMSInvalidStateException{Message: aws.String("bad state")}
	f.getKeyPolicyErr = &kmstypes.KMSInvalidStateException{Message: aws.String("bad state")}

	got := NewKeyAuditor(f).KeyStatus(context.Background(), "key-1")

	require.Equal(t, keyStateUnknown, got.State)
	require.NotEqual(t, keyStateDeleted, got.State)
	require.NotEqual(t, keyStatePendingDeletion, got.State)
	require.NotEmpty(t, got.Reason)
}

func TestKeyStatusCancelledContextDoesNotFallBack(t *testing.T) {
	f := newFakeKMS()
	f.putKey("key-1", "{}")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.describeErr = ctx.Err()

	got := NewKeyAuditor(f).KeyStatus(ctx, "key-1")

	require.Equal(t, keyStateUnknown, got.State)
	require.Equal(t, checkedViaDescribeKey, got.CheckedVia)
	require.Zero(t, f.policyCalls, "a dead context makes a second call pointless")
}

func TestKeyStatusEmptyKeyIDIsNotProbed(t *testing.T) {
	f := newFakeKMS()

	got := NewKeyAuditor(f).KeyStatus(context.Background(), "")

	require.Equal(t, keyStateUnknown, got.State)
	require.Equal(t, checkedViaNoProbe, got.CheckedVia)
	require.Zero(t, f.describeCalls)
	require.Zero(t, f.policyCalls)
}
