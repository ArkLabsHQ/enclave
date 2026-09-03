package runtime

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/require"
)

// Genesis is deployment-wide and separate from the per-enclave intent chain: it
// leaves that chain empty, and the creator's own migration sequence starts at 1.
func TestDeploymentGenesisIsNotAMigrationIntent(t *testing.T) {
	ctx := context.Background()
	fx := newMigrationIntentFixture(t)

	genesis, err := fx.genesis.CommitGenesis(ctx, fx.source)
	require.NoError(t, err)
	require.Equal(t, fx.source, genesis.PCR0)
	require.False(t, genesis.PublishedAt.IsZero())

	committed, err := fx.genesis.Genesis(ctx)
	require.NoError(t, err)
	require.Equal(t, genesis.PCR0, committed.PCR0)
	require.Equal(t, genesis.VersionID, committed.VersionID)

	head, err := fx.log.Head(ctx, fx.source)
	require.NoError(t, err)
	require.Nil(t, head, "genesis must not appear in the creator's intent chain")

	_, err = fx.log.Abort(ctx, fx.source)
	require.ErrorIs(t, err, errMigrationIntentAbsent)
	target := strings.Repeat("cd", 48)
	requested, err := fx.log.Request(ctx, fx.source, target)
	require.NoError(t, err)
	require.Equal(t, uint64(1), requested.Sequence)
}

// The create-only write makes genesis a fact, not a revisable record.
func TestDeploymentGenesisCommitsOnlyOnce(t *testing.T) {
	ctx := context.Background()
	fx := newMigrationIntentFixture(t)

	_, err := fx.genesis.CommitGenesis(ctx, fx.source)
	require.NoError(t, err)

	_, err = fx.genesis.CommitGenesis(ctx, strings.Repeat("cd", 48))
	require.ErrorIs(t, err, errGenesisAlreadyCommitted)

	committed, err := fx.genesis.Genesis(ctx)
	require.NoError(t, err)
	require.Equal(t, fx.source, committed.PCR0)
}

// The retention is resolved from the envelope, so what matters is that it
// reaches the Object Lock rather than being computed and dropped.
func TestGenesisRetentionComesFromTheEnvelope(t *testing.T) {
	for _, tc := range []struct {
		name  string
		isDev bool
	}{
		{name: "production", isDev: false},
		{name: "dev", isDev: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ENCLAVE_DEV", strconv.FormatBool(tc.isDev))
			fx := newMigrationIntentFixture(t)

			_, err := fx.genesis.CommitGenesis(context.Background(), fx.source)
			require.NoError(t, err)

			fx.s3.mu.Lock()
			stored := fx.s3.objects[deploymentGenesisKey][0]
			fx.s3.mu.Unlock()
			require.Equal(t, s3types.ObjectLockModeCompliance, stored.lockMode)
			require.WithinDuration(
				t,
				time.Now().Add(testCfg.GenesisRetention),
				stored.retainUntil,
				10*time.Second,
			)
		})
	}
}
