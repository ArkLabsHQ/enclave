package runtime

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDescriptorHash_DeterministicAndFieldSensitive(t *testing.T) {
	d := deploymentDescriptorV1{
		Schema: descriptorSchemaV1, Deployment: "prod", App: "my-app", Region: "us-east-1",
		GenesisPCR0: "aabb", AnchorBucket: "anc", LineageBucket: "lin",
	}
	h1, err := descriptorHash(d)
	require.NoError(t, err)
	require.Len(t, h1, 32)

	h2, err := descriptorHash(d)
	require.NoError(t, err)
	require.Equal(t, h1, h2) // deterministic

	d2 := d
	d2.AnchorBucket = "different"
	h3, err := descriptorHash(d2)
	require.NoError(t, err)
	require.NotEqual(t, h1, h3) // any field change moves the hash
}
