package runtime

import (
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNetworkingCID(t *testing.T) {
	for _, cid := range []uint32{4, 1024, 1025, 65536, math.MaxUint32 - 1} {
		t.Run(fmt.Sprint(cid), func(t *testing.T) {
			got, err := networkingCID(func() (uint32, error) { return cid, nil })
			require.NoError(t, err)
			require.Equal(t, cid, got)
		})
	}
	for _, cid := range []uint32{0, 1, 2, 3, 8002, 9000, math.MaxUint32} {
		t.Run(fmt.Sprintf("reject %d", cid), func(t *testing.T) {
			got, err := networkingCID(func() (uint32, error) { return cid, nil })
			require.ErrorContains(t, err, fmt.Sprintf("enclave CID %d", cid))
			require.Zero(t, got)
		})
	}
}

func TestNetworkingCIDDiscoveryFailure(t *testing.T) {
	want := errors.New("device unavailable")
	cid, err := networkingCID(func() (uint32, error) { return 1024, want })
	require.ErrorIs(t, err, want)
	require.ErrorContains(t, err, "/dev/vsock")
	require.Zero(t, cid, "discovery failure must not fall back to port 1024")
}
