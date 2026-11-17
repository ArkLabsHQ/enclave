package runtime

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/stretchr/testify/require"
)

func TestAcmeChallengeName(t *testing.T) {
	require.Equal(t, "_acme-challenge.enclave.test.", acmeChallengeName("enclave.test"))
	require.Equal(t, "_acme-challenge.enclave.test.", acmeChallengeName("enclave.test."))
}

func TestACMEIssuerDNS01RequiresZone(t *testing.T) {
	_, err := newACMEIssuer(nil, &fakeRoute53{}, "  ", "")
	require.ErrorContains(t, err, "hosted zone ID is required")
}

func TestACMEIssuerDNS01PublishesQuotedTXT(t *testing.T) {
	f := &fakeRoute53{}
	p, err := newACMEIssuer(nil, f, "Z123", "")
	require.NoError(t, err)

	name := acmeChallengeName("enclave.test")
	require.NoError(t, p.publishChallenge(context.Background(), name, []string{"tokenvalue"}))

	in := f.lastChange()
	require.NotNil(t, in)
	require.Equal(t, "Z123", aws.ToString(in.HostedZoneId))
	require.Len(t, in.ChangeBatch.Changes, 1)

	change := in.ChangeBatch.Changes[0]
	require.Equal(t, r53types.ChangeActionUpsert, change.Action)
	require.Equal(t, r53types.RRTypeTxt, change.ResourceRecordSet.Type)
	require.Equal(t, name, aws.ToString(change.ResourceRecordSet.Name))
	// Route53 requires TXT values wrapped in double quotes.
	require.Equal(t, `"tokenvalue"`,
		aws.ToString(change.ResourceRecordSet.ResourceRecords[0].Value))
	require.Positive(t, f.getCalls, "publish must confirm the change reached INSYNC")
}

func TestACMEIssuerDNS01WaitsForInSync(t *testing.T) {
	// The CA queries authoritative servers, so publishing must not return while
	// the change is still PENDING.
	f := &fakeRoute53{pendingCalls: 1}
	p, err := newACMEIssuer(nil, f, "Z123", "")
	require.NoError(t, err)

	require.NoError(t, p.publishChallenge(
		context.Background(), acmeChallengeName("enclave.test"), []string{"v"},
	))
	require.GreaterOrEqual(t, f.getCalls, 2, "must poll until INSYNC")
}

func TestACMEIssuerDNS01RemoveUsesDelete(t *testing.T) {
	f := &fakeRoute53{}
	p, err := newACMEIssuer(nil, f, "Z123", "")
	require.NoError(t, err)

	name := acmeChallengeName("enclave.test")
	require.NoError(t, p.removeChallenge(context.Background(), name, []string{"v"}))

	change := f.lastChange().ChangeBatch.Changes[0]
	require.Equal(t, r53types.ChangeActionDelete, change.Action)
	// DELETE names the exact record set, so it cannot remove a peer's differing
	// challenge value.
	require.Equal(t, `"v"`, aws.ToString(change.ResourceRecordSet.ResourceRecords[0].Value))
}

func TestACMEIssuerDNS01PublishError(t *testing.T) {
	f := &fakeRoute53{changeErr: errors.New("access denied")}
	p, err := newACMEIssuer(nil, f, "Z123", "")
	require.NoError(t, err)

	err = p.publishChallenge(context.Background(), "_acme-challenge.enclave.test.", []string{"v"})
	require.ErrorContains(t, err, "access denied")
}

// A malformed GetChange response is not a propagation delay, so it must fail
// immediately rather than be read as PENDING and burn the full sync timeout.
func TestACMEIssuerDNS01FailsFastOnMissingChangeInfo(t *testing.T) {
	f := &fakeRoute53{nilChangeInfo: true}
	p, err := newACMEIssuer(nil, f, "Z123", "")
	require.NoError(t, err)

	start := time.Now()
	err = p.publishChallenge(
		context.Background(), acmeChallengeName("enclave.test"), []string{"v"},
	)

	require.ErrorContains(t, err, "no change info")
	require.Equal(t, 1, f.getCalls, "must not keep polling a malformed response")
	require.Less(t, time.Since(start), route53SyncPoll, "must not wait out the poll interval")
}

func TestACMEIssuerDNS01RejectsEmptyValues(t *testing.T) {
	f := &fakeRoute53{}
	p, err := newACMEIssuer(nil, f, "Z123", "")
	require.NoError(t, err)

	require.Error(t, p.publishChallenge(context.Background(), "_acme-challenge.x.", nil))
}
