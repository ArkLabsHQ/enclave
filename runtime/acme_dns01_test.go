package runtime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/stretchr/testify/require"
)

// fakeRoute53 records change batches and reports PENDING until pendingCalls
// GetChange calls have been made.
type fakeRoute53 struct {
	mu            sync.Mutex
	changes       []*route53.ChangeResourceRecordSetsInput
	getCalls      int
	pendingCalls  int
	changeErr     error
	nilChangeInfo bool
}

func (f *fakeRoute53) ChangeResourceRecordSets(
	_ context.Context,
	in *route53.ChangeResourceRecordSetsInput,
	_ ...func(*route53.Options),
) (*route53.ChangeResourceRecordSetsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.changeErr != nil {
		return nil, f.changeErr
	}
	f.changes = append(f.changes, in)
	return &route53.ChangeResourceRecordSetsOutput{
		ChangeInfo: &r53types.ChangeInfo{Id: aws.String("/change/C1")},
	}, nil
}

func (f *fakeRoute53) GetChange(
	_ context.Context,
	_ *route53.GetChangeInput,
	_ ...func(*route53.Options),
) (*route53.GetChangeOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getCalls++
	if f.nilChangeInfo {
		return &route53.GetChangeOutput{}, nil
	}
	status := r53types.ChangeStatusInsync
	if f.getCalls <= f.pendingCalls {
		status = r53types.ChangeStatusPending
	}
	return &route53.GetChangeOutput{ChangeInfo: &r53types.ChangeInfo{Status: status}}, nil
}

func (f *fakeRoute53) GetHostedZone(
	_ context.Context,
	_ *route53.GetHostedZoneInput,
	_ ...func(*route53.Options),
) (*route53.GetHostedZoneOutput, error) {
	return &route53.GetHostedZoneOutput{}, nil
}

func (f *fakeRoute53) lastChange() *route53.ChangeResourceRecordSetsInput {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.changes) == 0 {
		return nil
	}
	return f.changes[len(f.changes)-1]
}

func TestAcmeChallengeName(t *testing.T) {
	require.Equal(t, "_acme-challenge.enclave.test.", acmeChallengeName("enclave.test"))
	require.Equal(t, "_acme-challenge.enclave.test.", acmeChallengeName("enclave.test."))
}

func TestRoute53ProviderRequiresZone(t *testing.T) {
	_, err := newRoute53Provider(&fakeRoute53{}, "  ")
	require.ErrorContains(t, err, "hosted zone ID is required")
}

func TestRoute53ProviderPublishesQuotedTXT(t *testing.T) {
	f := &fakeRoute53{}
	p, err := newRoute53Provider(f, "Z123")
	require.NoError(t, err)

	name := acmeChallengeName("enclave.test")
	require.NoError(t, p.PublishChallenge(context.Background(), name, []string{"tokenvalue"}))

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

func TestRoute53ProviderWaitsForInSync(t *testing.T) {
	// The CA queries authoritative servers, so publishing must not return while
	// the change is still PENDING.
	f := &fakeRoute53{pendingCalls: 1}
	p, err := newRoute53Provider(f, "Z123")
	require.NoError(t, err)

	require.NoError(t, p.PublishChallenge(
		context.Background(), acmeChallengeName("enclave.test"), []string{"v"},
	))
	require.GreaterOrEqual(t, f.getCalls, 2, "must poll until INSYNC")
}

func TestRoute53ProviderRemoveUsesDelete(t *testing.T) {
	f := &fakeRoute53{}
	p, err := newRoute53Provider(f, "Z123")
	require.NoError(t, err)

	name := acmeChallengeName("enclave.test")
	require.NoError(t, p.RemoveChallenge(context.Background(), name, []string{"v"}))

	change := f.lastChange().ChangeBatch.Changes[0]
	require.Equal(t, r53types.ChangeActionDelete, change.Action)
	// DELETE names the exact record set, so it cannot remove a peer's differing
	// challenge value.
	require.Equal(t, `"v"`, aws.ToString(change.ResourceRecordSet.ResourceRecords[0].Value))
}

func TestRoute53ProviderPublishError(t *testing.T) {
	f := &fakeRoute53{changeErr: errors.New("access denied")}
	p, err := newRoute53Provider(f, "Z123")
	require.NoError(t, err)

	err = p.PublishChallenge(context.Background(), "_acme-challenge.enclave.test.", []string{"v"})
	require.ErrorContains(t, err, "access denied")
}

// A malformed GetChange response is not a propagation delay, so it must fail
// immediately rather than be read as PENDING and burn the full sync timeout.
func TestRoute53ProviderFailsFastOnMissingChangeInfo(t *testing.T) {
	f := &fakeRoute53{nilChangeInfo: true}
	p, err := newRoute53Provider(f, "Z123")
	require.NoError(t, err)

	start := time.Now()
	err = p.PublishChallenge(
		context.Background(), acmeChallengeName("enclave.test"), []string{"v"},
	)

	require.ErrorContains(t, err, "no change info")
	require.Equal(t, 1, f.getCalls, "must not keep polling a malformed response")
	require.Less(t, time.Since(start), route53SyncPoll, "must not wait out the poll interval")
}

func TestRoute53ProviderRejectsEmptyValues(t *testing.T) {
	f := &fakeRoute53{}
	p, err := newRoute53Provider(f, "Z123")
	require.NoError(t, err)

	require.Error(t, p.PublishChallenge(context.Background(), "_acme-challenge.x.", nil))
}
