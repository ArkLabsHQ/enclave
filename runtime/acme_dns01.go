package runtime

// DNS-01 challenge publication.
//
// tls-alpn-01 cannot survive a load balancer: the CA dials :443 and gets hashed
// to an arbitrary target, but only the enclave that created the order holds the
// challenge certificate. DNS-01 moves the proof off the connection path, so any
// enclave can satisfy it for the whole fleet.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
)

const (
	acmeChallengePrefix = "_acme-challenge."

	// dnsChallengeTTL is short so a failed cleanup expires quickly.
	dnsChallengeTTL = 60

	route53SyncPoll    = 2 * time.Second
	route53SyncTimeout = 3 * time.Minute
)

// dnsProvider publishes and withdraws DNS-01 challenge records.
type dnsProvider interface {
	PublishChallenge(ctx context.Context, name string, values []string) error

	RemoveChallenge(ctx context.Context, name string, values []string) error
}

type route53Provider struct {
	r53    Route53API
	zoneID string
}

func newRoute53Provider(r53 Route53API, zoneID string) (*route53Provider, error) {
	if strings.TrimSpace(zoneID) == "" {
		return nil, errors.New("route53 provider: hosted zone ID is required")
	}
	return &route53Provider{r53: r53, zoneID: zoneID}, nil
}

func (p *route53Provider) PublishChallenge(
	ctx context.Context,
	name string,
	values []string,
) error {
	changeID, err := p.change(ctx, r53types.ChangeActionUpsert, name, values)
	if err != nil {
		return fmt.Errorf("publish DNS-01 record %q: %w", name, err)
	}
	return p.waitInSync(ctx, changeID)
}

func (p *route53Provider) RemoveChallenge(
	ctx context.Context,
	name string,
	values []string,
) error {
	if _, err := p.change(ctx, r53types.ChangeActionDelete, name, values); err != nil {
		return fmt.Errorf("remove DNS-01 record %q: %w", name, err)
	}
	return nil
}

func (p *route53Provider) change(
	ctx context.Context,
	action r53types.ChangeAction,
	name string,
	values []string,
) (string, error) {
	if len(values) == 0 {
		return "", errors.New("no challenge values")
	}
	records := make([]r53types.ResourceRecord, 0, len(values))
	for _, v := range values {
		records = append(records, r53types.ResourceRecord{Value: aws.String(quoteTXTValue(v))})
	}

	out, err := p.r53.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(p.zoneID),
		ChangeBatch: &r53types.ChangeBatch{
			Changes: []r53types.Change{{
				Action: action,
				ResourceRecordSet: &r53types.ResourceRecordSet{
					Name:            aws.String(name),
					Type:            r53types.RRTypeTxt,
					TTL:             aws.Int64(dnsChallengeTTL),
					ResourceRecords: records,
				},
			}},
		},
	})
	if err != nil {
		return "", err
	}
	if out == nil || out.ChangeInfo == nil {
		return "", errors.New("route53 returned no change info")
	}
	return aws.ToString(out.ChangeInfo.Id), nil
}

func (p *route53Provider) waitInSync(ctx context.Context, changeID string) error {
	ctx, cancel := context.WithTimeout(ctx, route53SyncTimeout)
	defer cancel()

	for {
		out, err := p.r53.GetChange(ctx, &route53.GetChangeInput{Id: aws.String(changeID)})
		if err != nil {
			return fmt.Errorf("get change %q: %w", changeID, err)
		}
		if out == nil || out.ChangeInfo == nil {
			return fmt.Errorf("get change %q: route53 returned no change info", changeID)
		}
		if out.ChangeInfo.Status == r53types.ChangeStatusInsync {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for change %q to sync: %w", changeID, ctx.Err())
		case <-time.After(route53SyncPoll):
		}
	}
}

// quoteTXTValue wraps a TXT value in the double quotes Route53 requires.
func quoteTXTValue(v string) string {
	return `"` + v + `"`
}

// acmeChallengeName is the fully-qualified TXT record name for an identifier.
func acmeChallengeName(domain string) string {
	return acmeChallengePrefix + strings.TrimSuffix(domain, ".") + "."
}
