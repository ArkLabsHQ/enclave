package runtime

// DNS-01 issuance driven directly against golang.org/x/crypto/acme. The challenge is published over DNS
import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"golang.org/x/crypto/acme"
)

// acmeIssuer performs one DNS-01 order at a time. Callers hold the renewal lease
// for its duration.
type acmeIssuer struct {
	client *acme.Client
	r53    Route53API
	zoneID string
	email  string
}

const (
	acmeChallengePrefix = "_acme-challenge."

	// dnsChallengeTTL is short so a failed cleanup expires quickly.
	dnsChallengeTTL = 60

	route53SyncPoll    = 2 * time.Second
	route53SyncTimeout = 3 * time.Minute
)

func newACMEIssuer(
	client *acme.Client,
	r53 Route53API,
	zoneID, email string,
) (*acmeIssuer, error) {
	if strings.TrimSpace(zoneID) == "" {
		return nil, errors.New("ACME issuer: hosted zone ID is required for DNS-01")
	}
	return &acmeIssuer{client: client, r53: r53, zoneID: zoneID, email: email}, nil
}

// Issue runs a complete order for domain using the fleet TLS key and returns
// the PEM certificate chain.
func (i *acmeIssuer) Issue(
	ctx context.Context,
	domain string,
	key crypto.Signer,
) (certPEM []byte, err error) {
	if key == nil {
		return nil, errors.New("certificate key is required")
	}

	if err := i.register(ctx); err != nil {
		return nil, err
	}

	order, err := i.client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return nil, fmt.Errorf("authorize order for %q: %w", domain, err)
	}

	if err := i.solveChallenges(ctx, order); err != nil {
		return nil, err
	}

	if _, err := i.client.WaitOrder(ctx, order.URI); err != nil {
		return nil, fmt.Errorf("wait for order %q: %w", order.URI, err)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	chain, _, err := i.client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("finalize order for %q: %w", domain, err)
	}
	if len(chain) == 0 {
		return nil, errors.New("CA returned an empty certificate chain")
	}
	return encodeCertChain(chain), nil
}

// register creates the ACME account. The account key is fleet-shared, so on
// every enclave but the first this is a no-op.
func (i *acmeIssuer) register(ctx context.Context) error {
	acct := &acme.Account{}
	if i.email != "" {
		acct.Contact = []string{"mailto:" + i.email}
	}
	if _, err := i.client.Register(ctx, acct, acme.AcceptTOS); err != nil &&
		!errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("register ACME account: %w", err)
	}
	return nil
}

func (i *acmeIssuer) solveChallenges(ctx context.Context, order *acme.Order) error {
	valuesByName := map[string][]string{}
	var accept []*acme.Challenge

	for _, authzURL := range order.AuthzURLs {
		authz, err := i.client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("get authorization %q: %w", authzURL, err)
		}
		if authz.Status == acme.StatusValid {
			continue // already satisfied by an earlier order
		}

		chal := dns01Challenge(authz)
		if chal == nil {
			return fmt.Errorf("authorization %q offers no dns-01 challenge", authzURL)
		}
		value, err := i.client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return fmt.Errorf("compute dns-01 record: %w", err)
		}

		name := acmeChallengeName(authz.Identifier.Value)
		valuesByName[name] = append(valuesByName[name], value)
		accept = append(accept, chal)
	}

	if len(accept) == 0 {
		return nil
	}

	// Withdraw whatever we managed to publish, on every exit path. The context
	// is detached so a cancelled order still cleans up after itself.
	published := map[string][]string{}
	defer func() {
		for name, values := range published {
			if err := i.removeChallenge(context.WithoutCancel(ctx), name, values); err != nil {
				slog.Warn("failed to withdraw dns-01 record", "name", name, "error", err)
			}
		}
	}()

	for name, values := range valuesByName {
		if err := i.publishChallenge(ctx, name, values); err != nil {
			return err
		}
		published[name] = values
	}

	for _, chal := range accept {
		if _, err := i.client.Accept(ctx, chal); err != nil {
			return fmt.Errorf("accept dns-01 challenge: %w", err)
		}
	}
	for _, authzURL := range order.AuthzURLs {
		if _, err := i.client.WaitAuthorization(ctx, authzURL); err != nil {
			return fmt.Errorf("authorization %q did not become valid: %w", authzURL, err)
		}
	}
	return nil
}

func (i *acmeIssuer) publishChallenge(
	ctx context.Context,
	name string,
	values []string,
) error {
	changeID, err := i.change(ctx, r53types.ChangeActionUpsert, name, values)
	if err != nil {
		return fmt.Errorf("publish DNS-01 record %q: %w", name, err)
	}
	return i.waitInSync(ctx, changeID)
}

func (i *acmeIssuer) removeChallenge(
	ctx context.Context,
	name string,
	values []string,
) error {
	if _, err := i.change(ctx, r53types.ChangeActionDelete, name, values); err != nil {
		return fmt.Errorf("remove DNS-01 record %q: %w", name, err)
	}
	return nil
}

func (i *acmeIssuer) change(
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

	out, err := i.r53.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(i.zoneID),
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

func (i *acmeIssuer) waitInSync(ctx context.Context, changeID string) error {
	ctx, cancel := context.WithTimeout(ctx, route53SyncTimeout)
	defer cancel()

	for {
		out, err := i.r53.GetChange(ctx, &route53.GetChangeInput{Id: aws.String(changeID)})
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

func parseECKey(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ACME account key is not PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ACME account key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("ACME account key of type %T cannot sign", key)
	}
	return signer, nil
}

func dns01Challenge(authz *acme.Authorization) *acme.Challenge {
	for _, chal := range authz.Challenges {
		if chal.Type == "dns-01" {
			return chal
		}
	}
	return nil
}

func encodeCertChain(chain [][]byte) []byte {
	var out []byte
	for _, der := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out
}

func encodeECKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// quoteTXTValue wraps a TXT value in the double quotes Route53 requires.
func quoteTXTValue(v string) string {
	return `"` + v + `"`
}

// acmeChallengeName is the fully-qualified TXT record name for an identifier.
func acmeChallengeName(domain string) string {
	return acmeChallengePrefix + strings.TrimSuffix(domain, ".") + "."
}
