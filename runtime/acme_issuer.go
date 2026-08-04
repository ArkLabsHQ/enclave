package runtime

// DNS-01 issuance driven directly against golang.org/x/crypto/acme.
//
// autocert is not usable here: it implements only http-01 and tls-alpn-01, and
// its Manager is process-local, so N enclaves would issue N simultaneous orders
// for one FQDN and exhaust the CA's duplicate-certificate limit. lego and
// certmagic would solve the protocol half but drag a large dependency tree into
// a measured EIF, so the order flow is written out here instead.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"

	"golang.org/x/crypto/acme"
)

// acmeIssuer performs one DNS-01 order at a time. Callers hold the renewal lease
// for its duration.
type acmeIssuer struct {
	client *acme.Client
	dns    dnsProvider
	email  string
}

func newACMEIssuer(client *acme.Client, dns dnsProvider, email string) *acmeIssuer {
	return &acmeIssuer{client: client, dns: dns, email: email}
}

// issue runs a complete order for domain and returns the PEM chain and key.
func (i *acmeIssuer) issue(ctx context.Context, domain string) (certPEM, keyPEM []byte, err error) {
	if err := i.register(ctx); err != nil {
		return nil, nil, err
	}

	order, err := i.client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return nil, nil, fmt.Errorf("authorize order for %q: %w", domain, err)
	}

	// Challenge records are withdrawn before this returns. Safe: an authorization
	// stays valid once validated, and finalization never re-queries DNS.
	if err := i.solveChallenges(ctx, order); err != nil {
		return nil, nil, err
	}

	if _, err := i.client.WaitOrder(ctx, order.URI); err != nil {
		return nil, nil, fmt.Errorf("wait for order %q: %w", order.URI, err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate certificate key: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}

	chain, _, err := i.client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, nil, fmt.Errorf("finalize order for %q: %w", domain, err)
	}
	if len(chain) == 0 {
		return nil, nil, errors.New("CA returned an empty certificate chain")
	}

	keyPEM, err = encodeECKey(key)
	if err != nil {
		return nil, nil, err
	}
	return encodeCertChain(chain), keyPEM, nil
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

// solveChallenges publishes every dns-01 record the order needs, accepts the
// challenges, and waits for the authorizations to go valid. Records are withdrawn
// before it returns, on every path.
func (i *acmeIssuer) solveChallenges(ctx context.Context, order *acme.Order) error {
	// One record name per identifier, but a name may carry several values, so
	// they are published as a set rather than one at a time.
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
		return nil // every authorization was already valid
	}

	// Withdraw whatever we managed to publish, on every exit path. The context
	// is detached so a cancelled order still cleans up after itself.
	published := map[string][]string{}
	defer func() {
		for name, values := range published {
			if err := i.dns.RemoveChallenge(context.WithoutCancel(ctx), name, values); err != nil {
				slog.Warn("failed to withdraw dns-01 record", "name", name, "error", err)
			}
		}
	}()

	for name, values := range valuesByName {
		if err := i.dns.PublishChallenge(ctx, name, values); err != nil {
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

// loadOrCreateAccountKey returns the fleet-shared ACME account key, creating one
// if the fleet has none. The create is conditional, so concurrent first boots
// converge on a single account instead of registering one each.
func loadOrCreateAccountKey(ctx context.Context, store *certStore) (crypto.Signer, error) {
	// Two passes at most: either a key is already stored, or we create one, or a
	// peer beat us to the create and the second pass loads theirs.
	for range 2 {
		pemBytes, err := store.loadAccountKey(ctx)
		if err != nil {
			return nil, err
		}
		if pemBytes != nil {
			return parseECKey(pemBytes)
		}

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ACME account key: %w", err)
		}
		encoded, err := encodeECKey(key)
		if err != nil {
			return nil, err
		}

		err = store.saveAccountKey(ctx, encoded)
		if err == nil {
			return key, nil
		}
		if !errors.Is(err, errCertChanged) {
			return nil, fmt.Errorf("store ACME account key: %w", err)
		}
	}
	return nil, errors.New("ACME account key: object kept disappearing between load and create")
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
