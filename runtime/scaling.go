package runtime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	sdk "github.com/ArkLabsHQ/threshold-magic/threshold_sdk"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/nacl/box"
)

// =============================================================================
// Enclave scaling and cluster membership
// =============================================================================
//
// Implements the leader–follower protocol used to scale an enclave cluster.
// The leader and its followers run separate images, so each has its own seed
// and KMS key and no follower can reach the leader secret. Followers are
// admitted through mutual attestation: the leader admits only the follower
// images it was built with, and a follower checks the leader runs on the same
// kernel. Once admitted, followers maintain membership via authenticated
// heartbeats, while the leader tracks liveness, evicts stale members, and
// persists bans to prevent re-admission.

const (
	handshakePathNonce = "/enclave/handshake/nonce"
	handshakePathAdmit = "/enclave/handshake/admit"
	heartbeatPath      = "/enclave/heartbeat"
	handshakeNonceLen  = 20
	handshakeNonceTTL  = 60 * time.Second

	scalingRoleLeader   = "leader"
	scalingRoleFollower = "follower"

	// relayTAPHost is the enclave's gvproxy TAP address. The leader's gRPC relay
	// always binds here, so the only configurable part is the port.
	relayTAPHost     = "192.168.127.2"
	defaultRelayPort = "9000"

	thresholdBannedKey   = "threshold/banned"
	thresholdSharePrefix = "threshold/share/"

	// followerReshareKeyTimeout bounds how long a joiner waits for its share after
	// joining the ceremony.
	followerReshareKeyTimeout = 5 * time.Minute
)

// sharedSecret is a signing secret's persisted share and the group key it
// belongs to. The leader secret is not kept: the leader derives it from its seed.
type sharedSecret struct {
	Share    string `json:"share"`     // hex; this node's threshold share
	GroupKey []byte `json:"group_key"` // the group's 33-byte compressed key
}

// admitRequestData is packed into the joiner's attestation UserData.
type admitRequestData struct {
	Nonce   []byte `json:"nonce"`   // joiner's own nonce, echoed by the leader
	HostPub []byte `json:"hostpub"` // joiner's threshold host pubkey (33-byte compressed)
}

// admitResponseData is sealed (NaCl box) into the leader's attestation UserData.
type admitResponseData struct {
	LeaderPub []byte `json:"leader_pub"` // leader's threshold host pubkey (33-byte)
	RelayPort string `json:"relay_port"` // relay port; joiner dials it on the leader's host
}

type heartbeatRequest struct {
	HostPub []byte `json:"hostpub"` // follower's threshold host pubkey (33-byte compressed)
	Nonce   []byte `json:"nonce"`   // a leader-issued nonce, echoed back
	Sig     []byte `json:"sig"`     // BIP-340 Schnorr over the heartbeat-tagged nonce
}

type ScalingEntity struct {
	mu              sync.Mutex
	cfg             *Config
	nsm             NSM
	storage         *thresholdStore         // durable shares and recovery blobs; leader: ban set
	shares          map[string]sharedSecret // env var -> share this node signs with now
	labels          []string                // env vars of the signing secrets
	reshared        chan struct{}           // signalled when a ceremony delivers a share
	hostSk          *secp.PrivateKey        // this node's threshold host key (follower: signs heartbeats)
	authorized      map[string]bool         // hex(hostpub) admitted after a valid handshake
	banned          map[string]bool         // hex(hostpub) durably evicted; refused at both admission gates
	lastSeen        map[string]time.Time    // hex(hostpub) -> last valid heartbeat (leader liveness tracking)
	nonces          map[string]time.Time    // base64(nonce) -> issued-at (one-shot, TTL-bounded)
	leaderPub       []byte                  // leader's threshold host pubkey, set at StartLeader
	role            string
	listenPort      string // leader: port the gRPC relay binds/advertises (on the TAP iface)
	leaderURL       string // follower: leader handshake base URL (e.g. https://host:443)
	leader          *sdk.Leader
	sdkBan          func(ctx context.Context, hostPubkey []byte) error // seam over leader.Ban (raw-keyed); set at startLeader
	follower        *sdk.Follower
	getLeaderSecret func(label string) ([]byte, error) // leader a0 resolver for GetLeaderSecret; nil on a follower.
}

func newScalingEntity(cfg *Config, nsm NSM) (*ScalingEntity, error) {
	role := cfg.ScalingRole
	if role != scalingRoleFollower && role != scalingRoleLeader {
		return nil, fmt.Errorf("invalid %s %q, want %q or %q",
			envScalingRole, role, scalingRoleLeader, scalingRoleFollower)
	}

	e := &ScalingEntity{
		cfg:        cfg,
		nsm:        nsm,
		shares:     make(map[string]sharedSecret),
		reshared:   make(chan struct{}, 1),
		authorized: make(map[string]bool),
		banned:     make(map[string]bool),
		lastSeen:   make(map[string]time.Time),
		nonces:     make(map[string]time.Time),
		role:       role,
	}

	switch role {
	case scalingRoleLeader:
		// The relay binds on the known TAP address, so only the port is configurable.
		e.listenPort = cfg.ScalingListenPort
	case scalingRoleFollower:
		if cfg.ScalingLeaderAddr == "" {
			return nil, fmt.Errorf("%s must be set for role %q", envScalingLeaderAddr, role)
		}
		e.leaderURL = cfg.ScalingLeaderAddr
	}

	return e, nil
}

func (a *ScalingEntity) IsLeader() bool {
	return a.role == scalingRoleLeader
}

// SetLeaderResolver wires the leader's a0 lookup (its seed-derived signing secrets),
// read by the DKG store to pin the group key. Leave unset on a follower.
func (a *ScalingEntity) SetLeaderResolver(fn func(label string) ([]byte, error)) {
	a.getLeaderSecret = fn
}

// Init starts this node's role. labels are the signing secrets' env vars: a share
// persisted for one is restored, and a follower without one requests it and waits.
func (a *ScalingEntity) Init(
	ctx context.Context,
	hostSk *secp.PrivateKey,
	storage *thresholdStore,
	labels []string,
) error {
	a.hostSk = hostSk
	a.storage = storage
	a.labels = labels

	if err := a.loadShares(ctx); err != nil {
		return fmt.Errorf("load shares: %w", err)
	}

	if a.role == scalingRoleLeader {
		err := a.startLeader(ctx, hostSk, storage)
		if err != nil {
			return fmt.Errorf("failed to start leader: %w", err)
		}

		slog.Info("threshold leader started")
		return nil
	}

	err := a.startFollower(ctx, hostSk, storage)
	if err != nil {
		return fmt.Errorf("failed to start follower: %w", err)
	}

	if err := a.awaitShares(ctx); err != nil {
		return err
	}

	slog.Info("threshold follower started")

	return nil
}

// Reshared is signalled when a ceremony delivers a share, so the app can be
// restarted to adopt it. A nil entity returns a nil channel.
func (a *ScalingEntity) Reshared() <-chan struct{} {
	if a == nil {
		return nil
	}
	return a.reshared
}

// applyShares returns static with every signing secret that has a share set to
// that share and its group key. A nil entity returns static unchanged.
func (a *ScalingEntity) applyShares(static []StaticSecret) []StaticSecret {
	if a == nil {
		return static
	}
	out := slices.Clone(static)
	a.mu.Lock()
	defer a.mu.Unlock()
	for i, secret := range out {
		if s, ok := a.shares[secret.EnvVar]; ok && secret.IsSigning() {
			out[i].Plaintext = s.Share
			out[i].GroupKey = s.GroupKey
		}
	}
	return out
}

func (a *ScalingEntity) hasShare(label string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.shares[label]
	return ok
}

// loadShares restores the shares this node persisted, so a reboot skips the ceremony.
func (a *ScalingEntity) loadShares(ctx context.Context) error {
	for _, label := range a.labels {
		blob, err := a.storage.Load(ctx, thresholdSharePrefix+label)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		var s sharedSecret
		if err := json.Unmarshal(blob, &s); err != nil {
			return fmt.Errorf("decode share for %q: %w", label, err)
		}
		a.mu.Lock()
		a.shares[label] = s
		a.mu.Unlock()
	}
	return nil
}

// storeShare persists a share delivered by a (re-)DKG ceremony, makes it what
// the app receives for label, and signals Reshared.
func (a *ScalingEntity) storeShare(
	ctx context.Context,
	label string,
	share, groupKey []byte,
) error {
	if !slices.Contains(a.labels, label) {
		return fmt.Errorf("no configured signing secret for reshare label %q", label)
	}
	s := sharedSecret{Share: hex.EncodeToString(share), GroupKey: groupKey}
	blob, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := a.storage.Store(ctx, thresholdSharePrefix+label, blob); err != nil {
		return err
	}
	a.mu.Lock()
	a.shares[label] = s
	a.mu.Unlock()
	select {
	case a.reshared <- struct{}{}:
	default:
	}
	return nil
}

// awaitShares (follower) requests a reshare for each signing secret without a
// share and waits for it: a follower has no signing secret until its group
// delivers one.
func (a *ScalingEntity) awaitShares(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, followerReshareKeyTimeout)
	defer cancel()
	for _, label := range a.labels {
		if a.hasShare(label) {
			continue
		}
		if err := a.follower.RequestReshare(ctx, label); err != nil {
			return fmt.Errorf("request reshare for %q: %w", label, err)
		}
		for !a.hasShare(label) {
			select {
			case <-ctx.Done():
				return fmt.Errorf("timeout waiting for a share of %q", label)
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	return nil
}

func (a *ScalingEntity) startLeader(
	ctx context.Context,
	hostSk *secp.PrivateKey,
	storage *thresholdStore,
) error {
	// The leader resolves a0 from its leader-secret cache so the group key pins to it.
	store := newDKGStore(storage, a.getLeaderSecret)

	banned, err := a.loadBannedSet(ctx)
	if err != nil {
		return fmt.Errorf("load ban set: %w", err)
	}
	a.mu.Lock()
	for k := range banned {
		a.banned[k] = true
	}
	a.mu.Unlock()

	listenAddr := net.JoinHostPort(relayTAPHost, a.listenPort)
	leader, err := sdk.NewLeader(hostSk, listenAddr, store, sdk.WithAuthorize(a.IsAuthorized))
	if err != nil {
		return fmt.Errorf("new threshold leader: %w", err)
	}

	a.setLeader(hostSk.PubKey().SerializeCompressed())
	go func() {
		if err := leader.Serve(context.Background()); err != nil && ctx.Err() == nil {
			slog.Error("threshold leader stopped", "error", err)
		}
	}()

	// The leader is a full participant, so each ceremony hands it its own share
	go func() {
		for out := range leader.Keys() {
			a.handleShare(scalingRoleLeader, out.Label, out.Secshare, out.ThresholdPubkey)
		}
	}()

	a.leader = leader
	a.sdkBan = leader.Ban

	go a.runLivenessMonitor(context.Background())

	return nil
}

func (a *ScalingEntity) startFollower(
	ctx context.Context,
	hostSk *secp.PrivateKey,
	storage *thresholdStore,
) error {
	// A follower has no leader secret, so it never answers GetLeaderSecret (nil resolver).
	store := newDKGStore(storage, nil)

	myHostPub := hostSk.PubKey().SerializeCompressed()

	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			//nolint:gosec // leader identity is pinned via attestation, not TLS PKI
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		},
	}
	leaderNonce, err := fetchHandshakeNonce(client, a.leaderURL)
	if err != nil {
		return fmt.Errorf("fetch handshake nonce: %w", err)
	}
	ourNonce := make([]byte, handshakeNonceLen)
	if _, err := rand.Read(ourNonce); err != nil {
		return err
	}
	encryptionPubkey, encryptionPrivkey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	reqData, err := json.Marshal(admitRequestData{Nonce: ourNonce, HostPub: myHostPub})
	if err != nil {
		return err
	}
	ourDoc, _, err := a.nsm.BuildAttestationDocument(
		WithNonce(leaderNonce), WithUserData(reqData), WithPublicKeyBytes(encryptionPubkey[:]),
	)
	if err != nil {
		return fmt.Errorf("attest: %w", err)
	}
	resp, err := client.Post(a.leaderURL+handshakePathAdmit, "text/plain",
		strings.NewReader(base64.StdEncoding.EncodeToString(ourDoc)))
	if err != nil {
		return fmt.Errorf("post admit: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf(
			"admit rejected: status %d: %s",
			resp.StatusCode,
			strings.TrimSpace(string(msg)),
		)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	// The leader runs another image, so only its kernel (PCR1) can match ours.
	// Unsigned mock documents pass only in dev (the NSM's InsecureVerifySkipped).
	ourPCR1, _, err := a.nsm.DescribePCR(1)
	if err != nil {
		return fmt.Errorf("read local PCR1: %w", err)
	}
	res, err := a.nsm.VerifyAttestationDocument(
		strings.TrimSpace(string(body)), map[uint]string{1: hex.EncodeToString(ourPCR1)},
	)
	if err != nil {
		return fmt.Errorf("verify leader attestation: %w", err)
	}
	if !bytes.Equal(res.Document.Nonce, ourNonce) {
		return errors.New("leader did not echo our nonce")
	}
	decryptedUserData, ok := box.OpenAnonymous(
		nil,
		res.Document.UserData,
		encryptionPubkey,
		encryptionPrivkey,
	)
	if !ok {
		return errors.New("failed to open sealed leader payload")
	}
	var leaderPayload admitResponseData
	if err := json.Unmarshal(decryptedUserData, &leaderPayload); err != nil {
		return errors.New("malformed leader payload")
	}
	if len(leaderPayload.LeaderPub) != 33 || leaderPayload.RelayPort == "" {
		return errors.New("incomplete leader payload")
	}
	leaderPub, err := secp.ParsePubKey(leaderPayload.LeaderPub)
	if err != nil {
		return fmt.Errorf("parse leader pubkey: %w", err)
	}
	relayPort := leaderPayload.RelayPort

	// The relay lives on the same host as the handshake URL; combine that host
	// with the leader-advertised port to get the dial address.
	leaderHost, err := hostFromURL(a.leaderURL)
	if err != nil {
		return fmt.Errorf("parse leader url: %w", err)
	}
	relayAddr := net.JoinHostPort(leaderHost, relayPort)

	follower, err := sdk.NewJoiningFollower(hostSk, relayAddr, leaderPub, store)
	if err != nil {
		return fmt.Errorf("new joining follower: %w", err)
	}
	hbCtx, hbCancel := context.WithCancel(context.Background())
	go func() {
		defer hbCancel()
		if err := follower.Serve(context.Background()); err != nil && ctx.Err() == nil {
			slog.Error("follower stopped", "error", err)
		}
	}()

	go func() {
		for out := range follower.Keys() {
			a.handleShare(scalingRoleFollower, out.Label, out.Secshare, out.ThresholdPubkey)
		}
	}()

	// Prove liveness to the leader so it doesn't evict us.
	go a.runFollowerHeartbeat(hbCtx, hostSk)

	a.follower = follower
	return nil
}

// handleShare persists one (re-)DKG output and makes it the app's signing secret.
func (a *ScalingEntity) handleShare(role, label string, share, groupKey []byte) {
	if len(share) == 0 {
		slog.Warn("threshold "+role+" received empty share", "envvar", label)
		return
	}
	if err := a.storeShare(context.Background(), label, share, groupKey); err != nil {
		slog.Warn("threshold "+role+" failed to store share", "envvar", label, "error", err)
	}
}

// setLeader records the leader's threshold pubkey returned to admitted joiners.
func (a *ScalingEntity) setLeader(leaderPub []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.leaderPub = leaderPub
}

// IsAuthorized is the WithAuthorize callback passed to thresholdsdk.NewLeader.
func (a *ScalingEntity) IsAuthorized(hostPubkey []byte) bool {
	key := hex.EncodeToString(hostPubkey)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.banned[key] {
		return false
	}
	return a.authorized[key]
}

// isBanned reports whether a host key is on the durable blocklist.
func (a *ScalingEntity) isBanned(hostPubkey []byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.banned[hex.EncodeToString(hostPubkey)]
}

// issueNonce mints a one-shot nonce, prunes expired ones, and records it.
func (a *ScalingEntity) issueNonce() (string, error) {
	n := make([]byte, handshakeNonceLen)
	if _, err := rand.Read(n); err != nil {
		return "", err
	}
	b64 := base64.StdEncoding.EncodeToString(n)
	a.mu.Lock()
	defer a.mu.Unlock()
	cutoff := time.Now().Add(-handshakeNonceTTL)
	for k, issued := range a.nonces {
		if issued.Before(cutoff) {
			delete(a.nonces, k)
		}
	}
	a.nonces[b64] = time.Now()
	return b64, nil
}

// consumeNonce returns true if the nonce was issued by us and unexpired, and
// removes it (one-shot).
func (a *ScalingEntity) consumeNonce(raw []byte) bool {
	b64 := base64.StdEncoding.EncodeToString(raw)
	a.mu.Lock()
	defer a.mu.Unlock()
	issued, ok := a.nonces[b64]
	if !ok {
		return false
	}
	delete(a.nonces, b64)
	return !issued.Before(time.Now().Add(-handshakeNonceTTL))
}

func (a *ScalingEntity) authorize(hostPubkey []byte) {
	key := hex.EncodeToString(hostPubkey)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.banned[key] {
		return // never re-admit a banned host key
	}
	a.authorized[key] = true
	a.lastSeen[key] = time.Now()
}

func (a *ScalingEntity) handleNonce(w http.ResponseWriter, r *http.Request) {
	b64, err := a.issueNonce()
	if err != nil {
		http.Error(w, "failed to issue nonce", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, b64)
}

func (a *ScalingEntity) handleAdmitFollower(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.MultiReader(r.Body))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	req, encryptionPubKey, err := a.verifyFollowerAttestation(string(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// Admit the follower's threshold host key.
	a.authorize(req.HostPub)

	// Build the sealed response and return our attestation echoing the joiner's nonce.
	a.mu.Lock()
	resp := admitResponseData{LeaderPub: a.leaderPub, RelayPort: a.listenPort}
	a.mu.Unlock()
	respJSON, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		return
	}
	var recipient [32]byte
	copy(recipient[:], encryptionPubKey)
	sealed, err := box.SealAnonymous(nil, respJSON, &recipient, rand.Reader)
	if err != nil {
		http.Error(w, "failed to seal response", http.StatusInternalServerError)
		return
	}
	ourDoc, _, err := a.nsm.BuildAttestationDocument(WithNonce(req.Nonce), WithUserData(sealed))
	if err != nil {
		http.Error(w, "failed to attest", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, base64.StdEncoding.EncodeToString(ourDoc))
}

// verifyFollower authenticates a Follower's base64 attestation doc: valid signature,
// the PCR0 of an admitted follower image, and a nonce we issued. Returns the
// Follower's request data and NaCl box public key.
func (a *ScalingEntity) verifyFollowerAttestation(docB64 string) (admitRequestData, []byte, error) {
	// Unsigned mock documents pass only in dev (the NSM's InsecureVerifySkipped);
	// a real deployment verifies against the AWS Nitro root.
	res, err := a.nsm.VerifyAttestationDocument(strings.TrimSpace(docB64), nil)
	if err != nil {
		return admitRequestData{}, nil, fmt.Errorf("verify attestation: %w", err)
	}
	if !slices.Contains(a.cfg.ScalingFollowerPCR0s, hex.EncodeToString(res.Document.PCRs[0])) {
		return admitRequestData{}, nil, errors.New("joiner PCR0 is not an admitted follower image")
	}
	if !a.consumeNonce(res.Document.Nonce) {
		return admitRequestData{}, nil, errors.New("unknown or expired nonce")
	}
	var req admitRequestData
	if err := json.Unmarshal(res.Document.UserData, &req); err != nil {
		return admitRequestData{}, nil, errors.New("malformed admit request")
	}
	if len(req.HostPub) != 33 {
		return admitRequestData{}, nil, errors.New("bad threshold host pubkey")
	}
	if a.isBanned(req.HostPub) {
		return admitRequestData{}, nil, errors.New("host key is banned")
	}
	if len(res.Document.PublicKey) != 32 {
		return admitRequestData{}, nil, errors.New("bad box public key")
	}
	return req, res.Document.PublicKey, nil
}

func (a *ScalingEntity) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	var req heartbeatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "malformed heartbeat", http.StatusBadRequest)
		return
	}
	if len(req.HostPub) != 33 {
		http.Error(w, "bad host pubkey", http.StatusBadRequest)
		return
	}
	if !a.consumeNonce(req.Nonce) {
		http.Error(w, "unknown or expired nonce", http.StatusUnauthorized)
		return
	}
	if !verifyHeartbeatSig(req.HostPub, req.Nonce, req.Sig) {
		http.Error(w, "signature verification failed", http.StatusUnauthorized)
		return
	}

	key := hex.EncodeToString(req.HostPub)
	a.mu.Lock()
	switch {
	case a.banned[key]:
		a.mu.Unlock()
		http.Error(w, "host key is banned", http.StatusForbidden)
		return
	case !a.authorized[key]:
		a.mu.Unlock()
		http.Error(w, "host key not admitted", http.StatusForbidden)
		return
	}
	a.lastSeen[key] = time.Now()
	a.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// runFollowerHeartbeat (follower) pings the leader every heartbeat interval until ctx is
// cancelled — which happens when its Serve returns (e.g. it was evicted).
func (a *ScalingEntity) runFollowerHeartbeat(ctx context.Context, hostSk *secp.PrivateKey) {
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			//nolint:gosec // leader identity is pinned via the attested handshake, not TLS PKI
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		},
	}
	hostPub := hostSk.PubKey().SerializeCompressed()
	ticker := time.NewTicker(a.cfg.ScalingHeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if err := a.sendHeartbeat(client, hostSk, hostPub); err != nil {
			slog.Debug("threshold follower heartbeat failed", "error", err)
		}
	}
}

func (a *ScalingEntity) sendHeartbeat(
	client *http.Client,
	hostSk *secp.PrivateKey,
	hostPub []byte,
) error {
	nonce, err := fetchHandshakeNonce(client, a.leaderURL)
	if err != nil {
		return fmt.Errorf("fetch nonce: %w", err)
	}
	sig, err := signHeartbeat(hostSk, nonce)
	if err != nil {
		return fmt.Errorf("sign heartbeat: %w", err)
	}
	body, err := json.Marshal(heartbeatRequest{HostPub: hostPub, Nonce: nonce, Sig: sig})
	if err != nil {
		return err
	}
	resp, err := client.Post(a.leaderURL+heartbeatPath, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf(
			"heartbeat rejected: status %d: %s",
			resp.StatusCode,
			strings.TrimSpace(string(msg)),
		)
	}
	return nil
}

// runLivenessMonitor (leader) evicts followers whose last heartbeat is older than the
// liveness timeout. Runs for the leader's lifetime.
func (a *ScalingEntity) runLivenessMonitor(ctx context.Context) {
	timeout := a.cfg.ScalingLivenessTimeout
	ticker := time.NewTicker(a.cfg.ScalingMonitorTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		for _, hostPub := range a.staleFollowers(timeout) {
			if err := a.Ban(ctx, hostPub); err != nil {
				slog.Error("threshold leader failed to evict follower",
					"hostpub", hex.EncodeToString(hostPub), "error", err)
			}
		}
	}
}

// staleFollowers returns the raw host pubkeys of admitted followers whose last heartbeat is
// older than timeout — never the leader's own key.
func (a *ScalingEntity) staleFollowers(timeout time.Duration) [][]byte {
	cutoff := time.Now().Add(-timeout)
	a.mu.Lock()
	defer a.mu.Unlock()
	leaderKey := hex.EncodeToString(a.leaderPub)
	var stale [][]byte
	for key := range a.authorized {
		if key == leaderKey {
			continue
		}
		if seen, ok := a.lastSeen[key]; ok && !seen.Before(cutoff) {
			continue // heard from recently
		}
		raw, err := hex.DecodeString(key)
		if err != nil {
			continue
		}
		stale = append(stale, raw)
	}
	return stale
}

func (a *ScalingEntity) loadBannedSet(ctx context.Context) (map[string]bool, error) {
	blob, err := a.storage.Load(ctx, thresholdBannedKey)
	if errors.Is(err, ErrNotFound) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	var list []string
	if err := json.Unmarshal(blob, &list); err != nil {
		return nil, fmt.Errorf("decode ban set: %w", err)
	}
	set := make(map[string]bool, len(list))
	for _, h := range list {
		set[h] = true
	}
	return set, nil
}

// storeBannedSet persists the blocklist as a sorted JSON array of hex host pubkeys.
func (a *ScalingEntity) storeBannedSet(ctx context.Context, set map[string]bool) error {
	list := make([]string, 0, len(set))
	for h := range set {
		list = append(list, h)
	}
	sort.Strings(list)
	blob, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return a.storage.Store(ctx, thresholdBannedKey, blob)
}

// Ban durably evicts a follower: it records the host key on the persistent blocklist,
// revokes its local admission, and drives the SDK ban — which notifies + drops the member
// and reshares every secret among the survivors. Leader-only; idempotent. hostPubkey is the
// raw 33-byte compressed key (the SDK's banned set is raw-keyed).
func (a *ScalingEntity) Ban(ctx context.Context, hostPubkey []byte) error {
	key := hex.EncodeToString(hostPubkey)

	a.mu.Lock()
	if a.banned[key] {
		a.mu.Unlock()
		return nil // already banned
	}
	a.banned[key] = true
	delete(a.authorized, key)
	delete(a.lastSeen, key)
	snapshot := make(map[string]bool, len(a.banned))
	for k := range a.banned {
		snapshot[k] = true
	}
	a.mu.Unlock()

	// Persist so the ban survives a leader restart. On failure keep the in-memory eviction
	// (availability) but log loudly — durability is degraded until the next successful write.
	if a.storage != nil {
		if err := a.storeBannedSet(ctx, snapshot); err != nil {
			slog.Error("threshold leader failed to persist ban", "hostpub", key, "error", err)
		}
	}

	// SDK eviction + reshare (drives its own Serve loop; call outside a.mu).
	if a.sdkBan != nil {
		if err := a.sdkBan(ctx, hostPubkey); err != nil {
			return fmt.Errorf("sdk ban: %w", err)
		}
	}
	slog.Warn("threshold leader banned follower", "hostpub", key)
	return nil
}

func hostFromURL(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("no host in url %q", baseURL)
	}
	return u.Hostname(), nil
}

func fetchHandshakeNonce(client *http.Client, baseURL string) ([]byte, error) {
	resp, err := client.Get(baseURL + handshakePathNonce)
	if err != nil {
		return nil, fmt.Errorf("fetch threshold nonce: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch threshold nonce: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(
		io.LimitReader(resp.Body, int64(base64.StdEncoding.EncodedLen(handshakeNonceLen)+1)),
	)
	if err != nil {
		return nil, err
	}
	n, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil || len(n) != handshakeNonceLen {
		return nil, errors.New("bad nonce from leader")
	}
	return n, nil
}

// heartbeatDigest is the BIP-340 tagged hash a heartbeat signature covers.
func heartbeatDigest(nonce []byte) []byte {
	h := chainhash.TaggedHash([]byte("introspector-enclave/scaling-heartbeat"), nonce)
	return h[:]
}

// signHeartbeat proves possession of the threshold host key over a fresh leader nonce.
func signHeartbeat(hostSk *secp.PrivateKey, nonce []byte) ([]byte, error) {
	priv, _ := btcec.PrivKeyFromBytes(hostSk.Serialize())
	sig, err := schnorr.Sign(priv, heartbeatDigest(nonce))
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

// verifyHeartbeatSig checks a heartbeat's BIP-340 signature against its host pubkey.
func verifyHeartbeatSig(hostPub, nonce, sigBytes []byte) bool {
	pub, err := btcec.ParsePubKey(hostPub)
	if err != nil {
		return false
	}
	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return false
	}
	return sig.Verify(heartbeatDigest(nonce), pub)
}

// deriveThresholdHostKey derives this node's threshold identity from its seed, so
// it survives restarts and migration.
func deriveThresholdHostKey(seed []byte) (*secp.PrivateKey, error) {
	return deriveValidScalar(
		seed,
		thresholdHostKeyDerivationName,
		func(candidate []byte) (*secp.PrivateKey, bool) {
			var scalar secp.ModNScalar
			if scalar.SetByteSlice(candidate) || scalar.IsZero() {
				return nil, false
			}
			return secp.NewPrivateKey(&scalar), true
		},
	)
}

// startScaling runs this node's threshold-scaling role, if it has one, once boot
// has established state. A leader starts serving admission; a follower joins its
// leader and waits for a share of every signing secret.
func startScaling(
	ctx context.Context,
	cfg *Config,
	nsm NSM,
	s3api S3API,
	ssm SSM,
	servers Servers,
	result bootState,
) (*ScalingEntity, error) {
	if cfg.ScalingRole == "" {
		return nil, nil
	}
	scaling, err := newScalingEntity(cfg, nsm)
	if err != nil {
		return nil, err
	}
	hostSk, err := deriveThresholdHostKey(result.masterSeed)
	if err != nil {
		return nil, fmt.Errorf("derive threshold host key: %w", err)
	}
	bucket, err := ssm.MustGet(ctx, cfg.certBucketParam())
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate bucket name: %w", err)
	}

	leaderSecrets := make(map[string][]byte)
	var labels []string
	for _, secret := range result.secrets.Static {
		if !secret.IsSigning() {
			continue
		}
		labels = append(labels, secret.EnvVar)
		if scaling.IsLeader() {
			a0, err := hex.DecodeString(secret.Plaintext)
			if err != nil {
				return nil, fmt.Errorf("decode leader secret %q: %w", secret.Name, err)
			}
			leaderSecrets[secret.EnvVar] = a0
		}
	}
	if scaling.IsLeader() {
		scaling.SetLeaderResolver(func(label string) ([]byte, error) {
			if a0, ok := leaderSecrets[label]; ok {
				return a0, nil
			}
			return nil, fmt.Errorf("no leader secret for %q", label)
		})
	}

	store := &thresholdStore{cfg: cfg, s3: s3api, dek: result.dek, bucket: bucket}
	if err := scaling.Init(ctx, hostSk, store, labels); err != nil {
		return nil, err
	}
	if scaling.IsLeader() {
		servers.ConfigureScalingHandlers(scaling)
	}
	return scaling, nil
}
