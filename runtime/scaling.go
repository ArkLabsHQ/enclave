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
	"os"
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

	"github.com/ArkLabsHQ/introspector-enclave/runtime/nitriding"
)

// =============================================================================
// Enclave scaling and cluster membership
// =============================================================================
//
// Implements the leader–follower protocol used to scale an enclave cluster.
// Followers are admitted through mutual attestation, proving they are running
// the same measured enclave image before exchanging host public keys. Once
// admitted, followers maintain membership via authenticated heartbeats, while
// the leader tracks liveness, evicts stale members, and persists bans to
// prevent re-admission.

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

	thresholdBannedKey = "threshold/banned"

	// followerReshareKeyTimeout bounds how long a joiner waits for its share after
	// joining the ceremony.
	followerReshareKeyTimeout = 5 * time.Minute
)

// PCR0 (EIF), PCR1 (kernel+bootstrap), PCR2 (application). Host-specific PCRs
// (PCR3 IAM role, PCR4 instance ID) are excluded so same-image enclaves on
// different EC2 instances are admitted.
var scalingIdentityPCRs = []uint{0, 1, 2}

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
	kms             *KMS
	storage         *Storage             // leader: durable ban-set persistence
	hostSk          *secp.PrivateKey     // this node's threshold host key (follower: signs heartbeats)
	authorized      map[string]bool      // hex(hostpub) admitted after a valid handshake
	banned          map[string]bool      // hex(hostpub) durably evicted; refused at both admission gates
	lastSeen        map[string]time.Time // hex(hostpub) -> last valid heartbeat (leader liveness tracking)
	nonces          map[string]time.Time // base64(nonce) -> issued-at (one-shot, TTL-bounded)
	leaderPub       []byte               // leader's threshold host pubkey, set at StartLeader
	role            string
	listenPort      string // leader: port the gRPC relay binds/advertises (on the TAP iface)
	leaderURL       string // follower: leader handshake base URL (e.g. https://host:443)
	leader          *sdk.Leader
	sdkBan          func(ctx context.Context, hostPubkey []byte) error // seam over leader.Ban (raw-keyed); set at startLeader
	follower        *sdk.Follower
	onShare         func(ctx context.Context, label string, share []byte) error // onShare persists+materializes a share delivered by a reshare ceremony.
	getLeaderSecret func(label string) ([]byte, error)                          // leader a0 resolver for GetLeaderSecret; nil on a follower.
}

func newScalingEntity() (*ScalingEntity, error) {
	role := os.Getenv("ENCLAVE_SCALING_ROLE")
	if role != scalingRoleFollower && role != scalingRoleLeader {
		return nil, fmt.Errorf("invalid ENCLAVE_SCALING_ROLE %q, want %q or %q", role, scalingRoleLeader, scalingRoleFollower)
	}

	e := &ScalingEntity{
		authorized: make(map[string]bool),
		banned:     make(map[string]bool),
		lastSeen:   make(map[string]time.Time),
		nonces:     make(map[string]time.Time),
		role:       role,
	}

	switch role {
	case scalingRoleLeader:
		// The relay binds on the known TAP address, so only the port is configurable.
		port := os.Getenv("ENCLAVE_SCALING_LISTEN_PORT")
		if port == "" {
			port = defaultRelayPort
		}
		e.listenPort = port
	case scalingRoleFollower:
		leaderURL := os.Getenv("ENCLAVE_SCALING_LEADER_ADDR")
		if leaderURL == "" {
			return nil, fmt.Errorf("ENCLAVE_SCALING_LEADER_ADDR must be set for role %q", role)
		}
		e.leaderURL = leaderURL
	}

	return e, nil
}

func (a *ScalingEntity) loadOrGenerateHostKey(ctx context.Context) (*secp.PrivateKey, error) {
	keyID, err := a.kms.GetKeyID(ctx)
	if err != nil {
		return nil, fmt.Errorf("get kms key id: %w", err)
	}
	paramName := secretCiphertextParam("threshold_host_key", keyID)

	ciphertextB64, err := a.kms.LoadCiphertext(ctx, paramName)
	if err != nil {
		return nil, err
	}

	if ciphertextB64 != "" {
		plaintext, err := a.kms.decryptToBytes(ctx, keyID, ciphertextB64)
		if err != nil {
			return nil, err
		}
		return secp.PrivKeyFromBytes(plaintext), nil
	}

	ciphertextBlob, plaintext, err := a.kms.generateDataKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	if err := a.kms.StoreCiphertext(ctx, paramName, base64.StdEncoding.EncodeToString(ciphertextBlob)); err != nil {
		return nil, err
	}

	return secp.PrivKeyFromBytes(plaintext), nil
}

func (a *ScalingEntity) IsLeader() bool {
	return a.role == scalingRoleLeader
}

// SetLeaderResolver wires the leader's a0 lookup (StaticSecrets.leaderSecret), read by
// the DKG store to pin the group key. Leave unset on a follower.
func (a *ScalingEntity) SetLeaderResolver(fn func(label string) ([]byte, error)) {
	a.getLeaderSecret = fn
}

// SetShareHandler wires the sink for reshared follower shares.
func (a *ScalingEntity) SetShareHandler(fn func(ctx context.Context, label string, share []byte) error) {
	a.onShare = fn
}

func (a *ScalingEntity) Init(ctx context.Context, storage *Storage) error {
	hostSk, err := a.loadOrGenerateHostKey(ctx)
	if err != nil {
		return fmt.Errorf("generate host key: %w", err)
	}
	a.hostSk = hostSk
	a.storage = storage

	if a.role == scalingRoleLeader {
		err := a.startLeader(ctx, hostSk, storage)

		if err != nil {
			return fmt.Errorf("failed to start leader: %w", err)
		}

		slog.Info("threshold leader started")
		return nil
	}

	err = a.startFollower(ctx, hostSk, storage)
	if err != nil {
		return fmt.Errorf("failed to start follower: %w", err)
	}

	slog.Info("threshold follower started")

	return nil
}

func (a *ScalingEntity) startLeader(ctx context.Context, hostSk *secp.PrivateKey, storage *Storage) error {
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
			a.handleShare(scalingRoleLeader, out.Label, out.Secshare)
		}
	}()

	a.leader = leader
	a.sdkBan = leader.Ban

	go a.runLivenessMonitor(context.Background())

	return nil
}

func (a *ScalingEntity) DeriveFollowerKey(ctx context.Context, StaticSecret StaticSecret) error {
	err := a.follower.RequestReshare(ctx, StaticSecret.EnvVar)
	if err != nil {
		return fmt.Errorf("request reshare: %w", err)
	}

	return nil

}

func (a *ScalingEntity) startFollower(ctx context.Context, hostSk *secp.PrivateKey, storage *Storage) error {
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
	ourDoc, err := nitriding.Attest(leaderNonce, reqData, encryptionPubkey[:])
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
		return fmt.Errorf("admit rejected: status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	leaderAttestationDoc, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		return errors.New("bad leader attestation encoding")
	}
	// Dev-aware verification (see verifyFollowerAttestation): mock docs pass in dev.
	res, err := verifyAttestationDoc(leaderAttestationDoc, nil)
	if err != nil {
		return fmt.Errorf("verify leader attestation: %w", err)
	}
	ourPCRs, err := nitriding.GetPCRs()
	if err != nil {
		return errors.New("read local PCRs")
	}
	if !nitriding.ArePCRsIdenticalForKeys(ourPCRs, res.Document.PCRs, scalingIdentityPCRs) {
		return errors.New("leader PCRs differ from ours")
	}
	if !bytes.Equal(res.Document.Nonce, ourNonce) {
		return errors.New("leader did not echo our nonce")
	}
	decryptedUserData, ok := box.OpenAnonymous(nil, res.Document.UserData, encryptionPubkey, encryptionPrivkey)
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
			a.handleShare(scalingRoleFollower, out.Label, out.Secshare)
		}
	}()

	// Prove liveness to the leader so it doesn't evict us.
	go a.runFollowerHeartbeat(hbCtx, hostSk)

	a.follower = follower
	return nil
}

// handleShare feeds one (re-)DKG output to the wired handler, which persists the
// share and sets its env var.
func (a *ScalingEntity) handleShare(role, label string, share []byte) {
	if len(share) == 0 {
		slog.Warn("threshold "+role+" received empty share", "envvar", label)
		return
	}
	if a.onShare == nil {
		slog.Error("threshold "+role+" received share with no handler wired; not persisted", "envvar", label)
		return
	}
	if err := a.onShare(context.Background(), label, share); err != nil {
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
	cutoff := nitriding.CurrentTime().Add(-handshakeNonceTTL)
	for k, issued := range a.nonces {
		if issued.Before(cutoff) {
			delete(a.nonces, k)
		}
	}
	a.nonces[b64] = nitriding.CurrentTime()
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
	return !issued.Before(nitriding.CurrentTime().Add(-handshakeNonceTTL))
}

func (a *ScalingEntity) authorize(hostPubkey []byte) {
	key := hex.EncodeToString(hostPubkey)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.banned[key] {
		return // never re-admit a banned host key
	}
	a.authorized[key] = true
	a.lastSeen[key] = nitriding.CurrentTime()
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
	followerAttestationDoc, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		http.Error(w, "invalid base64 attestation", http.StatusBadRequest)
		return
	}

	req, encryptionPubKey, err := a.verifyFollowerAttestation(followerAttestationDoc)
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
	ourDoc, err := nitriding.Attest(req.Nonce, sealed, nil)
	if err != nil {
		http.Error(w, "failed to attest", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, base64.StdEncoding.EncodeToString(ourDoc))
}

// verifyFollower authenticates a Follower's attestation doc: valid signature, PCRs
// identical to ours, and a nonce we issued. Returns the Follower's request data and
// NaCl box public key.
func (a *ScalingEntity) verifyFollowerAttestation(doc []byte) (admitRequestData, []byte, error) {
	// Dev-aware: honors skipCOSEVerification so the QEMU NSM's unsigned mock docs are
	// accepted in dev; a real deployment still verifies against the AWS Nitro root.
	res, err := verifyAttestationDoc(doc, nil)
	if err != nil {
		return admitRequestData{}, nil, fmt.Errorf("verify attestation: %w", err)
	}
	ourPCRs, err := nitriding.GetPCRs()
	if err != nil {
		return admitRequestData{}, nil, errors.New("read local PCRs")
	}
	if !nitriding.ArePCRsIdenticalForKeys(ourPCRs, res.Document.PCRs, scalingIdentityPCRs) {
		return admitRequestData{}, nil, errors.New("joiner PCRs differ from ours")
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
	a.lastSeen[key] = nitriding.CurrentTime()
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
	ticker := time.NewTicker(scalingHeartbeatInterval())
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

func (a *ScalingEntity) sendHeartbeat(client *http.Client, hostSk *secp.PrivateKey, hostPub []byte) error {
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
		return fmt.Errorf("heartbeat rejected: status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

// runLivenessMonitor (leader) evicts followers whose last heartbeat is older than the
// liveness timeout. Runs for the leader's lifetime.
func (a *ScalingEntity) runLivenessMonitor(ctx context.Context) {
	timeout := scalingLivenessTimeout()
	ticker := time.NewTicker(scalingMonitorTick())
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
	cutoff := nitriding.CurrentTime().Add(-timeout)
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(base64.StdEncoding.EncodedLen(handshakeNonceLen)+1)))
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
