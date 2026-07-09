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
	"strings"
	"sync"
	"time"

	sdk "thresholdsdk"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/nacl/box"

	"github.com/ArkLabsHQ/introspector-enclave/runtime/nitriding"
)

// =============================================================================
// Scaling Attested admission handshake
// =============================================================================
//
// A follower enclave must prove — before the  leader will admit its
// host key — that it is a genuine same-image (identical-PCR) enclave. This is a
// two-message, mutually-attested exchange over HTTP, distinct from the generic
// /enclave/state keysync so its semantics stay narrow:
//
//   1. follower: GET  /enclave/follower/nonce  -> a fresh leader nonce
//   2. follower: POST /enclave/follower/admit   (its attestation doc)
//              leader: verifies PCRs == ours + nonce is one we issued,
//                      authorizes the follower's follower host pubkey, and
//                      replies with its own attestation doc carrying the
//                      leader's follower host pubkey + relay address, sealed
//                      to the follower's NaCl box key.
//
// The follower then verifies the leader's PCRs before trusting the returned
// leader pubkey — so trust is mutual and nothing is pre-shared.

const (
	handshakePathNonce = "/enclave/handshake/nonce"
	handshakePathAdmit = "/enclave/handshake/admit"
	handshakeNonceLen  = 20
	handshakeNonceTTL  = 60 * time.Second

	scalingRoleLeader   = "leader"
	scalingRoleFollower = "follower"

	// relayTAPHost is the enclave's gvproxy TAP address. The leader's gRPC relay
	// always binds here, so the only configurable part is the port.
	relayTAPHost     = "192.168.127.2"
	defaultRelayPort = "9000"

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

type ScalingEntity struct {
	mu              sync.Mutex
	kms             *KMS
	authorized      map[string]bool      // hex(hostpub) admitted after a valid handshake
	nonces          map[string]time.Time // base64(nonce) -> issued-at (one-shot, TTL-bounded)
	leaderPub       []byte               // leader's threshold host pubkey, set at StartLeader
	role            string
	listenPort      string // leader: port the gRPC relay binds/advertises (on the TAP iface)
	leaderURL       string // follower: leader handshake base URL (e.g. https://host:443)
	leader          *sdk.Leader
	follower        *sdk.Follower
	signingSecrets  []StaticSecrets                                             // signing secrets to derive shares for
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

// SetLeaderResolver wires the leader's a0 lookup (StaticSecrets.leaderMaster), read by
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
	// The leader resolves a0 from its master cache so the group key pins to the master.
	store := newDKGStore(storage, a.getLeaderSecret)

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
	// A follower has no master, so it never answers GetLeaderSecret (nil resolver).
	store := newDKGStore(storage, nil)

	myHostPub := hostSk.PubKey().SerializeCompressed()

	leaderPubBytes, relayPort, err := followerJoinHandshake(a.leaderURL, myHostPub)
	if err != nil {
		return fmt.Errorf("handshake error: %w", err)
	}
	leaderPub, err := secp.ParsePubKey(leaderPubBytes)
	if err != nil {
		return fmt.Errorf("parse leader pubkey: %w", err)
	}

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
	go func() {
		if err := follower.Serve(context.Background()); err != nil && ctx.Err() == nil {
			slog.Error("follower stopped", "error", err)
		}
	}()

	go func() {
		for out := range follower.Keys() {
			a.handleShare(scalingRoleFollower, out.Label, out.Secshare)
		}
	}()

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
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.authorized[hex.EncodeToString(hostPubkey)]
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
	a.mu.Lock()
	defer a.mu.Unlock()
	a.authorized[hex.EncodeToString(hostPubkey)] = true
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

func (a *ScalingEntity) isLeader() bool {
	return a.role == scalingRoleLeader
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
	if len(res.Document.PublicKey) != 32 {
		return admitRequestData{}, nil, errors.New("bad box public key")
	}
	return req, res.Document.PublicKey, nil
}

// =============================================================================
// Follower (initiator) side
// =============================================================================

// hostFromURL extracts the host (without port) from a base URL such as
// "https://leader:443", used to locate the leader's relay on the same host.
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

// followerJoinHandshake performs the follower side against the leader's HTTP base
// URL (e.g. "https://leader:443"). It returns the leader's host pubkey and the
// relay port to dial (on the leader's host), after mutually verifying
// attestations. myHostPub is the joiner's own threshold host pubkey (33-byte
// compressed).
func followerJoinHandshake(baseURL string, myHostPub []byte) (leaderPub []byte, relayPort string, err error) {
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // see comment
		},
	}

	leaderNonce, err := fetchHandshakeNonce(client, baseURL)
	if err != nil {
		return nil, "", err
	}

	ourNonce := make([]byte, handshakeNonceLen)
	if _, err := rand.Read(ourNonce); err != nil {
		return nil, "", err
	}
	encryptionPubkey, encryptionPrivkey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}

	reqData, err := json.Marshal(admitRequestData{Nonce: ourNonce, HostPub: myHostPub})
	if err != nil {
		return nil, "", err
	}

	ourDoc, err := nitriding.Attest(leaderNonce, reqData, encryptionPubkey[:])
	if err != nil {
		return nil, "", fmt.Errorf("attest: %w", err)
	}

	b64 := base64.StdEncoding.EncodeToString(ourDoc)
	resp, err := client.Post(baseURL+handshakePathAdmit, "text/plain", strings.NewReader(b64))
	if err != nil {
		return nil, "", fmt.Errorf("post admit: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, "", fmt.Errorf("admit rejected: status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}

	leaderAttestationDoc, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		return nil, "", errors.New("bad leader attestation encoding")
	}

	// Dev-aware verification (see verifyFollowerAttestation): mock docs pass in dev.
	res, err := verifyAttestationDoc(leaderAttestationDoc, nil)
	if err != nil {
		return nil, "", fmt.Errorf("verify leader attestation: %w", err)
	}
	ourPCRs, err := nitriding.GetPCRs()
	if err != nil {
		return nil, "", errors.New("read local PCRs")
	}
	if !nitriding.ArePCRsIdenticalForKeys(ourPCRs, res.Document.PCRs, scalingIdentityPCRs) {
		return nil, "", errors.New("leader PCRs differ from ours")
	}
	if !bytes.Equal(res.Document.Nonce, ourNonce) {
		return nil, "", errors.New("leader did not echo our nonce")
	}

	decryptedUserData, ok := box.OpenAnonymous(nil, res.Document.UserData, encryptionPubkey, encryptionPrivkey)
	if !ok {
		return nil, "", errors.New("failed to open sealed leader payload")
	}
	var userData admitResponseData
	if err := json.Unmarshal(decryptedUserData, &userData); err != nil {
		return nil, "", errors.New("malformed leader payload")
	}
	if len(userData.LeaderPub) != 33 || userData.RelayPort == "" {
		return nil, "", errors.New("incomplete leader payload")
	}
	return userData.LeaderPub, userData.RelayPort, nil
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
