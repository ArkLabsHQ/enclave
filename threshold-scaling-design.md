# Threshold-shared static secrets for horizontal enclave scaling

## Implementation status (2026-07-01)

Done + green across `threshold-magic` and the enclave repo (all unit tests pass;
one known-red: `TestCLI_Build`, the real Nix EIF build, pending the deferred
module-publish + `vendorHash`):
- **A** Store decoupled from BadgerDB (`thresholdsdk/badgerstore`).
- **B** `WithAuthorize` hook on `NewLeader` (+ tests).
- **C** `kind: signing` config field + validation (+ tests).
- **E** leader/follower wiring `runtime/threshold_secret.go`; exported
  `thresholdcore.LeaderGroupPubkey(a0)` (verified against real ceremonies) so the
  master publishes the taproot-tweaked group key without a DKG.
- **F** `runtime/threshold_store.go` (Store over encrypted S3+DEK).
- **G** attested admission handshake `runtime/threshold_handshake.go` (leader
  responder `/enclave/threshold/{nonce,admit}` + follower initiator; mutual PCR
  attestation, NaCl-sealed payload, one-shot nonces) + `nitriding.GetPCRs`.
- **D** `LoadAll`/`ExtendPCRs` skip threshold secrets; setup phase in `Init`.
- **I** deps wired via local `replace` + vendored (Nix deferred by decision).
- Enclave-side discovery: follower reads leader URL from SSM
  (`thresholdLeaderParam`) with env override.

Remaining — **H (host-side infra, untestable here):** master supervisor publishes
the leader handshake URL to `…/Threshold/Leader` SSM; add the relay port to
`GVPROXY_FORWARD_PORTS`; tofu leader-only target group + SG rules.

## Context / problem

Today, scaling enclaves horizontally means **every replica independently pulls
the same full static secret** from KMS/SSM. Each secret is a random 32-byte
value, KMS-wrapped, decrypted at boot via NSM attestation, injected as a hex env
var (`runtime/static_secret.go`). Consequence: **every joiner holds the entire
secret** — compromise one replica, leak the whole key. There is also an unused
attested keysync initiator (`RequestKeys`, `runtime/nitriding/keysync_initiator.go`)
that only moves an opaque blob.

## Goal

For a secret **tagged `signing`**: the **master** creates the secret
normally (existing KMS path), then acts as a `threshold-sdk` **leader** and
splits it into Shamir shares. Master keeps its own share; each **joiner**
receives *its own share* as the secret. A **majority** (`t = ⌊n/2⌋+1`)
reconstructs/signs. **Untagged secrets are unchanged.** Leader sits **behind a
load balancer**; `signing` is the only threshold kind.

## The insight that keeps threshold-sdk unmodified

`thresholdsdk.Leader` takes its group secret `a0` from `store.GetLeaderSecret()`
(`threshold_sdk/leader.go:124`); followers contribute the identity element. So if
our `Store` adapter returns the **master's KMS-decrypted static secret** as the
leader secret, the group's reconstructed secret *is* the normally-created
secret. No change to threshold-sdk crypto is required for secret injection.

## Design (6 parts)

### 1. Tag secrets — add `kind` field
- `SecretConfig` (`cli/config.go:104`)
- `buildConfigSecretJSON` (`cli/build.go:52`)
- `StaticSecret` (`runtime/static_secret.go:31`)

each get `Kind string`. Valid values: `""` / `static` / `signing`.
`ENCLAVE_SECRETS_CONFIG` JSON carries it automatically (no `flake.nix` change).
Surface the field in the `cli/init.go` template and `cli/tofu.go`.

### 2. Runtime branch in `LoadAll` / `LoadOrGenerate` (`runtime/static_secret.go:95`)
- untagged → existing path (unchanged)
- `signing`, **master role** → creates/loads the secret via the existing
  KMS path; app env var = **full secret** (hex), exactly as today. The master
  additionally runs the threshold leader (part 3), seeding `a0` = this full
  secret and storing its own share.
- `signing`, **joiner role** → does **not** fetch the full secret from KMS;
  obtains **its own share** from the leader and sets the app env var = **share**
  (hex).
- Both roles expose a companion `<ENVVAR>_GROUP_PUBKEY`. `ExtendPCRs` extends
  with the **group pubkey** (fleet-identical), not the per-node share/secret.

### 3. Role wiring — new `runtime/threshold_secret.go`
- role via env `ENCLAVE_SCALING_ROLE` (leader|follower); the leader's relay
  address is discovered via the supervisor-brokered channel (part 7), **not** a
  hardcoded env. The joiner does **not** need a pre-shared leader pubkey — it
  pins the leader's threshold host pubkey during the attested handshake (part 5).
- master → `NewLeader(hostSk, tapListenAddr, store, WithAuthorize(admitFn))`,
  `go l.Serve(ctx)`; `tapListenAddr` = `192.168.127.2:<relayPort>` (the TAP iface,
  so the supervisor's gvproxy forward exposes it).
- joiner → read leader relay address (part 7) → attested handshake to leader
  (part 5) → `NewJoiningFollower(hostSk, relayAddr, leaderPub, store)`,
  `go f.Serve(ctx)`, read share from `f.Keys()` (`BIPDKGOutput.Secshare`) +
  `ThresholdPubkey`.
- `hostSk` = ephemeral per-boot secp256k1 (re-DKG on every membership change
  makes ephemeral host keys safe).

### 4a. Decouple `Store` from BadgerDB in threshold-sdk (prerequisite)
`thresholdsdk.Store` is already an interface, but the **BadgerDB implementation
lives in the same package** (`threshold_sdk/store.go` imports
`github.com/dgraph-io/badger/v4`). Go compiles per-package, so **any** importer of
`thresholdsdk` — and the enclave runtime must import it for `NewLeader` /
`NewJoiningFollower` — transitively pulls badger in, even though the enclave
never uses it. Fix in the threshold-magic repo:
- Keep in package `thresholdsdk` (`store.go`): only the `Store` interface,
  `ErrNotFound`, and the `recovery/` / `leader/secret` key constants. **No badger
  import.**
- Move `badgerStore` + `OpenBadgerStore` into a new subpackage
  `threshold_sdk/badgerstore` exposing `Open(path) (thresholdsdk.Store, error)`.
  Only this package imports badger.
- Update the three callers to `badgerstore.Open(...)`:
  `threshold_sdk/leader_test.go` (3 sites), `integration/cmd/dkgnode/main.go`.

Result: importing `thresholdsdk` links **zero** badger; the enclave provides its
own `Store`.

### 4b. `Store` adapter over enclave storage — new `runtime/threshold_store.go`
Implement the (now badger-free) `Store` interface (`threshold_sdk/store.go`) over
the existing encrypted `Storage` (S3 + AES-GCM DEK):
- `GetLeaderSecret()` → **the master's KMS-decrypted static secret** (the crux)
- `PutRecovery`/`GetRecovery`/`Has`/`List` → `Storage.Store/Load/List` under a
  reserved `threshold/` prefix

### 5. Attestation-gated admission (security binding)
threshold-sdk's `handleJoin` (`threshold_sdk/leader.go:379`) only checks a BIP340
proof-of-possession — it does **not** verify the joiner is a genuine same-PCR0
enclave. Bind the two:

**Upstream hook (threshold-magic repo).** Add an optional authorization callback
to the leader — `WithAuthorize(func(hostPubkey []byte) bool) Option` passed to
`NewLeader` (variadic option, non-breaking for existing callers), stored on
`Leader`. In `handleJoin`, right after `verifyJoinProof` succeeds
(`leader.go:384`) and before assigning an identifier, reject when
`l.authorize != nil && !l.authorize(hostPubkey)`. Nil callback = today's
behavior.

**Enclave side — who serves the handshake.** The responder does **not** exist
today (only the initiator `RequestKeys` in `keysync_initiator.go`). It is owned
by the **runtime**, served on the **external server** (`pubSrv`, `ExtPort`,
vsock/TCP — `runtime.go:574-621`), because peers reach each other over the
network; the internal server is loopback-only (`127.0.0.1:IntPort`) and
unreachable by peers. Add two threshold-admission endpoints there (separate from
the generic `/enclave/state` keysync so semantics stay clean), enabled only when
`ENCLAVE_SCALING_ROLE=leader`:
- `GET /enclave/threshold/nonce` → fresh nonce (existing `keysync_shared` nonce).
- `POST /enclave/threshold/admit` → verify the joiner's attestation
  (`nitrite.Verify` + `arePCRsIdentical` vs our PCRs), extract the joiner's
  threshold host pubkey from the attested payload, **add it to the authorized
  set** the `WithAuthorize` hook consults, and return the leader's own
  attestation (`nitriding.Attest`) whose user-data carries — encrypted to the
  joiner's NaCl box key via `box.SealAnonymous` — the **leader's threshold host
  pubkey** and the relay address.

The joiner runs the initiator side (reuse `keysync_initiator.go`): it verifies
the leader's attestation (PCR0-equality) before trusting the returned leaderPub,
so trust is **mutual** and no key is pre-shared. A PCR-mismatched joiner is never
authorized, so its subsequent gRPC `Join` is refused by the hook.

### 6. Deps + Nix build
Add `thresholdsdk` (+ `thresholdcore`) to `runtime/go.mod` pinned to a commit (or
dev `replace` → local path). With the store split (part 4a) the runtime links
**grpc but not badger**. Update `vendorHash` in enclave `flake.nix` (known
gitignored-vendor gotcha: set `""`, read expected hash from the build error).

### 7. Discovery + channel — brokered by the supervisor (host-side)
**Deployment topology: each enclave runs on its own EC2 instance (separate
computer), each with its own supervisor + gvproxy. There is no shared host.** All
leader↔joiner traffic is **cross-instance over the VPC**:
```
joiner enclave → joiner host gvproxy (egress NAT) → VPC
  → master host (private IP / leader-only LB) → master gvproxy (inbound forward)
  → master enclave relay listener 192.168.127.2:<relayPort>
```
The **supervisor** sets up the channel because only it can: it runs gvproxy,
owns host AWS creds (SSM/S3/DynamoDB), and knows the instance's VPC address. The
enclave runtime keeps only the crypto/attestation.

**Critical addressing rule.** Leader-directed traffic — **both** the part-5
attested handshake **and** the gRPC relay — must target the **master
specifically**, never a round-robin app load balancer (that would land on the
wrong instance). So joiners use the master's **published address** (its VPC
private IP, or a dedicated *leader-only* target group health-checked to the
current master), distinct from the app LB that fronts client traffic.

**Master supervisor**
- **Expose the relay port.** Dedicated TCP port (e.g. `9000`). Add it to
  `GVPROXY_FORWARD_PORTS` (`"443"` → `"443 9000"`, `supervisor/networking.go:125`
  + `user_data.sh.tftpl` / tofu env) so gvproxy forwards host `:9000` → enclave
  TAP `192.168.127.2:9000`. The attested-handshake HTTP endpoints (part 5) are on
  the enclave's `ExtPort` (443), also reached via the master's specific address.
- **Publish the leader address.** Write the master's VPC-reachable address (+
  handshake port + relay port) to SSM
  `/{deployment}/{appName}/{lock}/Threshold/Leader` (JSON:
  `{addr, handshakePort, relayPort, epoch, updated_at}`). SSM is regional, so
  discovery is inherently cross-instance.

**Joiner side (different instance)**
- The joiner **enclave runtime** reads `Threshold/Leader` from SSM (existing SSM
  egress via gvproxy + IAM), then runs the part-5 handshake and part-3 follower
  join **against the master's published address**.
- Egress is normal outbound NAT; the security group **already allows
  self-referencing inter-enclave TCP**, which covers instance-to-instance traffic
  within the same SG across the VPC — open the relay + handshake ports on it.

**Leader identity.** The master is a **designated** role
(`ENCLAVE_SCALING_ROLE=leader`), not elected — its supervisor publishes the
channel; joiners consume it. Dynamic election / failover (first-boot-wins via SSM
or the deployed DynamoDB KV table + heartbeat, updating `Threshold/Leader`) is
the documented upgrade path, out of scope this pass.

**Infra (tofu) additions:** relay port in `GVPROXY_FORWARD_PORTS`; a
**leader-only** target group/LB (or direct private-IP addressing) for the
handshake + relay ports pointing at the master — *not* the app LB; SG rules for
both ports across the self-referencing group.

## Decisions taken (please confirm / correct)

- **Master app gets the full secret; joiner apps get their share** (+ companion
  group-pubkey var on both). The master's KMS secret doubles as the threshold
  `a0`, so a majority of joiner shares reconstructs exactly the master's secret.
- **Static leader** (the master); leader loss ⇒ re-bootstrap. Leader-HA /
  failover is out of scope for this pass.

## Files

- New (enclave repo): `runtime/threshold_secret.go`, `runtime/threshold_store.go`,
  threshold-admission handlers in `runtime/runtime_handlers.go` (+ routes on the
  external mux in `runtime/runtime.go:574-621`)
- Modify (enclave repo): `runtime/static_secret.go`, `cli/config.go`,
  `cli/build.go`, `cli/init.go`, `cli/tofu.go`, `runtime/go.mod`, enclave
  `flake.nix`
- **Supervisor + infra (enclave repo)**: publish/read `Threshold/Leader` SSM
  param (`supervisor/`), add relay port to `GVPROXY_FORWARD_PORTS`
  (`supervisor/networking.go` + `user_data.sh.tftpl`); tofu: LB listener/target
  group for the relay port, SG rule check (`tofu/modules/enclave/`)
- **threshold-magic repo**:
  - new package `threshold_sdk/badgerstore/` (move `badgerStore` +
    `OpenBadgerStore` here); trim `threshold_sdk/store.go` to the interface only
    (drop badger import); update callers `leader_test.go`,
    `integration/cmd/dkgnode/main.go`
  - `WithAuthorize` option + `authorize` field on `Leader`, checked in
    `handleJoin` (`threshold_sdk/leader.go`)

## Verification

1. **Unit**: `kind` validation; a `Store` returning a fixed leader secret yields a
   group pubkey deterministic from that secret; a majority of shares reconstructs
   it (`thresholdcore.Reconstruct`).
2. **Threshold semantics** (mirror `TestDockerLeaderFollowerDKG`): master + N
   joiners in-process; assert `n = 2..N`, `t = ⌊n/2⌋+1`, group key **stable**
   across joins, each joiner's share reconstructs the master's secret.
3. **Attestation gate**: a PCR-mismatched follower is rejected before `Join`
   (bad attestation at `/enclave/threshold/admit` ⇒ host pubkey never authorized
   ⇒ `WithAuthorize` refuses the gRPC join).
4. **Discovery/channel**: master supervisor publishes `Threshold/Leader` to SSM
   and gvproxy forwards the relay port; a joiner reads the param, reaches the
   relay through the LB, and completes the handshake.
5. **End-to-end**: QEMU/KVM enclave boot (`test/`) with a `kind: signing` secret —
   master boots, one joiner obtains a share via the discovered relay address, both
   expose the same `_GROUP_PUBKEY`, and an untagged secret still loads via the
   unchanged KMS path.
6. **Build**: `go build -o /tmp/enclave ./cli/cmd/enclave` + full
   `nix build --impure` of the EIF (validates new deps + `vendorHash`).
