package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nitrite"
	"github.com/spf13/cobra"
)

const (
	lineagePrefix           = "lineage/"
	lineageSchemaV1         = "enclave.pcr0_lineage.v1"
	lineagePurposeGenesis   = "genesis"
	lineagePurposeMigration = "migration"
)

// lineageEntryV1 mirrors runtime/lineage.go; the cbor tags must stay in sync.
type lineageEntryV1 struct {
	Schema          string `cbor:"schema"`
	Purpose         string `cbor:"purpose"`
	PrevPCR0        string `cbor:"prev_pcr0"`
	SelfPCR0        string `cbor:"self_pcr0"`
	SelfAttestation string `cbor:"self_attest"`
	PrevAttestation string `cbor:"prev_attest"`
	Descriptor      []byte `cbor:"descriptor,omitempty"`
	Timestamp       int64  `cbor:"ts"`
}

func verifyLineageCmd() *cobra.Command {
	var genesisPCR0, currentPCR0, bucketFlag, baseURL, descriptorFile string
	var strictTLS bool
	cmd := &cobra.Command{
		Use:   "verify-lineage",
		Short: "Verify the immutable PCR0 version-lineage chain",
		Long: "Reads the Object-Lock lineage log from S3 and verifies the unbroken,\n" +
			"AWS-Nitro-attested chain of EIF versions from the pinned genesis PCR0 to\n" +
			"the current head. Each link is verified against the AWS Nitro root.\n" +
			"With --descriptor deployment.json, runs credential-less (anonymous public-bucket\n" +
			"reads) and verifies the genesis-attested descriptor — usable by any party. With\n" +
			"--base-url, also attests the live enclave and binds it to the chain head via\n" +
			"its PCR0.\n" +
			"The dev deployment skips the Nitro signature check (mock NSM, no AWS root).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runVerifyLineage(cmd.Context(), lineageOpts{
				genesisPCR0: genesisPCR0, currentPCR0: currentPCR0, bucket: bucketFlag,
				baseURL: baseURL, strictTLS: strictTLS, descriptorFile: descriptorFile,
			})
		},
	}
	cmd.Flags().StringVar(&descriptorFile, "descriptor", "", "Pinned deployment-descriptor.json — credential-less anonymous reads (overrides --genesis-pcr0/--lineage-bucket)")
	cmd.Flags().StringVar(&genesisPCR0, "genesis-pcr0", "", "Pinned genesis PCR0 hex — the root of trust (required unless --descriptor)")
	cmd.Flags().StringVar(&currentPCR0, "current-pcr0", "", "Expected head PCR0 hex (optional; asserted if set)")
	cmd.Flags().StringVar(&bucketFlag, "lineage-bucket", "", "Lineage bucket name (default: SSM LineageBucketName)")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Live enclave URL — bind it to the chain head via PCR0 (optional)")
	cmd.Flags().BoolVar(&strictTLS, "strict-tls", false, "Require a CA-signed TLS cert when attesting --base-url")
	return cmd
}

type lineageOpts struct {
	genesisPCR0, currentPCR0, bucket, baseURL, descriptorFile string
	region                                                    string
	strictTLS, skipSig                                        bool
}

// deploymentDescriptor mirrors runtime/descriptor.go: cbor tags match the attested
// blob in the genesis lineage entry; json tags match the out-of-band file.
type deploymentDescriptor struct {
	Schema        string `cbor:"schema" json:"schema"`
	Deployment    string `cbor:"deployment" json:"deployment"`
	App           string `cbor:"app" json:"app"`
	Region        string `cbor:"region" json:"region"`
	GenesisPCR0   string `cbor:"genesis_pcr0" json:"genesis_pcr0"`
	AnchorBucket  string `cbor:"anchor_bucket" json:"anchor_bucket"`
	LineageBucket string `cbor:"lineage_bucket" json:"lineage_bucket"`
}

func runVerifyLineage(ctx context.Context, opts lineageOpts) error {
	s3c, desc, err := resolveLineageSource(ctx, &opts)
	if err != nil {
		return err
	}
	if opts.genesisPCR0 == "" {
		return fmt.Errorf("need --genesis-pcr0 or --descriptor")
	}
	if opts.bucket == "" {
		return fmt.Errorf("lineage bucket not found (set --lineage-bucket, --descriptor, or provision LineageBucketName)")
	}
	genesisPCR0, currentPCR0 := opts.genesisPCR0, opts.currentPCR0

	if opts.skipSig {
		fmt.Fprintln(os.Stderr, "[verify-lineage] WARNING: dev deployment — NOT verifying AWS Nitro signatures (mock NSM)")
	}
	entries, skipped, err := loadLineageEntries(ctx, s3c, opts.bucket, opts.skipSig)
	if err != nil {
		return err
	}
	for _, s := range skipped {
		fmt.Fprintf(os.Stderr, "[verify-lineage] skipped unverifiable entry: %v\n", s)
	}

	chain, err := walkLineage(entries, genesisPCR0)
	if err != nil {
		return err
	}

	head := chain[len(chain)-1].SelfPCR0
	if currentPCR0 != "" && !strings.EqualFold(head, currentPCR0) {
		return fmt.Errorf("chain head %s does not match expected current PCR0 %s", head, currentPCR0)
	}

	// The genesis entry must attest exactly the pinned descriptor (binding the buckets
	// to the genesis enclave). With a descriptor this is the credential-less trust root.
	if desc != nil {
		if err := verifyGenesisDescriptor(entries, genesisPCR0, desc, opts.skipSig); err != nil {
			return fmt.Errorf("genesis descriptor: %w", err)
		}
	}

	for i, e := range chain {
		ts := time.Unix(e.Timestamp, 0).UTC().Format(time.RFC3339)
		if i == 0 {
			fmt.Printf("[verify-lineage] genesis    %s (%s)\n", e.SelfPCR0, ts)
		} else {
			fmt.Printf("[verify-lineage]   → %-9s %s (%s)\n", e.Purpose, e.SelfPCR0, ts)
		}
	}
	fmt.Printf("[verify-lineage] chain verified: %d version(s), unbroken from pinned genesis to head %s.\n", len(chain), head)
	if desc != nil {
		fmt.Println("[verify-lineage] genesis descriptor attested — canonical buckets bound to genesis.")
	}
	if currentPCR0 != "" {
		fmt.Printf("[verify-lineage] head matches expected current PCR0.\n")
	}

	if opts.baseURL != "" {
		if err := bindLiveEnclaveToHead(opts, chain[len(chain)-1]); err != nil {
			return fmt.Errorf("bind live enclave to chain head: %w", err)
		}
	}
	return nil
}

// resolveLineageSource picks the lineage source: a pinned descriptor (credential-less,
// anonymous public-bucket reads — the trust root is the out-of-band file) or, falling
// back, the local config + SSM bucket lookup (operator-side, with credentials).
func resolveLineageSource(ctx context.Context, opts *lineageOpts) (*s3.Client, *deploymentDescriptor, error) {
	if opts.descriptorFile != "" {
		desc, err := loadDescriptor(opts.descriptorFile)
		if err != nil {
			return nil, nil, err
		}
		opts.genesisPCR0 = desc.GenesisPCR0
		opts.bucket = desc.LineageBucket
		opts.region = desc.Region
		opts.skipSig = strings.EqualFold(desc.Deployment, "dev")
		s3c, err := newAnonymousS3Client(ctx, desc.Region)
		if err != nil {
			return nil, nil, err
		}
		fmt.Printf("[verify-lineage] pinned descriptor: %s/%s genesis=%s (anonymous, credential-less)\n", desc.Deployment, desc.App, prefix16(desc.GenesisPCR0))
		return s3c, desc, nil
	}

	cfg, err := loadConfig()
	if err != nil {
		return nil, nil, err
	}
	ac, err := newAWSClients(ctx, cfg.Region, cfg.Profile)
	if err != nil {
		return nil, nil, err
	}
	deployment := cfg.Deployment
	if deployment == "" {
		deployment = "dev"
	}
	opts.skipSig = strings.EqualFold(deployment, "dev")
	if opts.bucket == "" {
		opts.bucket = readSSMParamSilent(ctx, ac.ssmClient, deployment, cfg.Name, "LineageBucketName")
	}
	return ac.s3Client, nil, nil
}

func loadDescriptor(path string) (*deploymentDescriptor, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read descriptor: %w", err)
	}
	var d deploymentDescriptor
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("parse descriptor: %w", err)
	}
	if d.GenesisPCR0 == "" || d.LineageBucket == "" {
		return nil, fmt.Errorf("descriptor missing genesis_pcr0 / lineage_bucket")
	}
	return &d, nil
}

func prefix16(s string) string {
	if len(s) > 16 {
		return s[:16] + "..."
	}
	return s
}

// bindLiveEnclaveToHead proves the live enclave runs the chain-head version: the PCR0
// in its live AWS-Nitro attestation must equal the head entry's PCR0. A same-PCR0
// enclave is the head version by definition; a different version fails here.
func bindLiveEnclaveToHead(opts lineageOpts, head lineageEntryV1) error {
	client := verifyHTTPClient(!opts.strictTLS)

	livePCRs, err := liveAttestationPCRs(client, opts.baseURL, opts.skipSig)
	if err != nil {
		return fmt.Errorf("attest live enclave: %w", err)
	}
	livePCR0, ok := livePCRs[0]
	if !ok {
		return fmt.Errorf("live enclave attestation missing PCR0")
	}
	if !strings.EqualFold(hex.EncodeToString(livePCR0), head.SelfPCR0) {
		return fmt.Errorf("live enclave PCR0 %s does not match chain head %s — possible evil-twin lineage",
			hex.EncodeToString(livePCR0), head.SelfPCR0)
	}

	fmt.Printf("[verify-lineage] live enclave bound to chain head via PCR0 %s.\n", head.SelfPCR0)
	return nil
}

// liveAttestationPCRs fetches the live enclave's attestation document and returns its
// PCR map. skipSig (dev) parses it without the AWS Nitro signature check.
func liveAttestationPCRs(client *http.Client, baseURL string, skipSig bool) (map[uint][]byte, error) {
	nonce := make([]byte, 20)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	url := strings.TrimRight(baseURL, "/") + "/enclave/attestation?nonce=" + hex.EncodeToString(nonce)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	docB64 := strings.TrimSpace(string(payload))
	if strings.HasPrefix(docB64, "{") {
		var parsed struct {
			Document string `json:"document"`
		}
		if json.Unmarshal(payload, &parsed) == nil && parsed.Document != "" {
			docB64 = parsed.Document
		}
	}
	raw, err := base64.StdEncoding.DecodeString(docB64)
	if err != nil {
		return nil, fmt.Errorf("decode attestation document: %w", err)
	}
	return attestationPCRs(raw, skipSig)
}

// loadLineageEntries lists and Nitro-verifies every lineage object version, returning
// the valid entries keyed by lowercase self-PCR0 (first valid wins); rest are skipped.
func loadLineageEntries(ctx context.Context, s3c *s3.Client, bucket string, skipSig bool) (map[string]lineageEntryV1, []error, error) {
	valid := map[string]lineageEntryV1{}
	var skipped []error
	var keyMarker, verMarker *string
	for {
		out, err := s3c.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket:          aws.String(bucket),
			Prefix:          aws.String(lineagePrefix),
			KeyMarker:       keyMarker,
			VersionIdMarker: verMarker,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("list lineage objects: %w", err)
		}
		for _, v := range out.Versions {
			key := aws.ToString(v.Key)
			body, err := getS3ObjectVersion(ctx, s3c, bucket, key, aws.ToString(v.VersionId))
			if err != nil {
				skipped = append(skipped, fmt.Errorf("%s: %w", key, err))
				continue
			}
			var e lineageEntryV1
			if err := cbor.Unmarshal(body, &e); err != nil || e.Schema != lineageSchemaV1 {
				skipped = append(skipped, fmt.Errorf("%s: not a valid lineage entry", key))
				continue
			}
			if err := verifyLineageEntry(e, skipSig); err != nil {
				skipped = append(skipped, fmt.Errorf("%s: %w", key, err))
				continue
			}
			if _, ok := valid[strings.ToLower(e.SelfPCR0)]; !ok {
				valid[strings.ToLower(e.SelfPCR0)] = e
			}
		}
		if !aws.ToBool(out.IsTruncated) {
			break
		}
		keyMarker, verMarker = out.NextKeyMarker, out.NextVersionIdMarker
	}
	return valid, skipped, nil
}

func getS3ObjectVersion(ctx context.Context, s3c *s3.Client, bucket, key, versionID string) ([]byte, error) {
	out, err := s3c.GetObject(ctx, &s3.GetObjectInput{
		Bucket:    aws.String(bucket),
		Key:       aws.String(key),
		VersionId: aws.String(versionID),
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = out.Body.Close() }()
	return io.ReadAll(out.Body)
}

// verifyLineageEntry checks the entry's attestations: the self-attestation must carry
// PCR0 == SelfPCR0; a migration entry's predecessor must carry PCR0 == PrevPCR0 and
// PCR31 == SHA384(0⁴⁸ ‖ SelfPCR0). skipSig skips only the AWS Nitro signature check.
func verifyLineageEntry(e lineageEntryV1, skipSig bool) error {
	if _, err := attestedPCRs(e.SelfAttestation, e.SelfPCR0, skipSig); err != nil {
		return fmt.Errorf("self-attestation: %w", err)
	}
	if e.Purpose != lineagePurposeMigration {
		return nil
	}
	pcrs, err := attestedPCRs(e.PrevAttestation, e.PrevPCR0, skipSig)
	if err != nil {
		return fmt.Errorf("predecessor attestation: %w", err)
	}
	pcr31, ok := pcrs[31]
	if !ok {
		return fmt.Errorf("predecessor attestation missing PCR31")
	}
	want, err := pcr31Commitment(e.SelfPCR0)
	if err != nil {
		return err
	}
	if !bytes.Equal(pcr31, want) {
		return fmt.Errorf("predecessor PCR31 does not commit to successor %s", e.SelfPCR0)
	}
	return nil
}

// attestedPCRs returns a base64 attestation's PCR map after asserting its PCR0 equals
// expectedPCR0. Unless skipSig is set, the doc is verified against the AWS Nitro root.
func attestedPCRs(attestB64, expectedPCR0 string, skipSig bool) (map[uint][]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(attestB64)
	if err != nil {
		return nil, fmt.Errorf("decode attestation: %w", err)
	}
	pcrs, err := attestationPCRs(raw, skipSig)
	if err != nil {
		return nil, err
	}
	pcr0, ok := pcrs[0]
	if !ok {
		return nil, fmt.Errorf("attestation missing PCR0")
	}
	if !strings.EqualFold(hex.EncodeToString(pcr0), expectedPCR0) {
		return nil, fmt.Errorf("attested PCR0 %s != expected %s", hex.EncodeToString(pcr0), expectedPCR0)
	}
	return pcrs, nil
}

// attestationPCRs extracts the PCR map from a raw COSE Sign1 attestation document.
// Verified mode checks the AWS Nitro signature (zero time skips expiry — entries are
// historical); skipSig mode parses the doc WITHOUT verifying the signature (dev only,
// for QEMU mock attestations).
func attestationPCRs(raw []byte, skipSig bool) (map[uint][]byte, error) {
	if skipSig {
		return decodeUnverifiedPCRs(raw)
	}
	res, err := nitrite.Verify(raw, nitrite.VerifyOptions{})
	if err != nil && (res == nil || !res.SignatureOK) {
		return nil, fmt.Errorf("attestation verification failed: %w", err)
	}
	if res == nil || res.Document == nil {
		return nil, fmt.Errorf("attestation missing document")
	}
	return res.Document.PCRs, nil
}

// decodeUnverifiedPCRs parses a COSE Sign1 envelope (CBOR array; payload at index 2 is
// the attestation document) and returns its PCR map, WITHOUT checking the signature.
func decodeUnverifiedPCRs(raw []byte) (map[uint][]byte, error) {
	var cose []cbor.RawMessage
	if err := cbor.Unmarshal(raw, &cose); err != nil {
		return nil, fmt.Errorf("unmarshal COSE Sign1: %w", err)
	}
	if len(cose) < 3 {
		return nil, fmt.Errorf("invalid COSE Sign1 structure")
	}
	var payload []byte
	if err := cbor.Unmarshal(cose[2], &payload); err != nil {
		return nil, fmt.Errorf("unmarshal COSE payload: %w", err)
	}
	var doc struct {
		PCRs map[uint][]byte `cbor:"pcrs"`
	}
	if err := cbor.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("unmarshal attestation document: %w", err)
	}
	if doc.PCRs == nil {
		return nil, fmt.Errorf("attestation document has no PCRs")
	}
	return doc.PCRs, nil
}

func pcr31Commitment(pcr0Hex string) ([]byte, error) {
	b, err := hex.DecodeString(pcr0Hex)
	if err != nil {
		return nil, fmt.Errorf("decode PCR0 hex: %w", err)
	}
	sum := sha512.Sum384(append(make([]byte, 48), b...))
	return sum[:], nil
}

// walkLineage follows prev→self edges from the pinned genesis to the head,
// rejecting a missing root, a fork (one version with two successors), or a cycle.
func walkLineage(entries map[string]lineageEntryV1, genesisPCR0 string) ([]lineageEntryV1, error) {
	edges := map[string][]lineageEntryV1{}
	for _, e := range entries {
		if e.PrevPCR0 != "" {
			p := strings.ToLower(e.PrevPCR0)
			edges[p] = append(edges[p], e)
		}
	}

	root, ok := entries[strings.ToLower(genesisPCR0)]
	if !ok {
		return nil, fmt.Errorf("no verified lineage entry for pinned genesis %s", genesisPCR0)
	}

	chain := []lineageEntryV1{root}
	seen := map[string]bool{strings.ToLower(root.SelfPCR0): true}
	cur := strings.ToLower(root.SelfPCR0)
	for {
		next := edges[cur]
		if len(next) == 0 {
			break
		}
		if len(next) > 1 {
			return nil, fmt.Errorf("fork at %s: %d successors authorized — lineage is not a single chain", cur, len(next))
		}
		ns := strings.ToLower(next[0].SelfPCR0)
		if seen[ns] {
			return nil, fmt.Errorf("cycle detected at %s", ns)
		}
		chain = append(chain, next[0])
		seen[ns] = true
		cur = ns
	}
	return chain, nil
}

// verifyGenesisDescriptor checks the genesis entry attests exactly the pinned
// descriptor: its self-attestation's user_data == sha256(entry.Descriptor), and the
// attested descriptor's fields match the pinned file. Trust root for the pinned path.
func verifyGenesisDescriptor(entries map[string]lineageEntryV1, genesisPCR0 string, pinned *deploymentDescriptor, skipSig bool) error {
	g, ok := entries[strings.ToLower(genesisPCR0)]
	if !ok {
		return fmt.Errorf("no verified genesis entry for %s", genesisPCR0)
	}
	if len(g.Descriptor) == 0 {
		return fmt.Errorf("genesis entry carries no descriptor (recorded before this feature)")
	}
	ud, err := attestationUserData(g.SelfAttestation, skipSig)
	if err != nil {
		return fmt.Errorf("read genesis self-attestation user_data: %w", err)
	}
	want := sha256.Sum256(g.Descriptor)
	if !bytes.Equal(ud, want[:]) {
		return fmt.Errorf("descriptor not bound in the genesis attestation user_data")
	}
	var attested deploymentDescriptor
	if err := cbor.Unmarshal(g.Descriptor, &attested); err != nil {
		return fmt.Errorf("decode attested descriptor: %w", err)
	}
	if attested.GenesisPCR0 != pinned.GenesisPCR0 || attested.AnchorBucket != pinned.AnchorBucket ||
		attested.LineageBucket != pinned.LineageBucket || attested.Region != pinned.Region ||
		attested.Deployment != pinned.Deployment || attested.App != pinned.App {
		return fmt.Errorf("pinned descriptor does not match the genesis-attested one")
	}
	return nil
}

// attestationUserData returns a base64 attestation's user_data; skipSig parses without
// verifying the AWS Nitro signature (dev mock).
func attestationUserData(attestB64 string, skipSig bool) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(attestB64)
	if err != nil {
		return nil, fmt.Errorf("decode attestation: %w", err)
	}
	if skipSig {
		var cose []cbor.RawMessage
		if err := cbor.Unmarshal(raw, &cose); err != nil || len(cose) < 3 {
			return nil, fmt.Errorf("invalid COSE Sign1 structure")
		}
		var payload []byte
		if err := cbor.Unmarshal(cose[2], &payload); err != nil {
			return nil, fmt.Errorf("unmarshal COSE payload: %w", err)
		}
		var doc struct {
			UserData []byte `cbor:"user_data"`
		}
		if err := cbor.Unmarshal(payload, &doc); err != nil {
			return nil, fmt.Errorf("unmarshal attestation document: %w", err)
		}
		return doc.UserData, nil
	}
	res, err := nitrite.Verify(raw, nitrite.VerifyOptions{})
	if err != nil && (res == nil || !res.SignatureOK) {
		return nil, fmt.Errorf("attestation verification failed: %w", err)
	}
	if res == nil || res.Document == nil {
		return nil, fmt.Errorf("attestation missing document")
	}
	return res.Document.UserData, nil
}
