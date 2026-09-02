package runtime

// Auditing the fate of retired per-generation KMS keys. Every enclave
// generation mints its own key and migration is strictly additive, so a retired
// generation keeps a key that can still decrypt state until an operator removes
// it. This file reads that key's lifecycle state so the removal can be observed.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	kmscmd "github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// Audited key states. deleted is the only state that proves a generation can no
// longer decrypt, so it is reachable only from a positive absence signal.
const (
	keyStateExists          = "exists"
	keyStatePendingDeletion = "pending_deletion"
	keyStateDeleted         = "deleted"
	keyStateUnknown         = "unknown"
)

// How a state was established. get_key_policy cannot see a pending deletion, so
// it reports exists for a key that DescribeKey would call pending_deletion.
const (
	checkedViaDescribeKey  = "describe_key"
	checkedViaGetKeyPolicy = "get_key_policy"
	checkedViaNoProbe      = "none"
)

const (
	perKeyProbeTimeout   = 5 * time.Second
	kmsDefaultPolicyName = "default"
)

// KeyStatus is the audited lifecycle state of one KMS key.
type KeyStatus struct {
	State        string
	CheckedVia   string
	DeletionDate *time.Time
	Reason       string
}

// KeyAuditor reports the lifecycle state of an arbitrary KMS key ID. It calls
// only DescribeKey and GetKeyPolicy, never a mutating KMS API.
//
// KeyStatus returns no error: an unreadable key is a reported unknown, never a
// failed request, so a KMS outage cannot take the info endpoint down with it.
type KeyAuditor interface {
	KeyStatus(ctx context.Context, keyID string) KeyStatus
}

// NewKeyAuditor takes KMSAPI rather than KMS because auditing is key-agnostic:
// KMS is bound to one key ID, this reads any of them.
func NewKeyAuditor(api KMSAPI) KeyAuditor {
	return &keyAuditor{kms: api}
}

type keyAuditor struct {
	kms KMSAPI
}

// KeyStatus prefers DescribeKey, which distinguishes a pending deletion from a
// live key. Locked keys minted before DescribeKey was in the key policy deny it,
// so it falls back to GetKeyPolicy, which every key ever minted grants and which
// still tells deleted from present.
func (a *keyAuditor) KeyStatus(ctx context.Context, keyID string) KeyStatus {
	if keyID == "" {
		return KeyStatus{
			State:      keyStateUnknown,
			CheckedVia: checkedViaNoProbe,
			Reason:     "no KMS key ID to probe",
		}
	}
	ctx, cancel := context.WithTimeout(ctx, perKeyProbeTimeout)
	defer cancel()

	status, describeErr := a.describeStatus(ctx, keyID)
	if describeErr == nil {
		return status
	}
	return a.policyStatus(ctx, keyID, describeErr)
}

// describeStatus returns a conclusive status, or the error that means "try
// GetKeyPolicy instead".
func (a *keyAuditor) describeStatus(ctx context.Context, keyID string) (KeyStatus, error) {
	out, err := a.kms.DescribeKey(ctx, &kmscmd.DescribeKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		// Absence is conclusive, and a dead context makes a second call pointless.
		if isKMSNotFound(err) {
			return KeyStatus{State: keyStateDeleted, CheckedVia: checkedViaDescribeKey}, nil
		}
		if ctx.Err() != nil {
			return KeyStatus{
				State:      keyStateUnknown,
				CheckedVia: checkedViaDescribeKey,
				Reason:     fmt.Sprintf("describe_key: %v", err),
			}, nil
		}
		return KeyStatus{}, err
	}
	if out == nil || out.KeyMetadata == nil {
		return KeyStatus{
			State:      keyStateUnknown,
			CheckedVia: checkedViaDescribeKey,
			Reason:     "describe_key returned no key metadata",
		}, nil
	}
	return statusFromMetadata(out.KeyMetadata), nil
}

func statusFromMetadata(md *kmstypes.KeyMetadata) KeyStatus {
	switch md.KeyState {
	case kmstypes.KeyStatePendingDeletion, kmstypes.KeyStatePendingReplicaDeletion:
		return KeyStatus{
			State:        keyStatePendingDeletion,
			CheckedVia:   checkedViaDescribeKey,
			DeletionDate: md.DeletionDate,
		}
	default:
		return KeyStatus{State: keyStateExists, CheckedVia: checkedViaDescribeKey}
	}
}

// policyStatus is the fallback rung. It cannot see a pending deletion, so a key
// awaiting deletion reports exists here — understating deletion progress rather
// than ever claiming a live key is gone.
func (a *keyAuditor) policyStatus(
	ctx context.Context,
	keyID string,
	describeErr error,
) KeyStatus {
	_, err := a.kms.GetKeyPolicy(ctx, &kmscmd.GetKeyPolicyInput{
		KeyId:      aws.String(keyID),
		PolicyName: aws.String(kmsDefaultPolicyName),
	})
	switch {
	case err == nil:
		return KeyStatus{State: keyStateExists, CheckedVia: checkedViaGetKeyPolicy}
	case isKMSNotFound(err):
		return KeyStatus{State: keyStateDeleted, CheckedVia: checkedViaGetKeyPolicy}
	default:
		return KeyStatus{
			State:      keyStateUnknown,
			CheckedVia: checkedViaGetKeyPolicy,
			Reason: fmt.Sprintf(
				"describe_key: %v; get_key_policy: %v", describeErr, err,
			),
		}
	}
}

// isKMSNotFound reports the one signal that proves a key is gone. Nothing else
// may produce keyStateDeleted.
func isKMSNotFound(err error) bool {
	var notFound *kmstypes.NotFoundException
	return errors.As(err, &notFound)
}
