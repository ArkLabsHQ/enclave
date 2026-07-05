package runtime

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	sdk "thresholdsdk"
)

// thresholdRecoveryPrefix namespaces threshold recovery blobs in Storage.
const thresholdRecoveryPrefix = "threshold/recovery/"

// DkgStore implements thresholdsdk.Store over the enclave's encrypted
// Storage.
type DkgStore struct {
	storage *Storage
}

// newThresholdStore builds the adapter over the enclave's encrypted Storage.
func newThresholdStore(storage *Storage) *DkgStore {
	return &DkgStore{storage: storage}
}

func (s *DkgStore) recoveryKey(groupKey []byte) string {
	return thresholdRecoveryPrefix + hex.EncodeToString(groupKey)
}

func (s *DkgStore) PutRecovery(groupKey, blob []byte) error {
	return s.storage.Store(context.Background(), s.recoveryKey(groupKey), blob)
}

func (s *DkgStore) GetRecovery(groupKey []byte) ([]byte, error) {
	blob, err := s.storage.Load(context.Background(), s.recoveryKey(groupKey))
	if errors.Is(err, ErrNotFound) {
		return nil, sdk.ErrNotFound
	}
	return blob, err
}

func (s *DkgStore) Has(groupKey []byte) (bool, error) {
	_, err := s.storage.Load(context.Background(), s.recoveryKey(groupKey))
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *DkgStore) List() ([][]byte, error) {
	keys, err := s.storage.List(context.Background(), thresholdRecoveryPrefix)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, len(keys))
	for _, k := range keys {
		gk, derr := hex.DecodeString(strings.TrimPrefix(k, thresholdRecoveryPrefix))
		if derr != nil {
			continue // skip anything that isn't a hex-encoded group key
		}
		out = append(out, gk)
	}
	return out, nil
}

// GetLeaderSecret returns the label's master secret
func (s *DkgStore) GetLeaderSecret(label string) ([]byte, error) {
	v := strings.TrimSpace(os.Getenv(label))
	if v == "" {
		return nil, fmt.Errorf("leader master for %q not loaded", label)
	}
	return hex.DecodeString(v)
}

// Close is a no-op: the underlying Storage lifecycle is owned by the Runtime.
func (s *DkgStore) Close() error { return nil }

// compile-time assertion that the adapter satisfies the SDK interface.
var _ sdk.Store = (*DkgStore)(nil)
