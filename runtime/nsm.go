package runtime

import (
	"bytes"
	"crypto/sha512"
	"fmt"
	"log/slog"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

// Nsm holds an open Nitro Security Module session for a batch of PCR operations.
// Not safe for concurrent use: open one with NewNsm, run the ops on a single
// goroutine, and Close it (defer).
type Nsm struct {
	session *nsm.Session
}

// NewNsm opens an NSM session. The caller must Close it.
func NewNsm() (*Nsm, error) {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, fmt.Errorf("open NSM session: %w", err)
	}
	return &Nsm{session: session}, nil
}

// Close releases the NSM session.
func (n *Nsm) Close() error {
	return n.session.Close()
}

// lockPCR pins a PCR so further extendPCR calls are rejected by the NSM.
func (n *Nsm) lockPCR(index uint) error {
	resp, err := n.session.Send(&request.LockPCR{Index: uint16(index)})
	if err != nil {
		return fmt.Errorf("LockPCR(%d): %w", index, err)
	}
	if resp.Error != "" {
		return fmt.Errorf("LockPCR(%d): NSM error: %s", index, resp.Error)
	}
	return nil
}

// extendPCR appends data to PCR[index]'s rolling hash.
func (n *Nsm) extendPCR(index uint, data []byte) error {
	resp, err := n.session.Send(&request.ExtendPCR{Index: uint16(index), Data: data})
	if err != nil {
		return fmt.Errorf("ExtendPCR(%d): %w", index, err)
	}
	if resp.Error != "" {
		return fmt.Errorf("ExtendPCR(%d): NSM error: %s", index, resp.Error)
	}
	return nil
}

// describePCR returns PCR[index]'s current value and its lock state.
func (n *Nsm) describePCR(index uint) (data []byte, locked bool, err error) {
	resp, err := n.session.Send(&request.DescribePCR{Index: uint16(index)})
	if err != nil {
		return nil, false, fmt.Errorf("DescribePCR(%d): %w", index, err)
	}
	if resp.Error != "" {
		return nil, false, fmt.Errorf("DescribePCR(%d): NSM error: %s", index, resp.Error)
	}
	if resp.DescribePCR == nil {
		return nil, false, fmt.Errorf("DescribePCR(%d): empty response", index)
	}
	return resp.DescribePCR.Data, resp.DescribePCR.Lock, nil
}

func (n *Nsm) getPCR0() (string, error) {
	attestDoc, _, err := buildAttestationDocument(n.session)
	if err != nil {
		return "", fmt.Errorf("build attestation document: %w", err)
	}

	pcr0, err := extractPCR0FromAttestation(attestDoc)
	if err != nil {
		return "", fmt.Errorf("extract PCR0 from attestation: %w", err)
	}
	return pcr0, nil
}

func (n *Nsm) commitPCR(newPCR0Hex string, newPCR0Bytes []byte, pcrIndex uint) error {
	want := sha512.Sum384(append(make([]byte, 48), newPCR0Bytes...))
	cur, locked, err := n.describePCR(pcrIndex)
	if err != nil {
		return fmt.Errorf("describePCR(%d): %w", pcrIndex, err)
	}
	switch {
	case bytes.Equal(cur, want[:]):
		if !locked {
			if err := n.lockPCR(pcrIndex); err != nil {
				return fmt.Errorf("lock PCR%d: %w", pcrIndex, err)
			}
		}
		slog.Info("PCR31 already committed to new_pcr0, skipped re-extension", "new_pcr0", prefix16(newPCR0Hex))
		return nil
	case !bytes.Equal(cur, make([]byte, len(cur))):
		return fmt.Errorf("PCR%d holds an unexpected value; reboot the enclave to retry migration", pcrIndex)
	}
	if err := n.extendPCR(pcrIndex, newPCR0Bytes); err != nil {
		return fmt.Errorf("extend PCR%d with new_pcr0: %w", pcrIndex, err)
	}
	if err := n.lockPCR(pcrIndex); err != nil {
		return fmt.Errorf("lock PCR%d: %w", pcrIndex, err)
	}
	return nil

}
