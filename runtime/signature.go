package runtime

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

type PCR0SignatureInfo struct {
	PubkeyPEM    string `json:"pubkey_pem"`
	PCR0Hex      string `json:"pcr0_hex"`
	SignatureB64 string `json:"signature_b64"`
}

type Signature struct {
	mu        sync.RWMutex
	pubkeyPEM string
	pcr0Hex   string
	signature string
	ready     bool
}

func NewSignature() *Signature { return &Signature{} }

func (s *Signature) Ready() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ready
}

func (s *Signature) Load(ctx context.Context, ssmAPI ssmGetter) {
	deployment := getDeployment()
	appName := getAppName()
	pubkeyPath := fmt.Sprintf("/%s/%s/Signing/PubkeyPEM", deployment, appName)
	pcr0Path := fmt.Sprintf("/%s/%s/Signing/PCR0", deployment, appName)
	sigPath := fmt.Sprintf("/%s/%s/Signing/Signature", deployment, appName)

	pubkey, err := getSSMValue(ctx, ssmAPI, pubkeyPath)
	if err != nil {
		slog.Warn("signature: SSM pubkey not available", "path", pubkeyPath, "error", err)
		return
	}
	pcr0, err := getSSMValue(ctx, ssmAPI, pcr0Path)
	if err != nil {
		slog.Warn("signature: SSM PCR0 not available", "path", pcr0Path, "error", err)
		return
	}
	sig, err := getSSMValue(ctx, ssmAPI, sigPath)
	if err != nil {
		slog.Warn("signature: SSM signature not available", "path", sigPath, "error", err)
		return
	}

	s.mu.Lock()
	s.pubkeyPEM = pubkey
	s.pcr0Hex = pcr0
	s.signature = sig
	s.ready = true
	s.mu.Unlock()

	slog.Info("signature: loaded PCR0 signature from SSM", "pcr0", pcr0)
}

func getSSMValue(ctx context.Context, ssmAPI ssmGetter, name string) (string, error) {
	out, err := ssmAPI.GetParameter(ctx, &ssm.GetParameterInput{
		Name: aws.String(name),
	})
	if err != nil {
		return "", err
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return "", fmt.Errorf("%s: empty parameter", name)
	}
	return *out.Parameter.Value, nil
}

func (s *Signature) Snapshot() *PCR0SignatureInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.ready {
		return nil
	}
	return &PCR0SignatureInfo{
		PubkeyPEM:    s.pubkeyPEM,
		PCR0Hex:      s.pcr0Hex,
		SignatureB64: s.signature,
	}
}
