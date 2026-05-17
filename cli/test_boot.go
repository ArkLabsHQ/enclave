package cli

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	testProjectName    = "enclave-test"
	testHealthURL      = "https://127.0.0.1:8443/health"
	testHealthTimeout  = 5 * time.Minute
	testHealthInterval = 2 * time.Second
)

func bootTestStack(ctx context.Context, projectRoot string) error {
	composePath := filepath.Join(projectRoot, composeFilePath)
	if _, err := os.Stat(composePath); err != nil {
		return fmt.Errorf("%s missing (run `enclave test init` to scaffold it): %w", composeFilePath, err)
	}

	args := []string{
		"compose",
		"--project-name", testProjectName,
		"-f", composePath,
		"up", "-d", "--build",
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker compose up: %w", err)
	}

	fmt.Println("Waiting for enclave to report ready ...")
	if err := pollHealth(ctx, testHealthURL, testHealthTimeout); err != nil {
		return err
	}
	return nil
}

func tearDownTestStack(ctx context.Context, projectRoot string) error {
	composePath := filepath.Join(projectRoot, composeFilePath)
	if _, err := os.Stat(composePath); err != nil {
		return nil
	}
	args := []string{
		"compose",
		"--project-name", testProjectName,
		"-f", composePath,
		"down", "-v", "--remove-orphans",
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker compose down: %w", err)
	}
	return nil
}

func pollHealth(ctx context.Context, url string, timeout time.Duration) error {
	// Self-signed cert from the supervisor — real attestation pinning
	// is the user test driver's job.
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	deadline := time.Now().Add(timeout)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		resp, err := client.Get(url)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("enclave did not become healthy within %s (last URL: %s)", timeout, url)
		}
		time.Sleep(testHealthInterval)
	}
}
