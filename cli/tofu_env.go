package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/spf13/cobra"
)

const envValuesFileName = "env_values.auto.tfvars.json"

// envKeyRe is the POSIX env var name pattern: uppercase letters, digits,
// underscores; cannot start with a digit.
var envKeyRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// envValuesFile mirrors the JSON shape tofu reads from
// tofu/env_values.auto.tfvars.json: { "env_values": { "KEY": "value", ... } }
type envValuesFile struct {
	EnvValues map[string]string `json:"env_values"`
}

// tofuEnvCmd builds `enclave tofu env --key K --value V [--key … --value …]`.
// Sets/merges entries in tofu/env_values.auto.tfvars.json without hand-editing
// the JSON. Operator runs `tofu apply` afterwards to push to SSM.
func tofuEnvCmd() *cobra.Command {
	var keys, values []string
	cmd := &cobra.Command{
		Use:   "env",
		Short: "Set deploy-time env vars in tofu/env_values.auto.tfvars.json",
		Long: `Sets one or more entries in tofu/env_values.auto.tfvars.json without
hand-editing the JSON. Existing entries are preserved (merged); keys passed on
this command overwrite any prior value.

Example:
  enclave tofu env --key LOG_LEVEL --value debug --key FEATURE_X --value on

The next 'tofu apply' pushes the updated map to SSM at
/<deployment>/<app>/env/<key> — the enclave runtime picks them up at boot.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTofuEnv(keys, values)
		},
	}
	cmd.Flags().StringArrayVar(&keys, "key", nil,
		"Env var key (repeatable; must pair with --value in the same order)")
	cmd.Flags().StringArrayVar(&values, "value", nil,
		"Env var value (repeatable; must pair with --key in the same order). Commas in values are preserved verbatim.")
	return cmd
}

func runTofuEnv(keys, values []string) error {
	if len(keys) == 0 {
		return fmt.Errorf("at least one --key/--value pair is required")
	}
	if len(keys) != len(values) {
		return fmt.Errorf("got %d --key flags but %d --value flags; they must come in pairs", len(keys), len(values))
	}
	for _, k := range keys {
		if !envKeyRe.MatchString(k) {
			return fmt.Errorf("invalid env var name %q (must match %s)", k, envKeyRe.String())
		}
	}

	_, root, err := resolveEnclaveConfig()
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(root, "tofu", "main.tf")); os.IsNotExist(err) {
		return fmt.Errorf("tofu/main.tf not found — run 'enclave tofu init' first to scaffold the module")
	} else if err != nil {
		return fmt.Errorf("stat tofu/main.tf: %w", err)
	}

	path := filepath.Join(root, "tofu", envValuesFileName)
	existing := envValuesFile{EnvValues: map[string]string{}}
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &existing); err != nil {
			return fmt.Errorf("parse existing %s: %w", path, err)
		}
		if existing.EnvValues == nil {
			existing.EnvValues = map[string]string{}
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}

	for i, k := range keys {
		existing.EnvValues[k] = values[i]
		fmt.Printf("set %s\n", k)
	}

	// Stable, git-friendly output: ensure sorted keys.
	sortedKeys := make([]string, 0, len(existing.EnvValues))
	for k := range existing.EnvValues {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)
	sorted := make(map[string]string, len(sortedKeys))
	for _, k := range sortedKeys {
		sorted[k] = existing.EnvValues[k]
	}
	out := envValuesFile{EnvValues: sorted}

	body, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	body = append(body, '\n')
	if err := os.WriteFile(path, body, 0644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Printf("\nWrote %s\nNext: cd tofu && tofu apply\n", path)
	return nil
}
