package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testYAML = `name: myapp
region: us-east-1
account: "123456789012"
deployment: dev
runtime:
  rev: x
  hash: sha256-x
  vendor_hash: sha256-y
app:
  language: go
  nix_owner: ArkLabsHQ
  nix_repo: introspector-enclave
  nix_rev: x
  nix_hash: sha256-x
  nix_vendor_hash: sha256-y
  binary_name: myapp
secrets: []
tls:
  provider: letsencrypt
  fqdn: api.example.com
  email: ops@example.com
  route53_zone_id: Z123ABCDEFGHIJ
`

// chdirTemp creates a temp dir, chdirs into it, restores cwd on cleanup, and
// returns the temp dir path.
func chdirTemp(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	return tmp
}

// TestWriteTofuVars_Route53ZoneID verifies that tls.route53_zone_id round-trips
// from the loaded Config into terraform.tfvars.json under the expected key.
func TestWriteTofuVars_Route53ZoneID(t *testing.T) {
	cases := []struct {
		name     string
		zoneID   string
		wantJSON string
	}{
		{name: "empty zone id round-trips as empty", zoneID: "", wantJSON: ""},
		{name: "populated zone id round-trips verbatim", zoneID: "Z123456ABCDEFG", wantJSON: "Z123456ABCDEFG"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "tofu"), 0755); err != nil {
				t.Fatal(err)
			}

			cfg := &Config{
				Name:       "myapp",
				Region:     "us-east-1",
				Account:    "123456789012",
				Deployment: "dev",
				TLS: TLSConfig{
					FQDN:          "api.example.com",
					Provider:      "letsencrypt",
					Email:         "ops@example.com",
					Route53ZoneID: tc.zoneID,
				},
			}

			if err := writeTofuVars(cfg, root, true); err != nil {
				t.Fatalf("writeTofuVars: %v", err)
			}

			data, err := os.ReadFile(filepath.Join(root, "tofu", "terraform.tfvars.json"))
			if err != nil {
				t.Fatalf("read tfvars: %v", err)
			}

			var parsed struct {
				TLS struct {
					Route53ZoneID string `json:"route53_zone_id"`
				} `json:"tls"`
			}
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("unmarshal tfvars: %v", err)
			}

			if parsed.TLS.Route53ZoneID != tc.wantJSON {
				t.Errorf("tls.route53_zone_id = %q, want %q", parsed.TLS.Route53ZoneID, tc.wantJSON)
			}
		})
	}
}

func TestTofuReceiptIAMPolicy(t *testing.T) {
	requireContains(t, tofuModuleEnclaveMain, `  statement {
    sid     = "SSMReadWriteParams"
    actions = ["ssm:GetParameter", "ssm:PutParameter"]
    resources = [
      "arn:aws:ssm:${var.region}:${var.account}:parameter/${var.deployment}/${var.app_name}/${local.lock_segment}/KMSKeyID",
      "arn:aws:ssm:${var.region}:${var.account}:parameter/${var.deployment}/${var.app_name}/StateOriginReceipt/*/*",
      "arn:aws:ssm:${var.region}:${var.account}:parameter/${var.deployment}/${var.app_name}/MigrationStateOriginReceipt/*",
    ]
  }`)

	for _, notWant := range []string{
		`"arn:aws:ssm:${var.region}:${var.account}:parameter/${var.deployment}/${var.app_name}/StateOriginReceipt/*"`,
		`"ssm:Delete`,
	} {
		if strings.Contains(tofuModuleEnclaveMain, notWant) {
			t.Errorf("generated instance policy unexpectedly contains %q", notWant)
		}
	}
}

func TestTofuCandidateArtifactsAreAppendOnly(t *testing.T) {
	markers := []struct {
		name  string
		value string
	}{
		{"PCR-addressed EIF key", `candidate_eif_key        = "candidates/${local.effective_pcr0}/enclave.eif"`},
		{"PCR-addressed supervisor key", `candidate_supervisor_key = "candidates/${local.effective_pcr0}/supervisor"`},
		{"removed EIF object", `from = aws_s3_object.enclave_eif`},
		{"removed supervisor object", `from = aws_s3_object.supervisor_binary`},
		{"unified upload resource", `resource "terraform_data" "candidate_upload"`},
		{"artifact iteration", `for_each = local.candidate_artifacts`},
		{"content comparison", `cmp -s "$SOURCE" "$WORK/existing"`},
		{"overwrite refusal", `refusing to overwrite retained candidate s3://$BUCKET/$KEY`},
		{"instance upload dependency", `terraform_data.candidate_upload,`},
	}
	for _, marker := range markers {
		t.Run(marker.name, func(t *testing.T) {
			requireContains(t, tofuModuleEnclaveMain, marker.value)
		})
	}

	if strings.Contains(tofuModuleEnclaveMain, `resource "aws_s3_object"`) {
		t.Error("candidate publication uses lifecycle-managed aws_s3_object resources")
	}

	for _, name := range []string{
		"candidate_pcr0",
		"candidate_artifact_bucket",
		"candidate_eif_key",
		"candidate_supervisor_key",
		"migration_intent_bucket",
	} {
		requireContains(t, tofuModuleEnclaveMain, `output "`+name+`"`)
		requireContains(t, tofuRootMain, `value       = module.enclave.`+name)
	}
}

func TestTofuMigrationIntentInfrastructure(t *testing.T) {
	for _, want := range []string{
		`object_lock_enabled = true`,
		`resource "aws_s3_bucket_versioning" "migration_intent"`,
		`resource "aws_s3_bucket_policy" "migration_intent"`,
		`Action    = "s3:ListBucketVersions"`,
		`"s3:PutObjectRetention"`,
		`name      = "/${var.deployment}/${var.app_name}/MigrationIntentBucketName"`,
		`aws_ssm_parameter.migration_intent_bucket_name.arn`,
	} {
		requireContains(t, tofuModuleEnclaveMain, want)
	}
}

func TestTofuHasNoAutomaticMigration(t *testing.T) {
	if strings.Contains(tofuRootMain+tofuModuleEnclaveMain, "/migrate") {
		t.Error("generated Tofu contains automatic migration")
	}
	requireContains(t, tofuModuleEnclaveMain, "ignore_changes = [ami, user_data]")
}

func TestMigrationCooldownIsEIFOnly(t *testing.T) {
	if strings.Contains(frameworkUserData, "ENCLAVE_MIGRATION_COOLDOWN") {
		t.Error("host user data exports the EIF-only migration cooldown")
	}
	requireContains(t, frameworkFlakeNix,
		`ENCLAVE_MIGRATION_COOLDOWN=${buildCfg.migration_cooldown or "0s"}`)
	requireContains(t, frameworkFlakeNix,
		`ENCLAVE_MIGRATION_INTENT_RETENTION=${buildCfg.migration_intent_retention or "87600h"}`)
}

func requireContains(t *testing.T, value, substring string) {
	t.Helper()
	if !strings.Contains(value, substring) {
		t.Errorf("missing %q", substring)
	}
}

// TestTofuUpdate_RefreshesOnlyTfvars confirms that `enclave tofu update`
// regenerates terraform.tfvars.json from enclave.yaml while leaving the
// scaffolded module files (main.tf, modules/enclave/main.tf) untouched.
func TestTofuUpdate_RefreshesOnlyTfvars(t *testing.T) {
	tmp := chdirTemp(t)

	if err := os.WriteFile(filepath.Join(tmp, "enclave.yaml"), []byte(testYAML), 0644); err != nil {
		t.Fatal(err)
	}

	sentinelMain := "# SENTINEL main.tf — must not be overwritten\n"
	sentinelModule := "# SENTINEL modules/enclave/main.tf — must not be overwritten\n"
	if err := os.MkdirAll(filepath.Join(tmp, "tofu", "modules", "enclave"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "tofu", "main.tf"), []byte(sentinelMain), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "tofu", "modules", "enclave", "main.tf"), []byte(sentinelModule), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := tofuUpdateCmd()
	cmd.SetArgs([]string{"--remote"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("tofu update: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(tmp, "tofu", "terraform.tfvars.json"))
	if err != nil {
		t.Fatalf("read tfvars: %v", err)
	}
	var parsed struct {
		TLS struct {
			FQDN          string `json:"fqdn"`
			Route53ZoneID string `json:"route53_zone_id"`
		} `json:"tls"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal tfvars: %v", err)
	}
	if parsed.TLS.FQDN != "api.example.com" {
		t.Errorf("tls.fqdn = %q, want %q", parsed.TLS.FQDN, "api.example.com")
	}
	if parsed.TLS.Route53ZoneID != "Z123ABCDEFGHIJ" {
		t.Errorf("tls.route53_zone_id = %q, want %q", parsed.TLS.Route53ZoneID, "Z123ABCDEFGHIJ")
	}

	gotMain, _ := os.ReadFile(filepath.Join(tmp, "tofu", "main.tf"))
	if string(gotMain) != sentinelMain {
		t.Errorf("tofu/main.tf was modified; got %q, want %q", gotMain, sentinelMain)
	}
	gotModule, _ := os.ReadFile(filepath.Join(tmp, "tofu", "modules", "enclave", "main.tf"))
	if string(gotModule) != sentinelModule {
		t.Errorf("tofu/modules/enclave/main.tf was modified; got %q, want %q", gotModule, sentinelModule)
	}

	// backend.tf must NOT be written by `enclave tofu update`
	if _, err := os.Stat(filepath.Join(tmp, "tofu", "backend.tf")); !os.IsNotExist(err) {
		t.Errorf("tofu/backend.tf was created by update (or stat failed: %v); should be left alone", err)
	}
}

// --- enclave tofu env tests ---

// writeSentinelMainTF satisfies the precondition check by creating a
// placeholder tofu/main.tf in the temp dir. Tests use this so runTofuEnv
// passes the "scaffold already exists" guard.
func writeSentinelMainTF(t *testing.T, tmp string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(tmp, "tofu"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "tofu", "main.tf"), []byte("# sentinel\n"), 0644); err != nil {
		t.Fatal(err)
	}
}

func readEnvValuesFile(t *testing.T, tmp string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(tmp, "tofu", "env_values.auto.tfvars.json"))
	if err != nil {
		t.Fatalf("read env_values.auto.tfvars.json: %v", err)
	}
	var f envValuesFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("unmarshal env_values: %v", err)
	}
	return f.EnvValues
}

func TestTofuEnv_AddNewKeys(t *testing.T) {
	tmp := chdirTemp(t)
	writeSentinelMainTF(t, tmp)

	if err := runTofuEnv([]string{"FOO", "BAR"}, []string{"one", "two"}); err != nil {
		t.Fatalf("runTofuEnv: %v", err)
	}
	got := readEnvValuesFile(t, tmp)
	if got["FOO"] != "one" || got["BAR"] != "two" || len(got) != 2 {
		t.Errorf("env_values = %v, want {FOO:one, BAR:two}", got)
	}
}

func TestTofuEnv_MergesWithExisting(t *testing.T) {
	tmp := chdirTemp(t)
	writeSentinelMainTF(t, tmp)

	// Pre-populate one key.
	if err := os.WriteFile(
		filepath.Join(tmp, "tofu", "env_values.auto.tfvars.json"),
		[]byte(`{"env_values":{"EXISTING":"keep"}}`+"\n"),
		0644,
	); err != nil {
		t.Fatal(err)
	}
	if err := runTofuEnv([]string{"NEW_KEY"}, []string{"added"}); err != nil {
		t.Fatalf("runTofuEnv: %v", err)
	}
	got := readEnvValuesFile(t, tmp)
	if got["EXISTING"] != "keep" {
		t.Errorf("EXISTING was clobbered, got %q", got["EXISTING"])
	}
	if got["NEW_KEY"] != "added" {
		t.Errorf("NEW_KEY missing or wrong: got %q", got["NEW_KEY"])
	}
}

func TestTofuEnv_OverwritesExistingKey(t *testing.T) {
	tmp := chdirTemp(t)
	writeSentinelMainTF(t, tmp)

	if err := os.WriteFile(
		filepath.Join(tmp, "tofu", "env_values.auto.tfvars.json"),
		[]byte(`{"env_values":{"FOO":"old"}}`+"\n"),
		0644,
	); err != nil {
		t.Fatal(err)
	}
	if err := runTofuEnv([]string{"FOO"}, []string{"new"}); err != nil {
		t.Fatalf("runTofuEnv: %v", err)
	}
	got := readEnvValuesFile(t, tmp)
	if got["FOO"] != "new" {
		t.Errorf("FOO = %q, want %q", got["FOO"], "new")
	}
}

func TestTofuEnv_RejectsMismatchedKeyValuePairs(t *testing.T) {
	tmp := chdirTemp(t)
	writeSentinelMainTF(t, tmp)

	err := runTofuEnv([]string{"A", "B"}, []string{"1"})
	requireErrContains(t, err, "pairs")
}

func TestTofuEnv_RejectsInvalidKeyName(t *testing.T) {
	tmp := chdirTemp(t)
	writeSentinelMainTF(t, tmp)

	err := runTofuEnv([]string{"lowercase-bad"}, []string{"val"})
	requireErrContains(t, err, "invalid env var name")
}

func TestTofuEnv_RefusesWithoutScaffold(t *testing.T) {
	chdirTemp(t)
	// Don't create tofu/main.tf — precondition should fail.
	err := runTofuEnv([]string{"FOO"}, []string{"bar"})
	requireErrContains(t, err, "tofu/main.tf not found")
}

func TestTofuEnv_RejectsEmptyKeyValueArgs(t *testing.T) {
	tmp := chdirTemp(t)
	writeSentinelMainTF(t, tmp)

	err := runTofuEnv(nil, nil)
	requireErrContains(t, err, "at least one --key/--value pair is required")
}

// TestTofuEnv_PreservesCommasAndNewlines guards against the StringSlice
// gotcha (values with commas getting split). The CLI uses StringArrayVar so
// "a,b,c" stays one value, and a multi-line PEM-style string round-trips
// verbatim.
func TestTofuEnv_PreservesCommasAndNewlines(t *testing.T) {
	tmp := chdirTemp(t)
	writeSentinelMainTF(t, tmp)

	multiline := "-----BEGIN CERTIFICATE-----\nQ0E=\n-----END CERTIFICATE-----"
	if err := runTofuEnv(
		[]string{"COMMA_VALUE", "PEM_CERT"},
		[]string{"a,b,c", multiline},
	); err != nil {
		t.Fatalf("runTofuEnv: %v", err)
	}
	got := readEnvValuesFile(t, tmp)
	if got["COMMA_VALUE"] != "a,b,c" {
		t.Errorf("COMMA_VALUE = %q, want %q (commas must NOT be split)", got["COMMA_VALUE"], "a,b,c")
	}
	if got["PEM_CERT"] != multiline {
		t.Errorf("PEM_CERT was not preserved verbatim:\n  got  %q\n  want %q", got["PEM_CERT"], multiline)
	}
}

// TestTofuUpdate_FailsWithoutScaffold confirms `enclave tofu update` refuses
// to run when there's no prior scaffold (tofu/main.tf missing).
func TestTofuUpdate_FailsWithoutScaffold(t *testing.T) {
	tmp := chdirTemp(t)

	if err := os.WriteFile(filepath.Join(tmp, "enclave.yaml"), []byte(testYAML), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := tofuUpdateCmd()
	err := cmd.Execute()
	requireErrContains(t, err, "tofu/main.tf not found")
}

// TestYesNo verifies the y/n prompt parsing and default semantics.
func TestYesNo(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		defaultYes bool
		want       bool
	}{
		{name: "empty input + default yes", input: "\n", defaultYes: true, want: true},
		{name: "empty input + default no", input: "\n", defaultYes: false, want: false},
		{name: "explicit y", input: "y\n", defaultYes: false, want: true},
		{name: "explicit yes", input: "YES\n", defaultYes: false, want: true},
		{name: "explicit n", input: "n\n", defaultYes: true, want: false},
		{name: "explicit no", input: "No\n", defaultYes: true, want: false},
		{name: "garbage falls back to default", input: "maybe\n", defaultYes: true, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var w bytes.Buffer
			got, err := yesNo(strings.NewReader(tc.input), &w, "ok?", tc.defaultYes)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("yesNo(%q, default=%v) = %v, want %v", tc.input, tc.defaultYes, got, tc.want)
			}
		})
	}
}

// TestPromptWithDefault verifies empty-input fallback and trim behavior.
func TestPromptWithDefault(t *testing.T) {
	cases := []struct {
		name, input, def, want string
	}{
		{name: "empty returns default", input: "\n", def: "fallback", want: "fallback"},
		{name: "value returned", input: "custom\n", def: "fallback", want: "custom"},
		{name: "trims whitespace", input: "  spaced  \n", def: "x", want: "spaced"},
		{name: "EOF treated as empty", input: "", def: "fallback", want: "fallback"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var w bytes.Buffer
			got, err := promptWithDefault(strings.NewReader(tc.input), &w, "label", tc.def)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestWriteBackendConfig_AppliesOverride confirms operator-chosen values
// flow into backend.tf (not the computed defaults).
func TestWriteBackendConfig_AppliesOverride(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "tofu"), 0755); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		Name:       "myapp",
		Region:     "us-east-1",
		Account:    "123456789012",
		Deployment: "dev",
	}
	override := &backendOverride{
		bucket: "custom-bucket-name",
		table:  "custom-lock-table",
		region: "eu-west-2",
	}
	if err := writeBackendConfig(cfg, root, override); err != nil {
		t.Fatalf("writeBackendConfig: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(root, "tofu", "backend.tf"))
	if err != nil {
		t.Fatalf("read backend.tf: %v", err)
	}
	bodyStr := string(body)
	for _, want := range []string{`bucket         = "custom-bucket-name"`, `dynamodb_table = "custom-lock-table"`, `region         = "eu-west-2"`} {
		if !strings.Contains(bodyStr, want) {
			t.Errorf("backend.tf missing %q\n--- body ---\n%s", want, bodyStr)
		}
	}
	// And — the computed defaults must NOT have leaked through.
	for _, notWanted := range []string{"dev-myapp-tfstate-123456789012-us-east-1", "dev-myapp-tfstate-lock"} {
		if strings.Contains(bodyStr, notWanted) {
			t.Errorf("backend.tf unexpectedly contains computed default %q", notWanted)
		}
	}
}

// TestWriteBackendConfig_NilOverrideUsesDefaults confirms backwards-compatible
// behavior: nil override emits the computed-from-yaml defaults.
func TestWriteBackendConfig_NilOverrideUsesDefaults(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "tofu"), 0755); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		Name:       "myapp",
		Region:     "us-east-1",
		Account:    "123456789012",
		Deployment: "dev",
	}
	if err := writeBackendConfig(cfg, root, nil); err != nil {
		t.Fatalf("writeBackendConfig: %v", err)
	}
	body, _ := os.ReadFile(filepath.Join(root, "tofu", "backend.tf"))
	for _, want := range []string{`"dev-myapp-tfstate-123456789012-us-east-1"`, `"dev-myapp-tfstate-lock"`, `"us-east-1"`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("backend.tf missing default %q\n--- body ---\n%s", want, body)
		}
	}
}
