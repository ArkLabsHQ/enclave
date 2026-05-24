package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

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
				Name:    "myapp",
				Region:  "us-east-1",
				Account: "123456789012",
				Prefix:  "dev",
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
