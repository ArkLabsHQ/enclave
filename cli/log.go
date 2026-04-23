package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func logCmd() *cobra.Command {
	var (
		level   string
		limit   int
		since   string
		asJSON  bool
		history bool
	)

	cmd := &cobra.Command{
		Use:   "log",
		Short: "Show enclave application logs",
		Long:  "Retrieves structured log entries from the enclave supervisor via the supervisor server.\nUse --history to query CloudWatch Logs for past logs (requires ENCLAVE_LOG_CLOUDWATCH=true on the enclave).",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLog(level, limit, since, asJSON, history)
		},
	}

	cmd.Flags().StringVar(&level, "level", "", "minimum level to show (debug, info, warn, error)")
	cmd.Flags().IntVar(&limit, "limit", 100, "maximum number of entries to display")
	cmd.Flags().StringVar(&since, "since", "", "show entries newer than this (duration like 5m or RFC3339 timestamp)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output raw JSON array")
	cmd.Flags().BoolVar(&history, "history", false, "query CloudWatch Logs for historical traces")

	return cmd
}

func runLog(level string, limit int, since string, asJSON bool, history bool) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := cfg.validateAccount(); err != nil {
		return err
	}

	root, err := findRepoRoot()
	if err != nil {
		return err
	}

	outputs, err := loadTofuOutputs(root)
	if err != nil {
		return err
	}

	ctx := context.Background()
	ac, err := newAWSClients(ctx, cfg.Region, cfg.Profile)
	if err != nil {
		return err
	}

	instanceID := outputs.getOutput("instance_id")
	if instanceID == "" {
		return fmt.Errorf("instance_id not found in tofu outputs")
	}

	// Build query string.
	params := url.Values{}
	if level != "" {
		params.Set("level", level)
	}
	if limit > 0 {
		params.Set("limit", fmt.Sprintf("%d", limit))
	}
	if since != "" {
		sinceTS, err := parseSince(since)
		if err != nil {
			return fmt.Errorf("invalid --since value: %w", err)
		}
		params.Set("since", sinceTS)
	}
	if history {
		params.Set("history", "true")
	}

	curlURL := "http://localhost:8443/enclave-logs"
	if q := params.Encode(); q != "" {
		curlURL += "?" + q
	}

	curlCmd := fmt.Sprintf("curl -sf '%s' 2>/dev/null || echo '[]'", curlURL)
	output := ac.runCommandOutput(ctx, instanceID, curlCmd)
	if output == "" {
		output = "[]"
	}

	if asJSON {
		fmt.Println(output)
		return nil
	}

	// Parse and display in human-readable format.
	var entries []logEntry
	if err := json.Unmarshal([]byte(output), &entries); err != nil {
		return fmt.Errorf("failed to parse traces: %w", err)
	}

	if len(entries) == 0 {
		fmt.Println("No log entries found.")
		return nil
	}

	// Print table header.
	fmt.Printf("%-27s %-7s %-12s %s\n", "TIMESTAMP", "LEVEL", "SOURCE", "MESSAGE")
	for _, e := range entries {
		// Format timestamp to be more readable.
		ts := e.Timestamp
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			ts = t.Format("2006-01-02T15:04:05.000Z")
		}

		line := fmt.Sprintf("%-27s %-7s %-12s %s", ts, e.Level, e.Source, e.Message)

		// Append attributes inline.
		if len(e.Attributes) > 0 {
			attrs := make([]string, 0, len(e.Attributes))
			for k, v := range e.Attributes {
				attrs = append(attrs, fmt.Sprintf("%s=%v", k, v))
			}
			line += "  " + strings.Join(attrs, " ")
		}

		fmt.Println(line)
	}

	return nil
}

// logEntry mirrors the JSON shape from the supervisor.
type logEntry struct {
	ID         string         `json:"id"`
	Timestamp  string         `json:"timestamp"`
	Level      string         `json:"level"`
	Message    string         `json:"message"`
	Attributes map[string]any `json:"attributes,omitempty"`
	Source     string         `json:"source"`
}

// parseSince converts a duration string (e.g. "5m", "1h") or RFC3339 timestamp
// into an RFC3339 timestamp string suitable for the API query.
func parseSince(s string) (string, error) {
	// Try as RFC3339 first.
	if _, err := time.Parse(time.RFC3339, s); err == nil {
		return s, nil
	}
	if _, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return s, nil
	}

	// Try as duration relative to now.
	d, err := time.ParseDuration(s)
	if err != nil {
		return "", fmt.Errorf("%q is not a valid duration or RFC3339 timestamp", s)
	}
	return time.Now().UTC().Add(-d).Format(time.RFC3339Nano), nil
}
