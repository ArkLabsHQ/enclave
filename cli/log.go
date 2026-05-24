package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func logCmd() *cobra.Command {
	var (
		level      string
		limit      int
		since      string
		asJSON     bool
		history    bool
		instanceID string
		region     string
		profile    string
	)

	cmd := &cobra.Command{
		Use:   "log",
		Short: "Show enclave application logs",
		Long:  "Retrieves structured log entries from the enclave supervisor via SSM RunCommand.\nUse --history to query CloudWatch Logs for past logs (requires ENCLAVE_LOG_CLOUDWATCH=true on the enclave).",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLog(level, limit, since, asJSON, history, instanceID, region, profile)
		},
	}

	cmd.Flags().StringVar(&level, "level", "", "minimum level to show (debug, info, warn, error)")
	cmd.Flags().IntVar(&limit, "limit", 100, "maximum number of entries to display")
	cmd.Flags().StringVar(&since, "since", "", "show entries newer than this (duration like 5m or RFC3339 timestamp)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output raw JSON array")
	cmd.Flags().BoolVar(&history, "history", false, "query CloudWatch Logs for historical traces")
	cmd.Flags().StringVar(&instanceID, "instance-id", "", "EC2 instance ID (required)")
	cmd.Flags().StringVar(&region, "region", "", "AWS region (required)")
	cmd.Flags().StringVar(&profile, "profile", "", "AWS named profile (optional; defaults to AWS_PROFILE env var or the default credential chain)")
	_ = cmd.MarkFlagRequired("instance-id")
	_ = cmd.MarkFlagRequired("region")

	return cmd
}

func runLog(level string, limit int, since string, asJSON bool, history bool, instanceID, region, profile string) error {
	ctx := context.Background()
	ac, err := newAWSClients(ctx, region, profile)
	if err != nil {
		return err
	}

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

	path := "/enclave-logs"
	if q := params.Encode(); q != "" {
		path += "?" + q
	}

	body, err := ac.fetchSupervisor(ctx, instanceID, path)
	if err != nil {
		return fmt.Errorf("read logs from supervisor on %s: %w", instanceID, err)
	}
	defer func() { _ = body.Close() }()

	if asJSON {
		return streamBodyToStdout(body)
	}

	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		fmt.Println("No log entries found.")
		return nil
	}

	var entries []logEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("failed to parse logs: %w", err)
	}

	if len(entries) == 0 {
		fmt.Println("No log entries found.")
		return nil
	}

	fmt.Printf("%-27s %-7s %-12s %s\n", "TIMESTAMP", "LEVEL", "SOURCE", "MESSAGE")
	for _, e := range entries {
		ts := e.Timestamp
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			ts = t.Format("2006-01-02T15:04:05.000Z")
		}

		line := fmt.Sprintf("%-27s %-7s %-12s %s", ts, e.Level, e.Source, e.Message)

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

// streamBodyToStdout copies an HTTP response body to stdout for --json
// output, ensuring exactly one trailing newline so the result composes
// cleanly with jq / shell pipelines regardless of whether the supervisor's
// payload already ends in a newline.
func streamBodyToStdout(body io.Reader) error {
	tracker := &lastByteTracker{w: os.Stdout}
	if _, err := io.Copy(tracker, body); err != nil {
		return err
	}
	if !tracker.endsWithNewline() {
		fmt.Println()
	}
	return nil
}

// lastByteTracker is an io.Writer that remembers the last byte written so
// streamBodyToStdout can decide whether to emit a trailing newline.
type lastByteTracker struct {
	w    io.Writer
	last byte
	any  bool
}

func (l *lastByteTracker) Write(p []byte) (int, error) {
	n, err := l.w.Write(p)
	if n > 0 {
		l.last = p[n-1]
		l.any = true
	}
	return n, err
}

func (l *lastByteTracker) endsWithNewline() bool {
	return l.any && l.last == '\n'
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
