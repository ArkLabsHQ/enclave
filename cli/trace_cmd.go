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

func traceCmd() *cobra.Command {
	var (
		service string
		limit   int
		since   string
		asJSON  bool
		history bool
	)

	cmd := &cobra.Command{
		Use:   "trace",
		Short: "Show enclave trace spans",
		Long:  "Retrieves distributed trace spans from the enclave supervisor via the management server.\nUse --history to query CloudWatch Logs for past spans (requires ENCLAVE_LOG_CLOUDWATCH=true on the enclave).",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTraceCmd(service, limit, since, asJSON, history)
		},
	}

	cmd.Flags().StringVar(&service, "service", "", "filter by source (app, supervisor)")
	cmd.Flags().IntVar(&limit, "limit", 100, "maximum number of spans to display")
	cmd.Flags().StringVar(&since, "since", "", "show spans newer than this (duration like 5m or RFC3339 timestamp)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output raw JSON array")
	cmd.Flags().BoolVar(&history, "history", false, "query CloudWatch Logs for historical spans")

	return cmd
}

func runTraceCmd(service string, limit int, since string, asJSON bool, history bool) error {
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

	params := url.Values{}
	if service != "" {
		params.Set("service", service)
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

	curlURL := "http://localhost:8443/enclave-traces"
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

	var entries []spanDisplayEntry
	if err := json.Unmarshal([]byte(output), &entries); err != nil {
		return fmt.Errorf("failed to parse spans: %w", err)
	}

	if len(entries) == 0 {
		fmt.Println("No trace spans found.")
		return nil
	}

	fmt.Printf("%-27s %-8s %-12s %-30s %s\n", "START", "STATUS", "SOURCE", "NAME", "DURATION")
	for _, e := range entries {
		start := e.Start
		if t, err := time.Parse(time.RFC3339Nano, start); err == nil {
			start = t.Format("2006-01-02T15:04:05.000Z")
		}

		duration := ""
		if st, err1 := time.Parse(time.RFC3339Nano, e.Start); err1 == nil {
			if et, err2 := time.Parse(time.RFC3339Nano, e.End); err2 == nil {
				duration = et.Sub(st).String()
			}
		}

		line := fmt.Sprintf("%-27s %-8s %-12s %-30s %s", start, e.Status, e.Source, e.Name, duration)

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

type spanDisplayEntry struct {
	ID         string         `json:"id"`
	TraceID    string         `json:"trace_id"`
	ParentID   string         `json:"parent_id,omitempty"`
	Name       string         `json:"name"`
	Start      string         `json:"start"`
	End        string         `json:"end"`
	Status     string         `json:"status"`
	Attributes map[string]any `json:"attributes,omitempty"`
	Source     string         `json:"source"`
}
