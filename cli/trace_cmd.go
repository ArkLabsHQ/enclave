package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func traceCmd() *cobra.Command {
	var (
		service    string
		limit      int
		since      string
		asJSON     bool
		history    bool
		instanceID string
		region     string
	)

	cmd := &cobra.Command{
		Use:   "trace",
		Short: "Show enclave trace spans",
		Long:  "Retrieves distributed trace spans from the enclave supervisor via SSM RunCommand.\nUse --history to query CloudWatch Logs for past spans (requires ENCLAVE_LOG_CLOUDWATCH=true on the enclave).",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTraceCmd(service, limit, since, asJSON, history, instanceID, region)
		},
	}

	cmd.Flags().StringVar(&service, "service", "", "filter by source (app, supervisor)")
	cmd.Flags().IntVar(&limit, "limit", 100, "maximum number of spans to display")
	cmd.Flags().StringVar(&since, "since", "", "show spans newer than this (duration like 5m or RFC3339 timestamp)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output raw JSON array")
	cmd.Flags().BoolVar(&history, "history", false, "query CloudWatch Logs for historical spans")
	cmd.Flags().StringVar(&instanceID, "instance-id", "", "EC2 instance ID (required)")
	cmd.Flags().StringVar(&region, "region", "", "AWS region (required)")
	_ = cmd.MarkFlagRequired("instance-id")
	_ = cmd.MarkFlagRequired("region")

	return cmd
}

func runTraceCmd(service string, limit int, since string, asJSON bool, history bool, instanceID, region string) error {
	ctx := context.Background()
	ac, err := newAWSClients(ctx, region, "")
	if err != nil {
		return err
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

	path := "/enclave-traces"
	if q := params.Encode(); q != "" {
		path += "?" + q
	}

	body, err := ac.fetchSupervisor(ctx, instanceID, path)
	if err != nil {
		return fmt.Errorf("read traces from supervisor on %s: %w", instanceID, err)
	}
	defer body.Close()

	if asJSON {
		return streamBodyToStdout(body)
	}

	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		fmt.Println("No trace spans found.")
		return nil
	}

	var entries []spanDisplayEntry
	if err := json.Unmarshal(data, &entries); err != nil {
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
