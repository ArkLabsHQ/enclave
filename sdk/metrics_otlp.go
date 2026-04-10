package sdk

import (
	"fmt"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/proto"
)

// parseOTLPMetrics parses an OTLP ExportMetricsServiceRequest and stores
// the metric values in the global enclaveMetrics.appMetrics map.
// Returns the number of data points processed.
func parseOTLPMetrics(body []byte) (int, error) {
	var req colmetricspb.ExportMetricsServiceRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		return 0, fmt.Errorf("unmarshal OTLP metrics: %w", err)
	}

	count := 0
	for _, rm := range req.ResourceMetrics {
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				name := m.Name
				switch data := m.Data.(type) {
				case *metricspb.Metric_Sum:
					for _, dp := range data.Sum.DataPoints {
						val := dataPointValue(dp)
						enclaveMetrics.SetAppMetric(name, val)
						count++
					}
				case *metricspb.Metric_Gauge:
					for _, dp := range data.Gauge.DataPoints {
						val := dataPointValue(dp)
						enclaveMetrics.SetAppMetric(name, val)
						count++
					}
				case *metricspb.Metric_Histogram:
					for _, dp := range data.Histogram.DataPoints {
						if dp.Sum != nil {
							enclaveMetrics.SetAppMetric(name+"_sum", *dp.Sum)
						}
						enclaveMetrics.SetAppMetric(name+"_count", float64(dp.Count))
						count++
					}
				}
			}
		}
	}
	return count, nil
}

// dataPointValue extracts the numeric value from a NumberDataPoint.
func dataPointValue(dp *metricspb.NumberDataPoint) float64 {
	switch v := dp.Value.(type) {
	case *metricspb.NumberDataPoint_AsInt:
		return float64(v.AsInt)
	case *metricspb.NumberDataPoint_AsDouble:
		return v.AsDouble
	default:
		return 0
	}
}
