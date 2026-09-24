package runtime

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	runtimeMetricGoroutines     = "goroutines"
	runtimeMetricNumCPU         = "num_cpu"
	runtimeMetricHeapAllocBytes = "heap_alloc_bytes"
	runtimeMetricHeapSysBytes   = "heap_sys_bytes"
	runtimeMetricSysBytes       = "sys_bytes"
	runtimeMetricMemTotalKB     = "mem_total_kb"
	runtimeMetricMemFreeKB      = "mem_free_kb"
	runtimeMetricMemAvailableKB = "mem_available_kb"
	runtimeMetricGCPauseTotalNS = "gc_pause_total_ns"
	runtimeMetricGCCount        = "gc_num_gc"
	runtimeMetricCPUUser        = "cpu_user"
	runtimeMetricCPUNice        = "cpu_nice"
	runtimeMetricCPUSystem      = "cpu_system"
	runtimeMetricCPUIdle        = "cpu_idle"
)

// readProcCPU reads CPU counters from /proc/stat.
func readProcCPU() (map[string]float64, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return nil, fmt.Errorf("empty /proc/stat")
	}
	line := scanner.Text()
	if !strings.HasPrefix(line, "cpu ") {
		return nil, fmt.Errorf("unexpected /proc/stat format")
	}

	fields := strings.Fields(line)
	if len(fields) < 5 {
		return nil, fmt.Errorf("too few fields in /proc/stat")
	}

	result := make(map[string]float64)
	names := []string{
		runtimeMetricCPUUser,
		runtimeMetricCPUNice,
		runtimeMetricCPUSystem,
		runtimeMetricCPUIdle,
	}
	for i, name := range names {
		if v, err := strconv.ParseFloat(fields[i+1], 64); err == nil {
			result[name] = v
		}
	}
	return result, nil
}

// readProcMeminfo reads /proc/meminfo for memory info.
func readProcMeminfo() (map[string]float64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	result := make(map[string]float64)
	wanted := map[string]string{
		"MemTotal:":     runtimeMetricMemTotalKB,
		"MemFree:":      runtimeMetricMemFreeKB,
		"MemAvailable:": runtimeMetricMemAvailableKB,
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		for prefix, name := range wanted {
			if strings.HasPrefix(line, prefix) {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if v, err := strconv.ParseFloat(fields[1], 64); err == nil {
						result[name] = v
					}
				}
			}
		}
	}
	return result, nil
}
