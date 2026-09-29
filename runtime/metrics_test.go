package runtime

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadProcCPU(t *testing.T) {
	if _, err := os.Stat("/proc/stat"); err != nil {
		t.Skipf("/proc/stat unavailable: %v", err)
	}

	result, err := readProcCPU()

	require.NoError(t, err)
	require.Contains(t, result, "cpu_user")
	require.Contains(t, result, "cpu_idle")
}

func TestReadProcMeminfo(t *testing.T) {
	if _, err := os.Stat("/proc/meminfo"); err != nil {
		t.Skipf("/proc/meminfo unavailable: %v", err)
	}

	result, err := readProcMeminfo()

	require.NoError(t, err)
	require.Contains(t, result, "mem_total_kb")
}
