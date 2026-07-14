package runtime

import (
	"context"
	"log/slog"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const (
	ptpDevicePath          = "/dev/ptp0"
	clockSyncInterval      = 5 * time.Second
	clockSyncSlewThreshold = 5 * time.Millisecond
)

// StartClockSync binds CLOCK_REALTIME to the hypervisor's PTP clock (/dev/ptp0),
// which the host cannot forge or skew. It hard-steps at boot, then slews for the
// enclave's lifetime (until ctx is cancelled). No-op if /dev/ptp0 is absent
// (e.g. QEMU without ptp_kvm). Call once at the start of Run, before any
// outbound TLS validates certs or listeners serve traffic.
func StartClockSync(ctx context.Context) {
	file, err := os.OpenFile(ptpDevicePath, os.O_RDONLY, 0)
	if err != nil {
		slog.Warn("clock sync disabled: /dev/ptp0 unavailable", "error", err)
		return
	}
	// The clock id is derived from the live fd, so runClockSync keeps it open.
	phc := fdToClockID(file.Fd())

	var ptp unix.Timespec
	if err := unix.ClockGettime(phc, &ptp); err != nil {
		slog.Warn("clock sync disabled: cannot read PTP clock", "error", err)
		_ = file.Close()
		return
	}
	if err := unix.ClockSettime(unix.CLOCK_REALTIME, &ptp); err != nil {
		slog.Warn("clock sync: initial hard-step failed; slew loop will converge", "error", err)
	} else {
		slog.Info("clock sync: initial hard-step to hypervisor PTP completed")
	}

	go runClockSync(ctx, file, phc)
}

// runClockSync gradually slews CLOCK_REALTIME toward the PTP clock until ctx is
// cancelled, then releases the device. ADJ_OFFSET_SINGLESHOT never steps backward.
func runClockSync(ctx context.Context, file *os.File, phc int32) {
	defer func() { _ = file.Close() }()
	ticker := time.NewTicker(clockSyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("clock sync stopping")
			return
		case <-ticker.C:
		}

		var ptp, sys unix.Timespec
		if err := unix.ClockGettime(phc, &ptp); err != nil {
			slog.Warn("clock sync: read PTP clock", "error", err)
			continue
		}
		if err := unix.ClockGettime(unix.CLOCK_REALTIME, &sys); err != nil {
			slog.Warn("clock sync: read system clock", "error", err)
			continue
		}

		offsetNsec := clockOffsetNsec(ptp, sys)

		magnitudeNsec := offsetNsec
		if magnitudeNsec < 0 {
			magnitudeNsec = -magnitudeNsec
		}
		if magnitudeNsec <= clockSyncSlewThreshold.Nanoseconds() {
			continue
		}

		// ADJ_OFFSET_SINGLESHOT offset is in microseconds; sign sets the direction.
		tx := unix.Timex{
			Modes:  unix.ADJ_OFFSET_SINGLESHOT,
			Offset: offsetNsec / 1000,
		}
		if _, err := unix.ClockAdjtime(unix.CLOCK_REALTIME, &tx); err != nil {
			slog.Warn("clock sync: slew failed", "error", err, "offset_us", offsetNsec/1000)
			continue
		}
		slog.Debug("clock sync: slewed CLOCK_REALTIME toward PTP", "offset_ms", offsetNsec/1_000_000)
	}
}

// fdToClockID is the kernel's FD_TO_CLOCKID macro: ((~fd) << 3) | 3.
func fdToClockID(fd uintptr) int32 {
	return int32(^uint32(fd)<<3 | 3)
}

// clockOffsetNsec returns ptp - sys in ns; positive means CLOCK_REALTIME is behind.
func clockOffsetNsec(ptp, sys unix.Timespec) int64 {
	return (ptp.Sec*1_000_000_000 + ptp.Nsec) - (sys.Sec*1_000_000_000 + sys.Nsec)
}
