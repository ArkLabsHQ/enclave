package runtime

import (
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

// runClockSync gradually slews CLOCK_REALTIME toward the PTP clock until stop is
// closed, then releases the device. ADJ_OFFSET_SINGLESHOT never steps backward.
func runClockSync(stop <-chan bool, file *os.File, phc int32) {
	defer func() { _ = file.Close() }()
	ticker := time.NewTicker(clockSyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
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
