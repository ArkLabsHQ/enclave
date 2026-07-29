package runtime

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// ClockSyncer disciplines CLOCK_REALTIME against the parent instance's PTP
// hardware clock (/dev/ptp0), compensating for oscillator frequency drift to
// maintain an accurate enclave clock.
//
// On each synchronization interval it measures:
//
//	offset = PHC - CLOCK_REALTIME
//
// The measured offset is fed into a PI (proportional-integral) controller that
// computes a frequency adjustment applied via ADJ_FREQUENCY. Large offsets are
// treated as gross errors and corrected with ClockSettime.
//
// The proportional term provides a fast response to the current offset, while
// the integral term continuously estimates the oscillator's frequency error,
// allowing the clock to converge to zero steady-state offset.
//
// This follows the same control strategy as linuxptp's PI clock servo, with
// gains tuned for the enclave's longer synchronization interval. Unlike a
// conventional Linux system, a Nitro Enclave cannot run its own network-based
// time synchronization service, so CLOCK_REALTIME would otherwise accumulate
// drift over time.
//
// Sign convention: offset = PHC - CLOCK_REALTIME. A positive offset means
// CLOCK_REALTIME is behind the PHC, so a positive frequency correction speeds
// it up.
//
// References:
//   - PI controller: https://en.wikipedia.org/wiki/PID_controller
//   - linuxptp PI servo: https://github.com/richardcochran/linuxptp/blob/master/pi.c

const (
	ptpDevicePath = "/dev/ptp0"

	freqScale        = 1 << 16 // ppm << 16
	kernelMaxFreqPpm = 500.0
	nsPerPpmPerSec   = 1000.0 // 1 ppm == 1 us/s == 1000 ns/s
	nsPerSecond      = 1_000_000_000
	defaultMaxStepNs = 100 * 1_000_000 // 100 ms

	clockSyncRetryInterval  = 10 * time.Second
	clockSyncFailureTimeout = time.Minute
)

// offsetMeasurement is one PHC/REALTIME comparison.
type offsetMeasurement struct {
	xMonoNs  int64
	phcNs    int64
	offsetNs int64
}

type servoConfig struct {
	kp           float64 // proportional gain (fraction of the offset nulled per interval)
	ki           float64 // integral gain
	freqClampPpm float64
	maxStepNs    int64
}

func defaultServoConfig() servoConfig {
	return servoConfig{
		kp:           0.5,
		ki:           0.05,
		freqClampPpm: 100.0,
		maxStepNs:    defaultMaxStepNs,
	}
}

// clockSyncer owns the open PHC device and carries the PI servo state inline
// (integralPpm is the standing frequency correction; lastXMonoNs/hasPreviousMeasurement
// bound the per-poll interval).
type clockSyncer struct {
	file     *os.File
	fd       int
	interval time.Duration

	retryInterval  time.Duration
	failureTimeout time.Duration

	cfg                    servoConfig
	integralPpm            float64 // integral term: the standing frequency correction
	lastXMonoNs            int64
	hasPreviousMeasurement bool
}

func StartClockSyncer(ctx context.Context) (context.Context, error) {
	cs, err := newClockSyncer()
	if err != nil {
		return nil, err
	}

	runCtx, cancel := context.WithCancelCause(ctx)
	go func() {
		cancel(cs.run(runCtx))
	}()
	return runCtx, nil
}

func newClockSyncer() (*clockSyncer, error) {
	file, err := openPTPDevice()
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", ptpDevicePath, err)
	}
	// The dynamic clock id is derived from the live fd, so the syncer keeps it open.
	phc := fdToClockID(file.Fd())

	var ptp, sys unix.Timespec
	if err := clockGettime(phc, &ptp); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("read PTP clock %s: %w", ptpDevicePath, err)
	}
	if err := clockGettime(unix.CLOCK_REALTIME, &sys); err == nil {
		slog.Info("clock sync: initial offset before hard-step", "offset_ms", clockOffsetNsec(ptp, sys)/1_000_000)
	}
	if err := clockSettime(unix.CLOCK_REALTIME, &ptp); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("initial hard-step to PHC failed: %w", err)
	}
	slog.Info("clock sync: initial hard-step to hypervisor PTP completed")

	return &clockSyncer{
		file:           file,
		fd:             int(file.Fd()),
		interval:       clockPollInterval(),
		retryInterval:  clockSyncRetryInterval,
		failureTimeout: clockSyncFailureTimeout,
		cfg:            defaultServoConfig(),
	}, nil
}

func (cs *clockSyncer) run(ctx context.Context) error {
	defer func() { _ = cs.file.Close() }()

	timer := time.NewTimer(cs.interval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("clock sync stopping")
			return nil

		case <-timer.C:
		}

		if err := cs.step(ctx); err != nil {
			return err
		}

		timer.Reset(cs.interval)
	}
}

// step performs a single synchronization cycle.
func (cs *clockSyncer) step(ctx context.Context) error {
	deadline := time.Now().Add(cs.failureTimeout)

	stepOnce := func() error {
		offsetMeasurement, err := cs.measureOffset()
		if err != nil {
			return fmt.Errorf("measure offset: %w", err)
		}
		if err := cs.adjust(offsetMeasurement); err != nil {
			return fmt.Errorf("apply adjustment: %w", err)
		}
		return nil
	}

	for {
		err := stepOnce()
		if err == nil {
			return nil
		}

		// PHC read failures are usually transient rather than indicating a
		// dead clock. During ENA resets the AWS driver returns EOPNOTSUPP
		// while the PTP device is reinitializing (/dev/ptp0 remains valid),
		// and EBUSY during the subsequent ~1 ms back-off.
		if time.Now().After(deadline) {
			return fmt.Errorf(
				"clock sync failed for %s: %w",
				cs.failureTimeout,
				err,
			)
		}

		slog.Warn("clock sync: read failed, retrying", "error", err)

		timer := time.NewTimer(cs.retryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

var (
	openPTPDevice = func() (*os.File, error) { return os.OpenFile(ptpDevicePath, os.O_RDONLY, 0) }
	clockGettime  = unix.ClockGettime
	clockAdjtime  = unix.ClockAdjtime
	clockSettime  = unix.ClockSettime
)

// adjust folds one measurement into the PI loop and applies the resulting correction.
func (cs *clockSyncer) adjust(m offsetMeasurement) error {
	raw := m.offsetNs
	// Gross offset: jump the clock and restart the loop (the standing frequency persists).
	if raw > cs.cfg.maxStepNs || raw < -cs.cfg.maxStepNs {
		cs.hasPreviousMeasurement = false
		ts := unix.NsecToTimespec(m.phcNs)
		err := clockSettime(unix.CLOCK_REALTIME, &ts)
		if err == nil {
			slog.Warn("clock sync: hard-step", "offset_ms", float64(m.offsetNs)/1e6)
		}
		return err
	}

	applied := cs.integralPpm // warm-up holds the standing integral until there is an interval
	proportionalPpm := 0.0
	if correctingFreqPpm, ok := cs.frequencyErrorPpm(m); ok {
		cs.integralPpm = clampFloat(cs.integralPpm+cs.cfg.ki*correctingFreqPpm, -cs.cfg.freqClampPpm, cs.cfg.freqClampPpm)
		proportionalPpm = cs.cfg.kp * correctingFreqPpm
		applied = clampFloat(proportionalPpm+cs.integralPpm, -cs.cfg.freqClampPpm, cs.cfg.freqClampPpm)
	}
	cs.lastXMonoNs = m.xMonoNs
	cs.hasPreviousMeasurement = true

	tx := unix.Timex{
		Modes:  unix.ADJ_FREQUENCY | unix.ADJ_STATUS,
		Status: unix.STA_FREQHOLD,
		Freq:   ppmToKernelFreq(applied),
	}
	if _, err := clockAdjtime(unix.CLOCK_REALTIME, &tx); err != nil {
		return err
	}

	slog.Info("clock sync: disciplined",
		"freq_ppm", applied, // what is applied: proportional + integral
		"integral_ppm", cs.integralPpm,
		"proportional_ppm", proportionalPpm,
		"offset_us", float64(raw)/1e3,
	)
	return nil
}

func (cs *clockSyncer) frequencyErrorPpm(m offsetMeasurement) (ppm float64, ok bool) {
	elapsedSeconds := float64(m.xMonoNs-cs.lastXMonoNs) / nsPerSecond
	if !cs.hasPreviousMeasurement || elapsedSeconds <= 0 {
		return 0, false
	}
	return float64(m.offsetNs) / (elapsedSeconds * nsPerPpmPerSec), true
}

func (cs *clockSyncer) measureOffset() (offsetMeasurement, error) {
	phc := fdToClockID(uintptr(cs.fd))
	var sys, phcTs, mono unix.Timespec
	if err := clockGettime(unix.CLOCK_REALTIME, &sys); err != nil {
		return offsetMeasurement{}, fmt.Errorf("read realtime: %w", err)
	}
	if err := clockGettime(phc, &phcTs); err != nil {
		return offsetMeasurement{}, fmt.Errorf("read PHC: %w", err)
	}
	if err := clockGettime(unix.CLOCK_MONOTONIC_RAW, &mono); err != nil {
		return offsetMeasurement{}, fmt.Errorf("read monotonic-raw: %w", err)
	}
	phcNs := unix.TimespecToNsec(phcTs)
	return offsetMeasurement{
		xMonoNs:  unix.TimespecToNsec(mono),
		phcNs:    phcNs,
		offsetNs: phcNs - unix.TimespecToNsec(sys),
	}, nil
}

func ppmToKernelFreq(ppm float64) int64 {
	ppm = clampFloat(ppm, -kernelMaxFreqPpm, kernelMaxFreqPpm)
	return int64(math.Round(ppm * freqScale))
}

func clampFloat(v, lo, hi float64) float64 {
	return math.Max(lo, math.Min(hi, v))
}

// fdToClockID is the kernel's FD_TO_CLOCKID macro: ((~fd) << 3) | 3.
func fdToClockID(fd uintptr) int32 {
	return int32(^uint32(fd)<<3 | 3)
}

// clockOffsetNsec returns ptp - sys in ns; positive means CLOCK_REALTIME is behind.
func clockOffsetNsec(ptp, sys unix.Timespec) int64 {
	return (ptp.Sec*nsPerSecond + ptp.Nsec) - (sys.Sec*nsPerSecond + sys.Nsec)
}
