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

	cfg                    servoConfig
	integralPpm            float64 // integral term: the standing frequency correction
	lastXMonoNs            int64
	hasPreviousMeasurement bool
}

func StartClockSyncer(ctx context.Context) error {
	cs, err := newClockSyncer()
	if err != nil {
		return err
	}
	go cs.run(ctx)
	return nil
}

func newClockSyncer() (*clockSyncer, error) {
	file, err := os.OpenFile(ptpDevicePath, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", ptpDevicePath, err)
	}
	// The dynamic clock id is derived from the live fd, so the syncer keeps it open.
	phc := fdToClockID(file.Fd())

	var ptp, sys unix.Timespec
	if err := unix.ClockGettime(phc, &ptp); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("read PTP clock %s: %w", ptpDevicePath, err)
	}
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &sys); err == nil {
		slog.Info("clock sync: initial offset before hard-step", "offset_ms", clockOffsetNsec(ptp, sys)/1_000_000)
	}
	if err := unix.ClockSettime(unix.CLOCK_REALTIME, &ptp); err != nil {
		slog.Warn("clock sync: initial hard-step failed; servo will converge", "error", err)
	} else {
		slog.Info("clock sync: initial hard-step to hypervisor PTP completed")
	}

	if IsDev() {
		maybeInjectCustomTime()
	}

	return &clockSyncer{
		file:     file,
		fd:       int(file.Fd()),
		interval: clockPollInterval(),
		cfg:      defaultServoConfig(),
	}, nil
}

// maybeInjectCustomTime offsets CLOCK_REALTIME
func maybeInjectCustomTime() {
	step := clockStepNs()
	if step == 0 {
		return
	}
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &now); err != nil {
		return
	}
	skewed := unix.NsecToTimespec(unix.TimespecToNsec(now) + step)
	if err := unix.ClockSettime(unix.CLOCK_REALTIME, &skewed); err != nil {
		slog.Warn("clock sync: DEV test skew failed", "error", err)
		return
	}
	slog.Warn("clock sync: DEV test skew injected", "step_ns", step)
}

func (cs *clockSyncer) run(ctx context.Context) {
	defer func() { _ = cs.file.Close() }()
	ticker := time.NewTicker(cs.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("clock sync stopping")
			return
		case <-ticker.C:
		}
		if err := cs.step(); err != nil {
			slog.Error("clock sync: step failed", "error", err)
		}

	}
}

// step is one poll cycle: measure the offset, run the PI loop, apply the correction.
func (cs *clockSyncer) step() error {
	offsetMeasurement, err := cs.measureOffset()
	if err != nil {
		return fmt.Errorf("measure offset: %w", err)
	}
	if err := cs.adjust(offsetMeasurement); err != nil {
		return fmt.Errorf("apply adjustment: %w", err)
	}
	return nil
}

var (
	clockAdjtime = unix.ClockAdjtime
	clockSettime = unix.ClockSettime
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
			slog.Info("clock sync: hard-step", "offset_ms", float64(m.offsetNs)/1e6)
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
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &sys); err != nil {
		return offsetMeasurement{}, fmt.Errorf("read realtime: %w", err)
	}
	if err := unix.ClockGettime(phc, &phcTs); err != nil {
		return offsetMeasurement{}, fmt.Errorf("read PHC: %w", err)
	}
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC_RAW, &mono); err != nil {
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
