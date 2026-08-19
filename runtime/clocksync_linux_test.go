package runtime

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// drift parameterizes a closed-loop simulation for simulateDrift.
type drift struct {
	nativeDriftPpm float64
	sigmaNs        float64 // measurement noise std (0 = clean)
	intervalS      float64 // nominal poll interval
	jitterS        float64 // interval jitter std (0 = fixed cadence)
	steps          int
	rng            *rand.Rand
}

type driftResult struct {
	applied        float64 // final applied ppm (integral + a proportional kick from the last sample)
	integral       float64 // final integralPpm — the stable frequency estimate
	offsetNs       float64 // final residual offset
	maxAbs         float64 // max |applied| over the run (clamp invariant)
	integralSpread float64 // max-min of integralPpm over the final quarter (post-convergence)
}

// simulateDrift closes the servo loop against a modeled clock: each cycle stubs the kernel
// write seams to capture what adjust applies, then accrues drift at -(native+applied).
func simulateDrift(cs *clockSyncer, d drift) driftResult {
	origAdj, origSet := clockAdjtime, clockSettime
	defer func() { clockAdjtime, clockSettime = origAdj, origSet }()
	var freqUnits int64
	var hardStepped bool
	clockAdjtime = func(_ int32, tx *unix.Timex) (int, error) { freqUnits = tx.Freq; return 0, nil }
	clockSettime = func(_ int32, _ *unix.Timespec) error { hardStepped = true; return nil }

	var res driftResult
	var trueOffsetNs, appliedSim float64
	var xMonoNs int64
	minI, maxI := math.Inf(1), math.Inf(-1)
	for step := 0; step < d.steps; step++ {
		measured := trueOffsetNs
		if d.rng != nil && d.sigmaNs > 0 {
			measured += d.rng.NormFloat64() * d.sigmaNs
		}
		hardStepped = false
		_ = cs.adjust(offsetMeasurement{
			xMonoNs:  xMonoNs,
			phcNs:    int64(trueOffsetNs),
			offsetNs: int64(math.Round(measured)),
		})
		if hardStepped {
			trueOffsetNs = 0
		} else {
			appliedSim = float64(freqUnits) / freqScale // ADJ_FREQUENCY sets absolute rate
			if a := math.Abs(appliedSim); a > res.maxAbs {
				res.maxAbs = a
			}
		}
		if step >= 3*d.steps/4 { // spread of the estimate once converged
			minI, maxI = math.Min(minI, cs.integralPpm), math.Max(maxI, cs.integralPpm)
		}
		interval := d.intervalS
		if d.rng != nil && d.jitterS > 0 {
			if j := interval + d.rng.NormFloat64()*d.jitterS; j > 0 {
				interval = j
			}
		}
		fTotal := d.nativeDriftPpm + appliedSim
		trueOffsetNs += -(fTotal) * nsPerPpmPerSec * interval
		xMonoNs += int64(interval * nsPerSecond)
	}
	res.applied, res.integral, res.offsetNs, res.integralSpread = appliedSim, cs.integralPpm, trueOffsetNs, maxI-minI
	return res
}

// captureAdjust runs cs.adjust(m) with the kernel write seams stubbed, returning the
// frequency it would apply (ppm) and, for a hard-step, the target it would set — without
// touching the real clock.
func captureAdjust(
	cs *clockSyncer,
	m offsetMeasurement,
) (appliedPpm float64, hardStep bool, stepToNs int64) {
	origAdj, origSet := clockAdjtime, clockSettime
	defer func() { clockAdjtime, clockSettime = origAdj, origSet }()
	var freqUnits int64
	clockAdjtime = func(_ int32, tx *unix.Timex) (int, error) { freqUnits = tx.Freq; return 0, nil }
	clockSettime = func(_ int32, ts *unix.Timespec) error {
		hardStep, stepToNs = true, unix.TimespecToNsec(*ts)
		return nil
	}
	_ = cs.adjust(m)
	return float64(freqUnits) / freqScale, hardStep, stepToNs
}

func TestFdToClockID(t *testing.T) {
	// FD_TO_CLOCKID(fd) = ((~fd) << 3) | 3. For fd=3: ((~3)<<3)|3 = (-4<<3)|3 = -29.
	cases := map[uintptr]int32{
		3:  -29,
		4:  -37,
		10: -85,
	}
	for fd, want := range cases {
		require.Equal(t, want, fdToClockID(fd), "fdToClockID(%d)", fd)
	}
}

func TestClockOffsetNsec(t *testing.T) {
	ts := func(sec, nsec int64) unix.Timespec { return unix.Timespec{Sec: sec, Nsec: nsec} }

	cases := []struct {
		name     string
		ptp, sys unix.Timespec
		want     int64
	}{
		{"ptp 2s ahead", ts(100, 500), ts(98, 500), 2_000_000_000},
		{"ptp 0.5s behind", ts(5, 200_000_000), ts(5, 700_000_000), -500_000_000},
		{"in sync", ts(42, 123), ts(42, 123), 0},
		// Crosses the 1e9 boundary: must not mis-handle the second/nanosecond split.
		{"one ns across boundary", ts(5, 999_999_999), ts(6, 0), -1},
		{"one ns ahead across boundary", ts(6, 0), ts(5, 999_999_999), 1},
	}
	for _, c := range cases {
		require.Equal(t, c.want, clockOffsetNsec(c.ptp, c.sys), c.name)
	}
}

func TestFreqPpmToUnits(t *testing.T) {
	cases := []struct {
		name string
		ppm  float64
		want int64
	}{
		{"one ppm", 1.0, 65536},
		{"native 11.6 ppm slow-correction", 11.6, 760218}, // round(11.6*65536)=760217.6
		{"negative one ppm", -1.0, -65536},
		{"zero", 0, 0},
		{"clamp above +500", 1000, 500 * 65536},
		{"clamp below -500", -1000, -500 * 65536},
	}
	for _, c := range cases {
		require.Equal(t, c.want, ppmToKernelFreq(c.ppm), c.name)
	}
}

// TestObserveSignDirection asserts, in closed loop, that a slow REALTIME (native<0,
// offset grows positive) drives a positive frequency correction and a fast clock a
// negative one
func TestObserveSignDirection(t *testing.T) {
	for _, nativePpm := range []float64{-11.6, +11.6} {
		s := &clockSyncer{cfg: defaultServoConfig()}
		res := simulateDrift(s, drift{nativeDriftPpm: nativePpm, intervalS: 30, steps: 20})
		require.Less(
			t,
			nativePpm*res.applied,
			0.0,
			"native %v: correction opposes drift",
			nativePpm,
		)
	}
}

func TestObserveHardStep(t *testing.T) {
	cs := &clockSyncer{cfg: defaultServoConfig()}
	// First sample has no interval yet: holds the (zero) standing frequency.
	applied, isHardStep, _ := captureAdjust(cs, offsetMeasurement{xMonoNs: 0, offsetNs: 1000})
	require.Zero(t, applied, "fresh servo holds zero frequency")
	require.False(t, isHardStep, "first sample does not trigger hard-step")
	// Second sample gives an interval: the PI loop engages and applies a correction.
	applied, isHardStep, _ = captureAdjust(
		cs,
		offsetMeasurement{xMonoNs: nsPerSecond, offsetNs: 1000},
	)
	require.NotZero(t, applied, "PI engages once there is an interval")
	require.False(t, isHardStep, "small offset does not trigger hard-step")
	// Third sample is a gross offset: triggers a hard-step and resets the interval baseline.
	_, isHardStep, stepToNs := captureAdjust(
		cs,
		offsetMeasurement{
			xMonoNs:  2 * nsPerSecond,
			phcNs:    42_000_000_000,
			offsetNs: 200 * 1_000_000,
		},
	)
	require.True(t, isHardStep, "gross offset triggers hard-step")
	require.Equal(t, int64(42_000_000_000), stepToNs)
	require.Equal(
		t,
		int64(2*nsPerSecond),
		cs.lastXMonoNs,
		"hard-step restarts the interval baseline",
	)
}

func TestAdjustCommitsStateOnlyOnSuccess(t *testing.T) {
	origAdj := clockAdjtime
	defer func() { clockAdjtime = origAdj }()

	cs := &clockSyncer{cfg: defaultServoConfig()}
	captureAdjust(cs, offsetMeasurement{xMonoNs: 0, offsetNs: 6_000_000})
	captureAdjust(cs, offsetMeasurement{xMonoNs: 300 * nsPerSecond, offsetNs: 6_000_000})

	integral, baseline := cs.integralPpm, cs.lastXMonoNs
	require.NotZero(t, integral, "warm-up leaves a standing integral")

	clockAdjtime = func(int32, *unix.Timex) (int, error) { return 0, errors.New("EPERM") }
	err := cs.adjust(offsetMeasurement{xMonoNs: 310 * nsPerSecond, offsetNs: 6_200_000})

	require.Error(t, err)
	require.Equal(t, integral, cs.integralPpm, "integral must not advance past a failed adjustment")
	require.Equal(t, baseline, cs.lastXMonoNs, "baseline must not advance past a failed adjustment")
}

func TestClockPollInterval(t *testing.T) {
	cases := []struct {
		name            string
		dev, deployment string
		want            time.Duration
	}{
		{"dev polls fast", "true", "prod", 5 * time.Second},
		{"prod polls every 5min", "", "prod", 5 * time.Minute},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("ENCLAVE_DEV", c.dev)
			t.Setenv("ENCLAVE_DEPLOYMENT", c.deployment)
			require.Equal(t, c.want, clockPollInterval())
		})
	}
}

func TestMeasureOffset(t *testing.T) {
	original := clockGettime
	t.Cleanup(func() { clockGettime = original })
	const fd = 3
	phcID := fdToClockID(fd)
	var calls []int32
	clockGettime = func(clockID int32, ts *unix.Timespec) error {
		calls = append(calls, clockID)
		switch clockID {
		case unix.CLOCK_REALTIME:
			*ts = unix.Timespec{Sec: 100, Nsec: 200}
		case phcID:
			*ts = unix.Timespec{Sec: 100, Nsec: 500}
		case unix.CLOCK_MONOTONIC_RAW:
			*ts = unix.Timespec{Sec: 5, Nsec: 7}
		default:
			t.Fatalf("unexpected clock ID: %d", clockID)
		}
		return nil
	}

	got, err := (&clockSyncer{fd: fd}).measureOffset()

	require.NoError(t, err)
	require.Equal(t, offsetMeasurement{
		xMonoNs:  5*nsPerSecond + 7,
		phcNs:    100*nsPerSecond + 500,
		offsetNs: 300,
	}, got)
	require.Equal(t, []int32{
		unix.CLOCK_REALTIME,
		phcID,
		unix.CLOCK_MONOTONIC_RAW,
	}, calls)
}

func TestAdjustSetsFrequencyOnly(t *testing.T) {
	origAdj := clockAdjtime
	defer func() { clockAdjtime = origAdj }()

	var modes uint32
	clockAdjtime = func(_ int32, tx *unix.Timex) (int, error) { modes = tx.Modes; return 0, nil }

	cs := &clockSyncer{cfg: defaultServoConfig()}
	require.NoError(t, cs.adjust(offsetMeasurement{xMonoNs: 0, offsetNs: 1000}))

	require.Equal(
		t,
		uint32(unix.ADJ_FREQUENCY),
		modes,
		"ADJ_STATUS would replace every writable status flag, clearing STA_UNSYNC and pending STA_INS/STA_DEL",
	)
}

// TestNewClockSyncer covers the OS-facing bootstrap: every failure path is fatal
// (that decision is what gates whether the enclave boots), and success wires the
// retry/timeout defaults.
func TestNewClockSyncer(t *testing.T) {
	origOpen, origGet, origSet := openPTPDevice, clockGettime, clockSettime
	defer func() { openPTPDevice, clockGettime, clockSettime = origOpen, origGet, origSet }()

	realFile := func(t *testing.T) *os.File {
		f, err := os.CreateTemp(t.TempDir(), "ptp")
		require.NoError(t, err)
		return f
	}
	ok := func(int32, *unix.Timespec) error { return nil }
	fail := func(msg string) func(int32, *unix.Timespec) error {
		return func(int32, *unix.Timespec) error { return errors.New(msg) }
	}

	t.Run("open failure is fatal", func(t *testing.T) {
		openPTPDevice = func() (*os.File, error) { return nil, errors.New("no device") }
		clockGettime, clockSettime = ok, ok
		cs, err := newClockSyncer()
		require.ErrorContains(t, err, "open")
		require.Nil(t, cs)
	})

	t.Run("PHC read failure is fatal", func(t *testing.T) {
		f := realFile(t)
		openPTPDevice = func() (*os.File, error) { return f, nil }
		clockGettime, clockSettime = fail("EOPNOTSUPP"), ok
		cs, err := newClockSyncer()
		require.ErrorContains(t, err, "read PTP clock")
		require.Nil(t, cs)
	})

	t.Run("initial hard-step failure is fatal", func(t *testing.T) {
		f := realFile(t)
		openPTPDevice = func() (*os.File, error) { return f, nil }
		clockGettime, clockSettime = ok, fail("EPERM")
		cs, err := newClockSyncer()
		require.ErrorContains(t, err, "initial hard-step")
		require.Nil(t, cs)
	})

	t.Run("success wires retry/timeout defaults", func(t *testing.T) {
		f := realFile(t)
		openPTPDevice = func() (*os.File, error) { return f, nil }
		clockGettime, clockSettime = ok, ok
		cs, err := newClockSyncer()
		require.NoError(t, err)
		require.NotNil(t, cs)
		require.Equal(t, clockSyncRetryInterval, cs.retryInterval)
		require.Equal(t, clockSyncFailureTimeout, cs.failureTimeout)
		_ = cs.file.Close()
	})
}

// TestStepRetry covers the retry/deadline logic that decides whether a transient
// PHC read failure is tolerated or halts the runtime.
func TestStepRetry(t *testing.T) {
	origGet, origAdj := clockGettime, clockAdjtime
	defer func() { clockGettime, clockAdjtime = origGet, origAdj }()
	clockAdjtime = func(int32, *unix.Timex) (int, error) { return 0, nil }

	newCS := func() *clockSyncer {
		return &clockSyncer{
			cfg:            defaultServoConfig(),
			retryInterval:  time.Millisecond,
			failureTimeout: 20 * time.Millisecond,
		}
	}

	t.Run("transient failure recovers before the deadline", func(t *testing.T) {
		var reads int
		clockGettime = func(int32, *unix.Timespec) error {
			if reads++; reads <= 3 {
				return errors.New("EBUSY")
			}
			return nil
		}
		require.NoError(t, newCS().step(context.Background()))
	})

	t.Run("failure past the deadline halts", func(t *testing.T) {
		clockGettime = func(int32, *unix.Timespec) error { return errors.New("EOPNOTSUPP") }
		require.ErrorContains(t, newCS().step(context.Background()), "clock sync failed")
	})

	t.Run("ctx cancel during backoff is a clean stop", func(t *testing.T) {
		clockGettime = func(int32, *unix.Timespec) error { return errors.New("EOPNOTSUPP") }
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		require.NoError(t, newCS().step(ctx))
	})
}

func TestObserveFreqStep(t *testing.T) {
	// Within the ±clamp the integral tracks the drift exactly; beyond it the integral
	// saturates at the rail and never winds past it, at either sign.
	cases := []struct {
		nativeDriftPpm float64
		wantFreq       float64
	}{
		{-50, +50},   // within range: tracks exactly, clamp does not bite
		{+50, -50},   //
		{-250, +100}, // wants +250, saturates at the +rail
		{+250, -100}, // wants -250, saturates at the -rail
	}
	for _, c := range cases {
		cfg := defaultServoConfig()
		cfg.maxStepNs = 5 * nsPerSecond // let the offset accrue without hard-stepping
		s := &clockSyncer{cfg: cfg}
		res := simulateDrift(s, drift{nativeDriftPpm: c.nativeDriftPpm, intervalS: 30, steps: 400})
		require.InDelta(
			t,
			c.wantFreq,
			res.integral,
			0.05,
			"native %v: integral tracks/saturates",
			c.nativeDriftPpm,
		)
		require.InDelta(
			t,
			c.wantFreq,
			res.applied,
			0.05,
			"native %v: applied tracks/saturates",
			c.nativeDriftPpm,
		)
		require.LessOrEqual(
			t,
			res.maxAbs,
			100.0,
			"native %v: applied never exceeds the clamp",
			c.nativeDriftPpm,
		)
	}

	// checks a distinct property from convergence: once locked, the integral (frequency estimate) must stay quiet under sustained noise.
	rng := rand.New(rand.NewSource(1))
	cs := &clockSyncer{cfg: defaultServoConfig()}
	res := simulateDrift(
		cs,
		drift{nativeDriftPpm: 20, sigmaNs: 100_000, intervalS: 30, steps: 800, rng: rng},
	)
	require.InDelta(t, -20.0, res.integral, 1.0, "integral converges near -native under noise")
	require.LessOrEqual(
		t,
		res.integralSpread,
		2.0,
		"frequency estimate must not chatter once locked",
	)
}

// TestSyncHandlesMeasurementGap verifies that after a long gap (missed polls) the servo
// sees a large dt + a large accrued offset and computes a sane frequency from offset/dt,
// rather than exploding.
func TestSyncHandlesMeasurementGap(t *testing.T) {
	cs := &clockSyncer{cfg: defaultServoConfig()}
	captureAdjust(cs, offsetMeasurement{xMonoNs: 0, offsetNs: 0}) // prime the baseline

	// 5-minute gap: at +20 ppm the offset accrues 20e-6 * 300 * 1e9 = 6 ms.
	const gapS = 300.0
	applied, hardStep, _ := captureAdjust(cs, offsetMeasurement{
		xMonoNs:  int64(gapS * nsPerSecond),
		offsetNs: 6_000_000,
	})
	require.False(t, hardStep, "6ms offset is below the 100ms step threshold")
	// correctingFreqPpm = 6e6/(300*1000) = 20 ppm; applied = kp*20 + ki*20 = 10 + 1 = 11.
	require.InDelta(t, 11.0, applied, 1.0, "a large dt yields a sane frequency, not an explosion")

	// A 2-hour gap at the same +20 ppm accrues 20e-6 * 7200 * 1e9 = 144 ms — past the
	// 100 ms threshold, so the servo hard-steps onto the PHC instead of slewing.
	_, hardStep, stepToNs := captureAdjust(cs, offsetMeasurement{
		xMonoNs:  int64((gapS + 7200) * nsPerSecond),
		phcNs:    123_456_789,
		offsetNs: 144_000_000,
	})
	require.True(t, hardStep, "144ms offset exceeds the 100ms step threshold")
	require.Equal(t, int64(123_456_789), stepToNs, "hard-step targets the PHC")
	require.Equal(
		t,
		int64((gapS+7200)*nsPerSecond),
		cs.lastXMonoNs,
		"hard-step restarts the interval baseline",
	)
}

// TestServoConvergence closes the loop through adjust() and asserts the integral term
// converges to cancel the native drift with the residual offset bounded — across
// multiple noise seeds (so a pass isn't luck), interval jitter, and the ±clamp invariant.
func TestServoConvergence(t *testing.T) {
	const intervalS = 30.0
	const steps = 800

	cases := []struct {
		name         string
		nativePpm    float64
		sigmaNs      float64
		jitterS      float64
		tolerancePpm float64
		tolOffsetN   float64
	}{
		{"zero drift, no noise", 0, 0, 0, 0.05, 1_000},
		{"slow 11.6ppm, no noise", -11.6, 0, 0, 0.05, 5_000},
		{"fast 11.6ppm, no noise", +11.6, 0, 0, 0.05, 5_000},
		{"slow 11.6ppm, 50us noise", -11.6, 50_000, 0, 1.0, 2_000_000},
		{"fast 50ppm, 200us noise", +50, 200_000, 0, 2.0, 5_000_000},
		{"slow 50ppm, 200us noise", -50, 200_000, 0, 2.0, 5_000_000},
		{"slow 11.6ppm, jittered interval", -11.6, 50_000, 2.0, 1.0, 3_000_000},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			seeds := int64(1) // deterministic cases don't need repeats
			if c.sigmaNs > 0 || c.jitterS > 0 {
				seeds = 5
			}
			for seed := int64(1); seed <= seeds; seed++ {
				rng := rand.New(rand.NewSource(seed))
				s := &clockSyncer{cfg: defaultServoConfig()}
				res := simulateDrift(s, drift{
					nativeDriftPpm: c.nativePpm, sigmaNs: c.sigmaNs, intervalS: intervalS,
					jitterS: c.jitterS, steps: steps, rng: rng,
				})
				require.InDelta(
					t,
					-c.nativePpm,
					res.integral,
					c.tolerancePpm,
					"seed %d: integral should cancel native drift",
					seed,
				)
				require.InDelta(
					t,
					0.0,
					res.offsetNs,
					c.tolOffsetN,
					"seed %d: residual offset bounded",
					seed,
				)
				require.LessOrEqual(
					t,
					res.maxAbs,
					100.0,
					"seed %d: applied never exceeds the clamp",
					seed,
				)
			}
		})
	}
}
