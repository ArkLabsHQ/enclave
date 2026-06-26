package runtime

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestFdToClockID(t *testing.T) {
	// FD_TO_CLOCKID(fd) = ((~fd) << 3) | 3. For fd=3: ((~3)<<3)|3 = (-4<<3)|3 = -29.
	cases := map[uintptr]int32{
		3:  -29,
		4:  -37,
		10: -85,
	}
	for fd, want := range cases {
		if got := fdToClockID(fd); got != want {
			t.Errorf("fdToClockID(%d) = %d, want %d", fd, got, want)
		}
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
		if got := clockOffsetNsec(c.ptp, c.sys); got != c.want {
			t.Errorf("%s: clockOffsetNsec = %d, want %d", c.name, got, c.want)
		}
	}
}
