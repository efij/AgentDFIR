package browser

import (
	"math"
	"time"
)

// Browser history clocks. Each is converted to UTC and the raw value is
// kept beside it, because a conversion an examiner cannot re-check is an
// opinion, not evidence.
const (
	ClockWebKit = "WebKit µs since 1601-01-01" // Chrome, Edge, Brave, Arc, Vivaldi, Opera, Chromium
	ClockPRTime = "PRTime µs since 1970-01-01" // Firefox
	ClockCocoa  = "Cocoa s since 2001-01-01"   // Safari
)

const (
	webkitToUnixSec = 11644473600 // seconds between 1601-01-01 and 1970-01-01
	cocoaToUnixSec  = 978307200   // seconds between 1970-01-01 and 2001-01-01
)

// plausible bounds a converted time: before 1995 or after 2200 the value
// is corrupt, zero, or on a different clock, and is reported raw only.
var (
	minPlausible = time.Date(1995, 1, 1, 0, 0, 0, 0, time.UTC)
	maxPlausible = time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)
)

// webkitTime converts a Chromium visit_time.
func webkitTime(us int64) (time.Time, bool) {
	if us <= 0 {
		return time.Time{}, false
	}
	return plausible(time.UnixMicro(us - webkitToUnixSec*1_000_000).UTC())
}

// prTime converts a Firefox visit_date.
func prTime(us int64) (time.Time, bool) {
	if us <= 0 {
		return time.Time{}, false
	}
	return plausible(time.UnixMicro(us).UTC())
}

// cocoaTime converts a Safari visit_time (REAL seconds; an integer is
// accepted too).
func cocoaTime(v any) (time.Time, bool) {
	var sec float64
	switch x := v.(type) {
	case float64:
		sec = x
	case int64:
		sec = float64(x)
	default:
		return time.Time{}, false
	}
	if sec <= 0 || math.IsNaN(sec) || math.IsInf(sec, 0) || sec > 1e10 {
		return time.Time{}, false
	}
	whole, frac := math.Modf(sec)
	return plausible(time.Unix(int64(whole)+cocoaToUnixSec, int64(frac*1e9)).UTC())
}

func plausible(t time.Time) (time.Time, bool) {
	if t.Before(minPlausible) || t.After(maxPlausible) {
		return time.Time{}, false
	}
	return t, true
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05.000000Z")
}
