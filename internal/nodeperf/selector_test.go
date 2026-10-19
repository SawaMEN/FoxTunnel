package nodeperf

import (
	"testing"
	"time"
)

func quality(origin string, delay float64, success uint64, when time.Time) Snapshot {
	return Snapshot{
		Origin: origin, RequestLatencyMS: delay, SuccessfulResponses: success,
		Samples: success, LastSuccess: when,
	}
}

func TestAdaptiveColdStartSpreadsWithoutProbes(t *testing.T) {
	now := time.Now()
	candidates := []Candidate{{Origin: "https://a"}, {Origin: "https://b"}}
	state := SelectionState{}
	for _, want := range []int{0, 1, 0, 1} {
		var got int
		got, state = Select(candidates, nil, state, now)
		if got != want {
			t.Fatalf("cold start: got %d, want %d", got, want)
		}
	}
	if state.Preferred != "" {
		t.Fatalf("unmeasured route became preferred: %+v", state)
	}
}

func TestAdaptiveRequiresRecentSamples(t *testing.T) {
	now := time.Now()
	candidates := []Candidate{{Origin: "https://a"}, {Origin: "https://b"}}
	measurements := []Snapshot{quality("https://a", 5, 2, now), quality("https://b", 40, 3, now)}
	got, state := Select(candidates, measurements, SelectionState{}, now)
	if got != 1 || state.Preferred != "https://b" {
		t.Fatalf("under-sampled route was selected: %d %+v", got, state)
	}
	measurements[0] = quality("https://a", 3, 30, now.Add(-3*time.Minute))
	got, _ = Select(candidates, measurements, SelectionState{}, now)
	if got != 1 {
		t.Fatalf("stale route was selected: %d", got)
	}
}

func TestAdaptiveHysteresisAndDwell(t *testing.T) {
	now := time.Now()
	candidates := []Candidate{{Origin: "https://a"}, {Origin: "https://b"}}
	measurements := []Snapshot{quality("https://a", 20, 10, now), quality("https://b", 75, 10, now)}
	state := SelectionState{Preferred: "https://b", Since: now.Add(-10 * time.Second)}
	got, next := Select(candidates, measurements, state, now)
	if got != 1 || next.Preferred != "https://b" {
		t.Fatalf("switch before dwell: %d %+v", got, next)
	}
	state.Since = now.Add(-time.Minute)
	got, next = Select(candidates, measurements, state, now)
	if got != 0 || next.Preferred != "https://a" || !next.Since.Equal(now) {
		t.Fatalf("strong sustained improvement ignored: %d %+v", got, next)
	}
	measurements[0].RequestLatencyMS = 68
	got, _ = Select(candidates, measurements, state, now)
	if got != 1 {
		t.Fatalf("tiny improvement caused a switch: %d", got)
	}
}

func TestAdaptiveExplorationPreservesPreference(t *testing.T) {
	now := time.Now()
	candidates := []Candidate{{Origin: "https://a"}, {Origin: "https://b"}}
	samples := []Snapshot{quality("https://a", 30, 8, now)}
	state := SelectionState{Preferred: "https://a", Since: now.Add(-time.Minute), Decisions: 5}
	got, state := Select(candidates, samples, state, now)
	if got != 1 || state.Preferred != "https://a" {
		t.Fatalf("expected cold exploration without switching: %d %+v", got, state)
	}
	got, _ = Select(candidates, samples, state, now)
	if got != 0 {
		t.Fatalf("failed to restore known preferred: %d", got)
	}
}

func TestAdaptiveCooldownRetriesAndTried(t *testing.T) {
	now := time.Now()
	candidates := []Candidate{
		{Origin: "https://a"},
		{Origin: "https://b", RetryAt: now.Add(time.Minute)},
	}
	samples := []Snapshot{quality("https://a", 80, 4, now), quality("https://b", 1, 4, now)}
	got, _ := Select(candidates, samples, SelectionState{Preferred: "https://b"}, now)
	if got != 0 {
		t.Fatalf("chosen cooling endpoint: %d", got)
	}
	candidates[0].RetryAt = now.Add(15 * time.Second)
	got, _ = Select(candidates, samples, SelectionState{}, now)
	if got != 0 {
		t.Fatalf("all cooling did not choose earliest retry: %d", got)
	}
	candidates[0].Tried = true
	got, _ = Select(candidates, samples, SelectionState{}, now)
	if got != 1 {
		t.Fatalf("already tried origin reused: %d", got)
	}
	candidates[1].Tried = true
	got, _ = Select(candidates, samples, SelectionState{}, now)
	if got != -1 {
		t.Fatalf("all tried: %d", got)
	}
}

func TestAdaptiveFailureAndActivePenalty(t *testing.T) {
	now := time.Now()
	candidates := []Candidate{{Origin: "https://a", Active: 3}, {Origin: "https://b"}}
	a := quality("https://a", 30, 5, now)
	b := quality("https://b", 32, 5, now)
	a.RecentFailurePct = 20
	got, _ := Select(candidates, []Snapshot{a, b}, SelectionState{}, now)
	if got != 1 {
		t.Fatalf("failure risk or load ignored: %d", got)
	}
}

func TestAdaptiveResetQualityPreservesActiveAndBytes(t *testing.T) {
	m := New()
	m.Begin("https://a")
	m.Observe("https://a", 10*time.Millisecond, 200, nil)
	m.Transfer("https://a", 64, 128)
	m.InvalidateQuality()
	s := m.Snapshot()
	if len(s) != 1 || s[0].ActiveRequests != 1 || s[0].UploadedBytes != 64 ||
		s[0].DownloadedBytes != 128 || s[0].SuccessfulResponses != 0 || !s[0].LastSuccess.IsZero() {
		t.Fatalf("bad reset: %+v", s)
	}
	m.End("https://a")
}
