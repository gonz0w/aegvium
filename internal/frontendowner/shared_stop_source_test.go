//go:build aegvium_frontend_source

// SPDX-License-Identifier: BSD-3-Clause
package frontendowner

import (
	"testing"
	"time"
)

func TestSharedStopKeepsEarliestEpochAndPhysicalRights(t *testing.T) {
	start := time.Unix(100, 0)
	var r retirement
	r.begin(start.Add(time.Second))
	r.begin(start)
	r.begin(start.Add(2 * time.Second))
	if !r.origin.Equal(start) || !r.end.Equal(start.Add(4*time.Second)) || !r.killAt.Equal(start.Add(2*time.Second)) {
		t.Fatal("shared epoch was renewed")
	}
	if r.live(start.Add(4*time.Second)) || !signalPhase(childOriginal) || !waitPhase(childOriginal) {
		t.Fatal("missed target revoked original-child authority")
	}
	phase, unknown := classifyTerminal(41, 41, waitSucceeded, false)
	if phase != childConsumed || unknown || signalPhase(phase) || waitPhase(phase) {
		t.Fatal("late actual terminal cannot authorize more signals/wait")
	}
	phase, unknown = classifyTerminal(41, 42, waitSucceeded, false)
	if phase != childLost || !unknown || signalPhase(phase) || waitPhase(phase) {
		t.Fatal("wrong child acquired rights")
	}
}

func TestSharedStopEarlierEpochArrivesDuringRetirement(t *testing.T) {
	start := time.Unix(100, 0)
	var r retirement
	r.begin(start)
	if r.observe(start.Add(-time.Second), start.Add(2*time.Second)) {
		t.Fatal("valid earlier stop expired before its shared cutoff")
	}
	if !r.origin.Equal(start.Add(-time.Second)) || !r.killDue(start.Add(2*time.Second)) {
		t.Fatal("earlier notification during retirement did not shorten escalation")
	}
	late := r.observe(start.Add(-2*time.Second), start.Add(2*time.Second))
	if !late || !r.end.Equal(start.Add(2*time.Second)) || !signalPhase(childOriginal) || !waitPhase(childOriginal) {
		t.Fatal("queued earlier epoch did not expire without losing physical rights")
	}
	late = r.observe(start.Add(time.Second), start.Add(3*time.Second)) || late
	if !late || !r.origin.Equal(start.Add(-2*time.Second)) || !r.end.Equal(start.Add(2*time.Second)) {
		t.Fatal("later notification renewed an expired retirement")
	}
}
