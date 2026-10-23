// SPDX-License-Identifier: BSD-3-Clause
package localcontrol

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestSharedStopExactOneWayWire(t *testing.T) {
	raw, e := os.ReadFile("../../tools/tests/fixtures/shared-stop.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Wire struct {
			Valid   string   `json:"valid"`
			Origin  int64    `json:"origin"`
			Invalid []string `json:"invalid"`
		} `json:"wire"`
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("frozen literal")
	}
	wire, e := StopRequest(f.Wire.Origin)
	if e != nil || wire != f.Wire.Valid || len(wire) > 32 {
		t.Fatal("exact bounded literal")
	}
	stop, origin, e := ParseRequest([]byte(wire), 0, 0)
	if e != nil || !stop || origin != 123456 {
		t.Fatal("root shared origin")
	}
	for _, s := range f.Wire.Invalid {
		if _, _, e := ParseRequest([]byte(s), 0, 0); e == nil {
			t.Fatal("noncanonical/overflow framing")
		}
	}
	for _, ids := range [][2]uint32{{1, 0}, {0, 1}} {
		if _, _, e := ParseRequest([]byte(wire), ids[0], ids[1]); e == nil {
			t.Fatal("nonroot epoch")
		}
	}
	for _, legacy := range []string{Status, Stop} {
		stop, origin, e := ParseRequest([]byte(legacy), 0, 0)
		if e != nil || origin != 0 || stop != (legacy == Stop) {
			t.Fatal("legacy profile changed")
		}
	}
}
func TestSharedStopNeverRenewsNotificationTime(t *testing.T) {
	for _, r := range []struct {
		origin, now int64
		remaining   time.Duration
	}{{1000, 1000, 4 * time.Second}, {1000, 1050, 3950 * time.Millisecond}, {1000, 4999, time.Millisecond}, {1000, 5000, 0}, {1000, 9000, 0}} {
		left, e := Remaining(r.origin, r.now)
		if e != nil || left != r.remaining {
			t.Fatal("common budget boundary")
		}
	}
	if _, e := Remaining(1000, 999); e == nil {
		t.Fatal("future epoch")
	}
	if _, e := StopRequest(9223372036854771808); e == nil {
		t.Fatal("deadline overflow")
	}
	sample := time.Unix(100, 0)
	origin, e := ConservativeOrigin(sample, 1000, 1050)
	if e != nil || !origin.Equal(sample.Add(-50*time.Millisecond)) {
		t.Fatal("conservative transfer")
	}
	late, e := ConservativeOrigin(sample, 1000, 5000)
	if e != nil || late.Add(4*time.Second).After(sample) {
		t.Fatal("late notification gained grace")
	}
	if _, e := ConservativeOrigin(time.Time{}, 1000, 1050); e == nil {
		t.Fatal("missing sample")
	}
}
