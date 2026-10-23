//go:build aegvium_frontend_source

// SPDX-License-Identifier: BSD-3-Clause
package frontendowner

import (
	"bytes"
	"crypto/sha256"

	"github.com/gonz0w/aegvium/internal/backendconfig"
	"github.com/gonz0w/aegvium/internal/localcontrol"
	"github.com/gonz0w/aegvium/internal/pairmodel"
)

// PrepareSuccessorSource prepares only a normal, stopped bundled successor. The
// same immutable native gate precedes all effects; this is no cleanup/reset API.
func PrepareSuccessorSource() error { return prepareSuccessorQualifiedSource() }
func PrepareSuccessorBeforeSource(text string) error {
	origin, e := localcontrol.Epoch(text)
	if e != nil {
		return ErrUnavailable
	}
	return prepareSuccessorBeforeQualifiedSource(origin)
}

func nextGeneration(old string) (string, bool) {
	if !generation(old) || old == "00000000000000000000000000000000" {
		return "", false
	}
	out := []byte(old)
	for i := 31; i >= 0; i-- {
		if out[i] == 'f' {
			out[i] = '0'
			continue
		}
		if out[i] == '9' {
			out[i] = 'a'
		} else {
			out[i]++
		}
		return string(out), true
	}
	return "", false
}
func launchIntent(raw []byte, g string) bool {
	return generation(g) && g != "00000000000000000000000000000000" && len(raw) == 33 && string(raw[:32]) == g && raw[32] == '\n'
}

// These checks bind DATA only. Qualified protected-history/namespace provenance
// and actual exclusive locks remain necessary; parsed bytes never create them.
func inspectorClean(raw []byte, g string) bool {
	if len(raw) != 128 || string(raw[:8]) != "AEGOWN1\n" || raw[8] != 'C' || !generation(g) || g == "00000000000000000000000000000000" || string(raw[16:48]) != g || !bytes.Equal(raw[9:16], make([]byte, 7)) || !bytes.Equal(raw[80:], make([]byte, 48)) {
		return false
	}
	var input [96]byte
	copy(input[:48], raw[:48])
	copy(input[48:], raw[80:])
	sum := sha256.Sum256(input[:])
	return bytes.Equal(sum[:], raw[48:80])
}

// Normal restart changes generation binding only: no role, key, route, endpoint,
// policy, backend or public-listener change is admitted by this command.
func successorData(old, next, backend, nextBackend []byte, record [104]byte) bool {
	if len(old) < 48 || len(next) != len(old) || len(backend) < 72 || len(nextBackend) != len(backend) || !dataProfileRecord(record[:]) || string(old[:8]) != "AGPAIR2\n" || !bytes.Equal(old[:8], next[:8]) || !bytes.Equal(old[40:], next[40:]) {
		return false
	}
	oldModel, e := pairmodel.Parse(old)
	newModel, e2 := pairmodel.Parse(next)
	if e != nil || e2 != nil {
		return false
	}
	a, e := oldModel.Projection()
	b, e2 := newModel.Projection()
	want, ok := nextGeneration(a.Generation)
	digest := sha256.Sum256(old)
	if e != nil || e2 != nil || !ok || b.Generation != want || string(record[8:40]) != a.Generation || !bytes.Equal(record[40:72], digest[:]) {
		return false
	}
	if _, e = backendconfig.Parse(backend, old); e != nil {
		return false
	}
	if _, e = backendconfig.Parse(nextBackend, next); e != nil {
		return false
	}
	return bytes.Equal(backend[:8], nextBackend[:8]) && bytes.Equal(backend[72:], nextBackend[72:])
}

// deriveSuccessor is data-only. The private normal-clean owner calls it with
// current protected files under both existing locks; these bytes cannot supply
// that custody or physical cleanup provenance. No caller supplies new material.
func deriveSuccessor(old, backend []byte, record [104]byte) ([]byte, []byte, error) {
	if len(old) < 48 || len(old) > 8192 || len(backend) < 72 || len(backend) > 8192 {
		return nil, nil, ErrUnavailable
	}
	g, ok := nextGeneration(string(old[8:40]))
	if !ok {
		return nil, nil, ErrUnavailable
	}
	next, nextBackend := bytes.Clone(old), bytes.Clone(backend)
	copy(next[8:40], g)
	digest := sha256.Sum256(next)
	copy(nextBackend[8:40], g)
	copy(nextBackend[40:72], digest[:])
	if !successorData(old, next, backend, nextBackend, record) {
		return nil, nil, ErrUnavailable
	}
	return next, nextBackend, nil
}

func successorRoleFacts(f fileFacts, gid uint32) bool {
	return gid != 0 && f.gid == gid && f.uid == 0 && f.inode != 0 && f.mode == 0100440 && f.links == 1 && f.size > 0
}
func successorSamePlacement(a, b fileFacts) bool {
	return a.device == b.device && a.inode == b.inode && a.mode == b.mode && a.uid == b.uid && a.gid == b.gid && a.links == b.links && a.size == b.size
}
