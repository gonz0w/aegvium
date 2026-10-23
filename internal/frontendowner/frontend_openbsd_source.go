//go:build openbsd && aegvium_frontend_source

// Adapted from private Vectivium e28959892903225887d855677c307712a59ce071; see LICENSE.Vectivium.
// No public relicensing is made.
package frontendowner

import (
	"bytes"
	"context"

	"github.com/gonz0w/aegvium/internal/frontendclient"
	"github.com/gonz0w/aegvium/internal/frontendconfig"
	"github.com/gonz0w/aegvium/internal/localcontrol"
)

type preparedFrontend struct {
	config    *heldFile
	control   *frontendclient.Source
	context   context.Context
	withdrawn bool
	matched   bool
}

// prepareFrontend is private source below the immutable false native gate. It
// cannot grant native authority and admits no caller receipt.
func (h *history) prepareFrontend(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || !h.live() || !h.consumed || h.uncertain || h.frontend != nil || !dataProfileRecord(h.record[:]) {
		return h.fail(ErrUnavailable)
	}
	if h.checkFrontendPrincipal() != nil {
		return h.fail(ErrUnavailable)
	}
	f := &preparedFrontend{context: ctx}
	h.frontend = f // one attempt, including all partial/failed preparation
	listen, err := h.readLocal("frontend-listen", 21)
	if err != nil {
		return err
	}
	candidate, err := frontendconfig.Compile(h.descriptor, h.role, string(listen))
	if err != nil || !dataProfileRecord(h.record[:]) {
		return h.fail(ErrUnavailable)
	}
	f.config, err = h.open(h.configDir, "frontend.cfg", false, 0600, false)
	if err != nil {
		return err
	}
	raw, err := h.readLocalHeld(f.config, "frontend.cfg", 32768)
	if err != nil || !bytes.Equal(raw, candidate.Bytes()) {
		return h.fail(ErrUnavailable)
	}
	combined, err := h.readLocal("frontend.pem", 81920)
	if err != nil {
		return err
	}
	cert, key, err := splitFrontendPEM(combined)
	if err != nil {
		return h.fail(err)
	}
	serverPEM, err := h.readLocal("inspector-root.pem", 32768)
	if err != nil {
		return err
	}
	serverDER, err := singleRootPEM(serverPEM)
	if err != nil {
		return h.fail(err)
	}
	clientDER, err := h.readLocal("client.der", 16384)
	if err != nil {
		return err
	}
	// Actual constructor verifies local role, pins, chains/usage and key. Tests
	// never call this function or substitute a transport/Peer/proof object.
	f.control, err = frontendclient.NewSource(ctx, frontendclient.Materials{
		Descriptor: h.descriptor, FrontendRole: h.role,
		CertificatePEM: cert, PrivateKeyPEM: key,
		InspectorRootDER: serverDER, FrontendRootDER: clientDER,
	})
	if err != nil {
		return h.fail(err)
	}
	match, err := f.control.MatchPreparedSource()
	tuple, complete := match.Tuple()
	if err != nil || !complete || tuple != h.record || ctx.Err() != nil || !h.live() {
		// The client deliberately exposes no cleanup-success proof on failure.
		// Its retained original endpoint may be uncertain; retain this writer too.
		h.uncertain = true
		f.withdraw()
		return h.fail(ErrUnavailable)
	}
	// This same protected held file is inherited, never reopened by config name.
	if _, err := f.config.file.Seek(0, 0); err != nil {
		return h.fail(err)
	}
	f.matched = true
	return nil
}

func (f *preparedFrontend) withdraw() {
	if f == nil {
		return
	}
	f.withdrawn = true
	f.matched = false
	if f.control != nil {
		f.control.RetireSource()
	}
}

func (h *history) frontendLive() bool {
	f := h.frontend
	return f != nil && f.matched && !f.withdrawn && f.context != nil && f.context.Err() == nil && f.config != nil && f.config.fd() >= 3
}

// Full source composition below the immutable false native entry gate. The actual
// Aeg DATA receiver owns the final per-request generation/backend barrier.
func runPreparedSource(ctx context.Context) (out error) {
	if ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	owned, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx = owned
	h, err := openHistory()
	if err != nil {
		return ErrUnavailable
	}
	h.service, err = localcontrol.OpenFrontendSource()
	h.cancelService = cancel
	if err != nil {
		h.uncertain = true
		return h.fail(ErrUnavailable)
	}
	defer func() {
		if h.frontend != nil {
			h.frontend.withdraw()
		}
		if h.child == nil || h.child.phase == childUnused || h.child.phase == childConsumed {
			if h.service.Close() != nil {
				h.uncertain = true
			}
		}
		if h.close() != nil {
			out = ErrUnavailable
		}
	}()
	if h.pollService("starting") != nil || h.consumeLocal() != nil || h.pollService("starting") != nil ||
		ctx.Err() != nil || h.prepareFrontend(ctx) != nil || h.pollService("starting") != nil || ctx.Err() != nil ||
		h.beginLaunchHistory() != nil || h.launchForeground() != nil {
		return ErrUnavailable
	}
	if h.child.supervise(ctx) != nil {
		return h.fail(ErrUnavailable)
	}
	return nil
}

// Read only the exact protected databases used by the fresh package profile.
// This is uncalled native source, not an account lookup in portable tests.
func (h *history) checkFrontendPrincipal() error {
	if !h.live() || len(h.files) == 0 {
		return h.fail(ErrUnavailable)
	}
	etc, err := h.open(h.files[0], "etc", true, 0755, false)
	if err != nil {
		return err
	}
	var databases [2]string
	for i, input := range []struct {
		name string
		perm uint32
	}{{"master.passwd", 0600}, {"group", 0644}} {
		f, e := h.open(etc, input.name, false, input.perm, false)
		if e != nil {
			return e
		}
		raw, e := h.readProtectedHeld(etc, f, input.name, 262144)
		if ce := f.close(); ce != nil {
			h.uncertain = true
			return h.fail(ErrUnavailable)
		}
		if e != nil {
			return e
		}
		databases[i] = string(raw)
	}
	if etc.close() != nil {
		h.uncertain = true
		return h.fail(ErrUnavailable)
	}
	if !frontendconfig.PackagePrincipalData(databases[0], databases[1]) {
		return h.fail(ErrUnavailable)
	}
	return nil
}

// Same event loop only; no new actor or storage I/O. Accepted STOP cancels the
// private preparation context and never renews a child retirement deadline.
func (h *history) pollService(phase string) error {
	stop, err := h.service.Poll(phase)
	if err != nil {
		h.uncertain = true
		return h.fail(ErrUnavailable)
	}
	if stop && h.cancelService != nil {
		h.cancelService()
	}
	return nil
}
