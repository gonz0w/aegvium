//go:build openbsd && aegvium_frontend_source

// Adapted from private Vectivium e28959892903225887d855677c307712a59ce071; see LICENSE.Vectivium.
// No public relicensing is made.
package frontendowner

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type originalChild struct {
	cmd                  *exec.Cmd
	queue                *heldFile
	phase                childPhase
	retirement           retirement
	term, kill, exitSeen bool
	uncertain            bool
	startErr, waitErr    error
	state                *os.ProcessState
	frontend             *preparedFrontend
}

// launchForeground is a private lifetime operation below the immutable false
// native gate, not an admission API. It requires the same protected config,
// consumed generation and completed control operation. Per-request DATA/backend
// admission still belongs to Aeg; native qualification remains mandatory.
func (h *history) launchForeground() error {
	if !h.live() || !h.consumed || !h.launchCommitted || !dataProfileRecord(h.record[:]) || !h.frontendLive() || h.uncertain || h.child != nil || signal.Ignored(syscall.SIGCHLD) {
		return h.fail(ErrUnavailable)
	}
	if h.checkFrontendPrincipal() != nil {
		return h.fail(ErrUnavailable)
	}
	child := &originalChild{phase: childUnused, frontend: h.frontend}
	h.child = child // the attempt cannot be repeated after any error
	qfd, err := unix.Kqueue()
	if err != nil {
		return h.fail(err)
	}
	if _, err := unix.FcntlInt(uintptr(qfd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		// Retain the known handle even when flag installation failed.
		child.queue = &heldFile{file: os.NewFile(uintptr(qfd), "owned-child-kqueue")}
		h.files = append(h.files, child.queue)
		return h.fail(err)
	}
	child.queue, err = h.hold(qfd, "owned-child-kqueue")
	if err != nil {
		return err
	}
	child.cmd = &exec.Cmd{
		Path:       "/usr/local/sbin/haproxy",
		Args:       []string{"/usr/local/sbin/haproxy", "-db", "-f", "/dev/fd/3"},
		ExtraFiles: []*os.File{h.frontend.config.file},
		Env:        []string{"PATH=/usr/bin:/bin:/usr/local/bin", "LANG=C", "LC_ALL=C", "TZ=UTC"},
		Dir:        "/", Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
	}
	if !h.live() || !h.frontendLive() {
		return h.fail(ErrUnavailable)
	}
	child.phase = childStartAttempt
	child.startErr = child.cmd.Start()
	if child.startErr != nil {
		// Cmd.Start may have performed fallible fork/exec/retirement internally.
		// Without an actual returned owner there are no invented signal rights.
		child.uncertain, h.uncertain = true, true
		return h.fail(child.startErr)
	}
	if child.cmd.Process == nil || child.cmd.Process.Pid <= 1 {
		child.phase, child.uncertain, h.uncertain = childLost, true, true
		return h.fail(ErrUnavailable)
	}
	child.phase = childOriginal
	var ev unix.Kevent_t
	unix.SetKevent(&ev, child.cmd.Process.Pid, unix.EVFILT_PROC, unix.EV_ADD|unix.EV_ENABLE|unix.EV_ONESHOT)
	ev.Fflags = unix.NOTE_EXIT
	zero := unix.NsecToTimespec(0)
	if _, err := unix.Kevent(child.queue.fd(), []unix.Kevent_t{ev}, nil, &zero); err != nil {
		child.uncertain, h.uncertain = true, true
		h.fail(err)
		return child.retire() // original handle only, last stop before sole wait
	}
	if !h.live() || !h.frontendLive() {
		h.fail(ErrUnavailable)
		return child.retire()
	}
	return nil
}

func (c *originalChild) pollExit() (bool, error) {
	if c.phase != childOriginal || c.cmd == nil || c.cmd.Process == nil || c.queue.fd() < 0 {
		return false, ErrUnavailable
	}
	var events [1]unix.Kevent_t
	zero := unix.NsecToTimespec(0)
	n, err := unix.Kevent(c.queue.fd(), nil, events[:], &zero)
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil
	}
	ev := events[0]
	if n != 1 || ev.Ident != uint64(c.cmd.Process.Pid) || ev.Filter != unix.EVFILT_PROC || ev.Flags&unix.EV_ERROR != 0 || ev.Fflags&unix.NOTE_EXIT == 0 {
		return false, ErrUnavailable
	}
	c.exitSeen = true // nonreaping observation on the registered original child
	return true, nil
}

func (c *originalChild) stop(kill bool) error {
	if !signalPhase(c.phase) || c.cmd == nil || c.cmd.Process == nil || !c.retirement.live(time.Now()) {
		return ErrUnavailable
	}
	if kill {
		if c.kill {
			return ErrUnavailable
		}
		c.kill = true
		return c.cmd.Process.Signal(syscall.SIGKILL)
	}
	if c.term {
		return ErrUnavailable
	}
	c.term = true
	return c.cmd.Process.Signal(syscall.SIGTERM)
}

func (c *originalChild) waitOnce() error {
	if !waitPhase(c.phase) || !c.exitSeen || c.cmd == nil || c.cmd.Process == nil || !c.retirement.origin.IsZero() && !c.retirement.live(time.Now()) {
		return ErrUnavailable
	}
	c.phase = childWaitSealed // revoke ALL signals before the consuming wait
	c.waitErr = c.cmd.Wait()
	c.state = c.cmd.ProcessState
	observed, kind := 0, waitUnknown
	if c.state != nil {
		observed = c.state.Pid()
		if c.waitErr == nil {
			kind = waitSucceeded
		} else if exit, ok := c.waitErr.(*exec.ExitError); ok && exit.ProcessState == c.state {
			kind = waitExitFailure
		}
	}
	c.phase, c.uncertain = classifyTerminal(c.cmd.Process.Pid, observed, kind, c.uncertain)
	if c.phase != childConsumed {
		return ErrUnavailable // irrevocable: no signals/wait retry/Release
	}
	if !c.retirement.origin.IsZero() && !c.retirement.live(time.Now()) {
		c.uncertain = true
	}
	if c.waitErr != nil || c.uncertain {
		return ErrUnavailable
	}
	return nil
}

// supervise has no concurrent consuming wait. CONTROL comparison is historical
// preparation, never Ready/allow. The actual DATA receiver owns each request
// barrier. Native qualification is still absent; this is no autostart/reload API.
func (c *originalChild) supervise(ctx context.Context) error {
	if ctx == nil || c.phase != childOriginal {
		return ErrUnavailable
	}
	for {
		if ctx.Err() != nil {
			return c.retire()
		}
		done, err := c.pollExit()
		if err != nil {
			c.uncertain = true
			return c.retire()
		}
		if done {
			c.frontend.withdraw()
			return c.waitOnce()
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (c *originalChild) retire() error {
	if c.phase != childOriginal {
		return ErrUnavailable
	}
	c.frontend.withdraw()          // before first TERM; never a remote revocation claim
	c.retirement.begin(time.Now()) // once; error paths cannot extend grace
	if !c.term {
		if err := c.stop(false); err != nil {
			c.uncertain = true
		}
	}
	for c.retirement.live(time.Now()) {
		done, err := c.pollExit()
		if err != nil {
			c.uncertain = true
		}
		if done {
			return c.waitOnce()
		}
		if c.retirement.killDue(time.Now()) && !c.kill {
			if err := c.stop(true); err != nil {
				c.uncertain = true
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	c.phase = childLost
	// No late signal or blocking wait after expiry. Actual owner/lock stay retained and no
	// replacement can depend on retirement. An enclosing native boundary is
	// still required for blocking syscalls/helper death and a final real join.
	c.uncertain = true
	return ErrUnavailable
}
