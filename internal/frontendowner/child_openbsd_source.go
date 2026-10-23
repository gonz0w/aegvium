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

	"github.com/gonz0w/aegvium/internal/localcontrol"
	"golang.org/x/sys/unix"
)

type originalChild struct {
	cmd                  *exec.Cmd
	queue                *heldFile
	phase                childPhase
	retirement           retirement
	term, kill, exitSeen bool
	uncertain, late      bool
	startErr, waitErr    error
	state                *os.ProcessState
	frontend             *preparedFrontend
	service              *localcontrol.Frontend
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
	child := &originalChild{phase: childUnused, frontend: h.frontend, service: h.service}
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
	if h.pollService("starting") != nil || !h.frontendLive() || h.currentIntent(h.record) != nil {
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
	if err == unix.EINTR {
		return false, nil
	}
	if err != nil {
		c.phase, c.uncertain = childLost, true
		return false, err
	}
	if n == 0 {
		return false, nil
	}
	ev := events[0]
	if n != 1 || ev.Ident != uint64(c.cmd.Process.Pid) || ev.Filter != unix.EVFILT_PROC || ev.Flags&unix.EV_ERROR != 0 || ev.Fflags&unix.NOTE_EXIT == 0 {
		c.phase, c.uncertain = childLost, true
		return false, ErrUnavailable
	}
	c.exitSeen = true // nonreaping observation on the registered original child
	return true, nil
}

func (c *originalChild) stop(kill bool) error {
	if !signalPhase(c.phase) || c.cmd == nil || c.cmd.Process == nil {
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
	if !waitPhase(c.phase) || !c.exitSeen || c.cmd == nil || c.cmd.Process == nil {
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
		c.late = true
	}
	if c.waitErr != nil || c.uncertain || c.late {
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
		stop, err := c.service.Poll("owned-running")
		if err != nil {
			c.uncertain = true
			return c.retire()
		}
		if stop || ctx.Err() != nil {
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
	c.frontend.withdraw()
	c.retirement.begin(time.Now())
	c.pollRetiringService()
	if !c.term && !c.retirement.killDue(time.Now()) {
		if e := c.stop(false); e != nil {
			c.uncertain = true
		}
	}
	for {
		// Keep the existing endpoint responsive while retiring. A queued earlier
		// root epoch can shorten this same owner's deadline, never renew it.
		// Endpoint failure is sticky but cannot discard original wait rights.
		c.pollRetiringService()
		now := time.Now()
		if !c.retirement.live(now) {
			c.late = true
		}
		done, e := c.pollExit()
		if e != nil {
			c.uncertain = true
		}
		if done {
			return c.waitOnce()
		}
		if c.phase != childOriginal {
			return ErrUnavailable
		}
		if (c.late || c.retirement.killDue(now)) && !c.kill {
			if e := c.stop(true); e != nil {
				c.uncertain = true
			}
		}
		// Missing the target is sticky failure, not loss of original-child wait
		// authority. The same owner keeps cleanup outside any replacement grace.
		// Identity loss/ambiguous kernel observation still forbids guessed signals.
		if c.phase != childOriginal {
			return ErrUnavailable
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (c *originalChild) pollRetiringService() {
	if c.service == nil {
		return
	}
	if _, err := c.service.Poll("retiring"); err != nil {
		c.uncertain = true
	}
	if c.service.StoppedSource() {
		origin, err := c.service.StopOrigin()
		if err != nil {
			c.uncertain, c.late = true, true
			return
		}
		c.late = c.retirement.observe(origin, time.Now()) || c.late
	}
}
