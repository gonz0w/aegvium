/* SPDX-License-Identifier: BSD-3-Clause */
/* Included only in explicit AEG_INSPECTOR_SOURCE builds. It owns the actual
 * fork receipt and private parent endpoint; no supplied PID/FD/provider exists.
 * This source has no installed caller and creates no clean-history record. */
#include "launch_source_os.h"
#include "control_frame.h"
#include <errno.h>

static struct {
    bool attempted, terminal, no_child, lost, prepared, start_failed;
    pid_t child;
    size_t start_at, ack_at;
    unsigned char start[112], ack[64];
} source_launch;

static int source_event(enum aeg_owner_event e) {
    int64_t now; enum aeg_owner_intent ignored;
    if (aeg_start_clock(&now)!=0) {
        /* Preserve the actual Owned/terminal/identity observation even when
         * time becomes untrustworthy. Never lose the sole kernel fork receipt. */
        (void)aeg_owner_step(e,-1,&ignored);
        return AEG_NATIVE_UNCERTAIN;
    }
    return aeg_owner_step(e,now,&ignored)==AEG_OK ? AEG_NATIVE_OK : AEG_NATIVE_STATE;
}

int aeg_native_spawn_source(void) {
    struct aeg_owner_view owner=aeg_owner_get_view();
    struct aeg_storage_view storage=aeg_storage_get_view();
    uid_t uid=0; gid_t gid=0; pid_t pid; int observed, closed;
    if (source_launch.attempted) return AEG_NATIVE_STATE;
    source_launch.attempted=true;
    if (construction.view.phase!=AEG_NATIVE_PAIR || construction.view.uncertain ||
        !construction.view.bootstrap_written || !storage.committed || storage.uncertain ||
        owner.phase!=AEG_RESERVED || owner.stopped || !owner.held ||
        aeg_start_identity(&uid,&gid)!=0 || uid==0 || uid==(uid_t)-1 ||
        gid==0 || gid==(gid_t)-1) return AEG_NATIVE_STATE;
    pid=aeg_start_fork();
    if (pid==0) {
        if (aeg_native_child_prepare(uid,gid)==AEG_NATIVE_OK)
            (void)aeg_start_exec();
        aeg_start_child_exit(); /* Failed preparation/exec cannot return to S. */
    }
    if (pid<0) {
        source_launch.no_child=true;
        (void)source_event(AEG_NO_CHILD);
        return AEG_NATIVE_OS;
    }
    source_launch.child=pid; /* Sole origin: the positive actual fork return. */
    observed=source_event(AEG_OWNED);
    closed=aeg_native_parent_prepare(); /* Preserve cleanup even on clock fault. */
    return observed==AEG_NATIVE_OK ? closed : AEG_NATIVE_UNCERTAIN;
}

int aeg_native_prepared_source(void) {
    ssize_t n; size_t left;
    if (source_launch.child<=0 || source_launch.terminal || source_launch.lost ||
        source_launch.prepared || source_launch.start_failed ||
        construction.view.phase!=AEG_NATIVE_PARENT || construction.view.uncertain)
        return AEG_NATIVE_STATE;
    left=sizeof(source_launch.start)-source_launch.start_at;
    n=aeg_start_read(construction.fd[construction.parent],
        source_launch.start+source_launch.start_at,left);
    if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)) return AEG_NATIVE_PENDING;
    if (n<=0 || (size_t)n>left) goto failed;
    source_launch.start_at+=(size_t)n;
    if (source_launch.start_at<sizeof(source_launch.start)) return AEG_NATIVE_PENDING;
    if (memcmp(source_launch.start,"AGSTART1",8)!=0 ||
        memcmp(source_launch.start+8,construction.expected_start,104)!=0) goto failed;
    source_launch.prepared=true;
    return AEG_NATIVE_OK; /* Same-child diagnostic only; never Ready/allow. */
failed:
    source_launch.start_failed=true;
    (void)source_event(AEG_CONTROL_FAULT);
    return AEG_NATIVE_UNCERTAIN;
}

int aeg_native_wait_source(void) {
    int kind=0; pid_t observed;
    if (source_launch.child<=0 || source_launch.terminal || source_launch.lost)
        return AEG_NATIVE_STATE;
    observed=aeg_start_wait(source_launch.child,&kind);
    if (observed==0 || (observed<0 && errno==EINTR)) return AEG_NATIVE_PENDING;
    if (observed!=source_launch.child || kind<1 || kind>3) {
        source_launch.lost=true;
        (void)source_event(AEG_WAIT_LOST);
        return AEG_NATIVE_UNCERTAIN; /* Never signal after wait identity loss. */
    }
    if (kind==3) return source_event(AEG_WAIT_STOPPED);
    source_launch.terminal=true;
    return source_event(kind==1 ? AEG_WAIT_NORMAL : AEG_WAIT_SIGNAL);
}

int aeg_native_stop_source(void) {
    unsigned char frame[64]; int64_t now;
    if (source_launch.child<=0 || source_launch.terminal || source_launch.lost)
        return AEG_NATIVE_STATE;
    if (source_event(AEG_STOP)!=AEG_NATIVE_OK || aeg_start_clock(&now)!=0)
        return AEG_NATIVE_UNCERTAIN;
    if (aeg_owner_take_stop_frame(now,frame)!=AEG_OK) return AEG_NATIVE_STATE;
    if (aeg_os_bootstrap_send(construction.fd[construction.parent],frame,64)!=64) {
        (void)source_event(AEG_CONTROL_FAULT);
        return AEG_NATIVE_UNCERTAIN;
    }
    return AEG_NATIVE_OK;
}

int aeg_native_tick_source(void) {
    struct aeg_owner_view owner; enum aeg_owner_intent intent;
    int64_t now; ssize_t n; int waited, rc, saved;
    if (source_launch.child<=0 || source_launch.lost) return AEG_NATIVE_STATE;
    if (!source_launch.terminal) {
        waited=aeg_native_wait_source();
        if (waited!=AEG_NATIVE_OK && waited!=AEG_NATIVE_PENDING) return waited;
    }
    if (source_launch.terminal) return AEG_NATIVE_OK; /* FD closure still separate. */
    (void)source_event(AEG_TICK); /* Clock failure must not block owned escalation. */
    owner=aeg_owner_get_view();
    if (owner.stopped && owner.stop_claimed && !owner.retired_ack && !owner.kill_claimed &&
        !owner.unsafe_fault && source_launch.ack_at<64) {
        n=aeg_start_read(construction.fd[construction.parent],source_launch.ack+source_launch.ack_at,
            64-source_launch.ack_at);
        if (n>0 && (size_t)n<=64-source_launch.ack_at) {
            source_launch.ack_at+=(size_t)n;
            if (source_launch.ack_at==64 && aeg_start_clock(&now)==0)
                (void)aeg_owner_accept_retired_ack(source_launch.ack,64,now);
        } else if (n==0 || n>0 || (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR))
            (void)source_event(AEG_CONTROL_FAULT);
    }
    if (aeg_start_clock(&now)!=0) now=-1; /* Controller records fault and permits kill. */
    if (aeg_owner_step(AEG_TAKE_KILL,now,&intent)!=AEG_OK) return AEG_NATIVE_STATE;
    if (intent==AEG_SEND_KILL) {
        rc=aeg_start_kill(source_launch.child); saved=errno;
        (void)source_event(rc==0 ? AEG_SIGNAL_SENT_EVENT :
            saved==ESRCH ? AEG_SIGNAL_MISSING_EVENT : AEG_SIGNAL_DENIED_EVENT);
    }
    return AEG_NATIVE_OK; /* Kill/ACK never count as terminal or reclamation. */
}

int aeg_native_close_source(void) {
    int i; bool clean=true;
    if (source_launch.no_child && !construction.view.uncertain) {
        for (i=0;i<4;i++) if (!close_slot(i)) clean=false;
        return clean ? source_event(AEG_CLOSED) : AEG_NATIVE_UNCERTAIN;
    }
    if (!source_launch.terminal || source_launch.lost ||
        construction.view.uncertain || construction.view.phase!=AEG_NATIVE_PARENT)
        return AEG_NATIVE_STATE;
    if (!close_slot(construction.parent)) return AEG_NATIVE_UNCERTAIN;
    return source_event(AEG_CLOSED); /* Actual local close plus retained terminal. */
}
