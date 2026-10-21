/* SPDX-License-Identifier: BSD-3-Clause */
#include "controller.h"

static struct {
    struct aeg_owner_view view;
    int64_t last_ms;
    int64_t stop_ms;
} owner;

/* Only this component's logical storage; not S's total budget or RSS proof. */
_Static_assert(sizeof(owner) <= 512, "private controller logical storage bound");

static void
unverifiable(void)
{
    if (owner.view.target != AEG_MISSED && owner.view.target != AEG_MET)
        owner.view.target = AEG_UNVERIFIABLE;
}

static void
request_stop(void)
{
    if (!owner.view.stopped) {
        owner.view.stopped = true;
        owner.stop_ms = owner.last_ms;
        owner.view.target = owner.view.clock_fault || owner.view.identity_fault ?
            AEG_UNVERIFIABLE : AEG_PENDING;
    }
    if (owner.view.known_child)
        owner.view.phase = AEG_STOPPING;
}

static void
sample(int64_t now_ms)
{
    if (now_ms < 0 || now_ms < owner.last_ms) {
        owner.view.clock_fault = true;
        request_stop();
        unverifiable();
        return;
    }
    owner.last_ms = now_ms;
    /* Both operands are nonnegative, ordered int64 values: no addition or
     * signed subtraction overflow, including times near INT64_MAX. */
    if (owner.view.target == AEG_PENDING &&
        owner.last_ms - owner.stop_ms >= 4000)
        owner.view.target = AEG_MISSED;
}

static bool
kill_due(void)
{
    if (!owner.view.stopped || !owner.view.known_child)
        return false;
    return owner.view.unsafe_fault || owner.view.clock_fault ||
        owner.last_ms - owner.stop_ms >= 3000 ||
        (!owner.view.retired_ack && owner.last_ms - owner.stop_ms >= 100);
}

static bool
legal(enum aeg_owner_event event)
{
    if (!owner.view.held)
        return false;
    if (event >= AEG_OWNED && event <= AEG_LAUNCH_UNKNOWN)
        return owner.view.phase == AEG_RESERVED;
    if (event >= AEG_WAIT_NONE && event <= AEG_WAIT_ERROR)
        return owner.view.known_child &&
            (owner.view.phase == AEG_ACTIVE || owner.view.phase == AEG_STOPPING);
    if (event == AEG_ACK)
        return owner.view.known_child && owner.view.stopped &&
            owner.view.stop_claimed && !owner.view.protocol_closed;
    if (event >= AEG_SIGNAL_SENT_EVENT && event <= AEG_SIGNAL_DENIED_EVENT)
        return owner.view.known_child && owner.view.kill_claimed &&
            owner.view.signal_result == AEG_SIGNAL_NONE;
    /* Remaining valid events are allowed in every initialized held phase. */
    return true;
}

static void
identity_lost(void)
{
    request_stop();
    owner.view.identity_fault = true;
    owner.view.known_child = false;
    owner.view.phase = AEG_UNKNOWN_HELD;
    unverifiable();
}

static void
reclaim(void)
{
    if (owner.view.terminal == AEG_TERMINAL_UNKNOWN ||
        !owner.view.protocol_closed)
        return;
    owner.view.held = false;
    owner.view.phase = AEG_RECLAIMED;
    if (owner.view.stopped && owner.view.target == AEG_PENDING &&
        !owner.view.clock_fault && owner.last_ms - owner.stop_ms < 4000)
        owner.view.target = AEG_MET;
}

int
aeg_owner_prepare(const char *generation, size_t length, int64_t now_ms)
{
    size_t i;

    if (owner.view.phase != AEG_EMPTY)
        return AEG_STATE;
    owner.view.phase = AEG_REFUSED; /* Claim even an invalid first attempt. */
    if (generation == NULL || length != 32 || now_ms < 0)
        return AEG_INPUT;
    for (i = 0; i < length; i++) {
        if (!((generation[i] >= '0' && generation[i] <= '9') ||
            (generation[i] >= 'a' && generation[i] <= 'f')))
            return AEG_INPUT;
    }
    for (i = 0; i < length; i++)
        owner.view.generation[i] = generation[i];
    owner.view.generation[32] = '\0';
    owner.last_ms = now_ms;
    owner.view.held = true;
    owner.view.phase = AEG_RESERVED;
    return AEG_OK;
}

int
aeg_owner_step(enum aeg_owner_event event, int64_t now_ms,
    enum aeg_owner_intent *intent)
{
    if (intent == NULL || event < AEG_OWNED || event > AEG_CONTROL_FAULT)
        return AEG_INPUT;
    *intent = AEG_NONE;
    if (owner.view.phase == AEG_RECLAIMED &&
        (event == AEG_STOP || event == AEG_TICK))
        return AEG_OK; /* No clock sample or mutation after reclamation. */
    if (!legal(event))
        return AEG_STATE;
    sample(now_ms); /* Bad time must not discard an owned terminal receipt. */
    switch (event) {
    case AEG_OWNED:
        owner.view.known_child = true;
        owner.view.phase = owner.view.stopped ? AEG_STOPPING : AEG_ACTIVE;
        break;
    case AEG_NO_CHILD:
        owner.view.terminal = AEG_NO_CHILD_PROVED;
        owner.view.phase = AEG_TERMINAL_HELD;
        break;
    case AEG_LAUNCH_UNKNOWN:
    case AEG_WAIT_LOST:
    case AEG_WAIT_ERROR:
        identity_lost();
        break;
    case AEG_STOP:
        request_stop();
        break;
    case AEG_TAKE_STOP:
        if (owner.view.stopped && owner.view.known_child &&
            !owner.view.protocol_closed && !owner.view.stop_claimed &&
            !owner.view.kill_claimed && !owner.view.clock_fault &&
            !owner.view.identity_fault && !kill_due()) {
            owner.view.stop_claimed = true;
            *intent = AEG_SEND_STOP;
        }
        break;
    case AEG_ACK:
        if (!owner.view.clock_fault && !owner.view.identity_fault &&
            owner.last_ms - owner.stop_ms < 100)
            owner.view.retired_ack = true;
        break;
    case AEG_UNSAFE:
    case AEG_CONTROL_FAULT:
        owner.view.unsafe_fault = true;
        request_stop();
        break;
    case AEG_TAKE_KILL:
        if (!owner.view.identity_fault && !owner.view.kill_claimed && kill_due()) {
            owner.view.kill_claimed = true;
            *intent = AEG_SEND_KILL;
        }
        break;
    case AEG_WAIT_NORMAL:
    case AEG_WAIT_SIGNAL:
        owner.view.known_child = false;
        owner.view.terminal = event == AEG_WAIT_NORMAL ? AEG_NORMAL_EXIT :
            AEG_SIGNAL_EXIT;
        owner.view.phase = AEG_TERMINAL_HELD;
        break;
    case AEG_SIGNAL_SENT_EVENT:
        owner.view.signal_result = AEG_SIGNAL_SENT;
        break;
    case AEG_SIGNAL_MISSING_EVENT:
        owner.view.signal_result = AEG_SIGNAL_MISSING;
        break;
    case AEG_SIGNAL_DENIED_EVENT:
        owner.view.signal_result = AEG_SIGNAL_DENIED;
        break;
    case AEG_CLOSED:
        owner.view.protocol_closed = true;
        break;
    case AEG_TICK:
    case AEG_WAIT_NONE:
    case AEG_WAIT_STOPPED:
    case AEG_WAIT_INTERRUPTED:
        break;
    }
    reclaim();
    return AEG_OK;
}

struct aeg_owner_view
aeg_owner_get_view(void)
{
    struct aeg_owner_view view = owner.view;

    view.request_envelope = view.held ? 4 : 0;
    view.socket_envelope = view.held ? 8 : 0;
    return view;
}
