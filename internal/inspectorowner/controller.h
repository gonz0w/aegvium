/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef AEG_INSPECTOROWNER_CONTROLLER_H
#define AEG_INSPECTOROWNER_CONTROLLER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Private S event-loop component, not a native authority or concurrent API.
 * Inputs are trusted adapter observations; the explicit source adapter is unqualified.
 * No reset: one initialization attempt per process, including failed attempts.
 * See the frozen M2-S01/1 contract and its independent literal fixtures. */
enum aeg_owner_error { AEG_OK = 0, AEG_INPUT = 1, AEG_STATE = 2 };
enum aeg_owner_phase {
    AEG_EMPTY = 0, AEG_REFUSED, AEG_RESERVED, AEG_ACTIVE, AEG_STOPPING,
    AEG_TERMINAL_HELD, AEG_UNKNOWN_HELD, AEG_RECLAIMED
};
enum aeg_owner_terminal {
    AEG_TERMINAL_UNKNOWN = 0, AEG_NO_CHILD_PROVED, AEG_NORMAL_EXIT, AEG_SIGNAL_EXIT
};
enum aeg_owner_target {
    AEG_NOT_STOPPING = 0, AEG_PENDING, AEG_MET, AEG_MISSED, AEG_UNVERIFIABLE
};
enum aeg_owner_signal_result {
    AEG_SIGNAL_NONE = 0, AEG_SIGNAL_SENT, AEG_SIGNAL_MISSING, AEG_SIGNAL_DENIED
};
enum aeg_owner_intent { AEG_NONE = 0, AEG_SEND_STOP = 1, AEG_SEND_KILL = 2 };
enum aeg_owner_event {
    AEG_OWNED = 1, AEG_NO_CHILD, AEG_LAUNCH_UNKNOWN, AEG_STOP, AEG_TAKE_STOP,
    AEG_ACK, AEG_TICK, AEG_UNSAFE, AEG_TAKE_KILL, AEG_WAIT_NONE,
    AEG_WAIT_STOPPED, AEG_WAIT_INTERRUPTED, AEG_WAIT_NORMAL, AEG_WAIT_SIGNAL,
    AEG_WAIT_LOST, AEG_WAIT_ERROR, AEG_SIGNAL_SENT_EVENT,
    AEG_SIGNAL_MISSING_EVENT, AEG_SIGNAL_DENIED_EVENT, AEG_CLOSED,
    AEG_CONTROL_FAULT
};
struct aeg_owner_view {
    enum aeg_owner_phase phase;
    char generation[33];
    bool held;
    unsigned request_envelope;
    unsigned socket_envelope;
    bool known_child;
    bool stopped;
    bool stop_claimed;
    bool retired_ack;
    bool kill_claimed;
    bool protocol_closed;
    enum aeg_owner_terminal terminal;
    bool clock_fault;
    bool identity_fault;
    bool unsafe_fault;
    enum aeg_owner_signal_result signal_result;
    enum aeg_owner_target target;
};

int aeg_owner_prepare(const char *, size_t, int64_t);
int aeg_owner_step(enum aeg_owner_event, int64_t, enum aeg_owner_intent *);
/* Root local shared epoch; timing data only, never physical ownership. */
int aeg_owner_stop_at(int64_t, int64_t);
struct aeg_owner_view aeg_owner_get_view(void);

#endif
