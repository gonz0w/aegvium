/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef AEG_INSPECTOROWNER_NATIVE_CONSTRUCTION_H
#define AEG_INSPECTOROWNER_NATIVE_CONSTRUCTION_H
#include <stdbool.h>
#include <sys/types.h>
enum aeg_native_error { AEG_NATIVE_OK = 0, AEG_NATIVE_INPUT, AEG_NATIVE_STATE, AEG_NATIVE_OS, AEG_NATIVE_UNCERTAIN, AEG_NATIVE_PENDING };
enum aeg_native_phase { AEG_NATIVE_EMPTY = 0, AEG_NATIVE_PAIR, AEG_NATIVE_PARENT, AEG_NATIVE_CHILD, AEG_NATIVE_FAILED };
struct aeg_native_view {
    enum aeg_native_phase phase;
    bool attempted, branch_attempted, uncertain, identity_checked;
    bool bootstrap_attempted, bootstrap_written;
    unsigned known_owned_descriptors;
};
/* Private one-process/one-event-loop primitives; no caller exists. Neither branch
 * call proves a fork, child identity, authenticated peer or launch-history gate.
 * Future real child caller MUST terminate on failure; no exec/readiness here. */
int aeg_native_pair_prepare(void);
/* Zero-input committed-storage coupling. One nonblocking send, no FD getter. */
int aeg_native_bootstrap_emit(void);
int aeg_native_parent_prepare(void);
int aeg_native_child_prepare(uid_t, gid_t);
struct aeg_native_view aeg_native_get_view(void);
#ifdef AEG_INSPECTOR_SOURCE
/* Fixed source entry only; no supplied PID/FD or positive qualification input.
 * Source operations are below the immutable false supervisor entry gate. */
static inline bool aeg_supervisor_source_qualified(void) { return false; }
int aeg_native_spawn_source(void);
int aeg_native_prepared_source(void);
int aeg_native_wait_source(void);
int aeg_native_stop_source(void);
int aeg_native_tick_source(void);
int aeg_native_close_source(void);
int aeg_native_settle_source(void);
#endif
#endif
