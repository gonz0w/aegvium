/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef AEG_INSPECTOROWNER_NATIVE_CONSTRUCTION_H
#define AEG_INSPECTOROWNER_NATIVE_CONSTRUCTION_H
#include <stdbool.h>
#include <sys/types.h>
enum aeg_native_error { AEG_NATIVE_OK = 0, AEG_NATIVE_INPUT, AEG_NATIVE_STATE, AEG_NATIVE_OS, AEG_NATIVE_UNCERTAIN };
enum aeg_native_phase { AEG_NATIVE_EMPTY = 0, AEG_NATIVE_PAIR, AEG_NATIVE_PARENT, AEG_NATIVE_CHILD, AEG_NATIVE_FAILED };
struct aeg_native_view {
    enum aeg_native_phase phase;
    bool attempted, branch_attempted, uncertain, identity_checked;
    unsigned known_owned_descriptors;
};
/* Private one-process/one-event-loop primitives; no caller exists. Neither branch
 * call proves a fork, child identity, authenticated peer or launch-history gate.
 * Future real child caller MUST terminate on failure; no exec/readiness here. */
int aeg_native_pair_prepare(void);
int aeg_native_parent_prepare(void);
int aeg_native_child_prepare(uid_t, gid_t);
struct aeg_native_view aeg_native_get_view(void);
#endif
