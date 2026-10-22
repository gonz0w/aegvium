/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef AEG_INSPECTOROWNER_LAUNCH_STORAGE_H
#define AEG_INSPECTOROWNER_LAUNCH_STORAGE_H
#include <stdbool.h>
enum aeg_storage_error { AEG_STORAGE_OK = 0, AEG_STORAGE_STATE, AEG_STORAGE_OS, AEG_STORAGE_INPUT, AEG_STORAGE_UNCERTAIN };
enum aeg_storage_phase { AEG_STORAGE_EMPTY = 0, AEG_STORAGE_FAILED, AEG_STORAGE_LOCAL_PAIR, AEG_STORAGE_UPDATE_GUARD };
struct aeg_storage_view {
    enum aeg_storage_phase phase;
    bool attempted, uncertain, committed;
    unsigned known_descriptors;
};
/* Private, single event-loop/process attempt. No installed caller, initializer,
 * raw FD/path/profile input, cleanup/reset or positive launch authority. Trusted
 * C provenance and qualified native construction remain operational gates. */
int aeg_launch_storage_prepare(void);
int aeg_update_exclusion_prepare(void);
struct aeg_storage_view aeg_storage_get_view(void);
#endif
