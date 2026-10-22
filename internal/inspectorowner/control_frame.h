/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef AEG_INSPECTOROWNER_CONTROL_FRAME_H
#define AEG_INSPECTOROWNER_CONTROL_FRAME_H

#include "controller.h"
#define AEG_CONTROL_FRAME_SIZE 64

/* Private sole S event-loop source only. These functions authenticate no FD or
 * caller, perform no I/O and prove no native ownership, closure or reclamation.
 * Non-NULL output points to exactly64 writable bytes. No reset/replacement. */
int aeg_owner_take_stop_frame(int64_t, unsigned char [AEG_CONTROL_FRAME_SIZE]);

/* One admission-retirement ACK attempt, only in the existing expected state. */
int aeg_owner_accept_retired_ack(const unsigned char *, size_t, int64_t);

#endif
