/* SPDX-License-Identifier: BSD-3-Clause */
#include "control_frame.h"
#include <string.h>

static void
encode(unsigned char *frame, unsigned char opcode, const char *generation)
{
    memset(frame, 0, AEG_CONTROL_FRAME_SIZE);
    memcpy(frame, "AGCTRL1\n", 8);
    frame[8] = opcode;
    memcpy(frame + 16, generation, 32);
    frame[55] = 1; /* One fixed epoch, big-endian uint64. */
}

int
aeg_owner_take_stop_frame(int64_t now_ms,
    unsigned char frame[AEG_CONTROL_FRAME_SIZE])
{
    enum aeg_owner_intent intent = AEG_NONE;
    struct aeg_owner_view view;
    int rc;

    if (frame == NULL)
        return AEG_INPUT; /* Do not burn a stop claim without output storage. */
    memset(frame, 0, AEG_CONTROL_FRAME_SIZE);
    rc = aeg_owner_step(AEG_TAKE_STOP, now_ms, &intent);
    if (rc != AEG_OK)
        return rc;
    if (intent != AEG_SEND_STOP)
        return AEG_STATE;
    view = aeg_owner_get_view();
    encode(frame, 1, view.generation);
    return AEG_OK;
}

/* Same sole event loop and one process lifetime as controller.c. */
static bool ack_attempted;

int
aeg_owner_accept_retired_ack(const unsigned char *frame, size_t length,
    int64_t now_ms)
{
    struct aeg_owner_view view = aeg_owner_get_view();
    enum aeg_owner_intent ignored;
    unsigned char expected[AEG_CONTROL_FRAME_SIZE];
    int rc;

    if (!view.held || !view.known_child || !view.stopped ||
        !view.stop_claimed || view.retired_ack || view.protocol_closed || view.kill_claimed ||
        view.clock_fault || view.identity_fault || view.unsafe_fault ||
        ack_attempted)
        return AEG_STATE; /* No sample, flag consumption or state event. */
    ack_attempted = true;
    encode(expected, 2, view.generation);
    if (frame == NULL || length != sizeof(expected) ||
        memcmp(frame, expected, sizeof(expected)) != 0) {
        (void)aeg_owner_step(AEG_CONTROL_FAULT, now_ms, &ignored);
        return AEG_INPUT;
    }
    rc = aeg_owner_step(AEG_ACK, now_ms, &ignored);
    view = aeg_owner_get_view();
    if (rc == AEG_OK && view.retired_ack)
        return AEG_OK;
    (void)aeg_owner_step(AEG_CONTROL_FAULT, now_ms, &ignored);
    return AEG_STATE; /* Late/faulted is never qualified admission retirement. */
}
