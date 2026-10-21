/* SPDX-License-Identifier: BSD-3-Clause */
/* Ordinary finite host driver, never a native supervisor or inspector. */
#include "controller.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static const char *
boolean(bool value)
{
    return value ? "true" : "false";
}

static void
emit(int rc, enum aeg_owner_intent intent)
{
    struct aeg_owner_view v = aeg_owner_get_view();

    printf("{\"rc\":%d,\"intent\":%d,\"phase\":%d,\"generation\":\"%s\","
        "\"held\":%s,\"request_envelope\":%u,\"socket_envelope\":%u,"
        "\"known_child\":%s,\"stopped\":%s,\"stop_claimed\":%s,"
        "\"retired_ack\":%s,\"kill_claimed\":%s,\"protocol_closed\":%s,"
        "\"terminal\":%d,\"clock_fault\":%s,\"identity_fault\":%s,"
        "\"unsafe_fault\":%s,\"signal_result\":%d,\"target\":%d}\n",
        rc, intent, v.phase, v.generation, boolean(v.held),
        v.request_envelope, v.socket_envelope, boolean(v.known_child),
        boolean(v.stopped), boolean(v.stop_claimed), boolean(v.retired_ack),
        boolean(v.kill_claimed), boolean(v.protocol_closed), v.terminal,
        boolean(v.clock_fault), boolean(v.identity_fault),
        boolean(v.unsafe_fault), v.signal_result, v.target);
}

static void
mutate_copy(void)
{
    volatile struct aeg_owner_view copy = aeg_owner_get_view();
    size_t i;

    copy.phase = AEG_ACTIVE;
    for (i = 0; i < 32; i++)
        copy.generation[i] = 'f';
    copy.generation[32] = '\0';
    copy.held = !copy.held;
    copy.request_envelope = 99;
    copy.socket_envelope = 99;
    copy.known_child = !copy.known_child;
    copy.stopped = !copy.stopped;
    copy.stop_claimed = !copy.stop_claimed;
    copy.retired_ack = !copy.retired_ack;
    copy.kill_claimed = !copy.kill_claimed;
    copy.protocol_closed = !copy.protocol_closed;
    copy.terminal = AEG_SIGNAL_EXIT;
    copy.clock_fault = !copy.clock_fault;
    copy.identity_fault = !copy.identity_fault;
    copy.unsafe_fault = !copy.unsafe_fault;
    copy.signal_result = AEG_SIGNAL_DENIED;
    copy.target = AEG_MISSED;
}

int
main(void)
{
    char line[128];
    unsigned count = 0;

    while (fgets(line, sizeof(line), stdin) != NULL) {
        char generation[65] = {0}, extra;
        int rc = 0, number, null_value, seed;
        int64_t now;
        size_t length;
        enum aeg_owner_intent intent = AEG_SEND_KILL;

        if (++count > 64 || strchr(line, '\n') == NULL)
            return 64;
        if (line[0] == 'P') {
            if (sscanf(line, "P %" SCNd64 " %zu %d %64s %c",
                &now, &length, &null_value, generation, &extra) != 4)
                return 65;
            rc = aeg_owner_prepare(null_value ? NULL : generation, length, now);
        } else if (line[0] == 'S') {
            if (sscanf(line, "S %d %" SCNd64 " %d %d %c",
                &number, &now, &null_value, &seed, &extra) != 4)
                return 66;
            intent = (enum aeg_owner_intent)seed;
            rc = aeg_owner_step((enum aeg_owner_event)number, now,
                null_value ? NULL : &intent);
        } else if (strcmp(line, "M\n") == 0) {
            mutate_copy();
        } else if (strcmp(line, "V\n") != 0) {
            return 67;
        }
        emit(rc, intent);
    }
    return ferror(stdin) ? 68 : 0;
}
