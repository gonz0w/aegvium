/* SPDX-License-Identifier: BSD-3-Clause */
/* Finite ordinary host byte/controller fixture. No subject/process operations. */
#include "control_frame.h"
#include <stdio.h>
#include <string.h>

static const unsigned char golden_ack[64] = { 0x41, 0x47, 0x43, 0x54, 0x52, 0x4c, 0x31, 0x0a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static int
zero(const unsigned char *frame)
{
    size_t i;
    for (i = 0; i < 64; i++) if (frame[i] != 0) return 0;
    return 1;
}
int
main(int argc, char **argv)
{
    enum aeg_owner_intent ignored;
    unsigned char frame[64], again[64], ack[64];
    struct aeg_owner_view before, after;
    int pre, absent, nullout, first, second, accepted, duplicate;
    int64_t now = 99;
    size_t length = 64, i;
    const char *mode;

    if (argc != 2 || strlen(argv[1]) > 12) return 2;
    mode = argv[1];
    if (aeg_owner_prepare("00000000000000000000000000000000", 32, 0) != AEG_OK ||
        aeg_owner_step(AEG_OWNED, 0, &ignored) != AEG_OK) return 3;
    pre = aeg_owner_accept_retired_ack(NULL, 0, 10000);
    absent = aeg_owner_take_stop_frame(0, again);
    if (!zero(again)) return 4;
    if (aeg_owner_step(AEG_STOP, 0, &ignored) != AEG_OK) return 5;
    nullout = aeg_owner_take_stop_frame(0, NULL);
    first = aeg_owner_take_stop_frame(1, frame);
    memset(again, 0x7f, sizeof(again));
    second = aeg_owner_take_stop_frame(1, again);
    memcpy(ack, golden_ack, sizeof(ack));
    if (strcmp(mode, "valid99") == 0) { /* exact literal */ }
    else if (strcmp(mode, "late100") == 0) now = 100;
    else if (strcmp(mode, "miss4000") == 0) now = 4000;
    else if (strcmp(mode, "backward") == 0) now = 0;
    else if (strcmp(mode, "reserved") == 0) ack[9] = 1;
    else if (strcmp(mode, "stale") == 0) ack[16] = '1';
    else if (strcmp(mode, "priorAck") == 0) {
        if (aeg_owner_step(AEG_ACK, 99, &ignored) != AEG_OK) return 7;
        now = 10000; /* A prior direct transition must not bless this call. */
    }
    else if (strcmp(mode, "short") == 0) length = 63;
    else return 6;
    accepted = aeg_owner_accept_retired_ack(ack, length, now);
    before = aeg_owner_get_view();
    duplicate = aeg_owner_accept_retired_ack(golden_ack, 64, 10000);
    after = aeg_owner_get_view();
    printf("{\"pre\":%d,\"absent\":%d,\"nullout\":%d,\"first\":%d,\"second\":%d,\"zero\":%d,\"stop\":\"", pre, absent, nullout, first, second, zero(again));
    for (i = 0; i < 64; i++) printf("%02x", (unsigned)frame[i]);
    printf("\",\"accepted\":%d,\"duplicate\":%d,\"held\":%d,\"requests\":%u,\"sockets\":%u,\"known\":%d,\"ack\":%d,\"unsafe\":%d,\"clock\":%d,\"target\":%d,\"terminal\":%d,\"closed\":%d,\"dup_target\":%d,\"dup_clock\":%d,\"dup_unsafe\":%d,\"dup_ack\":%d}\n",
        accepted, duplicate, (int)before.held, before.request_envelope,
        before.socket_envelope, (int)before.known_child, (int)before.retired_ack,
        (int)before.unsafe_fault, (int)before.clock_fault, before.target,
        before.terminal, (int)before.protocol_closed, after.target,
        (int)after.clock_fault, (int)after.unsafe_fault, (int)after.retired_ack);
    return 0;
}
