/* SPDX-License-Identifier: BSD-3-Clause */
#include "native_construction.h"
#include "native_os.h"
#include "controller.h"

/* Private sources originate only in successful fixed OS acquisition calls.
 * Slots never escape through a view. No reset, raw FD input or positive issuer. */
static struct {
    struct aeg_native_view view;
    int fd[4];
    bool close_tried[4];
    int parent, child, nullfd;
    unsigned targets;
} construction = { .fd = { -1, -1, -1, -1 } };
_Static_assert(sizeof(construction) <= 256, "construction logical storage");

static int
adopt(int fd)
{
    int i, free_slot = -1;
    if (fd < 0) return -1;
    for (i = 0; i < 4; i++) {
        if (construction.fd[i] == fd) return -1;
        if (construction.fd[i] < 0) free_slot = i;
    }
    if (free_slot < 0) return -1;
    construction.fd[free_slot] = fd;
    construction.close_tried[free_slot] = false;
    return free_slot;
}

static bool
close_slot(int slot)
{
    if (slot < 0 || construction.fd[slot] < 0) return true;
    if (construction.close_tried[slot]) return false;
    construction.close_tried[slot] = true;
    if (aeg_os_close(construction.fd[slot]) != 0) {
        construction.view.uncertain = true;
        return false;
    }
    construction.fd[slot] = -1;
    return true;
}

static int
fail(int error, bool uncertain, bool cleanup)
{
    int i;
    construction.view.phase = AEG_NATIVE_FAILED;
    construction.view.uncertain |= uncertain;
    if (cleanup) for (i = 0; i < 4; i++)
        if (construction.fd[i] >= 0 && !construction.close_tried[i])
            (void)close_slot(i); /* Only independently owned sources, once. */
    return construction.view.uncertain ? AEG_NATIVE_UNCERTAIN : error;
}

static bool
relocate(int *slot)
{
    int fd, moved;
    if (construction.fd[*slot] >= 4) return true;
    fd = aeg_os_dup_high(construction.fd[*slot]);
    if (fd < 0) return false;
    if (fd < 4 || (moved = adopt(fd)) < 0) {
        construction.view.uncertain = true;
        return false; /* Unknown/alias output never authorizes guessed close. */
    }
    if (!close_slot(*slot)) return false;
    *slot = moved;
    return true;
}

int
aeg_native_pair_prepare(void)
{
    struct aeg_owner_view owner;
    int pair[2] = { -1, -1 }, fd;
    if (construction.view.attempted) return AEG_NATIVE_STATE;
    construction.view.attempted = true;
    owner = aeg_owner_get_view();
    if (owner.phase != AEG_RESERVED || !owner.held || owner.stopped ||
        owner.clock_fault || owner.identity_fault || owner.unsafe_fault)
        return fail(AEG_NATIVE_STATE, false, false);
    if (aeg_os_pair(pair) != 0)
        return fail(AEG_NATIVE_OS, pair[0] != -1 || pair[1] != -1, false);
    if (pair[0] < 0 || pair[1] < 0 || pair[0] == pair[1])
        return fail(AEG_NATIVE_UNCERTAIN, true, false);
    construction.parent = adopt(pair[0]);
    construction.child = adopt(pair[1]);
    fd = aeg_os_null();
    if (fd < 0) return fail(AEG_NATIVE_OS, false, true);
    construction.nullfd = adopt(fd);
    if (construction.nullfd < 0) return fail(AEG_NATIVE_UNCERTAIN, true, false);
    if (aeg_os_null_kind(fd) != 0) return fail(AEG_NATIVE_OS, false, true);
    if (!relocate(&construction.parent) || !relocate(&construction.child) ||
        !relocate(&construction.nullfd))
        return fail(AEG_NATIVE_OS, construction.view.uncertain,
            !construction.view.uncertain);
    construction.view.phase = AEG_NATIVE_PAIR;
    return AEG_NATIVE_OK;
}

static bool
claim_branch(void)
{
    if (!construction.view.attempted) {
        construction.view.attempted = true;
        construction.view.branch_attempted = true;
        construction.view.phase = AEG_NATIVE_FAILED;
        return false; /* Invalid initial ordering burns this process attempt. */
    }
    if (construction.view.phase != AEG_NATIVE_PAIR ||
        construction.view.branch_attempted) return false;
    construction.view.branch_attempted = true;
    return true;
}

int
aeg_native_parent_prepare(void)
{
    bool child_closed, null_closed;
    if (!claim_branch()) return AEG_NATIVE_STATE;
    child_closed = close_slot(construction.child);
    null_closed = close_slot(construction.nullfd);
    if (!child_closed || !null_closed)
        return fail(AEG_NATIVE_OS, true, false);
    construction.view.phase = AEG_NATIVE_PARENT;
    return AEG_NATIVE_OK;
}

int
aeg_native_child_prepare(uid_t uid, gid_t gid)
{
    uid_t u[3] = { 0, 0, 0 };
    gid_t g[3] = { 0, 0, 0 };
    int i, flags, rc;
    if (!claim_branch()) return AEG_NATIVE_STATE;
    if (uid == 0 || uid == (uid_t)-1 || gid == 0 || gid == (gid_t)-1)
        return fail(AEG_NATIVE_INPUT, false, false);
    rc = aeg_os_dup_target(construction.fd[construction.child], 3);
    if (rc != 3) return fail(AEG_NATIVE_OS, rc >= 0, rc < 0);
    construction.targets |= 1U << 3;
    for (i = 0; i < 3; i++) {
        rc = aeg_os_dup_target(construction.fd[construction.nullfd], i);
        if (rc != i) return fail(AEG_NATIVE_OS, rc >= 0, rc < 0);
        construction.targets |= 1U << i;
    }
    flags = aeg_os_getfd(3);
    if (flags != 0) return fail(AEG_NATIVE_OS, false, true);
    if (aeg_os_nonblock(3) != 1) return fail(AEG_NATIVE_OS, false, true);
    if (aeg_os_closefrom4() != 0)
        return fail(AEG_NATIVE_UNCERTAIN, true, false); /* No later OS call. */
    for (i = 0; i < 4; i++) construction.fd[i] = -1;
    if (aeg_os_clear_groups() != 0 || aeg_os_set_gid(gid) != 0 ||
        aeg_os_set_uid(uid) != 0 || aeg_os_group_count() != 0 ||
        aeg_os_get_gid(g) != 0 || g[0] != gid || g[1] != gid || g[2] != gid ||
        aeg_os_get_uid(u) != 0 || u[0] != uid || u[1] != uid || u[2] != uid)
        return fail(AEG_NATIVE_OS, true, false);
    construction.view.identity_checked = true;
    construction.view.phase = AEG_NATIVE_CHILD;
    return AEG_NATIVE_OK; /* Local preparation only, never exec/readiness. */
}

struct aeg_native_view
aeg_native_get_view(void)
{
    struct aeg_native_view view = construction.view;
    int i;
    view.known_owned_descriptors = 0;
    for (i = 0; i < 4; i++) if (construction.fd[i] >= 0)
        view.known_owned_descriptors++;
    for (i = 0; i < 4; i++) if (construction.targets & (1U << i))
        view.known_owned_descriptors++;
    return view; /* Known references only; uncertainty never establishes a cap. */
}
