/* SPDX-License-Identifier: BSD-3-Clause */
/* Every product OS boundary is intercepted. No host FD/identity/process calls. */
#include "native_construction.h"
#include "controller.h"
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

static int fail_at, calls, bad, peak, live, next_high = 4;
static bool owned[64];
static unsigned close_calls[64];
static char trace[64][40];
static const char *mode;

static int
note(const char *label, int a, int b, int count)
{
    if (calls >= 64) { bad++; return 1; }
    if (count == 0) (void)snprintf(trace[calls], 40, "%s", label);
    else if (count == 1) (void)snprintf(trace[calls], 40, "%s:%d", label, a);
    else (void)snprintf(trace[calls], 40, "%s:%d:%d", label, a, b);
    calls++;
    return calls == fail_at;
}
static void mark(int fd) {
    if (fd < 0 || fd >= 64 || owned[fd]) { bad++; return; }
    owned[fd] = true; live++; if (live > peak) peak = live;
}
static void unmark(int fd) {
    if (fd < 0 || fd >= 64 || !owned[fd]) { bad++; return; }
    owned[fd] = false; live--;
}
int aeg_test_socketpair(int family, int type, int protocol, int pair[2]) {
    if (family != AF_UNIX || type != (SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK) || protocol != 0) bad++;
    if (note("pair",0,0,0)) return -1;
    if (strcmp(mode,"pair-negative") == 0) { pair[0]=-1;pair[1]=3;return 0; }
    if (strcmp(mode,"pair-alias") == 0) { pair[0]=pair[1]=0;return 0; }
    pair[0] = strcmp(mode,"allocation2") == 0 ? 2 : 0;
    pair[1] = strcmp(mode,"allocation2") == 0 ? 0 : 3;
    mark(pair[0]);mark(pair[1]);return 0;
}
int aeg_test_open(const char *path, int flags, ...) {
    if (strcmp(path,"/dev/null") != 0 || flags != (O_RDWR|O_CLOEXEC|O_NOFOLLOW)) bad++;
    if (note("null",0,0,0)) return -1;
    if (strcmp(mode,"open-alias") == 0) return 0;
    mark(1);return 1;
}
int aeg_test_fstat(int fd, struct stat *st) {
    if (fd != 1 || st == NULL || !owned[fd]) bad++;
    if (note("stat",fd,0,1)) return -1;
    memset(st,0,sizeof(*st));st->st_mode = strcmp(mode,"nonchar") == 0 ? S_IFREG : S_IFCHR;return 0;
}
int aeg_test_fcntl(int fd, int command, ...) {
    va_list ap;int minimum, result;
    if (fd<0 || fd>=64 || !owned[fd]) bad++;
    if (command == F_DUPFD_CLOEXEC) {
        va_start(ap,command);minimum=va_arg(ap,int);va_end(ap);
        if (minimum != 4) bad++;
        if (note("high",fd,0,1)) return -1;
        if (strcmp(mode,"dup-alias") == 0) return fd;
        result=next_high++;mark(result);return result;
    }
    if (command == F_GETFD) {
        if (fd != 3) bad++;
        if (note("getfd",fd,0,1)) return -1;
        return strcmp(mode,"cloexec") == 0 ? FD_CLOEXEC : 0;
    }
    if (command == F_GETFL) {
        if (fd != 3) bad++;
        if (note("getfl",fd,0,1)) return -1;
        return strcmp(mode,"blocking") == 0 ? 0 : O_NONBLOCK;
    }
    bad++;return -1;
}
int aeg_test_close(int fd) {
    bool fails;
    if (fd<0 || fd>=64 || !owned[fd] || ++close_calls[fd] > 1) bad++;
    fails=note("close",fd,0,1);unmark(fd);
    return fails ? -1 : 0; /* Error can already have consumed the old FD. */
}
int aeg_test_dup2(int fd, int target) {
    if (fd<0 || fd>=64 || !owned[fd] || target<0 || target>3 || fd<4) bad++;
    if (note("dup",fd,target,2)) return -1;
    if (strcmp(mode,"dup-target") == 0) return 4;
    if (owned[target]) unmark(target);
    mark(target);return target;
}
int aeg_test_closefrom(int from) {
    int i;bool fails;
    if (from != 4) bad++;
    fails=note("closefrom",from,0,1);
    if (fails) { if (owned[4]) unmark(4);return -1; } /* Partial closure. */
    for (i=4;i<64;i++) if (owned[i]) unmark(i);
    return 0;
}
int aeg_test_setgroups(int count, const gid_t *groups) {
    if (count != 0 || groups != NULL) bad++;
    return note("groups",count,0,1) ? -1 : 0;
}
int aeg_test_setresgid(gid_t r,gid_t e,gid_t s) {
    if (r!=456 || e!=456 || s!=456) bad++;
    return note("gid",(int)r,0,1) ? -1 : 0;
}
int aeg_test_setresuid(uid_t r,uid_t e,uid_t s) {
    if (r!=123 || e!=123 || s!=123) bad++;
    return note("uid",(int)r,0,1) ? -1 : 0;
}
int aeg_test_getgroups(int count,gid_t *groups) {
    if (count!=0 || groups!=NULL) bad++;
    if (note("getgroups",0,0,0)) return -1;
    return strcmp(mode,"groups-nonzero") == 0 ? 1 : 0;
}
int aeg_test_getresgid(gid_t *r,gid_t *e,gid_t *s) {
    if (note("getgid",0,0,0)) return -1;
    *r=*e=*s=456;
    if (strcmp(mode,"gid0") == 0) *r=0;
    if (strcmp(mode,"gid1") == 0) *e=0;
    if (strcmp(mode,"gid2") == 0) *s=0;
    return 0;
}
int aeg_test_getresuid(uid_t *r,uid_t *e,uid_t *s) {
    if (note("getuid",0,0,0)) return -1;
    *r=*e=*s=123;
    if (strcmp(mode,"uid0") == 0) *r=0;
    if (strcmp(mode,"uid1") == 0) *e=0;
    if (strcmp(mode,"uid2") == 0) *s=0;
    return 0;
}

int main(int argc,char **argv) {
    struct aeg_native_view v;
    struct aeg_owner_view owner;
    uid_t uid=123;gid_t gid=456;
    int prepared,branch=-1,before,i,dup_prepare,dup_parent,dup_child;
    bool parent;
    if (argc!=2 || strlen(argv[1])>24) return 2;
    mode=argv[1];parent=strcmp(mode,"parent")==0 || strncmp(mode,"parent-fail-",12)==0;
    if (strncmp(mode,"fail-",5)==0) fail_at=atoi(mode+5);
    if (strncmp(mode,"parent-fail-",12)==0) fail_at=atoi(mode+12);
    if (fail_at<0 || fail_at>22) return 3;
    if (strcmp(mode,"controller")==0) {
        prepared=aeg_native_pair_prepare();
    } else if (strcmp(mode,"unprepared")==0) {
        prepared=-1;branch=aeg_native_parent_prepare();
    } else {
        if (aeg_owner_prepare("00000000000000000000000000000000",32,0)!=AEG_OK) return 4;
        prepared=aeg_native_pair_prepare();
        if (strcmp(mode,"zero-uid")==0) uid=0;
        if (strcmp(mode,"minus-uid")==0) uid=(uid_t)-1;
        if (strcmp(mode,"zero-gid")==0) gid=0;
        if (strcmp(mode,"minus-gid")==0) gid=(gid_t)-1;
        if (prepared==AEG_NATIVE_OK) branch=parent ? aeg_native_parent_prepare() : aeg_native_child_prepare(uid,gid);
    }
    before=calls;
    dup_prepare=aeg_native_pair_prepare();
    dup_parent=aeg_native_parent_prepare();
    dup_child=aeg_native_child_prepare(123,456);
    v=aeg_native_get_view();owner=aeg_owner_get_view();
    printf("{\"prepare\":%d,\"branch\":%d,\"phase\":%d,\"attempted\":%d,\"branch_attempted\":%d,\"uncertain\":%d,\"identity\":%d,\"known\":%u,\"peak\":%d,\"bad\":%d,\"duplicates\":[%d,%d,%d],\"duplicate_calls\":%d,\"owner\":[%d,%d,%u,%u,%d,%d],\"trace\":[",prepared,branch,v.phase,(int)v.attempted,(int)v.branch_attempted,(int)v.uncertain,(int)v.identity_checked,v.known_owned_descriptors,peak,bad,dup_prepare,dup_parent,dup_child,calls-before,owner.phase,(int)owner.held,owner.request_envelope,owner.socket_envelope,(int)owner.known_child,(int)owner.protocol_closed);
    for (i=0;i<calls;i++) printf("%s\"%s\"",i==0?"":",",trace[i]);
    puts("]}");return 0;
}
