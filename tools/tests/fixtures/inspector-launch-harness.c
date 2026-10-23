/* SPDX-License-Identifier: BSD-3-Clause */
/* Every source process, signal, wait and descriptor effect is intercepted. */
#define main previous_native_fixture_main
#define aeg_test_send aeg_test_bootstrap_send
#include "inspector-native-harness.c"
#undef main
#undef aeg_test_send
#include "launch_storage.h"
#include "launch_source_os.h"
#include "inspector-launch-literals.h"
#include <errno.h>
#include <setjmp.h>

static int forks, execs, kills, exits, stop_sends, read_calls, waits, last_signal;
static int64_t clock_ms;
static int wait_kind;
static bool starting=true;
static size_t read_at;
static jmp_buf child_jump;

int aeg_launch_storage_clean_source(void) { return AEG_STORAGE_OK; }
struct aeg_storage_view aeg_storage_get_view(void) {
    struct aeg_storage_view v={0};v.committed=true;return v;
}
const unsigned char *aeg_launch_bootstrap_take(size_t *n) {
    *n=sizeof(source_packet);return source_packet;
}
ssize_t aeg_test_send(int fd,const void *p,size_t n,int flags) {
#ifdef AEG_DIAGNOSTIC_FIXTURE
    if(fd==10) {
        extern ssize_t aeg_diag_test_log(int,const void *,size_t,int);
        return aeg_diag_test_log(fd,p,n,flags);
    }
#endif
    if(n!=64) return aeg_test_bootstrap_send(fd,p,n,flags);
    stop_sends++;
    if(fd!=4 || flags!=MSG_NOSIGNAL || memcmp(p,source_stop,64)!=0) bad++;
    return strcmp(mode,"source-short-stop")==0 ? 63 : 64;
}
int aeg_start_identity(uid_t *u,gid_t *g) { *u=123;*g=456;return 0; }
int aeg_start_clock(int64_t *n) {
    if(strcmp(mode,"source-clock")==0) return -1;
    *n=clock_ms;return 0;
}
pid_t aeg_start_fork(void) {
    forks++;
    if(strcmp(mode,"source-fork-error")==0) {errno=EAGAIN;return -1;}
    return strcmp(mode,"source-child")==0 ? 0 : 321;
}
int aeg_start_exec(void) {execs++;return -1;}
_Noreturn void aeg_start_child_exit(void) {exits++;longjmp(child_jump,1);}
ssize_t aeg_start_read(int fd,unsigned char *p,size_t n) {
    const unsigned char *src=starting ? source_started : source_ack;
    size_t total=starting ? sizeof(source_started) : sizeof(source_ack), count;
    if(fd!=4) bad++;
    read_calls++;
    if(starting && strcmp(mode,"source-fragments")==0 && read_calls<=2) {
        errno=read_calls==1 ? EAGAIN : EINTR;return -1;
    }
    if(read_at>=total) return 0;
    count=total-read_at;if(count>n) count=n;
    if(starting && strcmp(mode,"source-fragments")==0 && count>13) count=13;
    memcpy(p,src+read_at,count);
    if(starting && read_at==0 && strcmp(mode,"source-bad-start")==0) p[0]^=1;
    read_at+=count;return (ssize_t)count;
}
pid_t aeg_start_wait(pid_t pid,int *kind) {
    waits++;if(pid!=321) bad++;*kind=wait_kind;
    if(strcmp(mode,"source-lost")==0) {errno=ECHILD;return -1;}
    if(strcmp(mode,"source-wrong-pid")==0) return 999;
    return wait_kind ? 321 : 0;
}
int aeg_start_kill(pid_t pid) {
    kills++;last_signal=(int)pid;
    if(strcmp(mode,"source-missing")==0) {errno=ESRCH;return -1;}
    if(strcmp(mode,"source-denied")==0) {errno=EPERM;return -1;}
    return 0;
}

#ifndef AEG_LAUNCH_FIXTURE_MAIN
#define AEG_LAUNCH_FIXTURE_MAIN main
#endif
int AEG_LAUNCH_FIXTURE_MAIN(int argc,char **argv) {
    int spawned=-1,started=-1,stopped=-1,ticked=-1,waited=-1,closed=-1,again=-1,i,held_after_kill=-1;
    struct aeg_owner_view owner;struct aeg_native_view native;
    if(argc!=2 || strlen(argv[1])>32) return 2;
    mode=argv[1];expected_bootstrap=source_packet;expected_bootstrap_size=sizeof(source_packet);
    if(aeg_owner_prepare((const char *)source_packet+18,32,0)!=AEG_OK ||
        aeg_native_pair_prepare()!=AEG_NATIVE_OK || aeg_native_bootstrap_emit()!=AEG_NATIVE_OK) return 3;
    if(setjmp(child_jump)==0) spawned=aeg_native_spawn_source();
    if(exits) goto done;
    if(strcmp(mode,"source-fork-error")==0) {closed=aeg_native_close_source();goto done;}
    if(strcmp(mode,"source-clock")==0) {ticked=aeg_native_tick_source();goto done;}
    if(strcmp(mode,"source-lost")==0 || strcmp(mode,"source-wrong-pid")==0) {
        waited=aeg_native_wait_source();ticked=aeg_native_tick_source();closed=aeg_native_close_source();goto done;
    }
    for(i=0;i<20;i++) {started=aeg_native_prepared_source();if(started!=AEG_NATIVE_PENDING) break;}
    starting=false;read_at=0;
    stopped=aeg_native_stop_source();
    clock_ms=strcmp(mode,"source-late-ack")==0 ? 100 : 50;
    ticked=aeg_native_tick_source();
    clock_ms=3000;(void)aeg_native_tick_source();
    (void)aeg_native_tick_source(); /* A claimed kill cannot be sent twice. */
    held_after_kill=(int)aeg_owner_get_view().held;
    clock_ms=3500;wait_kind=1;waited=aeg_native_wait_source();
    (void)aeg_native_tick_source(); /* Terminal wait forbids signaling reused PID. */
    if(strcmp(mode,"source-close-error")==0) fail_at=calls+1;
    closed=aeg_native_close_source();again=aeg_native_close_source();
done:
    owner=aeg_owner_get_view();native=aeg_native_get_view();
    printf("{\"spawn\":%d,\"start\":%d,\"stop\":%d,\"tick\":%d,\"wait\":%d,\"close\":%d,\"again\":%d,\"forks\":%d,\"execs\":%d,\"exits\":%d,\"kills\":%d,\"signal_pid\":%d,\"stop_sends\":%d,\"read_calls\":%d,\"wait_calls\":%d,\"held\":%d,\"known\":%d,\"ack\":%d,\"terminal\":%d,\"target\":%d,\"phase\":%d,\"uncertain\":%d,\"descriptors\":%u,\"bad\":%d,\"signal_result\":%d,\"held_after_kill\":%d}\n",
        spawned,started,stopped,ticked,waited,closed,again,forks,execs,exits,kills,last_signal,stop_sends,read_calls,waits,
        (int)owner.held,(int)owner.known_child,(int)owner.retired_ack,owner.terminal,owner.target,native.phase,(int)native.uncertain,native.known_owned_descriptors,bad,owner.signal_result,held_after_kill);
    return 0;
}
