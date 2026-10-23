/* SPDX-License-Identifier: BSD-3-Clause */
/* Actual storage + sole source waiter composition. Every subject OS/SHA effect
 * is fixed-intercepted; no real descriptor, process, signal, lock or crypto. */
#define AEG_STORAGE_FIXTURE_MAIN retained_storage_fixture_main
#include "inspector-storage-harness.c"
#undef AEG_STORAGE_FIXTURE_MAIN
#include "launch_source_os.h"
#include <errno.h>

static const char *scenario;
static int64_t source_ms=1100;
static int wait_kind=1, fork_calls, wait_calls, kill_calls, prepared_calls;
static bool clock_failed;
int aeg_start_identity(uid_t *u,gid_t *g) { *u=123;*g=456;return 0; }
int aeg_start_clock(int64_t *n) { if(clock_failed) return -1;*n=source_ms;return 0; }
pid_t aeg_start_fork(void) { fork_calls++;return strcmp(scenario,"native-nochild")==0 ? -1 : 321; }
int aeg_start_exec(void) { bad++;return -1; }
_Noreturn void aeg_start_child_exit(void) { abort(); }
ssize_t aeg_start_read(int fd,unsigned char *p,size_t n) {
    if(fd!=4 || n!=112) { bad++;return -1; }
    memcpy(p,"AGSTART1",8);memcpy(p+8,bootstrap_wanted+10,104);
    prepared_calls++;return 112;
}
pid_t aeg_start_wait(pid_t pid,int *kind) {
    wait_calls++;if(pid!=321) bad++;*kind=wait_kind;
    if(strcmp(scenario,"native-lost")==0) {errno=ECHILD;return -1;}
    if(strcmp(scenario,"native-wrong")==0) return 999;
    if(strcmp(scenario,"native-interrupt")==0) {errno=EINTR;return -1;}
    return wait_kind==0 ? 0 : 321;
}
int aeg_start_kill(pid_t pid) { (void)pid;kill_calls++;bad++;return -1; }

int main(int argc,char **argv) {
    const char *base="launch";
    int rc,closed=-1,settled,again,before,after,setup_end,settle_start,first=-1;
    unsigned i;struct aeg_owner_view owner;struct aeg_storage_view storage;
    if(argc!=2 || strlen(argv[1])>64) return 2;
    scenario=argv[1];
    if(strncmp(scenario,"record-",7)==0) base=scenario;
    if(strcmp(scenario,"vector-nontrivial")==0) base="bootstrap-golden";
    if(strcmp(scenario,"vector-maximum")==0) base="edge";
    if(strcmp(scenario,"native-empty")==0) {
        settled=aeg_native_settle_source();setup_end=calls;settle_start=calls;goto report;
    }
    if(storage_fixture_prepare(base)!=AEG_STORAGE_OK) return 3;
    if(strcmp(scenario,"native-early")==0) first=aeg_native_settle_source();
    if(aeg_native_spawn_source()!=AEG_NATIVE_OK && strcmp(scenario,"native-nochild")!=0) return 4;
    if(strcmp(scenario,"native-view")==0) {
        enum aeg_owner_intent intent;
        (void)aeg_owner_step(AEG_WAIT_NORMAL,source_ms,&intent);
        (void)aeg_owner_step(AEG_CLOSED,source_ms,&intent);
        goto settle;
    }
    if(strcmp(scenario,"native-nochild")!=0) {
        if(aeg_native_prepared_source()!=AEG_NATIVE_OK) return 5;
        /* Actual sole wait may prove terminal independently of Stop/ACK. */
        if(strcmp(scenario,"native-pending")==0) wait_kind=0;
        if(strcmp(scenario,"native-stopped")==0) wait_kind=3;
        if(strcmp(scenario,"native-signaled")==0) wait_kind=2;
        if(strcmp(scenario,"native-late")==0) {
            enum aeg_owner_intent intent;
            (void)aeg_owner_step(AEG_STOP,source_ms,&intent);
            source_ms+=4000;
        }
        if(strcmp(scenario,"native-clock")==0) clock_failed=true;
        (void)aeg_native_wait_source();
    }
    if(strcmp(scenario,"native-close-error")==0) fail_at=calls+1;
    closed=aeg_native_close_source();
settle:
    clean_active=true;mode=scenario;
    if(strcmp(scenario,"clean-bytes")==0) disk[16]='2';
    if(strncmp(scenario,"clean-fail-",11)==0) fail_at=calls+atoi(scenario+11);
    setup_end=calls;
    settle_start=calls;
    settled=aeg_native_settle_source();
report:
    after=calls;
    before=calls;again=aeg_native_settle_source();
    storage=aeg_storage_get_view();owner=aeg_owner_get_view();
    printf("{\"rc\":%d,\"closed\":%d,\"again\":%d,\"duplicate_calls\":%d,\"first\":%d,\"writes\":%d,\"reads\":%d,\"settled\":%d,\"uncertain\":%d,\"known\":%u,\"phase\":%d,\"target\":%d,\"terminal\":%d,\"clock_fault\":%d,\"forks\":%d,\"waits\":%d,\"kills\":%d,\"bad\":%d,\"trace\":[",
        settled,closed,again,calls-before,first,writes,state_reads,(int)storage.settled,(int)storage.uncertain,storage.known_descriptors,owner.phase,owner.target,owner.terminal,(int)owner.clock_fault,fork_calls,wait_calls,kill_calls,bad);
    for(i=(unsigned)settle_start;i<(unsigned)after;i++) printf("%s\"%s\"",i==(unsigned)settle_start ? "" : ",",trace[i]);
    printf("],\"setup_calls\":%d,\"disk\":\"",setup_end);
    for(i=0;i<128;i++) printf("%02x",disk[i]);
    printf("\",\"records\":");rec_report();puts("}");
    rc=bad;return rc ? 6 : 0;
}
