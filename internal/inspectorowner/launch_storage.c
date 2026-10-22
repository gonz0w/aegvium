/* SPDX-License-Identifier: BSD-3-Clause */
#include "launch_storage.h"
#include "storage_os.h"
#include "controller.h"
#include "native_construction.h"
#include <string.h>

static struct {
    struct aeg_storage_view view;
    int fd[4];
    bool close_tried[4];
} store = { .fd = { -1,-1,-1,-1 } };
_Static_assert(sizeof(store) <= 128, "storage owner logical state");

static int fail(int rc) {
    store.view.phase = AEG_STORAGE_FAILED;
    store.view.uncertain = true;
    return rc;
}
static int adopt(int fd) {
    int i, slot = -1;
    if (fd < 0) return -1;
    for (i=0;i<4;i++) {
        if (store.fd[i] == fd) return -1;
        if (store.fd[i] < 0) slot=i;
    }
    if (slot < 0) return -1;
    store.fd[slot]=fd; store.close_tried[slot]=false;
    return slot;
}
static bool close_slot(int i) {
    if (i<0 || store.fd[i]<0 || store.close_tried[i]) return false;
    store.close_tried[i]=true;
    if (aeg_store_close(store.fd[i]) != 0) return false;
    store.fd[i]=-1;
    return true;
}
static bool directory(int fd) {
    struct stat s;
    return aeg_store_stat(fd,&s)==0 && S_ISDIR(s.st_mode) && s.st_uid==0 &&
        (s.st_mode & 0022)==0;
}
static bool file_kind(const struct stat *s, off_t size) {
    return S_ISREG(s->st_mode) && s->st_uid==0 && s->st_gid==0 &&
        (s->st_mode & 07777)==0600 && s->st_nlink==1 && s->st_size==size;
}
static bool identity(int dir, int fd, bool intent, struct stat *out) {
    struct stat a,b;
    off_t size=intent ? 33 : 128;
    if (aeg_store_stat(fd,&a)!=0 || !file_kind(&a,size) ||
        aeg_store_path_stat(dir,intent,&b)!=0 || !file_kind(&b,size) ||
        a.st_dev!=b.st_dev || a.st_ino!=b.st_ino) return false;
    if (out!=NULL) *out=a;
    return true;
}
static bool hex(unsigned char c) { return (c>='0' && c<='9') || (c>='a' && c<='f'); }
static bool parse(const unsigned char p[128]) {
    unsigned char digest[32];
    unsigned i; bool nonzero=false;
    if (memcmp(p,"AEGOWN1\n",8)!=0 || (p[8]!='C' && p[8]!='U')) return false;
    for (i=9;i<16;i++) if (p[i]!=0) return false;
    for (i=16;i<48;i++) { if (!hex(p[i])) return false; nonzero |= p[i]!='0'; }
    for (i=80;i<128;i++) if (p[i]!=0) return false;
    if (p[8]=='U' && !nonzero) return false;
    aeg_store_hash(p,digest);
    return memcmp(digest,p+48,32)==0;
}
static bool increment(unsigned char out[32], const unsigned char in[32]) {
    int i;
    memcpy(out,in,32);
    for (i=31;i>=0;i--) {
        if (out[i]=='f') { out[i]='0'; continue; }
        out[i]=out[i]=='9' ? 'a' : (unsigned char)(out[i]+1);
        return true;
    }
    return false;
}
static int prepare(bool update) {
    struct aeg_owner_view owner;
    struct aeg_native_view native;
    unsigned char frame[128], next[32], intent[33], check[128];
    int dir, opened, state, intentfd, i;
    int64_t now;
    struct stat initial, final;
    if (store.view.attempted) return AEG_STORAGE_STATE;
    store.view.attempted=true; /* Includes invalid order, both roles, reentry. */
    owner=aeg_owner_get_view(); native=aeg_native_get_view();
    if (owner.phase!=AEG_EMPTY || native.attempted)
        return fail(AEG_STORAGE_STATE);
    dir=adopt(aeg_store_root());
    if (dir<0 || !directory(store.fd[dir])) return fail(AEG_STORAGE_OS);
    for (i=0;i<3;i++) {
        opened=adopt(aeg_store_dir(store.fd[dir],(unsigned)i));
        if (opened<0 || !directory(store.fd[opened]) || !close_slot(dir))
            return fail(AEG_STORAGE_OS);
        dir=opened;
    }
    state=adopt(aeg_store_state(store.fd[dir]));
    if (state<0 || aeg_store_lock(store.fd[state])!=0 ||
        !identity(store.fd[dir],store.fd[state],false,&initial)) return fail(AEG_STORAGE_OS);
    if (aeg_store_read(store.fd[state],frame,128)!=128 || !parse(frame) || frame[8]!='C')
        return fail(AEG_STORAGE_INPUT);
    if (update) {
        if (!close_slot(dir)) return fail(AEG_STORAGE_OS);
        store.view.phase=AEG_STORAGE_UPDATE_GUARD;
        return AEG_STORAGE_OK; /* Exclusion only, never update permission/repair. */
    }
    if (!increment(next,frame+16)) return fail(AEG_STORAGE_INPUT);
    intentfd=adopt(aeg_store_intent(store.fd[dir]));
    if (intentfd<0 || !identity(store.fd[dir],store.fd[intentfd],true,NULL) ||
        aeg_store_read(store.fd[intentfd],intent,33)!=33)
        return fail(AEG_STORAGE_OS);
    for (i=0;i<32;i++) if (!hex(intent[i])) return fail(AEG_STORAGE_INPUT);
    if (intent[32]!='\n' || memcmp(intent,next,32)!=0 || !close_slot(intentfd))
        return fail(AEG_STORAGE_INPUT);
    frame[8]='U'; memcpy(frame+16,next,32); aeg_store_hash(frame,frame+48);
    /* No admission or child can precede this full durability/readback boundary.
     * Short/error writes never continue; fsync failure never readbacks as repair. */
    if (aeg_store_write(store.fd[state],frame)!=128 || aeg_store_sync(store.fd[state])!=0 ||
        aeg_store_read(store.fd[state],check,128)!=128 || memcmp(frame,check,128)!=0 ||
        !identity(store.fd[dir],store.fd[state],false,&final) ||
        initial.st_dev!=final.st_dev || initial.st_ino!=final.st_ino) return fail(AEG_STORAGE_UNCERTAIN);
    store.view.committed=true; /* Known burned even if all later steps fail. */
    if (!close_slot(dir) || aeg_store_clock(&now)!=0) return fail(AEG_STORAGE_OS);
    /* No storage I/O after this point, including stop/escalation/wait. */
    if (aeg_owner_prepare((const char *)next,32,now)!=AEG_OK ||
        aeg_native_pair_prepare()!=AEG_NATIVE_OK) return fail(AEG_STORAGE_UNCERTAIN);
    store.view.phase=AEG_STORAGE_LOCAL_PAIR;
    return AEG_STORAGE_OK; /* Unqualified local pair, never Owned/Ready/launch. */
}
int aeg_launch_storage_prepare(void) { return prepare(false); }
int aeg_update_exclusion_prepare(void) { return prepare(true); }
struct aeg_storage_view aeg_storage_get_view(void) {
    struct aeg_storage_view v=store.view; int i;
    v.known_descriptors=0;
    for (i=0;i<4;i++) if (store.fd[i]>=0) v.known_descriptors++;
    return v; /* No descriptors/generation/cleanup capabilities escape. */
}
