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
    unsigned char bootstrap[104];
    bool bootstrap_prepared;
} store = { .fd = { -1,-1,-1,-1 } };
_Static_assert(sizeof(store) <= 256, "storage owner logical state");

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
static bool directory(int fd, bool searchable) {
    struct stat s;
    return aeg_store_stat(fd,&s)==0 && S_ISDIR(s.st_mode) && s.st_uid==0 &&
        (s.st_mode & 0022)==0 && (!searchable || (s.st_mode & 0001)!=0);
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
static bool pin_identity(int dir, int fd, struct stat *out) {
    struct stat a,b;
    if(aeg_store_stat(fd,&a)!=0 || !file_kind(&a,65) ||
        aeg_store_pin_stat(dir,&b)!=0 || !file_kind(&b,65) ||
        a.st_dev!=b.st_dev || a.st_ino!=b.st_ino) return false;
    *out=a;return true;
}
static bool image_identity(int dir, int fd, struct stat *out) {
    struct stat a,b;
    if(aeg_store_stat(fd,&a)!=0 || aeg_store_image_stat(dir,&b)!=0) return false;
    if(!S_ISREG(a.st_mode) || !S_ISREG(b.st_mode) ||
        a.st_uid!=0 || b.st_uid!=0 || a.st_gid!=0 || b.st_gid!=0 ||
        (a.st_mode & 07777)!=0555 || (b.st_mode & 07777)!=0555 ||
        a.st_nlink!=1 || b.st_nlink!=1 || a.st_size<1 || a.st_size>67108864 ||
        a.st_size!=b.st_size || a.st_dev!=b.st_dev || a.st_ino!=b.st_ino)
        return false;
    *out=a;return true;
}
static unsigned char hex_value(unsigned char c) {
    return c<='9' ? (unsigned char)(c-'0') : (unsigned char)(c-'a'+10);
}
static bool verify_image(int namespace_fd) {
    unsigned char pin[65], wanted[32], digest[32];
    struct stat initial, final;
    int pinfd, dir, opened, image, i;
    pinfd=adopt(aeg_store_pin(namespace_fd));
    if(pinfd<0 || !pin_identity(namespace_fd,store.fd[pinfd],&initial) ||
        aeg_store_read(store.fd[pinfd],pin,65)!=65) return false;
    for(i=0;i<64;i++) if(!hex(pin[i])) return false;
    if(pin[64]!='\n' || !pin_identity(namespace_fd,store.fd[pinfd],&final) ||
        initial.st_dev!=final.st_dev || initial.st_ino!=final.st_ino) return false;
    for(i=0;i<32;i++) wanted[i]=(unsigned char)((hex_value(pin[2*i])<<4)|hex_value(pin[2*i+1]));
    if(!close_slot(pinfd)) return false;
    dir=adopt(aeg_store_root());
    if(dir<0 || !directory(store.fd[dir],true)) return false;
    for(i=0;i<4;i++) {
        opened=adopt(aeg_store_image_dir(store.fd[dir],(unsigned)i));
        if(opened<0 || !directory(store.fd[opened],true) || !close_slot(dir)) return false;
        dir=opened;
    }
    image=adopt(aeg_store_image(store.fd[dir]));
    if(image<0 || !image_identity(store.fd[dir],store.fd[image],&initial) ||
        aeg_store_image_hash(store.fd[image],initial.st_size,digest)!=0 ||
        memcmp(wanted,digest,32)!=0 ||
        !image_identity(store.fd[dir],store.fd[image],&final) ||
        initial.st_dev!=final.st_dev || initial.st_ino!=final.st_ino ||
        initial.st_size!=final.st_size) return false;
    /* OpenBSD pathname execution is NOT bound by a held FD. Exclusion and
     * cooperating ALL writers carry custody; no qualified loader/exec issuer. */
    return close_slot(image) && close_slot(dir);
}
static bool pair_identity(int dir, int fd, struct stat *out) {
    struct stat a,b;
    if(aeg_store_stat(fd,&a)!=0 || a.st_size<47 || a.st_size>8192 ||
        !file_kind(&a,a.st_size) || aeg_store_pair_stat(dir,&b)!=0 ||
        !file_kind(&b,a.st_size) || a.st_dev!=b.st_dev || a.st_ino!=b.st_ino)
        return false;
    *out=a;return true;
}
static bool prepare_bootstrap(int dir, const unsigned char next[32]) {
    /* Base-contract digest is the independently frozen SHA256(M2-H1/1). */
    static const unsigned char contract[32]={
        0x1d,0x98,0x71,0x34,0x08,0x64,0x20,0xd4,
        0x8b,0x30,0x0a,0x4c,0xfd,0xa0,0x16,0xff,
        0xc5,0x50,0xa0,0xbd,0xa6,0xa6,0xf2,0x0c,
        0x58,0x28,0x2d,0xb1,0xb7,0xd4,0x2d,0xca
    };
    unsigned char snapshot[8193];
    struct stat initial, final;
    int slot=adopt(aeg_store_pair_snapshot(dir));
    if(slot<0 || !pair_identity(dir,store.fd[slot],&initial) ||
        aeg_store_read(store.fd[slot],snapshot,(size_t)initial.st_size+1)!=initial.st_size ||
        memcmp(snapshot,"AGPAIR1\n",8)!=0 || memcmp(snapshot+8,next,32)!=0 ||
        memcmp(snapshot+40,"M2-H1/1",7)!=0 ||
        !pair_identity(dir,store.fd[slot],&final) ||
        initial.st_dev!=final.st_dev || initial.st_ino!=final.st_ino ||
        initial.st_size!=final.st_size || !close_slot(slot)) return false;
    /* Only full grammar in I's existing parser can construct an owned snapshot.
     * This prefix check and hash cannot establish frontend or launch authority. */
    memcpy(store.bootstrap,"AGCHECK1",8);
    memcpy(store.bootstrap+8,next,32);
    aeg_store_pair_hash(snapshot,(size_t)initial.st_size,store.bootstrap+40);
    memcpy(store.bootstrap+72,contract,32);
    store.bootstrap_prepared=true;
    return true;
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
    if (dir<0 || !directory(store.fd[dir],false)) return fail(AEG_STORAGE_OS);
    for (i=0;i<3;i++) {
        opened=adopt(aeg_store_dir(store.fd[dir],(unsigned)i));
        if (opened<0 || !directory(store.fd[opened],false) || !close_slot(dir))
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
    if(!verify_image(store.fd[dir]) || !prepare_bootstrap(store.fd[dir],next))
        return fail(AEG_STORAGE_OS);
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
    if(aeg_native_bootstrap_emit()!=AEG_NATIVE_OK) return fail(AEG_STORAGE_UNCERTAIN);
    return AEG_STORAGE_OK; /* Unqualified local pair, never Owned/Ready/launch. */
}
int aeg_launch_storage_prepare(void) { return prepare(false); }
int aeg_update_exclusion_prepare(void) { return prepare(true); }
const unsigned char *aeg_launch_bootstrap_take(void) {
    if(store.view.bootstrap_claimed || !store.bootstrap_prepared ||
        !store.view.committed || store.view.uncertain ||
        store.view.phase!=AEG_STORAGE_LOCAL_PAIR) return NULL;
    store.view.bootstrap_claimed=true;
    return store.bootstrap;
}
struct aeg_storage_view aeg_storage_get_view(void) {
    struct aeg_storage_view v=store.view; int i;
    v.known_descriptors=0;
    for (i=0;i<4;i++) if (store.fd[i]>=0) v.known_descriptors++;
    return v; /* No descriptors/generation/cleanup capabilities escape. */
}
