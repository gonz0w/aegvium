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
    /* AGBOOT1 + u16 length + AGCHECK104 + descriptor + one read sentinel. */
    unsigned char bootstrap[8307];
    size_t bootstrap_size;
    bool bootstrap_prepared;
    int checkpoint;
    dev_t checkpoint_device;
    ino_t checkpoint_inode;
    unsigned char consumed[128];
    unsigned char records[8192], image_digest[32];
    dev_t records_device;
    ino_t records_inode;
    unsigned active_segment;
    bool records_prepared;
} store = { .fd = { -1,-1,-1,-1 }, .checkpoint = -1 };
_Static_assert(sizeof(store) <= 17408, "storage owner logical state");

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
    memcpy(store.image_digest,digest,32);
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
    /* Independently frozen profile digests. Only explicit local version/profile
     * pairs are recognized; the complete descriptor still needs I's parser. */
    static const unsigned char contract1[32]={
        0x1d,0x98,0x71,0x34,0x08,0x64,0x20,0xd4,
        0x8b,0x30,0x0a,0x4c,0xfd,0xa0,0x16,0xff,
        0xc5,0x50,0xa0,0xbd,0xa6,0xa6,0xf2,0x0c,
        0x58,0x28,0x2d,0xb1,0xb7,0xd4,0x2d,0xca
    };
    static const unsigned char contract3[32]={
        0x78,0xfc,0x97,0x92,0x25,0xe6,0x78,0x15,
        0x30,0xd7,0x91,0xeb,0x61,0x56,0xd0,0x69,
        0x49,0xa0,0x83,0x31,0x3d,0x02,0xf6,0xcf,
        0x3c,0xc0,0xb1,0xb6,0x8b,0xbd,0x0b,0x35
    };
    const unsigned char *contract;
    unsigned char *snapshot=store.bootstrap+114;
    struct stat initial, final;
    int slot=adopt(aeg_store_pair_snapshot(dir));
    if(slot<0 || !pair_identity(dir,store.fd[slot],&initial) ||
        aeg_store_read(store.fd[slot],snapshot,(size_t)initial.st_size+1)!=initial.st_size ||
        memcmp(snapshot+8,next,32)!=0) return false;
    if(memcmp(snapshot,"AGPAIR1\n",8)==0 && memcmp(snapshot+40,"M2-H1/1",7)==0)
        contract=contract1;
    else if(memcmp(snapshot,"AGPAIR2\n",8)==0 && memcmp(snapshot+40,"M2-H1/3",7)==0)
        contract=contract3;
    else return false;
    if(!pair_identity(dir,store.fd[slot],&final) ||
        initial.st_dev!=final.st_dev || initial.st_ino!=final.st_ino ||
        initial.st_size!=final.st_size || !close_slot(slot)) return false;
    /* Only full grammar in I's existing parser can construct an owned snapshot.
     * This prefix check and hash cannot establish frontend or launch authority. */
    memcpy(store.bootstrap,"AGBOOT1\n",8);
    store.bootstrap[8]=(unsigned char)((size_t)initial.st_size>>8);
    store.bootstrap[9]=(unsigned char)initial.st_size;
    memcpy(store.bootstrap+10,"AGCHECK1",8);
    memcpy(store.bootstrap+18,next,32);
    aeg_store_pair_hash(snapshot,(size_t)initial.st_size,store.bootstrap+50);
    memcpy(store.bootstrap+82,contract,32);
    store.bootstrap_size=114+(size_t)initial.st_size;
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
/* Two fixed logical segments in one existing protected8192-byte file. No
 * directory scan, arbitrary path, create, truncate, unlink, repair or worker.
 * These records never supply checkpoint or physical-retirement authority. */
static bool records_identity(int dir, int fd, struct stat *out) {
    struct stat a,b;
    if(aeg_store_stat(fd,&a)!=0 || !file_kind(&a,8192) ||
        aeg_store_records_stat(dir,&b)!=0 || !file_kind(&b,8192) ||
        a.st_dev!=b.st_dev || a.st_ino!=b.st_ino) return false;
    *out=a;return true;
}
static bool zeroes(const unsigned char *p, size_t n) {
    size_t i;
    for(i=0;i<n;i++) if(p[i]!=0) return false;
    return true;
}
static bool record_segment(const unsigned char *p) {
    unsigned char digest[32], next[32];
    unsigned i;bool nonzero=false;
    if(memcmp(p,"AEGSEC1\n",8)!=0 || (p[8]!='A' && p[8]!='S') ||
        p[9]>30 || (p[9]&1)!=0 || (p[8]=='S' && p[9]!=30) ||
        !zeroes(p+10,6) || !zeroes(p+112,16)) return false;
    for(i=16;i<48;i++) { if(!hex(p[i])) return false;nonzero |= p[i]!='0'; }
    for(i=80;i<112;i++) if(!hex(p[i])) return false;
    if(!nonzero) return false;
    aeg_store_records_hash(p,digest);
    if(memcmp(digest,p+48,32)!=0 ||
        !zeroes(p+128+(size_t)p[9]*128,4096-128-(size_t)p[9]*128)) return false;
    for(i=0;i<p[9];i++) {
        const unsigned char *r=p+128+(size_t)i*128;
        unsigned j;bool used=false;
        if(memcmp(r,"AEGREQ1\n",8)!=0 || r[8]!=(i%2==0 ? 'U' : 'C') ||
            !zeroes(r+9,7) || (r[112]!=1 && r[112]!=3) || !zeroes(r+113,15)) return false;
        for(j=16;j<48;j++) { if(!hex(r[j])) return false;used |= r[j]!='0'; }
        if(!used) return false;
        if(i==0 && (!increment(next,p+80) || memcmp(next,r+16,32)!=0)) return false;
        if(i%2!=0 && memcmp(r+16,r-128+16,97)!=0) return false;
        if(i>0 && i%2==0 && (!increment(next,r-128+16) || memcmp(next,r+16,32)!=0)) return false;
    }
    return true;
}
static bool records_parse(const unsigned char current[32]) {
    unsigned char next[32];
    unsigned a=store.records[8]=='A' ? 0 : 1, b=1-a;
    const unsigned char *active=store.records+a*4096, *old=store.records+b*4096;
    const unsigned char *last=active+80;
    if(!record_segment(active) || active[8]!='A' || active[9]>28) return false;
    if(!zeroes(old,4096)) {
        if(!record_segment(old) || old[8]!='S' || !increment(next,old+16) ||
            memcmp(next,active+16,32)!=0) return false;
        last=old+128+29*128+16;
        if(memcmp(last,active+80,32)!=0) return false;
    } else if(memcmp(active+16,"00000000000000000000000000000001",32)!=0) return false;
    if(active[9]>0) last=active+128+((size_t)active[9]-1)*128+16;
    if(memcmp(last,current,32)!=0) return false;
    store.active_segment=a;return true;
}
static bool records_commit(int dir, int fd, unsigned segment) {
    unsigned char check[4096];
    unsigned char *p=store.records+segment*4096;
    struct stat now;
    aeg_store_records_hash(p,p+48);
    if(aeg_store_records_write(fd,p,(off_t)segment*4096)!=4096 ||
        aeg_store_sync(fd)!=0 ||
        aeg_store_records_read(fd,check,sizeof(check),(off_t)segment*4096)!=4096 ||
        memcmp(check,p,sizeof(check))!=0 || !records_identity(dir,fd,&now) ||
        now.st_dev!=store.records_device || now.st_ino!=store.records_inode) return false;
    return true; /* No continuation, retry or sync-error readback. */
}
static void record_append(unsigned char kind, const unsigned char generation[32]) {
    unsigned char *p=store.records+store.active_segment*4096;
    unsigned char *r=p+128+(size_t)p[9]*128;
    memset(r,0,128);memcpy(r,"AEGREQ1\n",8);r[8]=kind;
    memcpy(r+16,generation,32);memcpy(r+48,store.bootstrap+50,32);
    memcpy(r+80,store.image_digest,32);
    r[112]=store.bootstrap[160]=='3' ? 3 : 1;
    ++p[9];
}
static bool records_admit(int dir, const unsigned char current[32], const unsigned char next[32]) {
    struct stat initial, final;
    int slot=adopt(aeg_store_records(dir));
    if(slot<0 || !records_identity(dir,store.fd[slot],&initial) ||
        aeg_store_records_read(store.fd[slot],store.records,sizeof(store.records),0)!=8192 ||
        !records_identity(dir,store.fd[slot],&final) || initial.st_dev!=final.st_dev ||
        initial.st_ino!=final.st_ino || !records_parse(current)) return false;
    store.records_device=initial.st_dev;store.records_inode=initial.st_ino;
    record_append('U',next); /* Intent only: cannot assert U reached launch.state. */
    if(!records_commit(dir,store.fd[slot],store.active_segment) || !close_slot(slot)) return false;
    store.records_prepared=true;return true;
}
#ifdef AEG_INSPECTOR_SOURCE
/* Called only after the existing private same-child terminal/close guard and
 * exact retained U validation. At most one oldest sealed segment is recycled. */
static bool records_clean(int dir) {
    unsigned char check[8192], next[32];
    struct stat now;
    unsigned a=store.active_segment, b=1-a;
    unsigned char *active=store.records+a*4096, *old=store.records+b*4096;
    int slot;
    if(!store.records_prepared || active[9]>29 || (active[9]&1)==0) return false;
    slot=adopt(aeg_store_records(dir));
    if(slot<0 || !records_identity(dir,store.fd[slot],&now) ||
        now.st_dev!=store.records_device || now.st_ino!=store.records_inode ||
        aeg_store_records_read(store.fd[slot],check,sizeof(check),0)!=8192 ||
        memcmp(check,store.records,sizeof(check))!=0 ||
        !records_identity(dir,store.fd[slot],&now) ||
        now.st_dev!=store.records_device || now.st_ino!=store.records_inode) return false;
    record_append('C',store.consumed+16); /* Physical boundary, not checkpoint-C success. */
    if(active[9]==30) active[8]='S';
    if(!records_commit(dir,store.fd[slot],a)) return false;
    if(active[9]==30) {
        if(!increment(next,active+16)) return false;
        /* b was validated empty or the sole, older sealed segment at admission;
         * exact retained-byte comparison above excludes changing that decision. */
        if(!zeroes(old,4096) && (old[8]!='S' || memcmp(old+16,active+16,32)>=0)) return false;
        memset(old,0,4096);memcpy(old,"AEGSEC1\n",8);old[8]='A';memcpy(old+16,next,32);
        memcpy(old+80,store.consumed+16,32);
        if(!records_commit(dir,store.fd[slot],b)) return false;
        store.active_segment=b;
    }
    return close_slot(slot);
}
#endif
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
    if(!records_admit(store.fd[dir],frame+16,next)) return fail(AEG_STORAGE_UNCERTAIN);
    frame[8]='U'; memcpy(frame+16,next,32); aeg_store_hash(frame,frame+48);
    /* No admission or child can precede this full durability/readback boundary.
     * Short/error writes never continue; fsync failure never readbacks as repair. */
    if (aeg_store_write(store.fd[state],frame)!=128 || aeg_store_sync(store.fd[state])!=0 ||
        aeg_store_read(store.fd[state],check,128)!=128 || memcmp(frame,check,128)!=0 ||
        !identity(store.fd[dir],store.fd[state],false,&final) ||
        initial.st_dev!=final.st_dev || initial.st_ino!=final.st_ino) return fail(AEG_STORAGE_UNCERTAIN);
    store.view.committed=true; /* Known burned even if all later steps fail. */
    store.checkpoint=state;
    store.checkpoint_device=final.st_dev; store.checkpoint_inode=final.st_ino;
    memcpy(store.consumed,frame,128);
    if (!close_slot(dir) || aeg_store_clock(&now)!=0) return fail(AEG_STORAGE_OS);
    /* No storage I/O during active stop/escalation/wait. Normal clean settlement
     * is separate and requires the actual native terminal owner's full join. */
    if (aeg_owner_prepare((const char *)next,32,now)!=AEG_OK ||
        aeg_native_pair_prepare()!=AEG_NATIVE_OK) return fail(AEG_STORAGE_UNCERTAIN);
    store.view.phase=AEG_STORAGE_LOCAL_PAIR;
    if(aeg_native_bootstrap_emit()!=AEG_NATIVE_OK) return fail(AEG_STORAGE_UNCERTAIN);
    return AEG_STORAGE_OK; /* Unqualified local pair, never Owned/Ready/launch. */
}
int aeg_launch_storage_prepare(void) { return prepare(false); }
int aeg_update_exclusion_prepare(void) { return prepare(true); }
const unsigned char *aeg_launch_bootstrap_take(size_t *size) {
    if(size==NULL) return NULL;
    *size=0;
    if(store.view.bootstrap_claimed || !store.bootstrap_prepared ||
        !store.view.committed || store.view.uncertain ||
        store.view.phase!=AEG_STORAGE_LOCAL_PAIR) return NULL;
    store.view.bootstrap_claimed=true;
    *size=store.bootstrap_size;
    return store.bootstrap;
}
struct aeg_storage_view aeg_storage_get_view(void) {
    struct aeg_storage_view v=store.view; int i;
    v.known_descriptors=0;
    for (i=0;i<4;i++) if (store.fd[i]>=0) v.known_descriptors++;
    return v; /* No descriptors/generation/cleanup capabilities escape. */
}

#ifdef AEG_INSPECTOR_SOURCE
/* Only aeg_native_settle_source calls this bridge in production. No supplied
 * observation, PID, path, generation or parsed checkpoint can invoke it. */
int aeg_launch_storage_clean_source(void) {
    unsigned char check[128], clean[128];
    struct stat current;
    int dir, opened, fd, i;
    if(store.view.settlement_attempted) return AEG_STORAGE_STATE;
    store.view.settlement_attempted=true;
    if(!store.view.committed || store.view.uncertain ||
        store.view.phase!=AEG_STORAGE_LOCAL_PAIR || !store.view.bootstrap_claimed ||
        store.checkpoint<0 || store.checkpoint>=4 ||
        store.fd[store.checkpoint]<0 || store.close_tried[store.checkpoint])
        return fail(AEG_STORAGE_STATE);
    fd=store.fd[store.checkpoint]; /* Same original EX, never reopen the checkpoint. */
    dir=adopt(aeg_store_root());
    if(dir<0 || !directory(store.fd[dir],false)) return fail(AEG_STORAGE_OS);
    for(i=0;i<3;i++) {
        opened=adopt(aeg_store_dir(store.fd[dir],(unsigned)i));
        if(opened<0 || !directory(store.fd[opened],false) || !close_slot(dir))
            return fail(AEG_STORAGE_OS);
        dir=opened;
    }
    if(!identity(store.fd[dir],fd,false,&current) ||
        current.st_dev!=store.checkpoint_device || current.st_ino!=store.checkpoint_inode ||
        aeg_store_read(fd,check,128)!=128 || memcmp(check,store.consumed,128)!=0 ||
        !identity(store.fd[dir],fd,false,&current) ||
        current.st_dev!=store.checkpoint_device || current.st_ino!=store.checkpoint_inode)
        return fail(AEG_STORAGE_UNCERTAIN);
    if(!records_clean(store.fd[dir])) return fail(AEG_STORAGE_UNCERTAIN);
    memcpy(clean,store.consumed,128);
    clean[8]='C'; /* g stays consumed: next launch must use g+1, never reuseg. */
    aeg_store_hash(clean,clean+48);
    if(aeg_store_write(fd,clean)!=128 || aeg_store_sync(fd)!=0 ||
        aeg_store_read(fd,check,128)!=128 || memcmp(check,clean,128)!=0 ||
        !identity(store.fd[dir],fd,false,&current) ||
        current.st_dev!=store.checkpoint_device || current.st_ino!=store.checkpoint_inode)
        return fail(AEG_STORAGE_UNCERTAIN);
    if(!close_slot(dir)) return fail(AEG_STORAGE_UNCERTAIN);
    store.view.settled=true;
    store.view.phase=AEG_STORAGE_CLEAN;
    /* Retain the stable checkpoint/exclusion until S exits. This local storage
     * fact is not S exit, a4s pass, next-pair provenance, Ready or recovery. */
    return AEG_STORAGE_OK;
}
#endif
