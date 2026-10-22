/* SPDX-License-Identifier: BSD-3-Clause */
/* Compile the real fixed wrappers; every effect is intercepted by the header. */
#define main aeg_previous_native_fixture_main
#include "inspector-native-harness.c"
#undef main
#include "launch_storage.h"
static const char golden_C0[]="4145474f574e310a430000000000000030303030303030303030303030303030303030303030303030303030303030304cd860d8c625934cf230cae2ae976a244a656c163e4e18a3354d08d8233fec98000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
static const char golden_U1[]="4145474f574e310a55000000000000003030303030303030303030303030303030303030303030303030303030303031a93801f9a665510e0ca24b6ba66c79c618252890d9722850002fe1ef4eef86bb000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
static const char golden_Cfe[]="4145474f574e310a430000000000000066666666666666666666666666666666666666666666666666666666666666654dc9b55bc4774721f97520d8033b1ec9af159a3c072b0d86fe4400b04e051616000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
static const char golden_Uff[]="4145474f574e310a55000000000000006666666666666666666666666666666666666666666666666666666666666666105c28a634df45fa0e2bf6d9b38cef5b64d493da5aaf9c504538199c18b47492000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
static const char golden_Cff[]="4145474f574e310a43000000000000006666666666666666666666666666666666666666666666666666666666666666db5addb79a2238b49451c0bd5c225bb042177d8a51211ba148059c5c3454cb71000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
static unsigned char disk[128], intent_data[33];
static int writes, state_reads, hash_calls, reentrant_rc=-1;
static bool lock_held;
static void decode(const char *s,unsigned char *out) {
    unsigned i,v;
    for(i=0;i<128;i++) { if(sscanf(s+2*i,"%2x",&v)!=1) { bad++;return; } out[i]=(unsigned char)v; }
}
static bool is(const char *s) { return strcmp(mode,s)==0; }
static int storage_mark(int fd) { mark(fd);return fd; }
int aeg_storage_test_open(const char *path,int flags,...) {
    if(strcmp(path,"/dev/null")==0) return aeg_test_open(path,flags);
    if(strcmp(path,"/")!=0 || flags!=(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)) bad++;
    if(note("root",0,0,0)) return -1;
    if(is("reentrant")) reentrant_rc=aeg_update_exclusion_prepare();
    if(is("root-invalid")) return -2;
    return storage_mark(40);
}
int aeg_storage_test_openat(int fd,const char *path,int flags,...) {
    int result=-1;const char *label="invalid";
    if(fd<40 || fd>43 || !owned[fd]) bad++;
    if(strcmp(path,"var")==0 && fd==40) { result=41;label="var"; }
    if(strcmp(path,"db")==0 && fd==41) { result=42;label="db"; }
    if(strcmp(path,"aegvium")==0 && fd==42) { result=43;label="aegvium"; }
    if(result>=0) {
        if(flags!=(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)) bad++;
    } else if(strcmp(path,"launch.state")==0 && fd==43) {
        result=44;label="state";if(flags!=(O_RDWR|O_NOFOLLOW|O_CLOEXEC)) bad++;
    } else if(strcmp(path,"launch.intent")==0 && fd==43) {
        result=45;label="intent";if(flags!=(O_RDONLY|O_NOFOLLOW|O_CLOEXEC)) bad++;
    } else bad++;
    if(note(label,fd,0,1)) return -1;
    if((is("dir-alias") && result==41) || (is("state-alias") && result==44)) return fd;
    if(is("intent-alias") && result==45) return 44;
    return storage_mark(result);
}
static void meta(int fd,struct stat *s) {
    memset(s,0,sizeof(*s));s->st_dev=1;s->st_ino=(ino_t)fd;s->st_uid=0;s->st_gid=0;
    s->st_nlink=1;s->st_mode=(fd<=43 ? S_IFDIR|0755 : S_IFREG|0600);
    s->st_size=fd==44 ? 128 : 33;
    if(fd==40 && is("root-uid")) s->st_uid=1;
    if(fd==41 && is("dir-uid")) s->st_uid=1;
    if(fd==41 && is("dir-write")) s->st_mode|=0020;
    if(fd==41 && is("dir-type")) s->st_mode=S_IFREG|0755;
    if(fd==44 || fd==45) {
        const char *prefix=fd==44 ? "state-" : "intent-";char label[32];
        (void)snprintf(label,sizeof(label),"%suid",prefix);if(is(label)) s->st_uid=1;
        (void)snprintf(label,sizeof(label),"%sgid",prefix);if(is(label)) s->st_gid=1;
        (void)snprintf(label,sizeof(label),"%stype",prefix);if(is(label)) s->st_mode=S_IFLNK|0600;
        (void)snprintf(label,sizeof(label),"%smode",prefix);if(is(label)) s->st_mode|=04000;
        (void)snprintf(label,sizeof(label),"%slink",prefix);if(is(label)) s->st_nlink=2;
        (void)snprintf(label,sizeof(label),"%ssize",prefix);if(is(label)) s->st_size--;
    }
    if(fd==44 && writes && is("post-inode")) s->st_ino++;
}
int aeg_storage_test_fstat(int fd,struct stat *s) {
    if(fd<40) return aeg_test_fstat(fd,s);
    if(fd>45 || !owned[fd] || s==NULL) bad++;
    if(note("stat",fd,0,1)) return -1;
    meta(fd,s);return 0;
}
int aeg_storage_test_fstatat(int dir,const char *name,struct stat *s,int flags) {
    int fd=strcmp(name,"launch.state")==0 ? 44 : 45;
    if(dir!=43 || !owned[dir] || !owned[fd] || flags!=AT_SYMLINK_NOFOLLOW ||
        (fd==45 && strcmp(name,"launch.intent")!=0)) bad++;
    if(note(fd==44 ? "path-state" : "path-intent",dir,0,1)) return -1;
    meta(fd,s);
    if(fd==44 && is("path-dev")) s->st_dev++;
    if(fd==44 && is("path-inode")) s->st_ino++;
    if(fd==44 && is("path-mode")) s->st_mode|=0040;
    if(fd==45 && is("intent-dev")) s->st_dev++;
    return 0;
}
int aeg_storage_test_close(int fd) {
    if(fd<40) return aeg_test_close(fd);
    return aeg_test_close(fd); /* Same ledger, at-most-once, error may consume. */
}
int aeg_storage_test_flock(int fd,int op) {
    if(fd!=44 || !owned[fd] || op!=(LOCK_EX|LOCK_NB)) bad++;
    if(note("lock",fd,0,1)) return -1;
    lock_held=true;return 0;
}
ssize_t aeg_storage_test_pread(int fd,void *out,size_t n,off_t off) {
    if(!lock_held || off!=0 || (fd!=44 && fd!=45) || !owned[fd] ||
        n!=(fd==44 ? 128U : 33U)) bad++;
    if(note("read",fd,(int)n,2)) return -1;
    if(fd==44) {
        state_reads++;
        if(is("read-1")) return -1;
        if(is("read0")) return 0;
        if(is("read127")) return 127;
        if(is("read129")) return 129;
        memcpy(out,disk,n);
        if(is("readback") && state_reads==2) ((unsigned char *)out)[0]^=1;
    } else {
        memcpy(out,intent_data,n);
        if(is("intent-short")) return 32;
    }
    return (ssize_t)n;
}
ssize_t aeg_storage_test_pwrite(int fd,const void *p,size_t n,off_t off) {
    if(fd!=44 || !owned[fd] || !lock_held || owned[45] || off!=0 || n!=128) bad++;
    writes++;
    if(note("write",fd,0,1)) return -1;
    if(is("write-1")) return -1;
    if(is("write0")) return 0;
    if(is("write127")) { memcpy(disk,p,127);return 127; }
    if(is("write129")) return 129;
    memcpy(disk,p,128);
    if(is("write-full-error")) return -1;
    return 128;
}
int aeg_storage_test_fsync(int fd) {
    if(fd!=44 || !lock_held || writes!=1) bad++;
    return note("sync",fd,0,1) ? -1 : 0;
}
int aeg_storage_test_clock(int id,struct timespec *t) {
    if(id!=CLOCK_MONOTONIC || !t || owned[43] || writes!=1 || state_reads!=2) bad++;
    if(note("clock",0,0,0)) return -1;
    t->tv_sec=1;t->tv_nsec=2000000;
    if(is("clock-negative")) t->tv_sec=-1;
    if(is("clock-nsec")) t->tv_nsec=1000000000L;
    if(is("controller-late")) (void)aeg_owner_prepare("ffffffffffffffffffffffffffffffff",32,0);
    return 0;
}
void aeg_storage_test_sha_init(SHA2_CTX *ctx) {
    (void)note("sha-init",0,0,0);memset(ctx,0,sizeof(*ctx));
}
void aeg_storage_test_sha_update(SHA2_CTX *ctx,const unsigned char *p,size_t n) {
    (void)note("sha-update",(int)n,0,1);
    if(!p || n!=48 || ctx->updates>=2 || ctx->len+n>96) { bad++;return; }
    memcpy(ctx->input+ctx->len,p,n);ctx->len+=n;ctx->updates++;
}
void aeg_storage_test_sha_final(unsigned char *out,SHA2_CTX *ctx) {
    const char *const gold[]={golden_C0,golden_U1,golden_Cfe,golden_Uff,golden_Cff};
    unsigned char b[128];size_t i;
    (void)note("sha-final",0,0,0);hash_calls++;
    if(ctx->len!=96 || ctx->updates!=2) bad++;
    memset(out,0,32);
    for(i=0;i<5;i++) {
        decode(gold[i],b);
        if(memcmp(b,ctx->input,48)==0 && memcmp(b+80,ctx->input+48,48)==0) {
            memcpy(out,b+48,32);break;
        }
    }
    if(i==5) bad++; /* Detect wrong wrapper input, never an oracle Boolean. */
    if(is("hash-mismatch") && hash_calls==1) out[0]^=1;
}
int main(int argc,char **argv) {
    int rc,again1,again2,before;unsigned i;
    struct aeg_storage_view v;struct aeg_owner_view o;struct aeg_native_view native;
    if(argc!=2) return 2;
    mode=argv[1];if(strncmp(mode,"fail-",5)==0) fail_at=atoi(mode+5);
    decode(is("edge") ? golden_Cfe : is("nowrap") ? golden_Cff :
        (is("unclean") || is("update-unclean")) ? golden_U1 : golden_C0,disk);
    memcpy(intent_data,is("edge") ? "ffffffffffffffffffffffffffffffff" : "00000000000000000000000000000001",32);
    intent_data[32]='\n';
    if(is("magic")) disk[0]^=1;
    if(is("state-tag")) disk[8]='X';
    if(is("reserved")) disk[9]=1;
    if(is("uppercase")) disk[16]='A';
    if(is("suffix")) disk[127]=1;
    if(is("digest")) disk[48]^=1;
    if(is("unclean-zero")) disk[8]='U';
    if(is("intent-mismatch")) intent_data[31]='2';
    if(is("intent-upper")) intent_data[0]='A';
    if(is("intent-lf")) intent_data[32]=0;
    if(is("owner-prestate")) (void)aeg_owner_prepare("00000000000000000000000000000001",32,0);
    if(is("native-prestate")) (void)aeg_native_parent_prepare();
    rc=strncmp(mode,"update",6)==0 ? aeg_update_exclusion_prepare() : aeg_launch_storage_prepare();
    before=calls;again1=aeg_launch_storage_prepare();again2=aeg_update_exclusion_prepare();
    v=aeg_storage_get_view();o=aeg_owner_get_view();native=aeg_native_get_view();
    (void)printf("{\"rc\":%d,\"bad\":%d,\"phase\":%d,\"attempted\":%d,\"committed\":%d,\"uncertain\":%d,\"known\":%u,\"writes\":%d,\"reads\":%d,\"lock\":%d,\"owner\":%d,\"held\":%d,\"native\":%d,\"duplicates\":[%d,%d],\"duplicate_calls\":%d,\"reentrant\":%d,\"disk\":\"",
        rc,bad,v.phase,v.attempted,v.committed,v.uncertain,v.known_descriptors,writes,state_reads,lock_held,o.phase,o.held,native.phase,again1,again2,calls-before,reentrant_rc);
    for(i=0;i<128;i++) (void)printf("%02x",disk[i]);
    (void)printf("\",\"trace\":[");
    for(i=0;i<(unsigned)calls;i++) (void)printf("%s\"%s\"",i ? "," : "",trace[i]);
    (void)puts("]}");return 0;
}
