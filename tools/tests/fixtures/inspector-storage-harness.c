/* SPDX-License-Identifier: BSD-3-Clause */
/* Compile the real fixed wrappers; every effect is intercepted by the header. */
#define AEG_STORAGE_FIXTURE 1
#define main aeg_previous_native_fixture_main
#include "inspector-native-harness.c"
#undef main
#include "launch_storage.h"
static const char golden_C0[]="4145474f574e310a430000000000000030303030303030303030303030303030303030303030303030303030303030304cd860d8c625934cf230cae2ae976a244a656c163e4e18a3354d08d8233fec98000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
static const char golden_U1[]="4145474f574e310a55000000000000003030303030303030303030303030303030303030303030303030303030303031a93801f9a665510e0ca24b6ba66c79c618252890d9722850002fe1ef4eef86bb000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
static const char golden_Cfe[]="4145474f574e310a430000000000000066666666666666666666666666666666666666666666666666666666666666654dc9b55bc4774721f97520d8033b1ec9af159a3c072b0d86fe4400b04e051616000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
static const char golden_Uff[]="4145474f574e310a55000000000000006666666666666666666666666666666666666666666666666666666666666666105c28a634df45fa0e2bf6d9b38cef5b64d493da5aaf9c504538199c18b47492000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
static const char golden_Cff[]="4145474f574e310a43000000000000006666666666666666666666666666666666666666666666666666666666666666db5addb79a2238b49451c0bd5c225bb042177d8a51211ba148059c5c3454cb71000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
static const char golden_pair[]="414750414952310a30313233343536373839616263646566303132333435363738396162636465664d322d48312f31010b6170705f7072696d61727900106170702e6578616d706c652e7465737401bb3031303130313031303130313031303130313031303130313031303130313031303130313031303130313031303130313031303130313031303130313031303102001566726f6e742d612e696e7465726e616c2e74657374001566726f6e742d622e696e7465726e616c2e746573740a3139322e302e322e313020fb0015696e73706563742e696e7465726e616c2e74657374000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1ffffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e000001000000014000000080000001000000010000408";
static const char golden_bootstrap[]="4147434845434b3130313233343536373839616263646566303132333435363738396162636465665ec0935b94a4a4541abaa76768731aaccbc772a02e0dd926b36dde2660ef6e9d1d987134086420d48b300a4cfda016ffc550a0bda6a6f20c58282db1b7d42dca";
static const char golden_Cg[]="4145474f574e310a4300000000000000303132333435363738396162636465663031323334353637383961626364656582ded7d17c782ff3d8c75f8999bc0fa908f54ab3725b859921937ddb35efb956000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
static const char golden_Ug[]="4145474f574e310a550000000000000030313233343536373839616263646566303132333435363738396162636465664ccb134f46c1e316980f39725b921be937f230c86e18e61c43abc3105e3d14d9000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
static const char snapshot_default[]="2999ef5f7af41c6a2610f4ce5053b2b415ae291060bb0c60cde02a2b3cb035c0";
static const char snapshot_edge[]="ff8d673e62bc6b956ad76b818bd785e2b3b6e9e80ae81582c55059f5a8671a71";
static const char snapshot_golden[]="5ec0935b94a4a4541abaa76768731aaccbc772a02e0dd926b36dde2660ef6e9d";
static const char snapshot_minimum[]="b5ee46bc34100d717a0af3e666d2b2abead2a0ed5f2501f748fc08e6fceadc91";
static const char snapshot_maximum[]="476718db002b7c77e19157ed2a8039636f32263816599e469e967f5081d52d88";
static const char snapshot_badgrammar[]="b679e1321d62ee0d605102034316fa42b935e86a3723ed1d9d2195c692ec853a";
static unsigned char disk[128], intent_data[33], snapshot_data[8192], bootstrap_wanted[8306];
static size_t snapshot_length=313;
static const char *snapshot_digest;
static int snapshot_reads;

static const char image_pin[]="d855ba636ffdfea364522538421fa585c1927fe5ef4d8065b89549c6bf744213";
static unsigned char pin_data[65];
static int root_calls, pin_reads, image_reads;
static int writes, state_reads, hash_calls, reentrant_rc=-1;
static bool lock_held;
static void decode(const char *s,unsigned char *out) {
    unsigned i,v;
    for(i=0;i<128;i++) { if(sscanf(s+2*i,"%2x",&v)!=1) { bad++;return; } out[i]=(unsigned char)v; }
}
static void decode_n(const char *s,unsigned char *out,size_t n) {
    size_t i;unsigned v;
    for(i=0;i<n;i++) { if(sscanf(s+2*i,"%2x",&v)!=1) { bad++;return; } out[i]=(unsigned char)v; }
}
static bool is(const char *s) { return strcmp(mode,s)==0; }
static int storage_mark(int fd) { mark(fd);return fd; }
int aeg_storage_test_open(const char *path,int flags,...) {
    if(strcmp(path,"/dev/null")==0) return aeg_test_open(path,flags);
    if(strcmp(path,"/")!=0 || flags!=(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)) bad++;
    root_calls++;
    if(note(root_calls==1 ? "root" : "image-root",0,0,0)) return -1;
    if(root_calls>1) return storage_mark(47);
    if(is("reentrant")) reentrant_rc=aeg_update_exclusion_prepare();
    if(is("root-invalid")) return -2;
    return storage_mark(40);
}
int aeg_storage_test_openat(int fd,const char *path,int flags,...) {
    int result=-1;const char *label="invalid";
    if(fd<40 || fd>53 || !owned[fd]) bad++;
    if(strcmp(path,"var")==0 && fd==40) { result=41;label="var"; }
    if(strcmp(path,"db")==0 && fd==41) { result=42;label="db"; }
    if(strcmp(path,"aegvium")==0 && fd==42) { result=43;label="aegvium"; }
    if(strcmp(path,"usr")==0 && fd==47) { result=48;label="usr"; }
    if(strcmp(path,"local")==0 && fd==48) { result=49;label="local"; }
    if(strcmp(path,"libexec")==0 && fd==49) { result=50;label="libexec"; }
    if(strcmp(path,"aegvium")==0 && fd==50) { result=51;label="image-dir"; }
    if(result>=0) {
        if(flags!=(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)) bad++;
    } else if(strcmp(path,"launch.state")==0 && fd==43) {
        result=44;label="state";if(flags!=(O_RDWR|O_NOFOLLOW|O_CLOEXEC)) bad++;
    } else if(strcmp(path,"launch.intent")==0 && fd==43) {
        result=45;label="intent";if(flags!=(O_RDONLY|O_NOFOLLOW|O_CLOEXEC)) bad++;
    } else if(strcmp(path,"pair.snapshot")==0 && fd==43) {
        result=53;label="snapshot";if(flags!=(O_RDONLY|O_NOFOLLOW|O_CLOEXEC)) bad++;
    } else if(strcmp(path,"inspector.pin")==0 && fd==43) {
        result=46;label="pin";if(flags!=(O_RDONLY|O_NOFOLLOW|O_CLOEXEC)) bad++;
    } else if(strcmp(path,"inspector")==0 && fd==51) {
        result=52;label="image";if(flags!=(O_RDONLY|O_NOFOLLOW|O_CLOEXEC)) bad++;
    } else bad++;
    if(note(label,fd,0,1)) return -1;
    if((is("dir-alias") && result==41) || (is("state-alias") && result==44)) return fd;
    if(is("intent-alias") && result==45) return 44;
    if(is("pin-alias") && result==46) return 44;
    if(is("image-dir-alias") && result==48) return fd;
    if(is("image-alias") && result==52) return 44;
    if(is("snapshot-alias") && result==53) return 44;
    if(is("snapshot-invalid") && result==53) return -2;
    return storage_mark(result);
}
static void meta(int fd,struct stat *s) {
    memset(s,0,sizeof(*s));s->st_dev=1;s->st_ino=(ino_t)fd;s->st_uid=0;s->st_gid=0;
    s->st_nlink=1;s->st_mode=(fd<=43 || (fd>=47 && fd<=51) ? S_IFDIR|0755 : S_IFREG|0600);
    s->st_size=fd==44 ? 128 : fd==46 ? 65 : fd==52 ? 4113 : 33;
    if(fd==52) s->st_mode=S_IFREG|0555;
    if(fd==53) {
        s->st_size=(off_t)snapshot_length;
        if(is("snapshot-uid")) s->st_uid=1;
        if(is("snapshot-gid")) s->st_gid=1;
        if(is("snapshot-type")) s->st_mode=S_IFLNK|0600;
        if(is("snapshot-mode")) s->st_mode|=0040;
        if(is("snapshot-link")) s->st_nlink=2;
        if(is("snapshot-small")) s->st_size=46;
        if(is("snapshot-large")) s->st_size=8193;
        if(snapshot_reads && is("snapshot-post-inode")) s->st_ino++;
        if(snapshot_reads && is("snapshot-post-size")) s->st_size++;
    }
    if(fd==48 && is("image-dir-uid")) s->st_uid=1;
    if(fd==48 && is("image-dir-write")) s->st_mode|=0002;
    if(fd==48 && is("image-dir-search")) s->st_mode&=~0001;
    if(fd==48 && is("image-dir-type")) s->st_mode=S_IFREG|0755;
    if(fd==46 || fd==52) {
        const char *prefix=fd==46 ? "pin-" : "image-";char label[32];
        (void)snprintf(label,sizeof(label),"%suid",prefix);if(is(label)) s->st_uid=1;
        (void)snprintf(label,sizeof(label),"%sgid",prefix);if(is(label)) s->st_gid=1;
        (void)snprintf(label,sizeof(label),"%stype",prefix);if(is(label)) s->st_mode=S_IFLNK|0600;
        (void)snprintf(label,sizeof(label),"%smode",prefix);if(is(label)) s->st_mode|=04000;
        (void)snprintf(label,sizeof(label),"%slink",prefix);if(is(label)) s->st_nlink=2;
        (void)snprintf(label,sizeof(label),"%ssize",prefix);if(is(label)) s->st_size=0;
    }
    if(fd==52 && is("image-cap")) s->st_size=67108865;
    if(fd==46 && pin_reads && is("pin-post-inode")) s->st_ino++;
    if(fd==52 && image_reads && is("image-post-inode")) s->st_ino++;
    if(fd==52 && image_reads && is("image-post-size")) s->st_size++;
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
    if(fd>53 || !owned[fd] || s==NULL) bad++;
    if(note("stat",fd,0,1)) return -1;
    meta(fd,s);return 0;
}
int aeg_storage_test_fstatat(int dir,const char *name,struct stat *s,int flags) {
    int fd=strcmp(name,"launch.state")==0 ? 44 : strcmp(name,"launch.intent")==0 ? 45 : strcmp(name,"inspector.pin")==0 ? 46 : strcmp(name,"pair.snapshot")==0 ? 53 : 52;
    int expected_dir=fd==52 ? 51 : 43;
    const char *label=fd==44 ? "path-state" : fd==45 ? "path-intent" : fd==46 ? "path-pin" : fd==53 ? "path-snapshot" : "path-image";
    if(dir!=expected_dir || !owned[dir] || !owned[fd] || flags!=AT_SYMLINK_NOFOLLOW ||
        (fd==52 && strcmp(name,"inspector")!=0)) bad++;
    if(note(label,dir,0,1)) return -1;
    meta(fd,s);
    if(fd==44 && is("path-dev")) s->st_dev++;
    if(fd==44 && is("path-inode")) s->st_ino++;
    if(fd==44 && is("path-mode")) s->st_mode|=0040;
    if(fd==45 && is("intent-dev")) s->st_dev++;
    if(fd==46 && is("pin-path")) s->st_dev++;
    if(fd==52 && is("image-path")) s->st_ino++;
    if(fd==52 && is("image-path-link")) s->st_nlink=2;
    if(fd==53) {
        if(is("snapshot-path-dev")) s->st_dev++;
        if(is("snapshot-path-inode") || (snapshot_reads && is("snapshot-post-path"))) s->st_ino++;
        if(is("snapshot-path-link")) s->st_nlink=2;
        if(is("snapshot-path-size")) s->st_size++;
        if(is("snapshot-path-mode")) s->st_mode|=0040;
    }
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
    if(!lock_held || fd<44 || fd>53 || !owned[fd]) bad++;
    if(fd==53) {
        if(n!=snapshot_length+1 || off!=0) bad++;
        snapshot_reads++;
        if(note("read",fd,(int)n,2)) return -1;
        if(is("snapshot-read-negative")) return -2;
        if(is("snapshot-read-zero")) return 0;
        if(is("snapshot-read-short")) return (ssize_t)snapshot_length-1;
        if(is("snapshot-read-growth")) return (ssize_t)snapshot_length+1;
        if(is("snapshot-read-over")) return (ssize_t)snapshot_length+2;
        memcpy(out,snapshot_data,snapshot_length);
        return (ssize_t)snapshot_length;
    }
    if(fd==52) {
        size_t i;ssize_t requested;
        image_reads++;
        requested=image_reads==1 ? 4096 : image_reads==2 ? 17 : 1;
        if(n!=(size_t)requested || off!=(image_reads==1 ? 0 : image_reads==2 ? 4096 : 4113)) bad++;
        if(note("image-read",(int)off,(int)n,2)) return -1;
        if(image_reads<=2) {
            if((is("image-first-negative") && image_reads==1) || (is("image-tail-negative") && image_reads==2)) return -1;
            if((is("image-first-zero") && image_reads==1) || (is("image-tail-zero") && image_reads==2)) return 0;
            if((is("image-first-short") && image_reads==1) || (is("image-tail-short") && image_reads==2)) return requested-1;
            if((is("image-first-over") && image_reads==1) || (is("image-tail-over") && image_reads==2)) return requested+1;
            for(i=0;i<n;i++) ((unsigned char *)out)[i]=(unsigned char)(((size_t)off+i)%251);
            if(is("image-data") && image_reads==1) ((unsigned char *)out)[0]^=1;
            return requested;
        }
        if(is("image-eof-negative")) return -1;
        return is("image-eof-data") ? 1 : 0;
    }
    if(off!=0 || n!=(fd==44 ? 128U : fd==45 ? 33U : 65U) || (fd!=44 && fd!=45 && fd!=46)) bad++;
    if(note("read",fd,(int)n,2)) return -1;
    if(fd==44) {
        state_reads++;
        if(is("read-1")) return -1;
        if(is("read0")) return 0;
        if(is("read127")) return 127;
        if(is("read129")) return 129;
        memcpy(out,disk,n);
        if(is("readback") && state_reads==2) ((unsigned char *)out)[0]^=1;
    } else if(fd==45) {
        memcpy(out,intent_data,n);
        if(is("intent-short")) return 32;
    } else {
        pin_reads++;
        if(is("pin-zero")) return 0;
        if(is("pin-short")) return 64;
        if(is("pin-over")) return 66;
        memcpy(out,pin_data,n);
    }
    return (ssize_t)n;
}
ssize_t aeg_storage_test_pwrite(int fd,const void *p,size_t n,off_t off) {
    if(fd!=44 || !owned[fd] || !lock_held || owned[45] || owned[46] || owned[51] || owned[52] || owned[53] || off!=0 || n!=128) bad++;
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
    if(ctx->updates==0 && n==4096) ctx->image=true;
    if(ctx->updates==0 && n==snapshot_length) ctx->snapshot=true;
    if(ctx->snapshot) {
        if(!p || ctx->updates!=0 || n!=snapshot_length || n>8192 || memcmp(p,snapshot_data,n)!=0) { bad++;return; }
        memcpy(ctx->input,p,n);ctx->len=n;ctx->updates=1;return;
    }
    if(ctx->image) {
        size_t i;
        if(!p || n!=(ctx->updates==0 ? 4096U : 17U) || ctx->updates>=2) { bad++;return; }
        for(i=0;i<n;i++) if(p[i]!=(unsigned char)((ctx->len+i)%251)) {
            if(is("image-data") && ctx->len+i==0) ctx->bad_data=true;else bad++;
        }
        ctx->len+=n;ctx->updates++;return;
    }
    if(!p || n!=48 || ctx->updates>=2 || ctx->len+n>96) { bad++;return; }
    memcpy(ctx->input+ctx->len,p,n);ctx->len+=n;ctx->updates++;
}
void aeg_storage_test_sha_final(unsigned char *out,SHA2_CTX *ctx) {
    const char *const gold[]={golden_C0,golden_U1,golden_Cfe,golden_Uff,golden_Cff,golden_Cg,golden_Ug};
    unsigned char b[128];size_t i;
    (void)note("sha-final",0,0,0);
    if(ctx->snapshot) {
        if(ctx->len!=snapshot_length || ctx->updates!=1 || owned[53]) bad++;
        decode_n(snapshot_digest,out,32);return;
    }
    if(ctx->image) {
        if(ctx->len!=4113 || ctx->updates!=2 || image_reads!=3) bad++;
        for(i=0;i<32;i++) { unsigned v; if(sscanf(image_pin+2*i,"%2x",&v)!=1) { bad++;return; } out[i]=(unsigned char)v; }
        if(ctx->bad_data || is("image-digest")) out[0]^=1;
        return;
    }
    hash_calls++;
    if(ctx->len!=96 || ctx->updates!=2) bad++;
    memset(out,0,32);
    for(i=0;i<7;i++) {
        decode(gold[i],b);
        if(memcmp(b,ctx->input,48)==0 && memcmp(b+80,ctx->input+48,48)==0) {
            memcpy(out,b+48,32);break;
        }
    }
    if(i==7) bad++; /* Detect wrong wrapper input, never an oracle Boolean. */
    if(is("hash-mismatch") && hash_calls==1) out[0]^=1;
}
int main(int argc,char **argv) {
    int rc,again1,again2,before,emit_again=-1,branch_after=-1;unsigned i;
    struct aeg_storage_view v;struct aeg_owner_view o;struct aeg_native_view native;
    if(argc!=2) return 2;
    mode=argv[1];if(strncmp(mode,"fail-",5)==0) fail_at=atoi(mode+5);
    decode(is("bootstrap-golden") ? golden_Cg : is("edge") ? golden_Cfe : is("nowrap") ? golden_Cff :
        (is("unclean") || is("update-unclean")) ? golden_U1 : golden_C0,disk);
    memcpy(intent_data,is("edge") ? "ffffffffffffffffffffffffffffffff" : "00000000000000000000000000000001",32);
    intent_data[32]='\n';
    if(is("bootstrap-golden")) memcpy(intent_data,"0123456789abcdef0123456789abcdef",32);
    decode_n(golden_pair,snapshot_data,313);memcpy(snapshot_data+8,intent_data,32);
    snapshot_digest=is("edge") ? snapshot_edge : is("bootstrap-golden") ? snapshot_golden : snapshot_default;
    if(is("snapshot-minimum")) { snapshot_length=47;snapshot_digest=snapshot_minimum; }
    if(is("snapshot-maximum")) { snapshot_length=8192;snapshot_digest=snapshot_maximum; }
    if(is("snapshot-badgrammar")) { snapshot_data[47]=0;snapshot_digest=snapshot_badgrammar; }
    memcpy(bootstrap_wanted,"AGBOOT1\n",8);
    bootstrap_wanted[8]=(unsigned char)(snapshot_length>>8);
    bootstrap_wanted[9]=(unsigned char)snapshot_length;
    decode_n(golden_bootstrap,bootstrap_wanted+10,104);
    memcpy(bootstrap_wanted+18,intent_data,32);decode_n(snapshot_digest,bootstrap_wanted+50,32);
    memcpy(bootstrap_wanted+114,snapshot_data,snapshot_length);
    expected_bootstrap_size=114+snapshot_length;
    expected_bootstrap=bootstrap_wanted;
    if(is("snapshot-magic")) snapshot_data[0]^=1;
    if(is("snapshot-generation")) snapshot_data[39]='2';
    if(is("snapshot-upper")) snapshot_data[8]='A';
    if(is("snapshot-version")) snapshot_data[40]^=1;
    { size_t n=1;if(is("producer-precommit") && (aeg_launch_bootstrap_take(&n)!=NULL || n!=0)) bad++; }
    if(is("emitter-precommit")) (void)aeg_native_bootstrap_emit();
    memcpy(pin_data,image_pin,64);pin_data[64]='\n';
    if(is("pin-upper")) pin_data[0]='D';
    if(is("pin-nonhex")) pin_data[0]='g';
    if(is("pin-lf")) pin_data[64]=0;
    if(is("pin-digest")) pin_data[0]='0';
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
    native=aeg_native_get_view();
    if(native.bootstrap_attempted) emit_again=aeg_native_bootstrap_emit();
    if(send_calls && !native.bootstrap_written) branch_after=aeg_native_parent_prepare();
    { size_t n=1;if(aeg_launch_bootstrap_take(&n)!=NULL || n!=0) bad++; }
    v=aeg_storage_get_view();o=aeg_owner_get_view();native=aeg_native_get_view();
    (void)printf("{\"rc\":%d,\"bad\":%d,\"phase\":%d,\"attempted\":%d,\"committed\":%d,\"uncertain\":%d,\"known\":%u,\"writes\":%d,\"reads\":%d,\"lock\":%d,\"owner\":%d,\"held\":%d,\"native\":%d,\"duplicates\":[%d,%d],\"duplicate_calls\":%d,\"reentrant\":%d,\"disk\":\"",
        rc,bad,v.phase,v.attempted,v.committed,v.uncertain,v.known_descriptors,writes,state_reads,lock_held,o.phase,o.held,native.phase,again1,again2,calls-before,reentrant_rc);
    for(i=0;i<128;i++) (void)printf("%02x",disk[i]);
    (void)printf("\",\"send_calls\":%d,\"emit_again\":%d,\"branch_after\":%d,\"bootstrap_written\":%d,\"trace\":[",send_calls,emit_again,branch_after,native.bootstrap_written);
    for(i=0;i<(unsigned)calls;i++) (void)printf("%s\"%s\"",i ? "," : "",trace[i]);
    (void)puts("]}");return 0;
}
