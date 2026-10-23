/* SPDX-License-Identifier: BSD-3-Clause */
/* Fixed interception only. Separate trace preserves the prior independently
 * frozen checkpoint trace. Fake digest is NOT target SHA qualification. */
static unsigned char rec_disk[8192], rec_initial[8192];
static char rec_trace[96][16];
static int rec_calls, rec_hashes, rec_writes, rec_reads, rec_clean_start;
static int rec_offsets[4], rec_write_at[4], rec_close_count, rec_initial_active;
static bool rec_is(const char *name) {
    const char *p=mode;
    if(strncmp(p,"record-",7)!=0) return false;
    p+=7;
    if(strncmp(p,"clean-",6)==0) { if(!clean_active) return false;p+=6; }
    return strcmp(p,name)==0;
}
static int rec_note(const char *name) {
    int fail=0;
    if(rec_calls>=96) { bad++;return 1; }
    if(clean_active && rec_clean_start==0) rec_clean_start=rec_calls;
    (void)snprintf(rec_trace[rec_calls++],16,"%s",name);
    if(strncmp(mode,"record-admit-fail-",18)==0 && !clean_active) fail=atoi(mode+18);
    if(strncmp(mode,"record-clean-fail-",18)==0 && clean_active) fail=rec_clean_start+atoi(mode+18);
    return fail!=0 && rec_calls==fail;
}
static void rec_meta(struct stat *s) {
    memset(s,0,sizeof(*s));s->st_dev=1;s->st_ino=54;
    s->st_uid=0;s->st_gid=0;s->st_mode=S_IFREG|0600;s->st_nlink=1;s->st_size=8192;
    if(rec_is("uid")) s->st_uid=1;
    if(rec_is("gid")) s->st_gid=1;
    if(rec_is("type")) s->st_mode=S_IFLNK|0600;
    if(rec_is("mode")) s->st_mode|=0040;
    if(rec_is("links")) s->st_nlink=2;
    if(rec_is("size")) s->st_size++;
    if(rec_is("inode-drift") && rec_writes>0) s->st_ino++;
}
static ssize_t rec_read(void *out, size_t n, off_t off) {
    if(!lock_held || !owned[54] || off<0 || (size_t)off+n>8192 ||
        (n!=8192 && n!=4096) || (off!=0 && off!=4096)) bad++;
    rec_reads++;
    if(rec_note(n==8192 ? "read-all" : "readback")) return -1;
    if(rec_is("read-negative")) return -1;
    if(rec_is("read-short")) return (ssize_t)n-1;
    if(rec_is("read-over")) return (ssize_t)n+1;
    memcpy(out,rec_disk+(size_t)off,n);
    if(rec_is("readback") && n==4096) ((unsigned char *)out)[127]^=1;
    if(rec_is("bytes-drift") && clean_active) ((unsigned char *)out)[4095]^=1;
    return (ssize_t)n;
}
static ssize_t rec_write(const void *p, size_t n, off_t off) {
    if(!lock_held || !owned[54] || n!=4096 || (off!=0 && off!=4096) || rec_writes>=4) bad++;
    rec_offsets[rec_writes]=(int)off;rec_write_at[rec_writes]=calls;rec_writes++;
    if(rec_note(off==0 ? "write:0" : "write:4096")) return -1;
    if(rec_is("write-negative")) return -1;
    if(rec_is("write-short")) {memcpy(rec_disk+(size_t)off,p,2048);return 2048;}
    if(rec_is("write-over")) return 4097;
    memcpy(rec_disk+(size_t)off,p,n);
    if(rec_is("write-full-error")) return -1;
    return (ssize_t)n;
}
static void rec_decrement(unsigned char p[32]) {
    int i;
    for(i=31;i>=0;i--) {
        if(p[i]=='0') {p[i]='f';continue;}
        p[i]=p[i]=='a' ? '9' : (unsigned char)(p[i]-1);return;
    }
    bad++;
}
static void rec_segment(unsigned char *p, unsigned char state, unsigned count,
    unsigned sequence, const unsigned char last[32]) {
    unsigned char generation[32];int i;
    memset(p,0,4096);memcpy(p,"AEGSEC1\n",8);p[8]=state;p[9]=(unsigned char)count;
    memset(p+16,'0',32);p[47]=(unsigned char)('0'+sequence);memset(p+48,0xa5,32);
    memcpy(generation,last,32);
    for(i=0;i<(int)count/2;i++) rec_decrement(generation);
    memcpy(p+80,generation,32);memcpy(generation,last,32);
    for(i=(int)count-1;i>=0;i--) {
        unsigned char *r=p+128+(size_t)i*128;
        memcpy(r,"AEGREQ1\n",8);r[8]=i%2==0 ? 'U' : 'C';memcpy(r+16,generation,32);
        memset(r+48,0x31,32);memset(r+80,0x32,32);r[112]=1;
        if(i%2==0 && i>0) rec_decrement(generation);
    }
}
static void rec_initialize(const unsigned char current[32]) {
    unsigned char earlier[32];unsigned i;
    bool filled=strncmp(mode,"record-",7)==0;
    unsigned count=filled ? 28 : memcmp(current,"00000000000000000000000000000000",32)==0 ? 0 : 2;
    rec_segment(rec_disk,'A',count,filled ? 2 : 1,current);
    if(filled) {
        memcpy(earlier,current,32);for(i=0;i<14;i++) rec_decrement(earlier);
        rec_segment(rec_disk+4096,'S',30,1,earlier);
    }
    if(rec_is("first-rotate")) {memset(rec_disk+4096,0,4096);rec_disk[47]='1';}
    if(rec_is("magic")) rec_disk[0]^=1;
    if(rec_is("digest")) rec_disk[48]^=1;
    if(rec_is("reserved")) rec_disk[127]=1;
    if(rec_is("tail")) rec_disk[4095]=1;
    if(rec_is("odd")) rec_disk[9]=29;
    if(rec_is("full")) rec_disk[9]=30;
    if(rec_is("double-active")) rec_disk[4096+8]='A';
    if(rec_is("newer-sealed")) rec_disk[4096+47]='3';
    if(rec_is("stale")) rec_disk[128+27*128+47]='d';
    if(rec_is("pair-mismatch")) rec_disk[128+128+48]^=1;
    if(rec_is("bad-profile")) rec_disk[128+112]=2;
    if(rec_is("gap")) rec_disk[128+26*128+47]='c';
    if(rec_is("sequence-max")) {
        memset(rec_disk+16,'f',32);memset(rec_disk+4096+16,'f',32);rec_disk[4096+47]='e';
    }
    if(rec_is("swapped")) {
        unsigned char tmp[4096];memcpy(tmp,rec_disk,4096);
        memcpy(rec_disk,rec_disk+4096,4096);memcpy(rec_disk+4096,tmp,4096);
        rec_initial_active=1;
    }
    memcpy(rec_initial,rec_disk,sizeof(rec_disk));
}
static void rec_report(void) {
    int i;
    printf("{\"calls\":%d,\"hashes\":%d,\"writes\":%d,\"reads\":%d,\"closes\":%d,\"old_preserved\":%d,\"states\":[%u,%u],\"counts\":[%u,%u],\"offsets\":[",
        rec_calls,rec_hashes,rec_writes,rec_reads,rec_close_count,
        memcmp(rec_initial+(1-rec_initial_active)*4096,rec_disk+(1-rec_initial_active)*4096,4096)==0,
        (unsigned)rec_disk[8],(unsigned)rec_disk[4104],(unsigned)rec_disk[9],(unsigned)rec_disk[4105]);
    for(i=0;i<rec_writes;i++) printf("%s%d",i ? "," : "",rec_offsets[i]);
    printf("],\"at_checkpoint_calls\":[");
    for(i=0;i<rec_writes;i++) printf("%s%d",i ? "," : "",rec_write_at[i]);
    printf("],\"last_record\":\"");
    for(i=0;i<128;i++) printf("%02x",rec_disk[rec_initial_active*4096+128+(size_t)rec_initial[rec_initial_active*4096+9]*128+(size_t)i]);
    printf("\",\"trace\":[");
    for(i=0;i<rec_calls;i++) printf("%s\"%s\"",i ? "," : "",rec_trace[i]);
    printf("]}");
}
