/* SPDX-License-Identifier: BSD-3-Clause */
#include "service_control.h"
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "service-fixture-ops.h"

static const char *scenario,*wire="AGCTL1 STOP\n";
static int mkdirs,sockets,unlinks,closes,accepted,clocks;
static bool endpoint,directory_exists;
static size_t read_at,written;
static char reply[65];
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"check:%d\n",__LINE__);return 1; } } while(0)
static bool is(const char *s) { return strcmp(scenario,s)==0; }
uid_t fake_uid(void) { return is("nonroot") ? 1 : 0; }
gid_t fake_gid(void) { return 0; }
int fake_lstat(const char *p,struct stat *s) {
    memset(s,0,sizeof(*s));s->st_uid=0;s->st_gid=0;s->st_nlink=1;s->st_dev=9;
    if(strstr(p,"inspector.sock")!=NULL) {
        if(!endpoint && !is("stale")) { errno=ENOENT;return -1; }
        s->st_mode=S_IFSOCK|0600;s->st_ino=(is("drift") && accepted) ? 56 : 55;return 0;
    }
    s->st_mode=S_IFDIR|0755;s->st_ino=7;
    if(strcmp(p,"/var")==0 && is("ancestor")) s->st_mode=S_IFLNK|0755;
    if(strcmp(p,"/var/run/aegvium")==0) {
        if(!directory_exists) { errno=ENOENT;return -1; }
        s->st_mode=S_IFDIR|0700;
    }
    return 0;
}
int fake_mkdir(const char *p,mode_t m) { (void)p;(void)m;mkdirs++;directory_exists=true;return 0; }
int fake_socket(int d,int t,int p) { (void)d;(void)t;(void)p;sockets++;return is("low-listener") || is("low-close") ? 0 : 40; }
int fake_bind(int f,const struct sockaddr *a,socklen_t n) { (void)f;(void)a;(void)n;endpoint=true;return 0; }
int fake_chmod(const char *p,mode_t m) { (void)p;(void)m;return 0; }
int fake_listen(int f,int n) { (void)f;(void)n;return 0; }
int fake_accept4(int f,struct sockaddr *a,socklen_t *n,int flags) {
    (void)f;(void)a;(void)n;(void)flags;
    if(accepted) { errno=EAGAIN;return -1; }
    accepted=1;return is("low-client") ? 1 : 41;
}
int fake_peer(int f,uid_t *u,gid_t *g) { (void)f;*u=is("peer") ? 1 : 0;*g=0;return 0; }
int fake_clock(clockid_t c,struct timespec *t) {
    (void)c;clocks++;t->tv_sec=(is("clock") && clocks>1) ? 99 : ((is("timeout") && clocks>1) ? 101 : 100);t->tv_nsec=0;return 0;
}
ssize_t fake_recv(int f,void *p,size_t n,int flags) {
    size_t left=strlen(wire)-read_at;
    (void)f;(void)flags;
    if(is("timeout")) { errno=EAGAIN;return -1; }
    if(is("fragment") && n>2) n=2;
    if(n>left) n=left;
    memcpy(p,wire+read_at,n);read_at+=n;return (ssize_t)n;
}
ssize_t fake_send(int f,const void *p,size_t n,int flags) {
    (void)f;(void)flags;
    if(is("fragment") && n>2) n=2;
    if(written+n>64) return -1;
    memcpy(reply+written,p,n);written+=n;return (ssize_t)n;
}
int fake_close(int f) { closes++;if((is("close") && f==41) || (is("low-close") && f==0)) return -1;return 0; }
int fake_unlink(const char *p) { (void)p;unlinks++;if(is("unlink")) return -1;endpoint=false;return 0; }
int main(int argc,char **argv) {
    bool stop=false;int i,rc=0;
    if(argc!=2) return 2;
    scenario=argv[1];
    CHECK(aeg_service_request((const unsigned char *)"AGCTL1 STOP\n",12,0,0)==2);
    CHECK(aeg_service_request((const unsigned char *)"AGCTL1 STOP\nX",13,0,0)==0);
    CHECK(aeg_service_request((const unsigned char *)"AGCTL1 STOP\n",12,0,1)==0);
    if(is("status")) wire="AGCTL1 STATUS\n";
    if(is("shared")) wire="AGCTL2 STOP 99900\n";
    if(is("future")) wire="AGCTL2 STOP 100001\n";
    if(is("epoch-zero")) wire="AGCTL2 STOP 0\n";
    if(is("epoch-max")) wire="AGCTL2 STOP 9223372036854771807\n";
    if(is("prefix")) wire="AGCTL1 STOP";
    if(is("trailing")) wire="AGCTL1 STOP\nX";
    if(is("oversize")) wire="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
    rc=aeg_service_prepare();
    if(is("ancestor") || is("nonroot")) { CHECK(rc!=0 && mkdirs==0 && sockets==0 && unlinks==0);puts("PASS");return 0; }
    if(is("stale")) { CHECK(rc!=0 && sockets==0 && unlinks==0);puts("PASS");return 0; }
    if(is("low-listener") || is("low-close")) { CHECK(rc!=0 && closes==1 && unlinks==0);CHECK(aeg_service_close()!=0 && closes==1);puts("PASS");return 0; }
    CHECK(rc==0 && sockets==1);
    for(i=0;i<40;i++) { rc=aeg_service_poll(AEG_SERVICE_OWNED,&stop);if(rc!=0) break; }
    if(is("close") || is("drift") || is("clock")) {
        int before=closes;
        CHECK(rc!=0 && aeg_service_close()!=0 && closes==before && unlinks==0);
    } else {
        if(is("shared")) CHECK(stop && written==0 && aeg_service_stop_origin()==99900);
        else if(is("future") || is("epoch-zero") || is("epoch-max")) CHECK(!stop && written==0);
        else if(is("status")) CHECK(!stop && strcmp(reply,"AGCTL1 inspector owned-running qualified=0\n")==0);
        else if(is("prefix") || is("trailing") || is("oversize") || is("peer") || is("timeout") || is("low-client")) CHECK(!stop && written==0);
        else CHECK(stop && strcmp(reply,"AGCTL1 inspector retiring qualified=0\n")==0);
        rc=aeg_service_close();
        if(is("unlink")) CHECK(rc!=0 && endpoint);
        else CHECK(rc==0 && unlinks==1 && !endpoint);
        CHECK(aeg_service_close()!=0); /* never repeat endpoint cleanup */
    }
    puts("PASS");return 0;
}
