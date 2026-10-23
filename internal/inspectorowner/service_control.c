/* SPDX-License-Identifier: BSD-3-Clause */
#include "service_control.h"
#include <string.h>

int aeg_service_request(const unsigned char *p,size_t n,uint32_t uid,uint32_t gid) {
    if(p==NULL || uid!=0 || gid!=0) return 0;
    if(n==14 && memcmp(p,"AGCTL1 STATUS\n",14)==0) return 1;
    if(n==12 && memcmp(p,"AGCTL1 STOP\n",12)==0) return 2;
    return 0;
}
const char *aeg_service_reply(enum aeg_service_phase phase,bool stopping) {
    if(stopping) phase=AEG_SERVICE_RETIRING;
    switch(phase) {
    case AEG_SERVICE_STARTING:return "AGCTL1 inspector starting qualified=0\n";
    case AEG_SERVICE_OWNED:return "AGCTL1 inspector owned-running qualified=0\n";
    case AEG_SERVICE_RETIRING:return "AGCTL1 inspector retiring qualified=0\n";
    case AEG_SERVICE_TERMINAL:return "AGCTL1 inspector terminal qualified=0\n";
    case AEG_SERVICE_UNCERTAIN:return "AGCTL1 inspector uncertain qualified=0\n";
    }
    return NULL;
}

#if defined(__OpenBSD__) || defined(AEG_SERVICE_FIXTURE)
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#ifdef AEG_SERVICE_FIXTURE
#include "service-fixture-ops.h"
#endif

static struct {
    int listener,client;
    bool attempted,stopping,uncertain,closed;
    unsigned char request[33];
    size_t used,sent;
    const char *reply;
    struct timespec since,until;
    struct stat endpoint;
} service={.listener=-1,.client=-1};
_Static_assert(sizeof(service)<512,"bounded local service state");
static const char path[]="/var/run/aegvium/inspector.sock";
static bool ancestors(void) {
    const char *names[]={"/","/var","/var/run"};
    unsigned i;struct stat s;
    for(i=0;i<3;i++) if(lstat(names[i],&s)!=0 || !S_ISDIR(s.st_mode) ||
        s.st_uid!=0 || s.st_gid!=0 || (s.st_mode&0022)!=0) return false;
    return true;
}
static bool namespace(void) {
    struct stat s;
    return ancestors() && lstat("/var/run/aegvium",&s)==0 && S_ISDIR(s.st_mode) &&
        s.st_uid==0 && s.st_gid==0 && (s.st_mode&07777)==0700;
}
static bool socket_kind(const struct stat *s) {
    return S_ISSOCK(s->st_mode) && (s->st_mode&07777)==0600 &&
        s->st_uid==0 && s->st_gid==0 && s->st_nlink==1;
}
static bool current(void) {
    struct stat s;
    return namespace() && lstat(path,&s)==0 && socket_kind(&s) &&
        s.st_dev==service.endpoint.st_dev && s.st_ino==service.endpoint.st_ino;
}
static int fault(void) { service.uncertain=true;return -1; }
static int drop(void) {
    if(service.client<0) return 0;
    if(close(service.client)!=0) return fault(); /* sticky; never retry */
    service.client=-1;service.used=service.sent=0;service.reply=NULL;
    return 0;
}
int aeg_service_prepare(void) {
    struct sockaddr_un address={0};struct stat s;
    if(service.attempted) return -1;
    service.attempted=true;
    if(getuid()!=0 || geteuid()!=0 || getgid()!=0 || getegid()!=0) return fault();
    if(!ancestors()) return fault();
    if(mkdir("/var/run/aegvium",0700)!=0 && errno!=EEXIST) return fault();
    if(!namespace() || lstat(path,&s)==0 || errno!=ENOENT) return fault();
    service.listener=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
    if(service.listener<0) return fault();
    if(service.listener<3) {
        service.closed=true;
        if(close(service.listener)==0) service.listener=-1;
        return fault();
    }
    address.sun_family=AF_UNIX;address.sun_len=sizeof(address);
    memcpy(address.sun_path,path,sizeof(path));
    if(bind(service.listener,(const struct sockaddr *)&address,sizeof(address))!=0 ||
        chmod(path,0600)!=0 || lstat(path,&service.endpoint)!=0 ||
        !socket_kind(&service.endpoint) || !namespace() || listen(service.listener,1)!=0) return fault();
    return 0;
}
int aeg_service_poll(enum aeg_service_phase phase,bool *stop) {
    struct timespec now;uid_t uid;gid_t gid;ssize_t n;int request;
    if(stop==NULL || service.closed || service.uncertain || service.listener<0 || !current()) return fault();
    *stop=service.stopping;
    if(service.client<0) {
        service.client=accept4(service.listener,NULL,NULL,SOCK_CLOEXEC|SOCK_NONBLOCK);
        if(service.client<0) {
            if(errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR) return 0;
            return fault();
        }
        if(service.client<3) return drop();
        if(clock_gettime(CLOCK_MONOTONIC,&service.until)!=0 || service.until.tv_sec<0 ||
            service.until.tv_sec>=INT64_MAX-1 || service.until.tv_nsec<0 || service.until.tv_nsec>=1000000000) return fault();
        service.since=service.until;service.until.tv_sec++;
        if(getpeereid(service.client,&uid,&gid)!=0 || uid!=0 || gid!=0) return drop();
    }
    if(clock_gettime(CLOCK_MONOTONIC,&now)!=0 || now.tv_sec<service.since.tv_sec ||
        (now.tv_sec==service.since.tv_sec && now.tv_nsec<service.since.tv_nsec) ||
        now.tv_nsec<0 || now.tv_nsec>=1000000000) return fault();
    if(now.tv_sec>service.until.tv_sec || (now.tv_sec==service.until.tv_sec && now.tv_nsec>=service.until.tv_nsec)) return drop();
    if(service.reply==NULL) {
        n=recv(service.client,service.request+service.used,sizeof(service.request)-service.used,MSG_DONTWAIT);
        if(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)) return 0;
        if(n<0) return drop();
        service.used+=(size_t)n;
        if(service.used>=sizeof(service.request)) return drop();
        if(n!=0) return 0;
        request=aeg_service_request(service.request,service.used,0,0);
        if(request==0) return drop();
        if(request==2) service.stopping=true;
        *stop=service.stopping;
        service.reply=aeg_service_reply(phase,service.stopping);
        if(service.reply==NULL) return fault();
    }
    n=send(service.client,service.reply+service.sent,strlen(service.reply)-service.sent,MSG_DONTWAIT|MSG_NOSIGNAL);
    if(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)) return 0;
    if(n<=0) return drop();
    service.sent+=(size_t)n;
    return service.sent==strlen(service.reply) ? drop() : 0;
}
/* Actual private terminal owner only. Close/unlink must succeed before C/audit
 * settlement; a failed close/path check leaves the unknown endpoint retained. */
int aeg_service_close(void) {
    if(service.closed || service.uncertain || service.listener<0) return -1;
    service.closed=true;
    if(drop()!=0 || close(service.listener)!=0) return fault();
    service.listener=-1;
    if(!current() || unlink(path)!=0) return fault();
    return 0;
}
#endif
