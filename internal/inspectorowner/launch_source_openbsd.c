/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __OpenBSD__
#error "OpenBSD source only; never run this adapter in host fixtures"
#endif
#include "launch_source_os.h"
#include <sys/socket.h>
#include <sys/wait.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

int aeg_start_identity(uid_t *uid, gid_t *gid) {
    uid_t u[3]; gid_t g[3]; struct passwd *p;
    if (getresuid(&u[0],&u[1],&u[2]) != 0 ||
        getresgid(&g[0],&g[1],&g[2]) != 0 ||
        u[0] || u[1] || u[2] || g[0] || g[1] || g[2]) return -1;
    p=getpwnam("_aegvium");
    if (p==NULL || p->pw_uid==0 || p->pw_uid==(uid_t)-1 ||
        p->pw_gid==0 || p->pw_gid==(gid_t)-1) return -1;
    *uid=p->pw_uid; *gid=p->pw_gid; return 0;
}
int aeg_start_clock(int64_t *out) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC,&t)!=0 || t.tv_sec<0 ||
        t.tv_sec>INT64_MAX/1000 || t.tv_nsec<0 || t.tv_nsec>=1000000000 ||
        t.tv_sec*1000>INT64_MAX-t.tv_nsec/1000000) return -1;
    *out=t.tv_sec*1000+t.tv_nsec/1000000; return 0;
}
pid_t aeg_start_fork(void) {
    struct sigaction action={0};
    /* The fixed S executable has one thread and no wait handler. Do not inherit
     * SIG_IGN/SA_NOCLDWAIT: auto-reaping would permit PID reuse before kill. */
    action.sa_handler=SIG_DFL;
    if (sigemptyset(&action.sa_mask)!=0 || sigaction(SIGCHLD,&action,NULL)!=0) return -1;
    return fork();
}
int aeg_start_exec(void) {
    char *const argv[]={"/usr/local/libexec/aegvium/inspector",NULL};
    char *const envp[]={NULL};
    /* Unqualified INERT startup candidate only: no listener/backend code is
     * reachable. Actual loader/runtime/exec-survival must qualify separately.
     * Future serving requires its complete reviewed network/isolation closure. */
    if (pledge("stdio rpath prot_exec exec","stdio rpath prot_exec")!=0) return -1;
    return execve(argv[0],argv,envp);
}
_Noreturn void aeg_start_child_exit(void) { _exit(77); }
ssize_t aeg_start_read(int fd,unsigned char *p,size_t n) { return recv(fd,p,n,MSG_DONTWAIT); }
pid_t aeg_start_wait(pid_t pid,int *kind) {
    int status; pid_t result=waitpid(pid,&status,WNOHANG|WUNTRACED);
    *kind=0;
    if (result>0) {
        if (WIFEXITED(status)) *kind=1;
        else if (WIFSIGNALED(status)) *kind=2;
        else if (WIFSTOPPED(status)) *kind=3;
    }
    return result;
}
int aeg_start_kill(pid_t pid) { return kill(pid,SIGKILL); }
