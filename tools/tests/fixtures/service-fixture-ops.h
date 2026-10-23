/* SPDX-License-Identifier: BSD-3-Clause */
/* Every subject OS boundary is replaced at compile time; never a provider. */
#ifndef AEG_SERVICE_FIXTURE_OPS
#define AEG_SERVICE_FIXTURE_OPS
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0x10000000
#endif
#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 0x20000000
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0x40000000
#endif
int fake_lstat(const char *,struct stat *);
int fake_mkdir(const char *,mode_t);
int fake_socket(int,int,int);
int fake_bind(int,const struct sockaddr *,socklen_t);
int fake_chmod(const char *,mode_t);
int fake_listen(int,int);
int fake_accept4(int,struct sockaddr *,socklen_t *,int);
int fake_peer(int,uid_t *,gid_t *);
int fake_clock(clockid_t,struct timespec *);
ssize_t fake_recv(int,void *,size_t,int);
ssize_t fake_send(int,const void *,size_t,int);
int fake_close(int);
int fake_unlink(const char *);
uid_t fake_uid(void);
gid_t fake_gid(void);
#define lstat fake_lstat
#define mkdir fake_mkdir
#define socket fake_socket
#define bind fake_bind
#define chmod fake_chmod
#define listen fake_listen
#define accept4 fake_accept4
#define getpeereid fake_peer
#define clock_gettime fake_clock
#define recv fake_recv
#define send fake_send
#define close fake_close
#define unlink fake_unlink
#define getuid fake_uid
#define geteuid fake_uid
#define getgid fake_gid
#define getegid fake_gid
#endif
