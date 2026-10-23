/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef AEG_INSPECTOR_NATIVE_TEST_OPS_H
#define AEG_INSPECTOR_NATIVE_TEST_OPS_H
#if !defined(AEG_NATIVE_TEST)
#error "test-only interception requires explicit test mode"
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
/* Labels only when the host lacks target constants. NEVER passed to host OS. */
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0x10000
#endif
#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 0x20000
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0x400
#endif
ssize_t aeg_test_send(int, const void *, size_t, int);
int aeg_test_socketpair(int, int, int, int [2]);
int aeg_test_socket(int,int,int);
int aeg_test_connect(int,const struct sockaddr *,socklen_t);
ssize_t aeg_test_recv(int,void *,size_t,int);
int aeg_test_open(const char *, int, ...);
int aeg_test_fstat(int, struct stat *);
int aeg_test_fcntl(int, int, ...);
int aeg_test_close(int);
int aeg_test_dup2(int, int);
int aeg_test_closefrom(int);
int aeg_test_setgroups(int, const gid_t *);
int aeg_test_setresgid(gid_t, gid_t, gid_t);
int aeg_test_setresuid(uid_t, uid_t, uid_t);
int aeg_test_getgroups(int, gid_t *);
int aeg_test_getresgid(gid_t *, gid_t *, gid_t *);
int aeg_test_getresuid(uid_t *, uid_t *, uid_t *);
#define send aeg_test_send
#define socketpair aeg_test_socketpair
#define socket aeg_test_socket
#define connect aeg_test_connect
#define recv aeg_test_recv
#define open aeg_test_open
#define fstat aeg_test_fstat
#define fcntl aeg_test_fcntl
#define close aeg_test_close
#define dup2 aeg_test_dup2
#define closefrom aeg_test_closefrom
#define setgroups aeg_test_setgroups
#define setresgid aeg_test_setresgid
#define setresuid aeg_test_setresuid
#define getgroups aeg_test_getgroups
#define getresgid aeg_test_getresgid
#define getresuid aeg_test_getresuid
#endif
