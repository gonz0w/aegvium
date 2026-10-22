/* SPDX-License-Identifier: BSD-3-Clause */
#if !defined(__OpenBSD__) && !defined(AEG_NATIVE_TEST)
#error "OpenBSD target only; host fixtures must intercept every OS boundary"
#endif
#include "native_os.h"
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int aeg_os_pair(int fd[2]) { return socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, fd); }
ssize_t aeg_os_bootstrap_send(int fd, const unsigned char *p, size_t n) { return send(fd,p,n,MSG_NOSIGNAL); }
int aeg_os_null(void) { return open("/dev/null", O_RDWR | O_CLOEXEC | O_NOFOLLOW); }
int aeg_os_null_kind(int fd) {
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISCHR(st.st_mode) ? 0 : -1;
}
int aeg_os_dup_high(int fd) { return fcntl(fd, F_DUPFD_CLOEXEC, 4); }
int aeg_os_close(int fd) { return close(fd); }
int aeg_os_dup_target(int fd, int target) { return dup2(fd, target); }
int aeg_os_getfd(int fd) { return fcntl(fd, F_GETFD); }
int aeg_os_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL);
    return flags < 0 ? -1 : (flags & O_NONBLOCK) != 0;
}
int aeg_os_closefrom4(void) { return closefrom(4); }
int aeg_os_clear_groups(void) { return setgroups(0, NULL); }
int aeg_os_set_gid(gid_t id) { return setresgid(id, id, id); }
int aeg_os_set_uid(uid_t id) { return setresuid(id, id, id); }
int aeg_os_group_count(void) { return getgroups(0, NULL); }
int aeg_os_get_gid(gid_t ids[3]) { return getresgid(&ids[0], &ids[1], &ids[2]); }
int aeg_os_get_uid(uid_t ids[3]) { return getresuid(&ids[0], &ids[1], &ids[2]); }
