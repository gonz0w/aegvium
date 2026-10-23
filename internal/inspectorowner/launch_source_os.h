/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef AEG_INSPECTOR_LAUNCH_SOURCE_OS_H
#define AEG_INSPECTOR_LAUNCH_SOURCE_OS_H
#include <stdint.h>
#include <sys/types.h>
int aeg_start_identity(uid_t *, gid_t *);
int aeg_start_clock(int64_t *);
pid_t aeg_start_fork(void);
int aeg_start_exec(void);
_Noreturn void aeg_start_child_exit(void);
ssize_t aeg_start_read(int, unsigned char *, size_t);
pid_t aeg_start_wait(pid_t, int *);
int aeg_start_kill(pid_t);
#endif
