/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef AEG_INSPECTOROWNER_NATIVE_OS_H
#define AEG_INSPECTOROWNER_NATIVE_OS_H
#include <sys/types.h>
/* Fixed-link private OS boundary. No runtime replacement/registration API. */
int aeg_os_pair(int [2]);
ssize_t aeg_os_bootstrap_send(int, const unsigned char *, size_t);
int aeg_os_null(void);
int aeg_os_null_kind(int);
int aeg_os_dup_high(int);
int aeg_os_close(int);
int aeg_os_dup_target(int, int);
int aeg_os_getfd(int);
int aeg_os_nonblock(int);
int aeg_os_closefrom4(void);
int aeg_os_clear_groups(void);
int aeg_os_set_gid(gid_t);
int aeg_os_set_uid(uid_t);
int aeg_os_group_count(void);
int aeg_os_get_gid(gid_t [3]);
int aeg_os_get_uid(uid_t [3]);
#ifdef AEG_INSPECTOR_SOURCE
int aeg_os_audit_pair(int [2]);
int aeg_os_log_open(int *);
ssize_t aeg_os_audit_receive(int, unsigned char *, size_t);
ssize_t aeg_os_log_send(int, const unsigned char *, size_t);
#endif
#endif
