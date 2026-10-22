/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef AEG_INSPECTOR_STORAGE_TEST_OPS_H
#define AEG_INSPECTOR_STORAGE_TEST_OPS_H
#include "inspector-native-ops.h"
#include <sys/file.h>
#include <time.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#undef open
#undef fstat
#undef close
int aeg_storage_test_open(const char *,int,...);
int aeg_storage_test_openat(int,const char *,int,...);
int aeg_storage_test_fstat(int,struct stat *);
int aeg_storage_test_fstatat(int,const char *,struct stat *,int);
int aeg_storage_test_close(int);
int aeg_storage_test_flock(int,int);
ssize_t aeg_storage_test_pread(int,void *,size_t,off_t);
ssize_t aeg_storage_test_pwrite(int,const void *,size_t,off_t);
int aeg_storage_test_fsync(int);
int aeg_storage_test_clock(int,struct timespec *);
typedef struct { unsigned char input[8192];size_t len;unsigned updates;bool image,snapshot,bad_data; } SHA2_CTX;
void aeg_storage_test_sha_init(SHA2_CTX *);
void aeg_storage_test_sha_update(SHA2_CTX *,const unsigned char *,size_t);
void aeg_storage_test_sha_final(unsigned char *,SHA2_CTX *);
#define open aeg_storage_test_open
#define openat aeg_storage_test_openat
#define fstat aeg_storage_test_fstat
#define fstatat aeg_storage_test_fstatat
#define close aeg_storage_test_close
#define flock aeg_storage_test_flock
#define pread aeg_storage_test_pread
#define pwrite aeg_storage_test_pwrite
#define fsync aeg_storage_test_fsync
#define clock_gettime aeg_storage_test_clock
#define SHA256Init aeg_storage_test_sha_init
#define SHA256Update aeg_storage_test_sha_update
#define SHA256Final aeg_storage_test_sha_final
#endif
