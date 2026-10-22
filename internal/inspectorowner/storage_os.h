/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef AEG_INSPECTOROWNER_STORAGE_OS_H
#define AEG_INSPECTOROWNER_STORAGE_OS_H
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdbool.h>
/* Fixed-link wrappers only; no runtime operation table or registration. */
int aeg_store_root(void);
int aeg_store_dir(int, unsigned);
int aeg_store_state(int);
int aeg_store_intent(int);
int aeg_store_pin(int);
int aeg_store_pin_stat(int, struct stat *);
int aeg_store_image_dir(int, unsigned);
int aeg_store_image(int);
int aeg_store_image_stat(int, struct stat *);
int aeg_store_image_hash(int, off_t, unsigned char [32]);
int aeg_store_stat(int, struct stat *);
int aeg_store_path_stat(int, bool, struct stat *);
int aeg_store_lock(int);
ssize_t aeg_store_read(int, unsigned char *, size_t);
ssize_t aeg_store_write(int, const unsigned char *);
int aeg_store_sync(int);
int aeg_store_close(int);
void aeg_store_hash(const unsigned char [128], unsigned char [32]);
int aeg_store_clock(int64_t *);
#endif
