/* SPDX-License-Identifier: BSD-3-Clause */
#if !defined(__OpenBSD__) && !defined(AEG_NATIVE_TEST)
#error "OpenBSD target only; fixtures must intercept every OS/crypto boundary"
#endif
#include "storage_os.h"
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#if !defined(AEG_NATIVE_TEST)
#include <sha2.h>
#endif
int aeg_store_root(void) { return open("/", O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); }
int aeg_store_dir(int fd, unsigned n) {
    static const char *const names[] = { "var", "db", "aegvium" };
    return n < 3 ? openat(fd, names[n], O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC) : -1;
}
int aeg_store_state(int fd) { return openat(fd, "launch.state", O_RDWR|O_NOFOLLOW|O_CLOEXEC); }
int aeg_store_intent(int fd) { return openat(fd, "launch.intent", O_RDONLY|O_NOFOLLOW|O_CLOEXEC); }
int aeg_store_pair_snapshot(int fd) { return openat(fd,"pair.snapshot",O_RDONLY|O_NOFOLLOW|O_CLOEXEC); }
int aeg_store_pair_stat(int fd, struct stat *s) { return fstatat(fd,"pair.snapshot",s,AT_SYMLINK_NOFOLLOW); }
int aeg_store_pin(int fd) { return openat(fd,"inspector.pin",O_RDONLY|O_NOFOLLOW|O_CLOEXEC); }
int aeg_store_pin_stat(int fd, struct stat *s) { return fstatat(fd,"inspector.pin",s,AT_SYMLINK_NOFOLLOW); }
int aeg_store_image_dir(int fd, unsigned n) {
    static const char *const names[] = { "usr", "local", "libexec", "aegvium" };
    return n<4 ? openat(fd,names[n],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC) : -1;
}
int aeg_store_image(int fd) { return openat(fd,"inspector",O_RDONLY|O_NOFOLLOW|O_CLOEXEC); }
int aeg_store_image_stat(int fd, struct stat *s) { return fstatat(fd,"inspector",s,AT_SYMLINK_NOFOLLOW); }
int aeg_store_stat(int fd, struct stat *s) { return fstat(fd, s); }
int aeg_store_path_stat(int fd, bool intent, struct stat *s) {
    return fstatat(fd, intent ? "launch.intent" : "launch.state", s, AT_SYMLINK_NOFOLLOW);
}
int aeg_store_lock(int fd) { return flock(fd, LOCK_EX|LOCK_NB); }
ssize_t aeg_store_read(int fd, unsigned char *p, size_t n) { return pread(fd,p,n,0); }
ssize_t aeg_store_write(int fd, const unsigned char *p) { return pwrite(fd,p,128,0); }
int aeg_store_sync(int fd) { return fsync(fd); }
int aeg_store_close(int fd) { return close(fd); }
void aeg_store_hash(const unsigned char p[128], unsigned char out[32]) {
    SHA2_CTX ctx;
    SHA256Init(&ctx);
    SHA256Update(&ctx,p,48);
    SHA256Update(&ctx,p+80,48);
    SHA256Final(out,&ctx);
}
void aeg_store_pair_hash(const unsigned char *p, size_t n, unsigned char out[32]) {
    SHA2_CTX ctx;
    SHA256Init(&ctx);
    SHA256Update(&ctx,p,n);
    SHA256Final(out,&ctx);
}
int aeg_store_image_hash(int fd, off_t bytes, unsigned char out[32]) {
    SHA2_CTX ctx;
    unsigned char block[4096], extra;
    off_t offset=0;
    size_t n;
    if(bytes<1 || bytes>67108864) return -1;
    SHA256Init(&ctx);
    while(offset<bytes) {
        n=(size_t)(bytes-offset);
        if(n>sizeof(block)) n=sizeof(block);
        if(pread(fd,block,n,offset)!=(ssize_t)n) return -1;
        SHA256Update(&ctx,block,n);
        offset+=(off_t)n;
    }
    if(pread(fd,&extra,1,bytes)!=0) return -1;
    SHA256Final(out,&ctx);
    return 0;
}
int aeg_store_clock(int64_t *out) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC,&t) != 0 || t.tv_sec < 0 ||
        t.tv_nsec < 0 || t.tv_nsec >= 1000000000L ||
        (uintmax_t)t.tv_sec > (uintmax_t)(INT64_MAX-999)/1000) return -1;
    *out = (int64_t)t.tv_sec*1000+t.tv_nsec/1000000;
    return 0;
}
