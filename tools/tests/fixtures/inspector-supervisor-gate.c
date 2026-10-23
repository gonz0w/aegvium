/* SPDX-License-Identifier: BSD-3-Clause */
/* Exercise actual source main + immutable gate, with all later calls trapped. */
#include <signal.h>
#include <poll.h>
static int effects;
static int fixture_sigemptyset(sigset_t *s) { (void)s;effects++;return -1; }
static int fixture_sigaction(int n,const struct sigaction *a,struct sigaction *o) { (void)n;(void)a;(void)o;effects++;return -1; }
static int fixture_poll(struct pollfd *p,nfds_t n,int t) { (void)p;(void)n;(void)t;effects++;return -1; }
#undef sigemptyset
#define sigemptyset fixture_sigemptyset
#define sigaction(...) fixture_sigaction(__VA_ARGS__)
#define poll fixture_poll
#define main fixture_supervisor_main
#include "../../../cmd/aegvium-supervisor/main.c"
#undef main
#undef sigemptyset
#undef sigaction
#undef poll
#include <stdio.h>
int aeg_launch_storage_prepare(void) {effects++;return AEG_STORAGE_STATE;}
struct aeg_owner_view aeg_owner_get_view(void) {struct aeg_owner_view v={0};effects++;return v;}
int aeg_native_spawn_source(void) {effects++;return AEG_NATIVE_STATE;}
int aeg_native_close_source(void) {effects++;return AEG_NATIVE_STATE;}
int aeg_native_settle_source(void) {effects++;return AEG_NATIVE_STATE;}
int aeg_native_prepared_source(void) {effects++;return AEG_NATIVE_STATE;}
int aeg_native_stop_epoch_source(int64_t origin) {(void)origin;effects++;return AEG_NATIVE_STATE;}
int aeg_native_stop_source(void) {effects++;return AEG_NATIVE_STATE;}
int aeg_native_tick_source(void) {effects++;return AEG_NATIVE_STATE;}
void aeg_native_diagnostics_prepare_source(void) {effects++;}
void aeg_native_diagnostics_source(void) {effects++;}
int main(void) {
    char *args[]={"synthetic-supervisor",NULL};
    int rc=fixture_supervisor_main(1,args);
    printf("{\"rc\":%d,\"effects\":%d}\n",rc,effects);
    return rc==77 && effects==0 ? 0 : 1;
}
