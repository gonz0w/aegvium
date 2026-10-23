/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef AEG_INSPECTOR_SOURCE
int main(void) { return 77; } /* Installed/default entry remains closed. */
#else
/* Fixed single-threaded source entry. No plugin, signal wait handler, foreign
 * child, PID argument, automatic restart or recovery exists. */
#include "native_construction.h"
#include "launch_storage.h"
#include "controller.h"
#include <poll.h>
#include <signal.h>
#include <stdbool.h>

static volatile sig_atomic_t stopping;
static void stop_handler(int signal_number) { (void)signal_number; stopping=1; }

int main(int argc,char **argv) {
    struct sigaction action={0};
    struct aeg_owner_view owner;
    bool prepared=false, stop_sent=false, failed=false;
    int rc, closed, settled;
    (void)argv;
    if (argc!=1 || !aeg_supervisor_source_qualified()) return 77;
    action.sa_handler=stop_handler;
    if (sigemptyset(&action.sa_mask)!=0 || sigaction(SIGTERM,&action,NULL)!=0 ||
        sigaction(SIGINT,&action,NULL)!=0) return 77;
    if (aeg_launch_storage_prepare()!=AEG_STORAGE_OK) return 1;
    if (stopping) return 1; /* Preserve burned U; never launch after observed stop. */
    if (aeg_native_spawn_source()!=AEG_NATIVE_OK) { stopping=1; failed=true; }
    if(!stopping) aeg_native_diagnostics_prepare_source();
    for (;;) {
        owner=aeg_owner_get_view();
        if (owner.identity_fault) return 1; /* Cold recovery, never PID adoption. */
        if (owner.terminal!=AEG_TERMINAL_UNKNOWN) {
            closed=aeg_native_close_source();
            /* Only after actual terminal + local closure. Storage may block
             * here; it never competes with active stop/escalation/wait. */
            settled=aeg_native_settle_source();
            owner=aeg_owner_get_view();
            return closed==AEG_NATIVE_OK && settled==AEG_NATIVE_OK &&
                owner.target==AEG_MET && !owner.clock_fault &&
                !owner.unsafe_fault && prepared && stop_sent && !failed ? 0 : 1;
        }
        if (!owner.known_child) return 1;
        if (!prepared && !stopping) {
            rc=aeg_native_prepared_source();
            if (rc==AEG_NATIVE_OK) prepared=true;
            else if (rc!=AEG_NATIVE_PENDING) { stopping=1; failed=true; }
        }
        if (stopping && !stop_sent) {
            stop_sent=true;
            if (aeg_native_stop_source()!=AEG_NATIVE_OK) failed=true;
        }
        if (aeg_native_tick_source()!=AEG_NATIVE_OK) failed=true;
        if(!stopping) aeg_native_diagnostics_source();
        /* Nonblocking source calls above; no journal I/O on active stop/wait.
         * Actual scheduling/resource/4s behavior remains unqualified. */
        (void)poll(NULL,0,10);
    }
}
#endif
