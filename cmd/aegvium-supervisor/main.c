/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef AEG_INSPECTOR_SOURCE
int main(void) { return 77; } /* Installed/default entry remains closed. */
#else
/* Fixed single-threaded source entry. No plugin, signal wait handler, foreign
 * child, PID argument, automatic restart or recovery exists. */
#include "native_construction.h"
#include "launch_storage.h"
#include "controller.h"
#include "service_control.h"
#include <poll.h>
#include <signal.h>
#include <stdbool.h>

static volatile sig_atomic_t stopping;
static void stop_handler(int signal_number) { (void)signal_number; stopping=1; }

int main(int argc,char **argv) {
    struct sigaction action={0};
    struct aeg_owner_view owner;
    bool prepared=false, stop_sent=false, failed=false;
    int rc, closed, settled, control_closed;
    bool requested=false;
    (void)argv;
    if (argc!=1 || !aeg_supervisor_source_qualified()) return 77;
    action.sa_handler=stop_handler;
    if (sigemptyset(&action.sa_mask)!=0 || sigaction(SIGTERM,&action,NULL)!=0 ||
        sigaction(SIGINT,&action,NULL)!=0) return 77;
    if (aeg_service_prepare()!=0) return 1;
    if (aeg_launch_storage_prepare()!=AEG_STORAGE_OK) { (void)aeg_service_close(); return 1; }
    if(aeg_service_poll(AEG_SERVICE_STARTING,&requested)!=0 || requested) stopping=1;
    if (stopping) { (void)aeg_service_close(); return 1; } /* Preserve burned U; never launch after observed stop. */
    if (aeg_native_spawn_source()!=AEG_NATIVE_OK) { stopping=1; failed=true; }
    if(!stopping) aeg_native_diagnostics_prepare_source();
    for (;;) {
        owner=aeg_owner_get_view();
        if (owner.identity_fault) return 1; /* Cold recovery, never PID adoption. */
        if (owner.terminal!=AEG_TERMINAL_UNKNOWN) {
            closed=aeg_native_close_source();
            /* Only after actual terminal + local closure. Storage may block
             * here; it never competes with active stop/escalation/wait. */
            control_closed=aeg_service_close();
            settled=control_closed==0 ? aeg_native_settle_source() : AEG_NATIVE_UNCERTAIN;
            owner=aeg_owner_get_view();
            return control_closed==0 && closed==AEG_NATIVE_OK && settled==AEG_NATIVE_OK &&
                owner.target==AEG_MET && !owner.clock_fault &&
                !owner.unsafe_fault && prepared && stop_sent && !failed ? 0 : 1;
        }
        if (!owner.known_child) return 1;
        if(aeg_service_poll(stopping ? AEG_SERVICE_RETIRING :
            prepared ? AEG_SERVICE_OWNED : AEG_SERVICE_STARTING,&requested)!=0) {
            stopping=1;failed=true;
        }
        if(requested) {
            stopping=1;
            if(aeg_native_stop_epoch_source(aeg_service_stop_origin())!=AEG_NATIVE_OK) failed=true;
        }
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
