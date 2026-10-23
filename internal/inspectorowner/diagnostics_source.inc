/* SPDX-License-Identifier: BSD-3-Clause */
/* Included only with the actual private source construction. No supplied FD,
 * destination or provider. Reports are untrusted inspector diagnostics. */
#include <limits.h>
#include <stdio.h>

static struct {
    struct aeg_diagnostic_view view;
    int log_slot;
} diagnostics={.log_slot=-1};

static void diag_increment(unsigned long long *v) { if(*v<ULLONG_MAX) ++*v; }
static unsigned long long diag_number(const unsigned char *p) {
    unsigned long long n=0; int i;
    for(i=0;i<8;i++) n=(n<<8)|p[i];
    return n;
}
static bool diag_running(void) {
    struct aeg_owner_view o=aeg_owner_get_view();
    return source_launch.child>0 && !source_launch.terminal && !source_launch.lost &&
        !o.stopped && o.known_child && !o.identity_fault &&
        construction.view.phase==AEG_NATIVE_PARENT && !construction.view.uncertain;
}
void aeg_native_diagnostics_prepare_source(void) {
    int fd=-1,rc;
    if(diagnostics.view.attempted || !diag_running()) return;
    diagnostics.view.attempted=true;
    rc=aeg_os_log_open(&fd);
    if(fd>=0) {
        diagnostics.log_slot=adopt(fd);
        if(diagnostics.log_slot<0) { construction.view.uncertain=true; return; }
    }
    if(rc!=0 || fd<0) {
        diagnostics.view.sink_unavailable=true;
        (void)close_slot(diagnostics.log_slot); /* Error is never retried. */
    }
}
void aeg_native_diagnostics_source(void) {
    unsigned char p[65]; char line[512]; ssize_t n; int i,j,written;
    unsigned long long sequence,gap;
    struct aeg_owner_view owner;
    if(!diag_running()) return;
    for(i=0;i<4;i++) {
        if(!diag_running()) return;
        n=aeg_os_audit_receive(construction.fd[construction.audit_parent],p,sizeof(p));
        if(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)) return;
        if(n<0) { diag_increment(&diagnostics.view.invalid); return; }
        if(n!=64 || memcmp(p,"AGDIAG1\n",8)!=0 || p[40]>5 || p[41]>63 || p[42]>1) {
            diag_increment(&diagnostics.view.invalid); continue;
        }
        for(j=43;j<64 && p[j]==0;j++);
        sequence=diag_number(p+8);
        if(j!=64 || sequence==0 || sequence<=diagnostics.view.sequence) {
            diag_increment(&diagnostics.view.invalid); continue;
        }
        gap=sequence-diagnostics.view.sequence-1;
        diagnostics.view.missing=ULLONG_MAX-diagnostics.view.missing<gap ?
            ULLONG_MAX : diagnostics.view.missing+gap;
        diagnostics.view.sequence=sequence;
        if(diagnostics.log_slot<0 || construction.fd[diagnostics.log_slot]<0 ||
            diagnostics.view.sink_unavailable) { diag_increment(&diagnostics.view.sink_lost); continue; }
        owner=aeg_owner_get_view();
        written=snprintf(line,sizeof(line),
            "<29>aegvium: qualified=0 source=inspector-reported seq=%llu lost=%llu overwritten=%llu total=%llu result=%u flags=%u prejob=%u gap=%llu invalid=%llu sink_lost=%llu supervisor_phase=%u supervisor_target=%u",
            sequence,diag_number(p+16),diag_number(p+24),diag_number(p+32),
            (unsigned)p[40],(unsigned)p[41],(unsigned)p[42],diagnostics.view.missing,
            diagnostics.view.invalid,diagnostics.view.sink_lost,(unsigned)owner.phase,(unsigned)owner.target);
        if(written<0 || (size_t)written>=sizeof(line) ||
            aeg_os_log_send(construction.fd[diagnostics.log_slot],(const unsigned char *)line,(size_t)written)!=written)
            diag_increment(&diagnostics.view.sink_lost);
    }
}
struct aeg_diagnostic_view aeg_native_diagnostics_view(void) { return diagnostics.view; }
