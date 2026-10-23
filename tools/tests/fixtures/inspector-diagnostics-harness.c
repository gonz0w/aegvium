/* SPDX-License-Identifier: BSD-3-Clause */
/* ALL product OS calls are fixed fakes from the retained source fixture graph. */
#define AEG_LAUNCH_FIXTURE_MAIN previous_launch_fixture_main
#include "inspector-launch-harness.c"
static const unsigned char diagnostic[64]={0x41,0x47,0x44,0x49,0x41,0x47,0x31,0x0a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x05,0x07,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static int receives,logs;
ssize_t aeg_diag_test_receive(int fd,void *data,size_t n,int flags) {
    unsigned char *p=data;
    if(fd!=8 || !owned[fd] || n!=65 || flags!=MSG_DONTWAIT) bad++;
    receives++;
    if(strcmp(mode,"idle")==0) {errno=EAGAIN;return -1;}
    if(strcmp(mode,"read-error")==0) {errno=EIO;return -1;}
    memcpy(p,diagnostic,64);
    p[15]=(unsigned char)receives;
    if(strcmp(mode,"gap")==0) p[15]=(unsigned char)(receives+2);
    if(strcmp(mode,"duplicate")==0) p[15]=1;
    if(strcmp(mode,"magic")==0) p[0]^=1;
    if(strcmp(mode,"reserved")==0) p[63]=1;
    if(strcmp(mode,"flags")==0) p[41]=64;
    if(strcmp(mode,"result")==0) p[40]=6;
    if(strcmp(mode,"prejob")==0) p[42]=2;
    if(strcmp(mode,"zero")==0) p[15]=0;
    if(strcmp(mode,"short")==0) return 63;
    if(strcmp(mode,"oversize")==0) {p[64]=0;return 65;}
    return 64;
}
ssize_t aeg_diag_test_log(int fd,const void *p,size_t n,int flags) {
    const char *text=p;
    if(fd!=10 || !owned[fd] || flags!=(MSG_DONTWAIT|MSG_NOSIGNAL) || n>=512 || n==0 ||
        strncmp(text,"<29>aegvium: qualified=0 source=inspector-reported ",48)!=0) bad++;
    logs++;
    if(strcmp(mode,"log-error")==0) {errno=EAGAIN;return -1;}
    if(strcmp(mode,"log-short")==0) return (ssize_t)n-1;
    return (ssize_t)n;
}
int main(int argc,char **argv) {
    int before,closed,again;struct aeg_diagnostic_view v;struct aeg_native_view nv;
    if(argc!=2) return 2;mode=argv[1];
    expected_bootstrap=source_packet;expected_bootstrap_size=sizeof(source_packet);
    if(aeg_owner_prepare((const char *)source_packet+18,32,0)!=0 || aeg_native_pair_prepare()!=0 ||
        aeg_native_bootstrap_emit()!=0 || aeg_native_spawn_source()!=0) return 3;
    if(strcmp(mode,"connect-error")==0) fail_at=calls+2;
    aeg_native_diagnostics_prepare_source();
    fail_at=0;
    if(strcmp(mode,"stop")==0) (void)aeg_native_stop_source();
    if(strcmp(mode,"terminal")==0) {wait_kind=1;(void)aeg_native_wait_source();}
    if(strcmp(mode,"lost")==0) {mode="source-lost";(void)aeg_native_wait_source();mode="lost";}
    before=calls;
    aeg_native_diagnostics_source();
    v=aeg_native_diagnostics_view();
    if(strcmp(mode,"terminal")!=0 && strcmp(mode,"lost")!=0) {wait_kind=1;(void)aeg_native_wait_source();}
    if(strcmp(mode,"close-reader")==0) fail_at=calls+2;
    if(strcmp(mode,"close-log")==0) fail_at=calls+3;
    closed=aeg_native_close_source();again=aeg_native_close_source();nv=aeg_native_get_view();
    printf("{\"receives\":%d,\"logs\":%d,\"seq\":%llu,\"invalid\":%llu,\"missing\":%llu,\"sink_lost\":%llu,\"unavailable\":%d,\"close\":%d,\"again\":%d,\"uncertain\":%d,\"known\":%u,\"peak\":%d,\"bad\":%d,\"close_reader\":%u,\"close_log\":%u,\"calls_before_drain\":%d}\n",receives,logs,v.sequence,v.invalid,v.missing,v.sink_lost,(int)v.sink_unavailable,closed,again,(int)nv.uncertain,nv.known_owned_descriptors,peak,bad,close_calls[8],close_calls[10],before);
    return 0;
}
