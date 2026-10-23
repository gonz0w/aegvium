/* SPDX-License-Identifier: BSD-3-Clause */
#include "controller.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"check:%d\n",__LINE__);return 1;}} while(0)
int main(int argc,char **argv) {
 enum aeg_owner_intent intent;struct aeg_owner_view v;int rc;
 if(argc!=2) return 2;
 CHECK(aeg_owner_prepare("11111111111111111111111111111111",32,1000)==AEG_OK);
 CHECK(aeg_owner_step(AEG_OWNED,1010,&intent)==AEG_OK);
 if(strcmp(argv[1],"future")==0 || strcmp(argv[1],"overflow")==0) {
  rc=strcmp(argv[1],"future")==0 ? aeg_owner_stop_at(1051,1050) : aeg_owner_stop_at(INT64_MAX-3999,INT64_MAX-3999);
  v=aeg_owner_get_view();CHECK(rc==AEG_INPUT && !v.stopped && v.known_child);puts("PASS");return 0;
 }
 if(strcmp(argv[1],"repeat_later")==0 || strcmp(argv[1],"repeat_earlier")==0) {
  CHECK(aeg_owner_stop_at(1000,1050)==AEG_OK);
  CHECK(aeg_owner_stop_at(strcmp(argv[1],"repeat_later")==0 ? 1050 : 900,1060)==AEG_OK);
  CHECK(aeg_owner_step(AEG_TICK,strcmp(argv[1],"repeat_later")==0 ? 5000 : 4900,&intent)==AEG_OK);
  v=aeg_owner_get_view();CHECK(v.target==AEG_MISSED && v.known_child && v.held);puts("PASS");return 0;
 }
 {
  int64_t now=strcmp(argv[1],"fresh")==0 ? 1050 : strcmp(argv[1],"ack_boundary")==0 ? 1100 : 5000;
  CHECK(aeg_owner_stop_at(1000,now)==AEG_OK);
  CHECK(aeg_owner_step(AEG_TAKE_STOP,now,&intent)==AEG_OK);
  CHECK(intent==(now==1050 ? AEG_SEND_STOP : AEG_NONE));
  CHECK(aeg_owner_step(AEG_TAKE_KILL,now,&intent)==AEG_OK);
  CHECK(intent==(now==1050 ? AEG_NONE : AEG_SEND_KILL));
  v=aeg_owner_get_view();CHECK(v.target==(now==5000 ? AEG_MISSED : AEG_PENDING));
  CHECK(v.known_child && v.held);
  CHECK(aeg_owner_step(AEG_WAIT_NORMAL,now+1,&intent)==AEG_OK);
  CHECK(aeg_owner_step(AEG_CLOSED,now+1,&intent)==AEG_OK);
  v=aeg_owner_get_view();CHECK(v.phase==AEG_RECLAIMED && !v.held && !v.known_child);
  CHECK(v.target==(now==5000 ? AEG_MISSED : AEG_MET));
 }
 puts("PASS");return 0;
}
