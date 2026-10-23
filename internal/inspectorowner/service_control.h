/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef AEG_SERVICE_CONTROL_H
#define AEG_SERVICE_CONTROL_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
enum aeg_service_phase { AEG_SERVICE_STARTING, AEG_SERVICE_OWNED, AEG_SERVICE_RETIRING, AEG_SERVICE_TERMINAL, AEG_SERVICE_UNCERTAIN };
int aeg_service_request(const unsigned char *,size_t,uint32_t,uint32_t);
int64_t aeg_service_epoch(const unsigned char *,size_t);
const char *aeg_service_reply(enum aeg_service_phase,bool);
#if defined(__OpenBSD__) || defined(AEG_SERVICE_FIXTURE)
int aeg_service_prepare(void);
int aeg_service_poll(enum aeg_service_phase,bool *);
int aeg_service_close(void);
int64_t aeg_service_stop_origin(void);
#else
/* Host gate fixtures never call a native service endpoint. */
static inline int aeg_service_prepare(void) { return -1; }
static inline int aeg_service_poll(enum aeg_service_phase p,bool *s) { (void)p;(void)s;return -1; }
static inline int aeg_service_close(void) { return -1; }
static inline int64_t aeg_service_stop_origin(void) { return -1; }
#endif
#endif
