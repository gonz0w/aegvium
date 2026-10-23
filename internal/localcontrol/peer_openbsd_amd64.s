//go:build openbsd && (aegvium_frontend_source || aegvium_service_source)

// Go Authors BSD trampoline pattern; see LICENSE.x-sys.
#include "textflag.h"
TEXT peer_trampoline<>(SB),NOSPLIT,$0-0
	JMP aeg_service_getpeereid(SB)
GLOBL ·peerTrampoline(SB), RODATA, $8
DATA ·peerTrampoline(SB)/8, $peer_trampoline<>(SB)
TEXT accept_trampoline<>(SB),NOSPLIT,$0-0
	JMP aeg_service_accept4(SB)
GLOBL ·acceptTrampoline(SB), RODATA, $8
DATA ·acceptTrampoline(SB)/8, $accept_trampoline<>(SB)
