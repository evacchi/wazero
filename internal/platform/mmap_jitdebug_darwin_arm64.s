//go:build darwin && arm64 && jitdebug

#include "textflag.h"

TEXT libc_pthread_jit_write_protect_np_trampoline<>(SB), NOSPLIT, $0-0
	JMP libc_pthread_jit_write_protect_np(SB)

GLOBL ·libc_pthread_jit_write_protect_np_trampoline_addr(SB), RODATA, $8
DATA ·libc_pthread_jit_write_protect_np_trampoline_addr(SB)/8, $libc_pthread_jit_write_protect_np_trampoline<>(SB)

TEXT libc_sys_icache_invalidate_trampoline<>(SB), NOSPLIT, $0-0
	JMP libc_sys_icache_invalidate(SB)

GLOBL ·libc_sys_icache_invalidate_trampoline_addr(SB), RODATA, $8
DATA ·libc_sys_icache_invalidate_trampoline_addr(SB)/8, $libc_sys_icache_invalidate_trampoline<>(SB)
