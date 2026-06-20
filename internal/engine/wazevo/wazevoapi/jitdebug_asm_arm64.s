//go:build jitdebug

#include "textflag.h"

// __jit_debug_register_code is the GDB/LLDB JIT debug interface hook.
// The debugger sets a breakpoint on this symbol. When called, it reads
// __jit_debug_descriptor to discover newly registered JIT code.
// Using a raw C name (no · prefix) so the Go linker doesn't mangle it.
TEXT __jit_debug_register_code(SB), NOSPLIT|NOFRAME, $0-0
	RET

// Go-callable trampoline that jumps to the C-named symbol above.
TEXT ·jitDebugRegisterCode(SB), NOSPLIT|NOFRAME, $0-0
	JMP __jit_debug_register_code(SB)
