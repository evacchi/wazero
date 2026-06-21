//go:build jitdebug

#include "textflag.h"

// __jit_debug_register_code is the GDB/LLDB JIT debug interface hook.
// The debugger sets a breakpoint on this symbol. When called, it reads
// __jit_debug_descriptor to discover newly registered JIT code.
// Using a raw C name (no · prefix) so the Go linker doesn't mangle it.
TEXT __jit_debug_register_code(SB), NOSPLIT|NOFRAME, $0-0
	RET

// Go-callable trampoline.
TEXT ·jitDebugRegisterCode(SB), NOSPLIT|NOFRAME, $0-0
	JMP __jit_debug_register_code(SB)

// jitDebugBreak traps after JIT registration. Under a debugger,
// skip with: register write pc `$pc+4`
TEXT ·jitDebugBreak(SB), NOSPLIT|NOFRAME, $0-0
	BRK $0xF000
	RET
