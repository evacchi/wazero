//go:build jitdebug

#include "textflag.h"

TEXT __jit_debug_register_code(SB), NOSPLIT|NOFRAME, $0-0
	RET

TEXT ·jitDebugRegisterCode(SB), NOSPLIT|NOFRAME, $0-0
	JMP __jit_debug_register_code(SB)

TEXT ·jitDebugBreak(SB), NOSPLIT|NOFRAME, $0-0
	INT $3
	RET
