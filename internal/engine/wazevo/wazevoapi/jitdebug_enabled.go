//go:build jitdebug

package wazevoapi

const JITDebugEnabled = true

// jitDebugRegisterCode calls __jit_debug_register_code.
// Implemented in jitdebug_asm_{arch}.s.
func jitDebugRegisterCode()

// jitDebugBreak traps after JIT registration so the debugger stops.
// Implemented in jitdebug_asm_{arch}.s.
func jitDebugBreak()
