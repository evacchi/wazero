//go:build jitdebug

package wazevoapi

const JITDebugEnabled = true

// jitDebugRegisterCode calls __jit_debug_register_code.
// Implemented in jitdebug_asm_{arch}.s.
func jitDebugRegisterCode()
