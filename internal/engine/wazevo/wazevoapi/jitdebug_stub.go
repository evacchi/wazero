//go:build !jitdebug

package wazevoapi

func jitDebugRegisterCode() {}
func jitDebugBreak()        {}
