package wazevo

import "github.com/tetratelabs/wazero/api"

// ShadowRefsTopOf returns how many shadow slots are still reserved on f's call
// engine. Exported for tests in the wazevo_test package, which cannot import
// this one's unexported fields.
func ShadowRefsTopOf(f api.Function) uintptr {
	return f.(*callEngine).execCtx.shadowRefsTop
}

// SetShadowStoreHook makes f's call engine run hook after every shadow store.
func SetShadowStoreHook(f api.Function, hook func()) {
	f.(*callEngine).shadowStoreHook = hook
}
