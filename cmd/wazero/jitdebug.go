//go:build jitdebug

package main

import "github.com/tetratelabs/wazero/internal/engine/wazevo/wazevoapi"

func setJITDebugWasmPath(path string) {
	wazevoapi.WasmFilePath = path
}
