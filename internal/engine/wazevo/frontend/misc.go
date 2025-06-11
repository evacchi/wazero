package frontend

import (
	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa"
	"github.com/tetratelabs/wazero/internal/wasm"
)

func FunctionIndexToFuncRef(idx wasm.Index) ssa.FuncRef {
	return ssa.FuncRef(idx)
}

// General tail call support requires a specialized calling convention. For now
// we support only a fixed number of arguments (those that will fit in registers
// on both the AMD64 and ARM64 calling conventions).
//
// On ARM64 the boundary is at 8 args, on AMD64 boundary is at 9 args
// Above that number, arguments are passed over the stack.
//
// For now, we fix the max at 8, which works on both platforms.
const tailCallMaxArgs = 8
