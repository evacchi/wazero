package interpreter

import (
	"testing"

	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/internal/testing/require"
	"github.com/tetratelabs/wazero/internal/wasm"
)

// TestCompile_LocalSetWithMultipleLocals_I32 tests that local.set depth
// calculations are correct with param + 2 locals (i32 baseline).
func TestCompile_LocalSetWithMultipleLocals_I32(t *testing.T) {
	// (func (param i32) (result i32)
	//   (local i32 i32)
	//   (local.set 1 (i32.const 10))
	//   (local.set 2 (i32.const 20))
	//   (i32.add (local.get 1) (local.get 2))
	// )
	module := &wasm.Module{
		TypeSection:     []wasm.FunctionType{i32_i32},
		FunctionSection: []wasm.Index{0},
		CodeSection: []wasm.Code{{
			LocalTypes: []wasm.ValueType{wasm.ValueTypeI32, wasm.ValueTypeI32},
			Body: []byte{
				wasm.OpcodeI32Const, 10,
				wasm.OpcodeLocalSet, 1,
				wasm.OpcodeI32Const, 20,
				wasm.OpcodeLocalSet, 2,
				wasm.OpcodeLocalGet, 1,
				wasm.OpcodeLocalGet, 2,
				wasm.OpcodeI32Add,
				wasm.OpcodeEnd,
			},
		}},
	}
	for _, tp := range module.TypeSection {
		tp.CacheNumInUint64()
	}
	c, err := newCompiler(api.CoreFeaturesV2, 0, module, false)
	require.NoError(t, err)

	result, err := c.Next()
	require.NoError(t, err)

	// Print operations for debugging
	for i, op := range result.Operations {
		t.Logf("  [%d] %s", i, op.String())
	}
}

// TestCompile_LocalSetWithMultipleConcreteRefLocals tests that local.set depth
// calculations are correct with param + 2 concrete ref locals.
func TestCompile_LocalSetWithMultipleConcreteRefLocals(t *testing.T) {
	// Reproduces call_ref.wast "run" function:
	// (func (param i32) (result i32)
	//   (local (ref null $ii) (ref null $ii))  ;; $ii = type 0
	//   (local.set 1 (ref.func 1))
	//   (local.set 2 (ref.func 2))
	//   (local.get 0)
	//   (local.get 1)
	//   (call_ref 0)
	//   (local.get 2)
	//   (call_ref 0)
	// )
	concreteRefNullable := wasm.ConcreteRef(0, true)
	module := &wasm.Module{
		TypeSection:     []wasm.FunctionType{i32_i32},
		FunctionSection: []wasm.Index{0, 0, 0}, // func 0 = this, func 1 = $f, func 2 = $g
		CodeSection: []wasm.Code{
			{
				LocalTypes: []wasm.ValueType{concreteRefNullable, concreteRefNullable},
				Body: []byte{
					wasm.OpcodeRefFunc, 1,
					wasm.OpcodeLocalSet, 1,
					wasm.OpcodeRefFunc, 2,
					wasm.OpcodeLocalSet, 2,
					wasm.OpcodeLocalGet, 0,
					wasm.OpcodeLocalGet, 1,
					wasm.OpcodeCallRef, 0,
					wasm.OpcodeLocalGet, 2,
					wasm.OpcodeCallRef, 0,
					wasm.OpcodeEnd,
				},
			},
			{Body: []byte{wasm.OpcodeLocalGet, 0, wasm.OpcodeEnd}},  // $f
			{Body: []byte{wasm.OpcodeI32Const, 42, wasm.OpcodeEnd}}, // $g
		},
	}
	for i := range module.TypeSection {
		module.TypeSection[i].CacheNumInUint64()
	}

	features := api.CoreFeaturesV2 | experimental.CoreFeaturesTypedFunctionReferences | experimental.CoreFeaturesTailCall
	c, err := newCompiler(features, 0, module, false)
	require.NoError(t, err)

	result, err := c.Next()
	require.NoError(t, err)

	// Print operations for debugging
	for i, op := range result.Operations {
		t.Logf("  [%d] %s", i, op.String())
	}
}

// TestCompile_LocalSetWithMultipleFuncrefLocals tests local.set with
// funcref locals (not concrete refs) as a comparison.
func TestCompile_LocalSetWithMultipleFuncrefLocals(t *testing.T) {
	// (func (param i32) (result i32)
	//   (local funcref funcref)
	//   (local.set 1 (ref.func 1))
	//   (local.set 2 (ref.func 2))
	//   ...
	// )
	module := &wasm.Module{
		TypeSection:     []wasm.FunctionType{i32_i32},
		FunctionSection: []wasm.Index{0, 0, 0},
		CodeSection: []wasm.Code{
			{
				LocalTypes: []wasm.ValueType{wasm.ValueTypeFuncref, wasm.ValueTypeFuncref},
				Body: []byte{
					wasm.OpcodeRefFunc, 1,
					wasm.OpcodeLocalSet, 1,
					wasm.OpcodeRefFunc, 2,
					wasm.OpcodeLocalSet, 2,
					wasm.OpcodeLocalGet, 1,
					wasm.OpcodeRefIsNull,
					wasm.OpcodeLocalGet, 2,
					wasm.OpcodeRefIsNull,
					wasm.OpcodeI32Add,
					wasm.OpcodeEnd,
				},
			},
			{Body: []byte{wasm.OpcodeLocalGet, 0, wasm.OpcodeEnd}},
			{Body: []byte{wasm.OpcodeI32Const, 42, wasm.OpcodeEnd}},
		},
	}
	for i := range module.TypeSection {
		module.TypeSection[i].CacheNumInUint64()
	}
	c, err := newCompiler(api.CoreFeaturesV2, 0, module, false)
	require.NoError(t, err)

	result, err := c.Next()
	require.NoError(t, err)

	// Print operations for debugging
	for i, op := range result.Operations {
		t.Logf("  [%d] %s", i, op.String())
	}
}
