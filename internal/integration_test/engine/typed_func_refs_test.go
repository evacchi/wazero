package adhoc

import (
	"context"
	"os"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/internal/platform"
	"github.com/tetratelabs/wazero/internal/testing/binaryencoding"
	"github.com/tetratelabs/wazero/internal/testing/require"
	"github.com/tetratelabs/wazero/internal/wasm"
)

func typedFuncRefsConfigs() []struct {
	name   string
	config wazero.RuntimeConfig
} {
	configs := []struct {
		name   string
		config wazero.RuntimeConfig
	}{
		{"interpreter", wazero.NewRuntimeConfigInterpreter().WithCoreFeatures(api.CoreFeaturesV2)},
	}
	if platform.CompilerSupported() {
		configs = append(configs, struct {
			name   string
			config wazero.RuntimeConfig
		}{"compiler", wazero.NewRuntimeConfigCompiler().WithCoreFeatures(api.CoreFeaturesV2)})
	}
	return configs
}

// TestLocalSetMultipleI32Locals validates that local.set works correctly
// when there are multiple locals (no concrete refs). This is a baseline test
// to verify that the existing local.set mechanism works.
func TestLocalSetMultipleI32Locals(t *testing.T) {
	// (module
	//   (func (export "test") (param i32) (result i32)
	//     (local i32)   ;; local 1
	//     (local i32)   ;; local 2
	//     (local.set 1 (i32.const 10))
	//     (local.set 2 (i32.const 20))
	//     (i32.add (local.get 1) (local.get 2))
	//   )
	// )
	mod := &wasm.Module{
		TypeSection: []wasm.FunctionType{
			{
				Params: []wasm.ValueType{wasm.ValueTypeI32}, Results: []wasm.ValueType{wasm.ValueTypeI32},
				ParamNumInUint64: 1, ResultNumInUint64: 1,
			},
		},
		FunctionSection: []wasm.Index{0},
		CodeSection: []wasm.Code{
			{
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
			},
		},
		ExportSection: []wasm.Export{{Name: "test", Type: wasm.ExternTypeFunc, Index: 0}},
	}

	for _, tc := range typedFuncRefsConfigs() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			r := wazero.NewRuntimeWithConfig(ctx, tc.config)
			defer r.Close(ctx)

			buf := binaryencoding.EncodeModule(mod)
			inst, err := r.InstantiateWithConfig(ctx, buf, wazero.NewModuleConfig())
			require.NoError(t, err)

			fn := inst.ExportedFunction("test")
			require.NotNil(t, fn)

			results, err := fn.Call(ctx, 5)
			require.NoError(t, err)
			require.Equal(t, []uint64{30}, results) // 10 + 20 = 30
		})
	}
}

// TestLocalSetMultipleFuncrefLocals validates that local.set works correctly
// when there are multiple funcref locals. This tests whether the depth
// calculation for local.set is correct with ref type locals.
func TestLocalSetMultipleFuncrefLocals(t *testing.T) {
	// (module
	//   (func (export "test") (result i32)
	//     (local funcref) ;; local 0
	//     (local funcref) ;; local 1
	//     ;; set local 0 to null, set local 1 to null
	//     (local.set 0 (ref.null func))
	//     (local.set 1 (ref.null func))
	//     ;; check both are null
	//     (i32.add
	//       (ref.is_null (local.get 0))
	//       (ref.is_null (local.get 1))
	//     )
	//   )
	// )
	mod := &wasm.Module{
		TypeSection: []wasm.FunctionType{
			{Results: []wasm.ValueType{wasm.ValueTypeI32}, ResultNumInUint64: 1},
		},
		FunctionSection: []wasm.Index{0},
		CodeSection: []wasm.Code{
			{
				LocalTypes: []wasm.ValueType{wasm.ValueTypeFuncref, wasm.ValueTypeFuncref},
				Body: []byte{
					wasm.OpcodeRefNull, wasm.ValueTypeFuncref.Kind(),
					wasm.OpcodeLocalSet, 0,
					wasm.OpcodeRefNull, wasm.ValueTypeFuncref.Kind(),
					wasm.OpcodeLocalSet, 1,
					wasm.OpcodeLocalGet, 0,
					wasm.OpcodeRefIsNull,
					wasm.OpcodeLocalGet, 1,
					wasm.OpcodeRefIsNull,
					wasm.OpcodeI32Add,
					wasm.OpcodeEnd,
				},
			},
		},
		ExportSection: []wasm.Export{{Name: "test", Type: wasm.ExternTypeFunc, Index: 0}},
	}

	for _, tc := range typedFuncRefsConfigs() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			r := wazero.NewRuntimeWithConfig(ctx, tc.config)
			defer r.Close(ctx)

			buf := binaryencoding.EncodeModule(mod)
			inst, err := r.InstantiateWithConfig(ctx, buf, wazero.NewModuleConfig())
			require.NoError(t, err)

			fn := inst.ExportedFunction("test")
			require.NotNil(t, fn)

			results, err := fn.Call(ctx)
			require.NoError(t, err)
			require.Equal(t, uint64(2), results[0]) // both locals are null
		})
	}
}

// TestLocalSetThreeLocals validates local.set with 3 locals targeting each one
// to verify depth calculations are correct for all positions.
func TestLocalSetThreeLocals(t *testing.T) {
	// (module
	//   (func (export "test") (result i32)
	//     (local i32) ;; local 0
	//     (local i32) ;; local 1
	//     (local i32) ;; local 2
	//     (local.set 0 (i32.const 10))
	//     (local.set 1 (i32.const 20))
	//     (local.set 2 (i32.const 30))
	//     ;; Return local 0 + local 1 + local 2
	//     (i32.add (i32.add (local.get 0) (local.get 1)) (local.get 2))
	//   )
	// )
	mod := &wasm.Module{
		TypeSection: []wasm.FunctionType{
			{Results: []wasm.ValueType{wasm.ValueTypeI32}, ResultNumInUint64: 1},
		},
		FunctionSection: []wasm.Index{0},
		CodeSection: []wasm.Code{
			{
				LocalTypes: []wasm.ValueType{wasm.ValueTypeI32, wasm.ValueTypeI32, wasm.ValueTypeI32},
				Body: []byte{
					wasm.OpcodeI32Const, 10,
					wasm.OpcodeLocalSet, 0,
					wasm.OpcodeI32Const, 20,
					wasm.OpcodeLocalSet, 1,
					wasm.OpcodeI32Const, 30,
					wasm.OpcodeLocalSet, 2,
					wasm.OpcodeLocalGet, 0,
					wasm.OpcodeLocalGet, 1,
					wasm.OpcodeI32Add,
					wasm.OpcodeLocalGet, 2,
					wasm.OpcodeI32Add,
					wasm.OpcodeEnd,
				},
			},
		},
		ExportSection: []wasm.Export{{Name: "test", Type: wasm.ExternTypeFunc, Index: 0}},
	}

	for _, tc := range typedFuncRefsConfigs() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			r := wazero.NewRuntimeWithConfig(ctx, tc.config)
			defer r.Close(ctx)

			buf := binaryencoding.EncodeModule(mod)
			inst, err := r.InstantiateWithConfig(ctx, buf, wazero.NewModuleConfig())
			require.NoError(t, err)

			fn := inst.ExportedFunction("test")
			require.NotNil(t, fn)

			results, err := fn.Call(ctx)
			require.NoError(t, err)
			require.Equal(t, []uint64{60}, results) // 10 + 20 + 30 = 60
		})
	}
}

// TestLocalSetParamAndMultipleLocals validates local.set when there is a param
// and multiple locals, setting each local separately.
func TestLocalSetParamAndMultipleLocals(t *testing.T) {
	// (module
	//   (func (export "test") (param i32) (result i32)
	//     (local i32) ;; local 1
	//     (local i32) ;; local 2
	//     (local.set 1 (i32.const 100))
	//     (local.set 2 (i32.const 200))
	//     ;; Return param + local 1 + local 2
	//     (i32.add (i32.add (local.get 0) (local.get 1)) (local.get 2))
	//   )
	// )
	mod := &wasm.Module{
		TypeSection: []wasm.FunctionType{
			{
				Params: []wasm.ValueType{wasm.ValueTypeI32}, Results: []wasm.ValueType{wasm.ValueTypeI32},
				ParamNumInUint64: 1, ResultNumInUint64: 1,
			},
		},
		FunctionSection: []wasm.Index{0},
		CodeSection: []wasm.Code{
			{
				LocalTypes: []wasm.ValueType{wasm.ValueTypeI32, wasm.ValueTypeI32},
				Body: []byte{
					wasm.OpcodeI32Const, 11, // 11 in signed LEB128
					wasm.OpcodeLocalSet, 1,
					wasm.OpcodeI32Const, 22, // 22 in signed LEB128
					wasm.OpcodeLocalSet, 2,
					wasm.OpcodeLocalGet, 0,
					wasm.OpcodeLocalGet, 1,
					wasm.OpcodeI32Add,
					wasm.OpcodeLocalGet, 2,
					wasm.OpcodeI32Add,
					wasm.OpcodeEnd,
				},
			},
		},
		ExportSection: []wasm.Export{{Name: "test", Type: wasm.ExternTypeFunc, Index: 0}},
	}

	for _, tc := range typedFuncRefsConfigs() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			r := wazero.NewRuntimeWithConfig(ctx, tc.config)
			defer r.Close(ctx)

			buf := binaryencoding.EncodeModule(mod)
			inst, err := r.InstantiateWithConfig(ctx, buf, wazero.NewModuleConfig())
			require.NoError(t, err)

			fn := inst.ExportedFunction("test")
			require.NotNil(t, fn)

			results, err := fn.Call(ctx, 5)
			require.NoError(t, err)
			require.Equal(t, uint64(38), results[0]) // 5 + 11 + 22 = 38
		})
	}
}

// TestCallRefWithConcreteRefLocals reproduces the call_ref.wast "run" function
// which uses (local (ref null $ii)) concrete ref locals, sets them with ref.func,
// and calls through them with call_ref.
func TestCallRefWithConcreteRefLocals(t *testing.T) {
	buf, err := os.ReadFile("../spectest/typed-function-references/testdata/call_ref.0.wasm")
	if err != nil {
		t.Skipf("could not read call_ref.0.wasm: %v", err)
	}

	configs := []struct {
		name   string
		config wazero.RuntimeConfig
	}{
		{"interpreter", wazero.NewRuntimeConfigInterpreter().WithCoreFeatures(
			api.CoreFeaturesV2 | experimental.CoreFeaturesTypedFunctionReferences | experimental.CoreFeaturesTailCall,
		)},
	}
	if platform.CompilerSupported() {
		configs = append(configs, struct {
			name   string
			config wazero.RuntimeConfig
		}{"compiler", wazero.NewRuntimeConfigCompiler().WithCoreFeatures(
			api.CoreFeaturesV2 | experimental.CoreFeaturesTypedFunctionReferences | experimental.CoreFeaturesTailCall,
		)})
	}

	for _, tc := range configs {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			r := wazero.NewRuntimeWithConfig(ctx, tc.config)
			defer r.Close(ctx)

			inst, err := r.InstantiateWithConfig(ctx, buf, wazero.NewModuleConfig())
			require.NoError(t, err)

			fn := inst.ExportedFunction("run")
			require.NotNil(t, fn)

			results, err := fn.Call(ctx, 0)
			require.NoError(t, err)
			require.Equal(t, uint64(0), results[0])

			results, err = fn.Call(ctx, 3)
			require.NoError(t, err)
			expected := uint64(0xfffffff7) // -9 as i32
			require.Equal(t, expected, results[0])
		})
	}
}
