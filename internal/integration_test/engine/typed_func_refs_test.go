package adhoc

import (
	"context"
	"os"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/internal/platform"
	"github.com/tetratelabs/wazero/internal/testing/require"
)

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
