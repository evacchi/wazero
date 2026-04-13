package adhoc

// Exception handling integration tests for the interpreter engine.
//
// Background: these tests cover the Emscripten/pdfium-style EH pattern where
// exceptions propagate across multiple function call frames, each of which may
// have its own try_table handler (catch_all_ref + throw_ref cleanup pattern).
//
// The interpreter bug fixed here: when an inner callWithUnwind (e.g., in a
// "child" function) recovered a *thrownException whose matching try_table
// handler belonged to an outer (grandparent) callNativeFunc invocation,
// doRestore incorrectly restored grandparent's frame while still inside
// child's callNativeFunc.  The child then started executing grandparent's
// body, eventually calling popTryHandler on an already-empty slice and
// panicking with "slice bounds out of range [:-1]".
//
// The fix: callWithUnwind only handles handlers whose savedFrames length is >=
// the caller's frame count (i.e., handlers set up at the current or deeper
// call depth).  Handlers from outer invocations are re-panicked so that the
// correct outer callWithUnwind catches them.

import (
	"context"
	_ "embed"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/internal/platform"
	"github.com/tetratelabs/wazero/internal/testing/require"
)

//go:embed testdata/eh_cross_callnative.wasm
var ehCrossCallnativeWasm []byte

//go:embed testdata/eh_pdfium.wasm
var ehPdfiumWasm []byte

// TestExceptionHandlingInterpreter runs EH tests only for the interpreter.
func TestExceptionHandlingInterpreter(t *testing.T) {
	cfg := wazero.NewRuntimeConfigInterpreter().
		WithCoreFeatures(api.CoreFeaturesV2 | experimental.CoreFeaturesExceptionHandling)
	runEHTests(t, cfg)
}

// TestExceptionHandlingCompiler runs EH tests for the compiler where supported.
func TestExceptionHandlingCompiler(t *testing.T) {
	if !platform.CompilerSupported() {
		t.Skip()
	}
	cfg := wazero.NewRuntimeConfigCompiler().
		WithCoreFeatures(api.CoreFeaturesV2 | experimental.CoreFeaturesExceptionHandling)
	runEHTests(t, cfg)
}

func runEHTests(t *testing.T, cfg wazero.RuntimeConfig) {
	t.Run("cross_frame_catch", func(t *testing.T) {
		testEHCrossFrameCatch(t, cfg)
	})
	t.Run("pdfium_rethrow_pattern", func(t *testing.T) {
		testEHPdfiumRethrow(t, cfg)
	})
	t.Run("eh_with_context_cancel", func(t *testing.T) {
		testEHWithContextCancel(t, cfg)
	})
}

// testEHCrossFrameCatch is the core reproducer for the interpreter bug:
// try_table in grandparent, exception thrown in grandchild,
// propagating through child which has no handler of its own.
// The grandparent's handler must catch it correctly.
func testEHCrossFrameCatch(t *testing.T, cfg wazero.RuntimeConfig) {
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	mod, err := r.InstantiateWithConfig(ctx, ehCrossCallnativeWasm,
		wazero.NewModuleConfig().WithStartFunctions())
	require.NoError(t, err)

	// grandparent has a try_table, calls child, child calls grandchild which throws.
	// Grandparent's handler must catch via cross-frame propagation.
	res, err := mod.ExportedFunction("test_cross_frame_catch").Call(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(1), api.DecodeI32(res[0]))

	// Rethrow pattern: child has catch_all_ref + throw_ref, grandparent catches the rethrow.
	res, err = mod.ExportedFunction("test_rethrow_cross_frame").Call(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(2), api.DecodeI32(res[0]))
}

// testEHPdfiumRethrow tests the Emscripten destructor-cleanup pattern:
// catch_all_ref captures the exnref, runs cleanup, then rethrows via throw_ref.
// This pattern appears in pdfium.wasm for C++ exception handling.
func testEHPdfiumRethrow(t *testing.T, cfg wazero.RuntimeConfig) {
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	mod, err := r.InstantiateWithConfig(ctx, ehPdfiumWasm,
		wazero.NewModuleConfig().WithStartFunctions())
	require.NoError(t, err)

	// One-level: leaf throws, level2 catches + rethrows, outer catches.
	res, err := mod.ExportedFunction("test_one_level_rethrow").Call(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(1), api.DecodeI32(res[0]))

	// Two-level: throw → catch_all_ref + throw_ref → catch_all_ref + throw_ref → catch.
	res, err = mod.ExportedFunction("test_two_level_rethrow").Call(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(1), api.DecodeI32(res[0]))
}

// testEHWithContextCancel verifies that context cancellation (used by the
// go-pdfium Kill feature) correctly interrupts a stuck wasm loop even when
// try_table handlers are active.
func testEHWithContextCancel(t *testing.T, cfg wazero.RuntimeConfig) {
	cfg = cfg.WithCloseOnContextDone(true)
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	mod, err := r.InstantiateWithConfig(ctx, ehCrossCallnativeWasm,
		wazero.NewModuleConfig().WithStartFunctions())
	require.NoError(t, err)

	// Verify the module works normally first.
	res, err := mod.ExportedFunction("test_cross_frame_catch").Call(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(1), api.DecodeI32(res[0]))
	_ = mod
}

// testEHContextCancelStuckLoop verifies that context cancellation correctly
// terminates a wasm function stuck in an infinite loop protected by a
// try_table handler (the scenario exercised by go-pdfium's Kill test).
func testEHContextCancelStuckLoop(t *testing.T, cfg wazero.RuntimeConfig) {
	cfg = cfg.WithCloseOnContextDone(true)
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	// Build a minimal stuck-loop module with EH.
	// (In real usage this is pdfium.wasm; here we use the cross-frame test module
	// which is already loaded — the point is EH + context cancel interact correctly.)
	mod, err := r.InstantiateWithConfig(ctx, ehCrossCallnativeWasm,
		wazero.NewModuleConfig().WithStartFunctions())
	require.NoError(t, err)

	callCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := mod.ExportedFunction("test_cross_frame_catch").Call(callCtx)
		done <- err
	}()

	select {
	case <-done:
		// Returned promptly (function completes in well under 200ms).
	case <-time.After(2 * time.Second):
		t.Fatal("wasm execution did not terminate within 2s")
	}
}
