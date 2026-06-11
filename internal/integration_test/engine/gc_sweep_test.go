package adhoc

import (
	"context"
	_ "embed"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/internal/testing/require"
	"github.com/tetratelabs/wazero/internal/wasm"
)

//go:embed testdata/gc_nested_ref.wasm
var gcNestedRefWasm []byte

//go:embed testdata/gc_alloc_many.wasm
var gcAllocManyWasm []byte

//go:embed testdata/gc_sweep_reentrant.wasm
var gcSweepReentrantWasm []byte

// TestGcNestedRefSurvivesGC validates that a struct reachable only through
// another struct's field survives Go's garbage collector.
//
// $inner is reachable through $outer's field. Because fields store Go
// pointers (*WasmStruct), Go's GC traces the graph and keeps $inner
// alive. We detect premature collection via runtime.SetFinalizer.
func TestGcNestedRefSurvivesGC(t *testing.T) {
	ctx := context.Background()
	cfg := wazero.NewRuntimeConfigInterpreter().
		WithCoreFeatures(api.CoreFeaturesV2 | experimental.CoreFeaturesGC)
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	mod, err := r.InstantiateWithConfig(ctx, gcNestedRefWasm,
		wazero.NewModuleConfig().WithStartFunctions())
	require.NoError(t, err)

	_, err = mod.ExportedFunction("setup").Call(ctx)
	require.NoError(t, err)

	// After setup + sweep at Call() return, GCRoots has only $outer
	// (from the global). $inner is removed from GCRoots.
	// Fish out the inner struct through the global → outer → field.
	mi := mod.(*wasm.ModuleInstance)
	outerTagged := mi.Globals[0].Val
	outer := (*wasm.WasmStruct)(wasm.UntagGCPointer(outerTagged))

	// The field stores inner — either as *WasmStruct (Go pointer, after fix)
	// or as uint64 (tagged pointer, before fix). Extract the *WasmStruct
	// either way so we can set a finalizer.
	var inner *wasm.WasmStruct
	switch v := outer.Fields[0].(type) {
	case *wasm.WasmStruct:
		inner = v
	case uint64:
		inner = (*wasm.WasmStruct)(wasm.UntagGCPointer(v))
	}

	var finalized atomic.Bool
	runtime.SetFinalizer(inner, func(*wasm.WasmStruct) {
		finalized.Store(true)
	})
	inner = nil // clear local ref; only the field (if Go-traceable) keeps it alive

	for i := 0; i < 10; i++ {
		runtime.GC()
		runtime.Gosched()
	}

	if finalized.Load() {
		t.Fatal("inner struct was collected by Go's GC despite being " +
			"reachable through outer's field — fields must store Go pointers")
	}

	// Also verify the value is readable through wasm.
	res, err := mod.ExportedFunction("read_inner").Call(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(42), api.DecodeI32(res[0]))
}

// TestGcSweepReentrantPreservesLiveObject reproduces the bug where a re-entrant
// host callback triggers GCSweep on its inner callEngine stack, which doesn't
// contain objects live in the outer call frame. The sweep removes those objects
// from GCRoots — which is incorrect because the outer frame still holds a
// reference to them (as a tagged uint64 in a local variable). If Go's GC then
// runs, it cannot see the tagged uint64 and may collect the object.
//
// The wasm module allocates a struct, stores it in a local, then calls a host
// function. The host function calls back into wasm (creating a nested Call()
// with its own callEngine and stack). When the inner Call() returns, GCSweep
// scans only the inner stack — the struct (in the outer frame's local) is
// invisible, so it's removed from GCRoots.
//
// This test detects the bug by checking GCRoots size: after the inner call,
// the struct allocated by the outer frame MUST still be in GCRoots.
func TestGcSweepReentrantPreservesLiveObject(t *testing.T) {
	ctx := context.Background()
	cfg := wazero.NewRuntimeConfigInterpreter().
		WithCoreFeatures(api.CoreFeaturesV2 | experimental.CoreFeaturesGC)
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	var mi *wasm.ModuleInstance
	var rootsBefore, rootsAfter int

	_, err := r.NewHostModuleBuilder("host").
		NewFunctionBuilder().WithFunc(func(ctx context.Context, mod api.Module) {
		rootsBefore = len(mi.GCRoots)
		mod.ExportedFunction("nop").Call(ctx)
		rootsAfter = len(mi.GCRoots)
	}).Export("callback").
		Instantiate(ctx)
	require.NoError(t, err)

	mod, err := r.InstantiateWithConfig(ctx, gcSweepReentrantWasm,
		wazero.NewModuleConfig().WithStartFunctions())
	require.NoError(t, err)
	mi = mod.(*wasm.ModuleInstance)

	res, err := mod.ExportedFunction("test").Call(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(42), api.DecodeI32(res[0]))

	// Before the inner call, the outer frame had just allocated a struct
	// via struct.new, so GCRoots should have at least 1 entry.
	// After the inner call (with GCSweep), GCRoots must still have that
	// entry — the struct is live in the outer frame's local.
	t.Logf("GCRoots before inner call: %d, after: %d", rootsBefore, rootsAfter)
	if rootsAfter < rootsBefore {
		t.Errorf("GCSweep removed %d entries during re-entrant call — "+
			"objects live in the outer frame were incorrectly swept",
			rootsBefore-rootsAfter)
	}
}

// TestGcAllocManyNoSweep verifies that with sweep disabled, all allocations
// accumulate in GCRoots. This is the expected (if wasteful) behavior until
// a proper tracing sweep is implemented.
func TestGcAllocManyNoSweep(t *testing.T) {
	ctx := context.Background()
	cfg := wazero.NewRuntimeConfigInterpreter().
		WithCoreFeatures(api.CoreFeaturesV2 | experimental.CoreFeaturesGC)
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	mod, err := r.InstantiateWithConfig(ctx, gcAllocManyWasm,
		wazero.NewModuleConfig().WithStartFunctions())
	require.NoError(t, err)

	_, err = mod.ExportedFunction("allocate_many").Call(ctx)
	require.NoError(t, err)

	mi := mod.(*wasm.ModuleInstance)
	gcRootsLen := len(mi.GCRoots)

	// With sweep disabled, all 100K objects stay in GCRoots.
	if gcRootsLen < 100000 {
		t.Errorf("GCRoots has %d entries, expected ~100000 (sweep is disabled)", gcRootsLen)
	}
}
