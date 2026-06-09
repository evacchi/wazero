package adhoc

// End-to-end tests for wasm-gc using GraalVM WebImage binaries.
// These tests are not committed yet — they exercise the import matching
// fallback for host functions with concrete GC ref params and require
// internal API access.

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"math"
	"os"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/internal/testing/require"
	"github.com/tetratelabs/wazero/internal/wasm"
	binaryformat "github.com/tetratelabs/wazero/internal/wasm/binary"
)

//go:embed testdata/java_webimage_hello.wasm
var javaWebImageHelloWasm []byte

func TestGcE2EJavaWebImageCompile(t *testing.T) {
	features := api.CoreFeaturesV2 |
		experimental.CoreFeaturesExceptionHandling |
		experimental.CoreFeaturesGC

	start := time.Now()
	module, err := binaryformat.DecodeModule(javaWebImageHelloWasm, features, 65536, false, false, false)
	require.NoError(t, err)
	t.Logf("decode: %v (%d types, %d functions, %d imports)",
		time.Since(start), len(module.TypeSection), len(module.FunctionSection), len(module.ImportSection))

	phases := map[int]string{
		-1: "tableInitExprs", -2: "imports", -3: "globals", -4: "tableValidation",
		-10: "concreteRefTypes", -11: "typeSection", -12: "startSection", -13: "allDeclarations",
	}
	validateStart := time.Now()
	wasm.SetValidateProgress(func(idx, total int) {
		if name, ok := phases[idx]; ok {
			t.Logf("  validate phase: %s (%v)", name, time.Since(validateStart))
		} else {
			t.Logf("  validate func %d/%d (%v)", idx, total, time.Since(validateStart))
		}
	})
	defer wasm.SetValidateProgress(nil)
	err = module.Validate(features)
	require.NoError(t, err)
	t.Logf("validate total: %v", time.Since(validateStart))

	ctx := context.Background()
	cfg := wazero.NewRuntimeConfigInterpreter().WithCoreFeatures(features)
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	store := extractStore(r)

	start = time.Now()
	typeIDs, err := store.GetFunctionTypeIDs(module.TypeSection)
	require.NoError(t, err)
	t.Logf("typeIDs: %v (%d IDs)", time.Since(start), len(typeIDs))

	module.BuildMemoryDefinitions()
	module.AssignModuleID(javaWebImageHelloWasm, nil, false)

	start = time.Now()
	err = store.Engine.CompileModule(ctx, module, nil, false)
	require.NoError(t, err)
	t.Logf("compile: %v", time.Since(start))
}

func TestGcE2EJavaWebImageInstantiate(t *testing.T) {
	var stdout, stderr bytes.Buffer
	ctx := context.Background()
	cfg := wazero.NewRuntimeConfigInterpreter().
		WithCoreFeatures(api.CoreFeaturesV2 |
			experimental.CoreFeaturesExceptionHandling |
			experimental.CoreFeaturesGC)
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	refs := newExternRefStore()

	// --- interop module ---
	_, err := r.NewHostModuleBuilder("interop").
		NewFunctionBuilder().WithFunc(func(_ context.Context) uintptr {
		return refs.store("")
	}).Export("genBacktrace").
		NewFunctionBuilder().WithFunc(func(_ context.Context) float64 {
		return float64(time.Now().UnixMilli())
	}).Export("Date.now").
		NewFunctionBuilder().WithFunc(func(_ context.Context) float64 {
		return float64(time.Now().UnixNano()) / 1e6
	}).Export("performance.now").
		NewFunctionBuilder().WithFunc(func(_ context.Context, code int32) {
		t.Logf("[wasm] exit code: %d", code)
	}).Export("runtime.setExitCode").
		NewFunctionBuilder().WithFunc(func(_ context.Context, ref uintptr) {
		if obj := refs.load(ref); obj != nil {
			if chars, ok := obj.([]uint16); ok {
				for _, c := range chars {
					stdout.WriteByte(byte(c))
				}
			} else if s, ok := obj.(string); ok {
				stdout.WriteString(s)
			}
		}
	}).Export("stdoutWriter.printChars").
		NewFunctionBuilder().WithFunc(func(_ context.Context, ref uintptr) {
		if obj := refs.load(ref); obj != nil {
			if chars, ok := obj.([]uint16); ok {
				for _, c := range chars {
					stderr.WriteByte(byte(c))
				}
			} else {
				stderr.WriteString(obj.(string))
			}
		}
	}).Export("stderrWriter.printChars").
		NewFunctionBuilder().WithFunc(func(_ context.Context) {
	}).Export("stderrWriter.flush").
		NewFunctionBuilder().WithFunc(func(_ context.Context) {
	}).Export("stdoutWriter.flush").
		NewFunctionBuilder().WithFunc(func(_ context.Context, ref uintptr) {
		t.Logf("[wasm:log] %v", refs.load(ref))
	}).Export("llog").
		NewFunctionBuilder().WithFunc(func(_ context.Context, _ uintptr) uintptr {
		return refs.store("<stack trace>")
	}).Export("formatStackTrace").
		NewFunctionBuilder().WithFunc(func(_ context.Context) uintptr {
		return refs.store(".")
	}).Export("getCurrentWorkingDirectory").
		Instantiate(ctx)
	require.NoError(t, err)

	// --- compat module ---
	_, err = r.NewHostModuleBuilder("compat").
		NewFunctionBuilder().WithFunc(func(_ context.Context, v float64) float64 {
		return math.Log(v)
	}).Export("f64log").
		Instantiate(ctx)
	require.NoError(t, err)

	// --- jsbody module ---
	_, err = r.NewHostModuleBuilder("jsbody").
		NewFunctionBuilder().WithFunc(func(_ context.Context, _ uintptr, v uintptr) int32 {
		if refs.load(v) == "undefined" {
			return 1
		}
		return 0
	}).Export("_JSFunctionIntrinsics.isUndefined___Object_Z").
		NewFunctionBuilder().WithFunc(func(_ context.Context, _ uintptr, v uintptr) uintptr {
		return v
	}).Export("_JSConversion.extractJavaScriptString___String_Object").
		NewFunctionBuilder().WithFunc(func(_ context.Context, _ uintptr, v uintptr) uintptr {
		return v
	}).Export("_JSConversion.asJavaObjectOrString___Object_Object").
		NewFunctionBuilder().WithFunc(func(_ context.Context, _ uintptr) uintptr {
		return refs.store("undefined")
	}).Export("_JSConversion.javaScriptUndefined___Object").
		NewFunctionBuilder().WithFunc(func(_ context.Context, _ uintptr, v uintptr) uintptr {
		return v
	}).Export("_JSConversion.extractJavaScriptProxy___Object_Object").
		NewFunctionBuilder().WithFunc(func(_ context.Context, _ uintptr, v uintptr) uintptr {
		return v
	}).Export("_JSConversion.javaScriptToJava___Object_Object").
		NewFunctionBuilder().WithFunc(func(_ context.Context, _ uintptr, v uintptr) uintptr {
		return v
	}).Export("_JSConversion.unproxy___Object_Object").
		NewFunctionBuilder().WithFunc(func(_ context.Context, v uintptr) uintptr {
		return v
	}).Export("_JSNumber.javaDouble___Double").
		NewFunctionBuilder().WithFunc(func(_ context.Context, a, b, c uintptr) uintptr {
		if a == b {
			return refs.store(true)
		}
		return refs.store(false)
	}).Export("_JSSymbol.referenceEquals___JSSymbol_JSSymbol_JSBoolean").
		NewFunctionBuilder().WithFunc(func(_ context.Context, v uintptr) uintptr {
		return v
	}).Export("_JSBoolean.javaBoolean___Boolean").
		NewFunctionBuilder().WithFunc(func(_ context.Context, v uintptr) uintptr {
		return v
	}).Export("_JSString.asString___String").
		NewFunctionBuilder().WithFunc(func(_ context.Context, _ uintptr) uintptr {
		return refs.store("object")
	}).Export("_JSObject.typeofString___JSString").
		NewFunctionBuilder().WithFunc(func(_ context.Context, _, _ uintptr) uintptr {
		return refs.store("undefined")
	}).Export("_JSObject.get___Object_Object").
		NewFunctionBuilder().WithFunc(func(_ context.Context, v uintptr) uintptr {
		return v
	}).Export("_JSValue.stringValue___String").
		Instantiate(ctx)
	require.NoError(t, err)

	// --- convert module ---
	// proxyCharArray has type (param (ref null 598)) (result externref).
	// The public API (api.ValueType = byte) can't express concrete GC ref
	// params, so we use the internal wasm.HostFunc + wasm.NewHostModule
	// which use wasm.ValueType (uint64) and can encode concrete refs.
	// Import matching falls back to EqualsSignature (raw uint64 comparison)
	// because the host module's TypeIDs won't match the guest's iso-recursive
	// canonical keys.
	convertModule := instantiateHostModuleWithConcreteRefs(t, ctx, r, "convert",
		[]string{"proxyCharArray"},
		map[string]*wasm.HostFunc{
			"proxyCharArray": {
				ExportName: "proxyCharArray",
				ParamTypes: []wasm.ValueType{wasm.ValueTypeConcreteRef(598, true)},
				ResultTypes: []wasm.ValueType{wasm.ValueTypeExternref},
				Code: wasm.Code{
					GoFunc: api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
						raw := stack[0]
						if raw == 0 || !wasm.IsGCRef(raw) {
							stack[0] = uint64(refs.store([]uint16{}))
							return
						}
						s := (*wasm.WasmStruct)(wasm.UntagGCPointer(raw))
						if len(s.Fields) <= 2 {
							stack[0] = uint64(refs.store([]uint16{}))
							return
						}
						arr, ok := s.Fields[2].(*wasm.WasmArray)
						if !ok || arr == nil {
							stack[0] = uint64(refs.store([]uint16{}))
							return
						}
						chars := make([]uint16, arr.Len())
						for i := range chars {
							switch v := arr.Get(uint32(i)).(type) {
							case uint16:
								chars[i] = v
							case int32:
								chars[i] = uint16(v)
							}
						}
						stack[0] = uint64(refs.store(chars))
					}),
				},
			},
		},
	)
	defer convertModule.Close(ctx)

	// Instantiate the guest module
	mod, err := r.InstantiateWithConfig(ctx, javaWebImageHelloWasm,
		wazero.NewModuleConfig().
			WithStdout(&stdout).
			WithStderr(&stderr).
			WithStartFunctions())
	require.NoError(t, err)

	// Build a Java String[] arg using the module's own exports,
	// mirroring the Java runner's toJavaStringArray / toJavaString protocol.
	greeting := "world"
	javaArgs := []string{greeting}

	arrayStringCreate := mod.ExportedFunction("array.string.create")
	arrayCharCreate := mod.ExportedFunction("array.char.create")
	arrayCharWrite := mod.ExportedFunction("array.char.write")
	stringFromChars := mod.ExportedFunction("string.fromchars")
	arrayObjectWrite := mod.ExportedFunction("array.object.write")
	mainFn := mod.ExportedFunction("main")

	require.NotNil(t, arrayStringCreate)
	require.NotNil(t, arrayCharCreate)
	require.NotNil(t, arrayCharWrite)
	require.NotNil(t, stringFromChars)
	require.NotNil(t, arrayObjectWrite)
	require.NotNil(t, mainFn)

	res, err := arrayStringCreate.Call(ctx, uint64(len(javaArgs)))
	require.NoError(t, err)
	stringArray := res[0]

	for i, s := range javaArgs {
		res, err = arrayCharCreate.Call(ctx, uint64(len(s)))
		require.NoError(t, err)
		charArray := res[0]

		for j, c := range s {
			_, err = arrayCharWrite.Call(ctx, charArray, uint64(j), uint64(c))
			require.NoError(t, err)
		}

		res, err = stringFromChars.Call(ctx, charArray)
		require.NoError(t, err)
		javaStr := res[0]

		_, err = arrayObjectWrite.Call(ctx, stringArray, uint64(i), javaStr)
		require.NoError(t, err)
	}

	_, err = mainFn.Call(ctx, stringArray)
	require.NoError(t, err)

	t.Logf("stdout: %q", stdout.String())
	t.Logf("stderr: %q", stderr.String())
	require.Contains(t, stdout.String(), "Hello")
}

type externRefStore struct {
	refs map[uintptr]any
	next uintptr
}

func newExternRefStore() *externRefStore {
	return &externRefStore{refs: make(map[uintptr]any), next: 1}
}

func (s *externRefStore) store(obj any) uintptr {
	if obj == nil {
		return 0
	}
	id := s.next
	s.next++
	s.refs[id] = obj
	return id
}

func (s *externRefStore) load(id uintptr) any {
	if id == 0 {
		return nil
	}
	return s.refs[id]
}

// instantiateHostModuleWithConcreteRefs creates and instantiates a host module
// using internal wasm.ValueType (uint64) params — needed for concrete GC ref
// types that api.ValueType (byte) can't represent.
func instantiateHostModuleWithConcreteRefs(
	t *testing.T, ctx context.Context, r wazero.Runtime,
	moduleName string,
	exportNames []string,
	funcs map[string]*wasm.HostFunc,
) api.Closer {
	t.Helper()

	features := api.CoreFeaturesV2 |
		experimental.CoreFeaturesExceptionHandling |
		experimental.CoreFeaturesGC

	module, err := wasm.NewHostModule(moduleName, exportNames, funcs, features)
	require.NoError(t, err)

	// NewHostModule doesn't call CacheNumInUint64 (reflection-parsed
	// functions set it directly). We need it for manually constructed
	// HostFunc entries.
	for i := range module.TypeSection {
		module.TypeSection[i].CacheNumInUint64()
	}

	store := extractStore(r)

	err = store.Engine.CompileModule(ctx, module, nil, false)
	require.NoError(t, err)

	// TypeIDs will differ from the guest module's (the host module can't
	// replicate the guest's rec group), but the EqualsSignature fallback
	// in import resolution handles the mismatch via raw uint64 comparison.
	typeIDs, err := store.GetFunctionTypeIDs(module.TypeSection)
	require.NoError(t, err)

	mi, err := store.Instantiate(ctx, module, moduleName, nil, typeIDs)
	require.NoError(t, err)
	return mi
}

func extractStore(r wazero.Runtime) *wasm.Store {
	rv := reflect.ValueOf(r).Elem()
	f := rv.FieldByName("store")
	return (*wasm.Store)(unsafe.Pointer(f.Pointer()))
}

func TestGcE2EJavacWebImageCompile(t *testing.T) {
	path := os.Getenv("JAVAC_WASM_PATH")
	if path == "" {
		t.Skip("set JAVAC_WASM_PATH to the javac.js.wasm binary to run this test")
	}
	wasmBytes, err := os.ReadFile(path)
	require.NoError(t, err)
	t.Logf("loaded %d bytes", len(wasmBytes))

	features := api.CoreFeaturesV2 |
		experimental.CoreFeaturesExceptionHandling |
		experimental.CoreFeaturesGC

	start := time.Now()
	module, err := binaryformat.DecodeModule(wasmBytes, features, 65536, false, false, false)
	require.NoError(t, err)
	t.Logf("decode: %v (%d types, %d functions, %d imports)",
		time.Since(start), len(module.TypeSection), len(module.FunctionSection), len(module.ImportSection))

	javacValidateStart := time.Now()
	wasm.SetValidateProgress(func(idx, total int) {
		if idx >= 0 && idx%5000 == 0 {
			t.Logf("  validate func %d/%d (%v)", idx, total, time.Since(javacValidateStart))
		}
	})
	defer wasm.SetValidateProgress(nil)
	err = module.Validate(features)
	require.NoError(t, err)
	t.Logf("validate total: %v", time.Since(javacValidateStart))

	ctx := context.Background()
	cfg := wazero.NewRuntimeConfigInterpreter().WithCoreFeatures(features)
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	store := extractStore(r)

	start = time.Now()
	typeIDs, err := store.GetFunctionTypeIDs(module.TypeSection)
	require.NoError(t, err)
	t.Logf("typeIDs: %v (%d IDs)", time.Since(start), len(typeIDs))

	start = time.Now()
	err = store.Engine.CompileModule(ctx, module, nil, false)
	require.NoError(t, err)
	t.Logf("compile: %v", time.Since(start))

	t.Logf("total exports: %d", len(module.ExportSection))
}

func TestGcE2EJavacWebImageInstantiate(t *testing.T) {
	path := os.Getenv("JAVAC_WASM_PATH")
	if path == "" {
		t.Skip("set JAVAC_WASM_PATH to the javac.js.wasm binary to run this test")
	}
	wasmBytes, err := os.ReadFile(path)
	require.NoError(t, err)

	var stdout, stderr bytes.Buffer
	ctx := context.Background()
	features := api.CoreFeaturesV2 |
		experimental.CoreFeaturesExceptionHandling |
		experimental.CoreFeaturesGC
	cfg := wazero.NewRuntimeConfigInterpreter().WithCoreFeatures(features)
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	refs := newExternRefStore()

	// Helper: create a Java String GC struct from a Go string via wasm exports.
	// Must be called after the guest module is instantiated, but we declare
	// it early so interop host functions can reference it. It will panic if
	// called before the guest module is available — that's fine, the interop
	// module is instantiated first but these closures are only invoked when
	// the guest module calls back into them.
	var guestMod api.Module
	javaStringToGcRef := func(mod api.Module, s string) uint64 {
		m := mod
		if m == nil {
			m = guestMod
		}
		charArray, _ := m.ExportedFunction("array.char.create").Call(ctx, uint64(len(s)))
		for i, c := range s {
			m.ExportedFunction("array.char.write").Call(ctx, charArray[0], uint64(i), uint64(c))
		}
		result, _ := m.ExportedFunction("string.fromchars").Call(ctx, charArray[0])
		return result[0]
	}

	// Helper: extract a Go string from a JS externref or GC String ref.
	jsValueToString := func(mod api.Module, ref uint64) string {
		if obj := refs.load(uintptr(ref)); obj != nil {
			if s, ok := obj.(string); ok {
				return s
			}
			if chars, ok := obj.([]uint16); ok {
				b := make([]byte, len(chars))
				for i, c := range chars {
					b[i] = byte(c)
				}
				return string(b)
			}
		}
		// Try extracting via string.tochars export (GC String ref)
		m := mod
		if m == nil {
			m = guestMod
		}
		if fn := m.ExportedFunction("string.tochars"); fn != nil {
			if result, err := fn.Call(ctx, ref); err == nil {
				raw := result[0]
				if raw != 0 && wasm.IsGCRef(raw) {
					s := (*wasm.WasmStruct)(wasm.UntagGCPointer(raw))
					if len(s.Fields) > 2 {
						if arr, ok := s.Fields[2].(*wasm.WasmArray); ok && arr != nil {
							chars := make([]uint16, arr.Len())
							for i := range chars {
								switch v := arr.Get(uint32(i)).(type) {
								case uint16:
									chars[i] = v
								case int32:
									chars[i] = uint16(v)
								}
							}
							b := make([]byte, len(chars))
							for i, c := range chars {
								b[i] = byte(c)
							}
							return string(b)
						}
					}
				}
			}
		}
		return fmt.Sprintf("%d", ref)
	}

	// --- interop module (superset of hello-world) ---
	_, err = r.NewHostModuleBuilder("interop").
		NewFunctionBuilder().WithFunc(func(_ context.Context) uintptr {
		t.Logf("[host] genBacktrace")
		return refs.store("")
	}).Export("genBacktrace").
		NewFunctionBuilder().WithFunc(func(_ context.Context) float64 {
		return float64(time.Now().UnixMilli())
	}).Export("Date.now").
		NewFunctionBuilder().WithFunc(func(_ context.Context) float64 {
		return float64(time.Now().UnixNano()) / 1e6
	}).Export("performance.now").
		NewFunctionBuilder().WithFunc(func(_ context.Context, code int32) {
		t.Logf("[wasm] exit code: %d", code)
	}).Export("runtime.setExitCode").
		NewFunctionBuilder().WithFunc(func(_ context.Context, ref uintptr) {
		if obj := refs.load(ref); obj != nil {
			if chars, ok := obj.([]uint16); ok {
				for _, c := range chars {
					stdout.WriteByte(byte(c))
				}
			} else if s, ok := obj.(string); ok {
				stdout.WriteString(s)
			}
		}
	}).Export("stdoutWriter.printChars").
		NewFunctionBuilder().WithFunc(func(_ context.Context, ref uintptr) {
		if obj := refs.load(ref); obj != nil {
			if chars, ok := obj.([]uint16); ok {
				for _, c := range chars {
					stderr.WriteByte(byte(c))
				}
			} else if s, ok := obj.(string); ok {
				stderr.WriteString(s)
			}
		}
		t.Logf("[host] stderrWriter.printChars stderr=%q", stderr.String())
	}).Export("stderrWriter.printChars").
		NewFunctionBuilder().WithFunc(func(_ context.Context) {
	}).Export("stderrWriter.flush").
		NewFunctionBuilder().WithFunc(func(_ context.Context) {
	}).Export("stdoutWriter.flush").
		NewFunctionBuilder().WithFunc(func(_ context.Context) {
	}).Export("stdoutWriter.close").
		NewFunctionBuilder().WithFunc(func(_ context.Context) {
	}).Export("stderrWriter.close").
		NewFunctionBuilder().WithFunc(func(_ context.Context, ref uintptr) {
		t.Logf("[host] llog: %v", refs.load(ref))
	}).Export("llog").
		NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, mod api.Module, stack []uint64) {
		t.Logf("[host] formatStackTrace")
		stack[0] = javaStringToGcRef(mod, "<stack trace>")
	}), []api.ValueType{api.ValueTypeExternref}, []api.ValueType{api.ValueTypeExternref}).Export("formatStackTrace").
		NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, mod api.Module, stack []uint64) {
		cwd, _ := os.Getwd()
		t.Logf("[host] getCurrentWorkingDirectory -> %s", cwd)
		stack[0] = javaStringToGcRef(mod, cwd)
	}), nil, []api.ValueType{api.ValueTypeExternref}).Export("getCurrentWorkingDirectory").
		Instantiate(ctx)
	require.NoError(t, err)

	// --- compat module (extra: f64log10, f64pow, f64rem, f32rem) ---
	_, err = r.NewHostModuleBuilder("compat").
		NewFunctionBuilder().WithFunc(func(_ context.Context, v float64) float64 {
		return math.Log(v)
	}).Export("f64log").
		NewFunctionBuilder().WithFunc(func(_ context.Context, v float64) float64 {
		return math.Log10(v)
	}).Export("f64log10").
		NewFunctionBuilder().WithFunc(func(_ context.Context, a, b float64) float64 {
		return math.Pow(a, b)
	}).Export("f64pow").
		NewFunctionBuilder().WithFunc(func(_ context.Context, a, b float64) float64 {
		return math.Remainder(a, b)
	}).Export("f64rem").
		NewFunctionBuilder().WithFunc(func(_ context.Context, a, b float32) float32 {
		return float32(math.Remainder(float64(a), float64(b)))
	}).Export("f32rem").
		Instantiate(ctx)
	require.NoError(t, err)

	// --- jsbody module ---
	e := api.ValueTypeExternref
	_ = api.ValueTypeI32
	f64 := api.ValueTypeF64
	_, err = r.NewHostModuleBuilder("jsbody").
		// random
		NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, mod api.Module, stack []uint64) {
		stack[0] = math.Float64bits(0.5)
	}), []api.ValueType{e}, []api.ValueType{f64}).Export("_WebImageUtil.random___D").
		// FileSystemInitializer: return map with length=0
		NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, mod api.Module, stack []uint64) {
		t.Logf("[host] prefetchedLibraryNames called")
		m := map[string]any{"length": float64(0)}
		stack[0] = uint64(refs.store(m))
	}), []api.ValueType{e}, []api.ValueType{e}).Export("_FileSystemInitializer.prefetchedLibraryNames___JSObject").
		NewFunctionBuilder().WithFunc(func(_ context.Context, _, _ uintptr) uintptr {
		return refs.store("undefined")
	}).Export("_FileSystemInitializer.prefetchedLibraryContent___String_String").
		NewFunctionBuilder().WithFunc(func(_ context.Context, _, _ uintptr) uintptr {
		return 0
	}).Export("_FileSystemInitializer.clearPrefetchedLibraryContent___String_V").
		// isUndefined
		NewFunctionBuilder().WithFunc(func(_ context.Context, _ uintptr, v uintptr) int32 {
		val := refs.load(v)
		if val == nil && v == 0 {
			return 1
		}
		if s, ok := val.(string); ok && s == "undefined" {
			return 1
		}
		return 0
	}).Export("_JSFunctionIntrinsics.isUndefined___Object_Z").
		// extractJavaScriptString: extract string from GC ref
		NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, mod api.Module, stack []uint64) {
		s := jsValueToString(mod, stack[1])
		stack[0] = uint64(refs.store(s))
	}), []api.ValueType{e, e}, []api.ValueType{e}).Export("_JSConversion.extractJavaScriptString___String_Object").
		// asJavaObjectOrString: if value is a string, create GC String
		NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, mod api.Module, stack []uint64) {
		ref := stack[1]
		if ref == 0 {
			stack[0] = 0
			return
		}
		val := refs.load(uintptr(ref))
		if s, ok := val.(string); ok {
			stack[0] = javaStringToGcRef(mod, s)
			return
		}
		stack[0] = ref
	}), []api.ValueType{e, e}, []api.ValueType{e}).Export("_JSConversion.asJavaObjectOrString___Object_Object").
		// javaScriptUndefined
		NewFunctionBuilder().WithFunc(func(_ context.Context, _ uintptr) uintptr {
		return refs.store("undefined")
	}).Export("_JSConversion.javaScriptUndefined___Object").
		// extractJavaScriptProxy: pass through
		NewFunctionBuilder().WithFunc(func(_ context.Context, _ uintptr, v uintptr) uintptr {
		return v
	}).Export("_JSConversion.extractJavaScriptProxy___Object_Object").
		// javaScriptToJava: convert JS value to Java via wasm exports
		NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, mod api.Module, stack []uint64) {
		ref := stack[1]
		if ref == 0 {
			stack[0] = 0
			return
		}
		val := refs.load(uintptr(ref))
		if val == nil {
			stack[0] = ref
			return
		}
		wrapExtern := mod.ExportedFunction("extern.wrap")
		wrapped, _ := wrapExtern.Call(ctx, ref)
		if s, ok := val.(string); ok && s == "undefined" {
			r, _ := mod.ExportedFunction("convert.create.jsundefined").Call(ctx)
			stack[0] = r[0]
			return
		}
		if _, ok := val.(string); ok {
			r, _ := mod.ExportedFunction("convert.create.jsstring").Call(ctx, wrapped[0])
			stack[0] = r[0]
			return
		}
		if n, ok := val.(float64); ok {
			numRef := uint64(refs.store(n))
			numWrapped, _ := wrapExtern.Call(ctx, numRef)
			r, _ := mod.ExportedFunction("convert.create.jsnumber").Call(ctx, numWrapped[0])
			stack[0] = r[0]
			return
		}
		if b, ok := val.(bool); ok {
			var bv uint64
			if b {
				bv = 1
			}
			bWrapped, _ := wrapExtern.Call(ctx, uint64(refs.store(b)))
			r, _ := mod.ExportedFunction("convert.create.jsboolean").Call(ctx, bWrapped[0], bv)
			stack[0] = r[0]
			return
		}
		if _, ok := val.(map[string]any); ok {
			r, _ := mod.ExportedFunction("convert.create.jsobject").Call(ctx, wrapped[0])
			stack[0] = r[0]
			return
		}
		r2, _ := mod.ExportedFunction("convert.create.jsobject").Call(ctx, wrapped[0])
		stack[0] = r2[0]
	}), []api.ValueType{e, e}, []api.ValueType{e}).Export("_JSConversion.javaScriptToJava___Object_Object").
		// extractJavaScriptString (logging)
		// (already defined above, this won't be reached)
		// unproxy: pass through
		NewFunctionBuilder().WithFunc(func(_ context.Context, _ uintptr, v uintptr) uintptr {
		return v
	}).Export("_JSConversion.unproxy___Object_Object").
		// _JSNumber.javaDouble: unbox via box.double export
		NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, mod api.Module, stack []uint64) {
		val := refs.load(uintptr(stack[0]))
		var d float64
		if n, ok := val.(float64); ok {
			d = n
		}
		r, _ := mod.ExportedFunction("box.double").Call(ctx, math.Float64bits(d))
		stack[0] = r[0]
	}), []api.ValueType{e}, []api.ValueType{e}).Export("_JSNumber.javaDouble___Double").
		// referenceEquals
		NewFunctionBuilder().WithFunc(func(_ context.Context, a, b, c uintptr) uintptr {
		if a == b {
			return refs.store(true)
		}
		return refs.store(false)
	}).Export("_JSSymbol.referenceEquals___JSSymbol_JSSymbol_JSBoolean").
		// javaBoolean: unbox via box.boolean export
		NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, mod api.Module, stack []uint64) {
		val := refs.load(uintptr(stack[0]))
		var b int64
		if bv, ok := val.(bool); ok && bv {
			b = 1
		}
		r, _ := mod.ExportedFunction("box.boolean").Call(ctx, uint64(b))
		stack[0] = r[0]
	}), []api.ValueType{e}, []api.ValueType{e}).Export("_JSBoolean.javaBoolean___Boolean").
		// _JSString.asString: convert JS string → GC String
		NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, mod api.Module, stack []uint64) {
		s := jsValueToString(mod, stack[0])
		stack[0] = javaStringToGcRef(mod, s)
	}), []api.ValueType{e}, []api.ValueType{e}).Export("_JSString.asString___String").
		// _JSString.of: extract string from Java String GC ref
		NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, mod api.Module, stack []uint64) {
		s := jsValueToString(mod, stack[1])
		stack[0] = uint64(refs.store(s))
	}), []api.ValueType{e, e}, []api.ValueType{e}).Export("_JSString.of___String_JSString").
		// typeofString
		NewFunctionBuilder().WithFunc(func(_ context.Context, _ uintptr) uintptr {
		return refs.store("object")
	}).Export("_JSObject.typeofString___JSString").
		// _JSObject.get
		NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, mod api.Module, stack []uint64) {
		obj := refs.load(uintptr(stack[0]))
		key := jsValueToString(mod, stack[1])
		if m, ok := obj.(map[string]any); ok {
			if v, exists := m[key]; exists {
				if ref, ok := v.(uint64); ok {
					stack[0] = ref
				} else {
					stack[0] = uint64(refs.store(v))
				}
				return
			}
		}
		stack[0] = uint64(refs.store("undefined"))
	}), []api.ValueType{e, e}, []api.ValueType{e}).Export("_JSObject.get___Object_Object").
		// _JSValue.stringValue
		NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, mod api.Module, stack []uint64) {
		val := refs.load(uintptr(stack[0]))
		var s string
		if val != nil {
			s = fmt.Sprintf("%v", val)
		} else {
			s = "undefined"
		}
		stack[0] = uint64(refs.store(s))
	}), []api.ValueType{e}, []api.ValueType{e}).Export("_JSValue.stringValue___String").
		Instantiate(ctx)
	require.NoError(t, err)

	// --- convert module (proxyCharArray with concrete GC ref) ---
	// Find the concrete type index for proxyCharArray's param from the binary.
	decoded, err := binaryformat.DecodeModule(wasmBytes, features, 65536, false, false, false)
	require.NoError(t, err)
	var proxyCharArrayTypeIdx uint32
	for _, imp := range decoded.ImportSection {
		if imp.Module == "convert" && imp.Name == "proxyCharArray" {
			ft := &decoded.TypeSection[imp.DescFunc]
			if len(ft.Params) > 0 && ft.Params[0].IsConcreteRef() {
				proxyCharArrayTypeIdx = ft.Params[0].TypeIndex()
			}
			break
		}
	}
	t.Logf("proxyCharArray concrete ref type index: %d", proxyCharArrayTypeIdx)

	convertModule := instantiateHostModuleWithConcreteRefs(t, ctx, r, "convert",
		[]string{"proxyCharArray"},
		map[string]*wasm.HostFunc{
			"proxyCharArray": {
				ExportName:  "proxyCharArray",
				ParamTypes:  []wasm.ValueType{wasm.ValueTypeConcreteRef(proxyCharArrayTypeIdx, true)},
				ResultTypes: []wasm.ValueType{wasm.ValueTypeExternref},
				Code: wasm.Code{
					GoFunc: api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
						raw := stack[0]
						if raw == 0 || !wasm.IsGCRef(raw) {
							stack[0] = uint64(refs.store([]uint16{}))
							return
						}
						s := (*wasm.WasmStruct)(wasm.UntagGCPointer(raw))
						if len(s.Fields) <= 2 {
							stack[0] = uint64(refs.store([]uint16{}))
							return
						}
						arr, ok := s.Fields[2].(*wasm.WasmArray)
						if !ok || arr == nil {
							stack[0] = uint64(refs.store([]uint16{}))
							return
						}
						chars := make([]uint16, arr.Len())
						for i := range chars {
							switch v := arr.Get(uint32(i)).(type) {
							case uint16:
								chars[i] = v
							case int32:
								chars[i] = uint16(v)
							}
						}
						stack[0] = uint64(refs.store(chars))
					}),
				},
			},
		},
	)
	defer convertModule.Close(ctx)

	instStart := time.Now()
	wasm.SetInstantiateProgress(func(phase string) {
		t.Logf("  instantiate: %s (%v)", phase, time.Since(instStart))
	})
	defer wasm.SetInstantiateProgress(nil)
	mod, err := r.InstantiateWithConfig(ctx, wasmBytes,
		wazero.NewModuleConfig().
			WithStdout(&stdout).
			WithStderr(&stderr))
	require.NoError(t, err)
	guestMod = mod
	t.Logf("instantiate total: %v", time.Since(instStart))

	// Build args: [filename, sourceCode] — the WebImage javac expects
	// the filename and the Java source code as separate arguments.
	javaArgs := []string{"HelloWorld.java", "public class HelloWorld { public static void main(String[] args) { System.out.println(42); } }"}

	arrayStringCreate := mod.ExportedFunction("array.string.create")
	arrayCharCreate := mod.ExportedFunction("array.char.create")
	arrayCharWrite := mod.ExportedFunction("array.char.write")
	stringFromChars := mod.ExportedFunction("string.fromchars")
	arrayObjectWrite := mod.ExportedFunction("array.object.write")
	mainFn := mod.ExportedFunction("main")

	require.NotNil(t, arrayStringCreate)
	require.NotNil(t, mainFn)

	res, err := arrayStringCreate.Call(ctx, uint64(len(javaArgs)))
	require.NoError(t, err)
	stringArray := res[0]

	for i, s := range javaArgs {
		res, err = arrayCharCreate.Call(ctx, uint64(len(s)))
		require.NoError(t, err)
		charArray := res[0]

		for j, c := range s {
			_, err = arrayCharWrite.Call(ctx, charArray, uint64(j), uint64(c))
			require.NoError(t, err)
		}

		res, err = stringFromChars.Call(ctx, charArray)
		require.NoError(t, err)
		javaStr := res[0]

		_, err = arrayObjectWrite.Call(ctx, stringArray, uint64(i), javaStr)
		require.NoError(t, err)
	}

	// Run main with a periodic progress ticker so we know it's not stuck.
	opCount := uint64(0)
	wasm.SetCallProgress(func() {
		opCount++
		if opCount%50_000_000 == 0 {
			t.Logf("  interpreter: %dM ops, stdout=%d stderr=%d refs=%d",
				opCount/1_000_000, stdout.Len(), stderr.Len(), refs.next-1)
		}
	})
	defer wasm.SetCallProgress(nil)

	runCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	mainStart := time.Now()
	_, err = mainFn.Call(runCtx, stringArray)
	t.Logf("main: %v (%dM ops)", time.Since(mainStart), opCount/1_000_000)
	t.Logf("stdout: %q", stdout.String())
	t.Logf("stderr: %q", stderr.String())
	if err != nil {
		t.Logf("main error: %v", err)
	}
}
