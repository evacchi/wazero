package ptx

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/tetratelabs/wazero/internal/leb128"
	"github.com/tetratelabs/wazero/internal/testing/require"
	"github.com/tetratelabs/wazero/internal/wasm"
)

const (
	i32 = wasm.ValueTypeI32
	f32 = wasm.ValueTypeF32
)

// fn builds a single-function module.
func fn(params, results []wasm.ValueType, locals []wasm.ValueType, body ...byte) *wasm.Module {
	return &wasm.Module{
		TypeSection:     []wasm.FunctionType{{Params: params, Results: results}},
		FunctionSection: []wasm.Index{0},
		CodeSection:     []wasm.Code{{LocalTypes: locals, Body: append(body, wasm.OpcodeEnd)}},
	}
}

var (
	// (a, b) -> a + b
	addI32 = fn([]wasm.ValueType{i32, i32}, []wasm.ValueType{i32}, nil,
		wasm.OpcodeLocalGet, 0, wasm.OpcodeLocalGet, 1, wasm.OpcodeI32Add)

	// (a, x, y) -> a*x + y
	saxpy = fn([]wasm.ValueType{f32, f32, f32}, []wasm.ValueType{f32}, nil,
		wasm.OpcodeLocalGet, 0, wasm.OpcodeLocalGet, 1, wasm.OpcodeF32Mul,
		wasm.OpcodeLocalGet, 2, wasm.OpcodeF32Add)

	// (n) -> sum(0..n-1), exercises loop block params.
	//
	//	loop
	//	  local.get 0 ; br_if-out when 0
	//	  acc += n ; n -= 1
	//	  br loop
	sumTo = fn([]wasm.ValueType{i32}, []wasm.ValueType{i32}, []wasm.ValueType{i32},
		wasm.OpcodeBlock, 0x40,
		wasm.OpcodeLoop, 0x40,
		wasm.OpcodeLocalGet, 0, wasm.OpcodeI32Eqz, wasm.OpcodeBrIf, 1,
		wasm.OpcodeLocalGet, 0, wasm.OpcodeI32Const, 1, wasm.OpcodeI32Sub, wasm.OpcodeLocalTee, 0,
		wasm.OpcodeLocalGet, 1, wasm.OpcodeI32Add, wasm.OpcodeLocalSet, 1,
		wasm.OpcodeBr, 0,
		wasm.OpcodeEnd,
		wasm.OpcodeEnd,
		wasm.OpcodeLocalGet, 1)

	// (a, b) -> max(a, b) via select.
	maxI32 = fn([]wasm.ValueType{i32, i32}, []wasm.ValueType{i32}, nil,
		wasm.OpcodeLocalGet, 0, wasm.OpcodeLocalGet, 1,
		wasm.OpcodeLocalGet, 0, wasm.OpcodeLocalGet, 1, wasm.OpcodeI32GtS,
		wasm.OpcodeSelect)
)

func TestCompile(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    *wasm.Module
		// want is a line the kernel must contain.
		want string
	}{
		{name: "add", m: addI32, want: "add.s32 %r4, %r2, %r3;"},
		{name: "saxpy", m: saxpy, want: "mul.rn.f32 %f5, %f2, %f3;"},
		{name: "sum_to", m: sumTo, want: "bra $Lblk2;"},
		{name: "max", m: maxI32, want: "selp.b32 %r5, %r2, %r3, %p1;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, err := Compile(tc.m, 0, tc.name)
			require.NoError(t, err)
			require.Contains(t, src, tc.want)
			ptxas(t, src)
		})
	}
}

func TestCompile_unsupported(t *testing.T) {
	// i32.load needs linear memory.
	m := fn([]wasm.ValueType{i32}, []wasm.ValueType{i32}, nil,
		append([]byte{wasm.OpcodeLocalGet, 0, wasm.OpcodeI32Load, 2}, leb128.EncodeUint32(0)...)...)
	m.MemorySection = &wasm.Memory{Min: 1}

	_, err := Compile(m, 0, "load")
	require.Error(t, err)
}

// ptxas validates src when the CUDA toolkit is installed.
func ptxas(t *testing.T, src string) {
	bin, err := exec.LookPath("ptxas")
	if err != nil {
		return
	}
	in := filepath.Join(t.TempDir(), "k.ptx")
	require.NoError(t, os.WriteFile(in, []byte(src), 0o600))
	out, err := exec.Command(bin, "-arch", ptxTarget, "-o", os.DevNull, in).CombinedOutput()
	require.NoError(t, err, string(out))
}
