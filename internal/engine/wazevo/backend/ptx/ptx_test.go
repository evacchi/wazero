package ptx

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/internal/testing/binaryencoding"
	"github.com/tetratelabs/wazero/internal/testing/require"
	"github.com/tetratelabs/wazero/internal/wasm"
)

const (
	i32 = wasm.ValueTypeI32
	f32 = wasm.ValueTypeF32

	// Function indices of the intrinsics every test kernel imports.
	fnThreadIdx = 0
	fnBlockIdx  = 1
	fnBlockDim  = 2
	fnBarrier   = 3
	// fnKernel is the index of the kernel itself, after the imports.
	fnKernel = 4

	// numElems spans several blocks and a partial tail block.
	numElems  = 1000
	blockSize = 256
	elemSize  = 4

	// align4 is the alignment immediate (log2) for 4-byte accesses.
	align4 = 2

	// Block types: no result, one i32 result.
	blockTypeEmpty = 0x40
	blockTypeI32   = 0x7f
)

// gridSize covers numElems with blockSize threads per block.
var gridSize = uint32((numElems + blockSize - 1) / blockSize)

// Type indices used by kernel.
const (
	typGeometry = iota
	typKernel
	typBarrier
)

// kernel builds a module exporting one kernel named name, importing
// gpu.thread_idx/block_idx/block_dim/barrier, with one page of memory.
func kernel(name string, params, locals []wasm.ValueType, body ...byte) *wasm.Module {
	intrinsic := func(n string, typ wasm.Index) wasm.Import {
		return wasm.Import{Type: wasm.ExternTypeFunc, Module: intrinsicModule, Name: n, DescFunc: typ}
	}
	return &wasm.Module{
		TypeSection: []wasm.FunctionType{
			typGeometry: {Params: []wasm.ValueType{i32}, Results: []wasm.ValueType{i32}},
			typKernel:   {Params: params},
			typBarrier:  {},
		},
		ImportSection: []wasm.Import{
			intrinsic("thread_idx", typGeometry),
			intrinsic("block_idx", typGeometry),
			intrinsic("block_dim", typGeometry),
			intrinsic(barrierName, typBarrier),
		},
		ImportFunctionCount: 4,
		MemorySection:       &wasm.Memory{Min: 1, Max: 1, IsMaxEncoded: true},
		FunctionSection:     []wasm.Index{typKernel},
		CodeSection:         []wasm.Code{{LocalTypes: locals, Body: append(body, wasm.OpcodeEnd)}},
		ExportSection:       []wasm.Export{{Type: wasm.ExternTypeFunc, Name: name, Index: fnKernel}},
	}
}

// gid sets local l = block_idx(0) * block_dim(0) + thread_idx(0).
func gid(l byte) []byte {
	return []byte{
		wasm.OpcodeI32Const, 0, wasm.OpcodeCall, fnBlockIdx,
		wasm.OpcodeI32Const, 0, wasm.OpcodeCall, fnBlockDim, wasm.OpcodeI32Mul,
		wasm.OpcodeI32Const, 0, wasm.OpcodeCall, fnThreadIdx, wasm.OpcodeI32Add,
		wasm.OpcodeLocalSet, l,
	}
}

// elem pushes the address base + idx*4 (locals).
func elem(base, idx byte) []byte {
	return []byte{
		wasm.OpcodeLocalGet, base,
		wasm.OpcodeLocalGet, idx, wasm.OpcodeI32Const, 2, wasm.OpcodeI32Shl,
		wasm.OpcodeI32Add,
	}
}

func cat(parts ...[]byte) (ret []byte) {
	for _, p := range parts {
		ret = append(ret, p...)
	}
	return
}

var (
	// vadd(a, b, out, n): out[i] = a[i] + b[i]
	vadd = kernel("vadd", []wasm.ValueType{i32, i32, i32, i32}, []wasm.ValueType{i32}, cat(
		gid(4),
		[]byte{wasm.OpcodeLocalGet, 4, wasm.OpcodeLocalGet, 3, wasm.OpcodeI32LtU, wasm.OpcodeIf, 0x40},
		elem(2, 4),
		elem(0, 4), []byte{wasm.OpcodeI32Load, align4, 0},
		elem(1, 4), []byte{wasm.OpcodeI32Load, align4, 0},
		[]byte{wasm.OpcodeI32Add, wasm.OpcodeI32Store, align4, 0},
		[]byte{wasm.OpcodeEnd},
	)...)

	// saxpy(a f32, x, y, n): y[i] = a*x[i] + y[i]
	saxpy = kernel("saxpy", []wasm.ValueType{f32, i32, i32, i32}, []wasm.ValueType{i32}, cat(
		gid(4),
		[]byte{wasm.OpcodeLocalGet, 4, wasm.OpcodeLocalGet, 3, wasm.OpcodeI32LtU, wasm.OpcodeIf, 0x40},
		elem(2, 4),
		[]byte{wasm.OpcodeLocalGet, 0},
		elem(1, 4), []byte{wasm.OpcodeF32Load, align4, 0, wasm.OpcodeF32Mul},
		elem(2, 4), []byte{wasm.OpcodeF32Load, align4, 0, wasm.OpcodeF32Add},
		[]byte{wasm.OpcodeF32Store, align4, 0},
		[]byte{wasm.OpcodeEnd},
	)...)

	// sumTo(in, out, n): out[i] = 0 + 1 + … + (in[i]-1), per-thread loop.
	//
	//	k := in[i]
	//	for k != 0 { k--; acc += k }
	sumTo = kernel("sum_to", []wasm.ValueType{i32, i32, i32}, []wasm.ValueType{i32, i32, i32}, cat(
		gid(3),
		[]byte{wasm.OpcodeLocalGet, 3, wasm.OpcodeLocalGet, 2, wasm.OpcodeI32LtU, wasm.OpcodeIf, 0x40},
		elem(0, 3), []byte{wasm.OpcodeI32Load, align4, 0, wasm.OpcodeLocalSet, 4},
		[]byte{
			wasm.OpcodeBlock, 0x40, wasm.OpcodeLoop, 0x40,
			wasm.OpcodeLocalGet, 4, wasm.OpcodeI32Eqz, wasm.OpcodeBrIf, 1,
			wasm.OpcodeLocalGet, 4, wasm.OpcodeI32Const, 1, wasm.OpcodeI32Sub, wasm.OpcodeLocalTee, 4,
			wasm.OpcodeLocalGet, 5, wasm.OpcodeI32Add, wasm.OpcodeLocalSet, 5,
			wasm.OpcodeBr, 0,
			wasm.OpcodeEnd, wasm.OpcodeEnd,
		},
		elem(1, 3), []byte{wasm.OpcodeLocalGet, 5, wasm.OpcodeI32Store, align4, 0},
		[]byte{wasm.OpcodeEnd},
	)...)

	// reduce(in, out, scratch, n): out[b] = sum of block b's elements.
	// Classic tree reduction over a per-block scratch tile in memory 0
	// (shared memory needs multi-memory):
	//
	//	tile[t] = gid < n ? in[gid] : 0;      barrier
	//	for s := block_dim/2; s > 0; s /= 2 {
	//	  if t < s { tile[t] += tile[t+s] };  barrier
	//	}
	//	if t == 0 { out[b] = tile[0] }
	//
	// The block's tile starts at scratch + (b*block_dim)*4, so thread t's
	// slot is scratch + gid*4. Locals: t=4, gid=5, slot=6, s=7.
	reduce = kernel("reduce", []wasm.ValueType{i32, i32, i32, i32}, []wasm.ValueType{i32, i32, i32, i32}, cat(
		[]byte{wasm.OpcodeI32Const, 0, wasm.OpcodeCall, fnThreadIdx, wasm.OpcodeLocalSet, 4},
		gid(5),
		elem(2, 5), []byte{wasm.OpcodeLocalSet, 6},

		// tile[t] = gid < n ? in[gid] : 0
		[]byte{
			wasm.OpcodeLocalGet, 6,
			wasm.OpcodeLocalGet, 5, wasm.OpcodeLocalGet, 3, wasm.OpcodeI32LtU,
			wasm.OpcodeIf, blockTypeI32,
		},
		elem(0, 5), []byte{wasm.OpcodeI32Load, align4, 0},
		[]byte{
			wasm.OpcodeElse, wasm.OpcodeI32Const, 0, wasm.OpcodeEnd,
			wasm.OpcodeI32Store, align4, 0,
			wasm.OpcodeCall, fnBarrier,
		},

		// s = block_dim / 2
		[]byte{
			wasm.OpcodeI32Const, 0, wasm.OpcodeCall, fnBlockDim,
			wasm.OpcodeI32Const, 1, wasm.OpcodeI32ShrU, wasm.OpcodeLocalSet, 7,
		},

		// Halving loop; s is uniform, so every thread reaches the barrier.
		[]byte{
			wasm.OpcodeBlock, blockTypeEmpty, wasm.OpcodeLoop, blockTypeEmpty,
			wasm.OpcodeLocalGet, 7, wasm.OpcodeI32Eqz, wasm.OpcodeBrIf, 1,

			wasm.OpcodeLocalGet, 4, wasm.OpcodeLocalGet, 7, wasm.OpcodeI32LtU, wasm.OpcodeIf, blockTypeEmpty,
			wasm.OpcodeLocalGet, 6,
			wasm.OpcodeLocalGet, 6, wasm.OpcodeI32Load, align4, 0,
			wasm.OpcodeLocalGet, 6, wasm.OpcodeLocalGet, 7, wasm.OpcodeI32Const, 2, wasm.OpcodeI32Shl, wasm.OpcodeI32Add,
			wasm.OpcodeI32Load, align4, 0,
			wasm.OpcodeI32Add, wasm.OpcodeI32Store, align4, 0,
			wasm.OpcodeEnd,

			wasm.OpcodeCall, fnBarrier,
			wasm.OpcodeLocalGet, 7, wasm.OpcodeI32Const, 1, wasm.OpcodeI32ShrU, wasm.OpcodeLocalSet, 7,
			wasm.OpcodeBr, 0,
			wasm.OpcodeEnd, wasm.OpcodeEnd,
		},

		// if t == 0 { out[b] = tile[0] }
		[]byte{
			wasm.OpcodeLocalGet, 4, wasm.OpcodeI32Eqz, wasm.OpcodeIf, blockTypeEmpty,
			wasm.OpcodeLocalGet, 1,
			wasm.OpcodeI32Const, 0, wasm.OpcodeCall, fnBlockIdx, wasm.OpcodeI32Const, 2, wasm.OpcodeI32Shl,
			wasm.OpcodeI32Add,
			wasm.OpcodeLocalGet, 6, wasm.OpcodeI32Load, align4, 0,
			wasm.OpcodeI32Store, align4, 0,
			wasm.OpcodeEnd,
		},
	)...)
)

// Memory layout shared by the tests: three arrays of numElems words.
const (
	arr0 = 0
	arr1 = arr0 + numElems*elemSize
	arr2 = arr1 + numElems*elemSize
	// memSize is the device buffer size: the module's one page, so CPU
	// and GPU agree on what is out of bounds.
	memSize = wasm.MemoryPageSize
)

// testCase is a kernel with inputs and the expected memory after a run.
type testCase struct {
	name string
	m    *wasm.Module
	// want is a line the PTX must contain.
	want string
	mem  []byte
	args []uint64
	exp  []byte
}

func putU32(mem []byte, off, i int, v uint32) {
	binary.LittleEndian.PutUint32(mem[off+elemSize*i:], v)
}

func cases() []testCase {
	// vadd: a[i] = i, b[i] = 3i.
	vaddMem, vaddExp := make([]byte, memSize), make([]byte, memSize)
	for i := 0; i < numElems; i++ {
		for _, mem := range [][]byte{vaddMem, vaddExp} {
			putU32(mem, arr0, i, uint32(i))
			putU32(mem, arr1, i, uint32(3*i))
		}
		putU32(vaddExp, arr2, i, uint32(4*i))
	}

	// saxpy: x[i] = i, y[i] = -i/3. Explicit float32 conversions block
	// Go's own FMA fusion, matching Wasm/PTX `.rn` semantics.
	const a = float32(2.5)
	saxpyMem, saxpyExp := make([]byte, memSize), make([]byte, memSize)
	for i := 0; i < numElems; i++ {
		x, y := float32(i), float32(-i)/3
		for _, mem := range [][]byte{saxpyMem, saxpyExp} {
			putU32(mem, arr0, i, math.Float32bits(x))
			putU32(mem, arr1, i, math.Float32bits(y))
		}
		putU32(saxpyExp, arr1, i, math.Float32bits(float32(a*x)+y))
	}

	// sumTo: in[i] = i, out[i] = i*(i-1)/2.
	sumMem, sumExp := make([]byte, memSize), make([]byte, memSize)
	for i := 0; i < numElems; i++ {
		putU32(sumMem, arr0, i, uint32(i))
		putU32(sumExp, arr0, i, uint32(i))
		putU32(sumExp, arr1, i, uint32(i*(i-1)/2))
	}

	// reduce: in[i] = i. Simulate the tree reduction, so the scratch tile
	// is checked too: its final state is fixed by the barriers.
	reduceMem, reduceExp := make([]byte, memSize), make([]byte, memSize)
	tile := make([]uint32, int(gridSize)*blockSize)
	for i := 0; i < numElems; i++ {
		putU32(reduceMem, arr0, i, uint32(i))
		putU32(reduceExp, arr0, i, uint32(i))
		tile[i] = uint32(i)
	}
	for b := 0; b < int(gridSize); b++ {
		t := tile[b*blockSize : (b+1)*blockSize]
		for s := blockSize / 2; s > 0; s /= 2 {
			for k := 0; k < s; k++ {
				t[k] += t[k+s]
			}
		}
		putU32(reduceExp, arr1, b, t[0])
	}
	for i, v := range tile {
		putU32(reduceExp, arr2, i, v)
	}

	return []testCase{
		{
			name: "vadd", m: vadd, want: "%tid.x;",
			mem: vaddMem, exp: vaddExp, args: []uint64{arr0, arr1, arr2, numElems},
		},
		{
			name: "saxpy", m: saxpy, want: "mul.rn.f32",
			mem: saxpyMem, exp: saxpyExp, args: []uint64{api.EncodeF32(a), arr0, arr1, numElems},
		},
		{
			name: "sum_to", m: sumTo, want: "ld.global.u32",
			mem: sumMem, exp: sumExp, args: []uint64{arr0, arr1, numElems},
		},
		{
			name: "reduce", m: reduce, want: "bar.sync 0;",
			mem: reduceMem, exp: reduceExp, args: []uint64{arr0, arr1, arr2, numElems},
		},
	}
}

func TestCompile(t *testing.T) {
	for _, tc := range cases() {
		t.Run(tc.name, func(t *testing.T) {
			k, err := Compile(tc.m, tc.name, Checked)
			require.NoError(t, err)
			require.Contains(t, k.String(), tc.want)
			require.Contains(t, k.String(), labelTrap)
			ptxas(t, k.String())

			// Unchecked drops every bounds check, hence the trap stub.
			k, err = Compile(tc.m, tc.name, Unchecked)
			require.NoError(t, err)
			require.False(t, strings.Contains(k.String(), labelTrap))
			ptxas(t, k.String())
		})
	}
}

// TestRunCPU runs each kernel on wazero, with gpu.* as host functions.
func TestRunCPU(t *testing.T) {
	for _, tc := range cases() {
		t.Run(tc.name, func(t *testing.T) {
			mem := append([]byte(nil), tc.mem...)
			require.NoError(t, runCPU(t, tc.m, tc.name, mem, tc.args, gridSize, blockSize))
			require.Equal(t, tc.exp, mem)
		})
	}
}

func TestCompile_unsupported(t *testing.T) {
	t.Run("unknown import", func(t *testing.T) {
		m := kernel("k", nil, nil)
		m.ImportSection[0].Name = "printf"
		_, err := Compile(m, "k", Checked)
		require.EqualError(t, err, "ptx: unknown intrinsic gpu.printf")
	})
	t.Run("non-constant dim", func(t *testing.T) {
		m := kernel("k", []wasm.ValueType{i32}, nil,
			wasm.OpcodeLocalGet, 0, wasm.OpcodeCall, fnThreadIdx, wasm.OpcodeDrop)
		_, err := Compile(m, "k", Checked)
		require.EqualError(t, err, "ptx: gpu.thread_idx needs a constant dim in 0..2")
	})
	t.Run("memory.grow", func(t *testing.T) {
		m := kernel("k", nil, nil,
			wasm.OpcodeI32Const, 1, wasm.OpcodeMemoryGrow, 0, wasm.OpcodeDrop)
		_, err := Compile(m, "k", Checked)
		require.Error(t, err)
	})
	t.Run("barrier signature", func(t *testing.T) {
		m := kernel("k", nil, nil)
		m.ImportSection[fnBarrier].DescFunc = typGeometry
		_, err := Compile(m, "k", Checked)
		require.EqualError(t, err, "ptx: gpu.barrier has signature i32_i32, want v_v")
	})
	t.Run("results", func(t *testing.T) {
		m := kernel("k", nil, nil, wasm.OpcodeI32Const, 0)
		m.TypeSection[1].Results = []wasm.ValueType{i32}
		_, err := Compile(m, "k", Checked)
		require.EqualError(t, err, `ptx: kernel "k" must not return values`)
	})
}

// coords is a simulated thread's position, read by the intrinsics.
type coords struct {
	tid, bid uint32
	bar      *barrier
}

type coordsKey struct{}

func at(ctx context.Context) *coords {
	return ctx.Value(coordsKey{}).(*coords)
}

// runCPU executes a 1D launch on wazero, sharing one memory like the
// GPU does. Blocks run in sequence; threads of a block run as
// goroutines, so gpu.barrier works.
func runCPU(t *testing.T, m *wasm.Module, name string, mem []byte, args []uint64, grid, block uint32) error {
	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	defer r.Close(ctx)

	// Only dim 0 is used: y and z are a 1-wide launch.
	idx := func(get func(*coords) uint32) func(context.Context, uint32) uint32 {
		return func(ctx context.Context, dim uint32) uint32 {
			if dim != 0 {
				return 0
			}
			return get(at(ctx))
		}
	}
	blockDim := func(_ context.Context, dim uint32) uint32 {
		if dim != 0 {
			return 1
		}
		return block
	}
	_, err := r.NewHostModuleBuilder(intrinsicModule).
		NewFunctionBuilder().WithFunc(idx(func(c *coords) uint32 { return c.tid })).Export("thread_idx").
		NewFunctionBuilder().WithFunc(idx(func(c *coords) uint32 { return c.bid })).Export("block_idx").
		NewFunctionBuilder().WithFunc(blockDim).Export("block_dim").
		NewFunctionBuilder().WithFunc(func(ctx context.Context) { at(ctx).bar.wait() }).Export(barrierName).
		Instantiate(ctx)
	require.NoError(t, err)

	mod, err := r.Instantiate(ctx, binaryencoding.EncodeModule(m))
	require.NoError(t, err)
	require.True(t, mod.Memory().Write(0, mem))

	for bid := uint32(0); bid < grid; bid++ {
		if err = runBlock(ctx, mod, name, args, bid, block); err != nil {
			return err
		}
	}

	out, ok := mod.Memory().Read(0, uint32(len(mem)))
	require.True(t, ok)
	copy(mem, out)
	return nil
}

// runBlock runs one block's threads concurrently and joins their errors.
func runBlock(ctx context.Context, mod api.Module, name string, args []uint64, bid, block uint32) error {
	bar := newBarrier(int(block))
	errs := make([]error, block)

	var wg sync.WaitGroup
	for tid := uint32(0); tid < block; tid++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// An exited (or trapped) thread must not hold up the others.
			defer bar.leave()

			// api.Function is not goroutine-safe: one per thread.
			fn := mod.ExportedFunction(name)
			c := context.WithValue(ctx, coordsKey{}, &coords{tid: tid, bid: bid, bar: bar})
			_, errs[tid] = fn.Call(c, args...)
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// barrier is a reusable block barrier. Exited threads leave it, as on
// GPUs since Volta, so a trap doesn't deadlock the block.
type barrier struct {
	mu   sync.Mutex
	cond *sync.Cond
	// n is the live thread count, arrived those waiting, gen the phase.
	n, arrived, gen int
}

func newBarrier(n int) *barrier {
	b := &barrier{n: n}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *barrier) wait() {
	b.mu.Lock()
	defer b.mu.Unlock()

	gen := b.gen
	b.arrived++
	if b.arrived == b.n {
		b.release()
		return
	}
	for gen == b.gen {
		b.cond.Wait()
	}
}

func (b *barrier) leave() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.n--
	if b.arrived > 0 && b.arrived == b.n {
		b.release()
	}
}

func (b *barrier) release() {
	b.arrived = 0
	b.gen++
	b.cond.Broadcast()
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
