//go:build cuda && linux && cgo

package ptx

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/tetratelabs/wazero/internal/testing/require"
)

// numElems spans several blocks and a partial tail block.
const numElems = 1000

func TestRun_sumTo(t *testing.T) {
	src, err := Compile(sumTo, 0, "sum_to")
	require.NoError(t, err)

	in := make([]byte, 4*numElems)
	for i := 0; i < numElems; i++ {
		binary.LittleEndian.PutUint32(in[4*i:], uint32(i))
	}
	out := make([]byte, 4*numElems)
	require.NoError(t, Run(src, "sum_to", [][]byte{in}, out, numElems))

	// sum(0..i-1) = i*(i-1)/2.
	for i := 0; i < numElems; i++ {
		require.Equal(t, uint32(i*(i-1)/2), binary.LittleEndian.Uint32(out[4*i:]), "i=%d", i)
	}
}

func TestRun_saxpy(t *testing.T) {
	src, err := Compile(saxpy, 0, "saxpy")
	require.NoError(t, err)

	const a = float32(2.5)
	as, xs, ys := make([]byte, 4*numElems), make([]byte, 4*numElems), make([]byte, 4*numElems)
	for i := 0; i < numElems; i++ {
		binary.LittleEndian.PutUint32(as[4*i:], math.Float32bits(a))
		binary.LittleEndian.PutUint32(xs[4*i:], math.Float32bits(float32(i)))
		binary.LittleEndian.PutUint32(ys[4*i:], math.Float32bits(float32(-i)/3))
	}
	out := make([]byte, 4*numElems)
	require.NoError(t, Run(src, "saxpy", [][]byte{as, xs, ys}, out, numElems))

	// Bit-exact: .rn ops forbid FMA contraction, as in Wasm.
	for i := 0; i < numElems; i++ {
		exp := float32(a*float32(i)) + float32(-i)/3 // explicit conversion blocks Go FMA fusion
		require.Equal(t, math.Float32bits(exp), binary.LittleEndian.Uint32(out[4*i:]), "i=%d", i)
	}
}
