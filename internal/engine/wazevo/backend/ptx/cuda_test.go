//go:build cuda && linux && cgo

package ptx

import (
	"fmt"
	"testing"

	"github.com/tetratelabs/wazero/internal/engine/wazevo/wazevoapi"
	"github.com/tetratelabs/wazero/internal/testing/require"
)

// TestRunGPU runs each kernel on the GPU and on wazero (CPU), and
// requires identical memory and the expected result.
func TestRunGPU(t *testing.T) {
	for _, tc := range cases() {
		for _, bc := range []BoundsCheck{Checked, Unchecked} {
			t.Run(fmt.Sprintf("%s/bc=%d", tc.name, bc), func(t *testing.T) {
				k, err := Compile(tc.m, tc.name, bc)
				require.NoError(t, err)

				gpu := append([]byte(nil), tc.mem...)
				status, err := k.Run(gpu, tc.args, gridSize, blockSize)
				require.NoError(t, err)
				require.Equal(t, uint32(0), status)

				cpu := append([]byte(nil), tc.mem...)
				require.NoError(t, runCPU(t, tc.m, tc.name, cpu, tc.args, gridSize, blockSize))
				require.Equal(t, cpu, gpu)
				require.Equal(t, tc.exp, gpu)
			})
		}
	}
}

// TestRunGPU_trap checks OOB sets status on GPU and traps on CPU.
func TestRunGPU_trap(t *testing.T) {
	tc := cases()[0]
	// out ends half past memory: upper half of the threads store OOB.
	args := []uint64{arr0, arr1, uint64(memSize - elemSize*numElems/2), numElems}

	k, err := Compile(tc.m, tc.name, Checked)
	require.NoError(t, err)
	status, err := k.Run(append([]byte(nil), tc.mem...), args, gridSize, blockSize)
	require.NoError(t, err)
	require.Equal(t, uint32(wazevoapi.ExitCodeMemoryOutOfBounds), status)

	err = runCPU(t, tc.m, tc.name, append([]byte(nil), tc.mem...), args, gridSize, blockSize)
	require.Error(t, err)
}
