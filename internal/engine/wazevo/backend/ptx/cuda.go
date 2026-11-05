//go:build cuda && linux && cgo

package ptx

/*
#cgo LDFLAGS: -lcuda
#include <cuda.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/tetratelabs/wazero/internal/wasm"
)

const (
	// numFixedParams counts mem0, mem0_len, status.
	numFixedParams = 3
	// slotSize holds any kernel param (u64 max).
	slotSize = 8
)

// Run JIT-loads k through the CUDA driver and launches a 1D grid of
// grid blocks of block threads. mem is copied to memory 0 and back.
// args are the Wasm params as raw bits (api.EncodeF32 etc).
//
// status is the Wasm exit code of a trapping thread, or 0.
// Opt-in via `-tags cuda` so the default build stays cgo-free.
func (k *Kernel) Run(mem []byte, args []uint64, grid, block uint32) (status uint32, err error) {
	if len(args) != len(k.params) {
		return 0, fmt.Errorf("cuda: want %d args, got %d", len(k.params), len(args))
	}
	if err = check(C.cuInit(0)); err != nil {
		return 0, err
	}

	// Context on device 0.
	var dev C.CUdevice
	if err = check(C.cuDeviceGet(&dev, 0)); err != nil {
		return 0, err
	}
	var ctx C.CUcontext
	if err = check(C.cuCtxCreate(&ctx, 0, dev)); err != nil {
		return 0, err
	}
	defer C.cuCtxDestroy(ctx)

	fn, mod, err := k.load()
	if err != nil {
		return 0, err
	}
	defer C.cuModuleUnload(mod)

	// Device buffers: memory 0 and the status word.
	var dmem, dstatus C.CUdeviceptr
	if err = check(C.cuMemAlloc(&dmem, C.size_t(len(mem)))); err != nil {
		return 0, err
	}
	defer C.cuMemFree(dmem)
	if err = check(C.cuMemAlloc(&dstatus, C.size_t(unsafe.Sizeof(C.uint(0))))); err != nil {
		return 0, err
	}
	defer C.cuMemFree(dstatus)
	if err = check(C.cuMemcpyHtoD(dmem, unsafe.Pointer(&mem[0]), C.size_t(len(mem)))); err != nil {
		return 0, err
	}
	if err = check(C.cuMemsetD32(dstatus, 0, 1)); err != nil {
		return 0, err
	}

	// Kernel params: one 8-byte slot each, in signature order. 4-byte
	// params use the slot's low half (little-endian). Both arrays live in
	// C memory: cgo forbids passing Go pointers to Go pointers.
	n := numFixedParams + len(args)
	slots := (*[1 << 16]uint64)(C.calloc(C.size_t(n), slotSize))[:n:n]
	defer C.free(unsafe.Pointer(&slots[0]))
	ptrs := (*[1 << 16]unsafe.Pointer)(C.calloc(C.size_t(n), C.size_t(unsafe.Sizeof(uintptr(0)))))[:n:n]
	defer C.free(unsafe.Pointer(&ptrs[0]))

	slots[0], slots[1], slots[2] = uint64(dmem), uint64(len(mem)), uint64(dstatus)
	for i, a := range args {
		slots[numFixedParams+i] = narrow(k.params[i], a)
	}
	for i := range slots {
		ptrs[i] = unsafe.Pointer(&slots[i])
	}

	if err = check(C.cuLaunchKernel(fn, C.uint(grid), 1, 1, C.uint(block), 1, 1, 0, nil, &ptrs[0], nil)); err != nil {
		return 0, err
	}
	if err = check(C.cuCtxSynchronize()); err != nil {
		return 0, err
	}

	if err = check(C.cuMemcpyDtoH(unsafe.Pointer(&mem[0]), dmem, C.size_t(len(mem)))); err != nil {
		return 0, err
	}
	var s C.uint
	err = check(C.cuMemcpyDtoH(unsafe.Pointer(&s), dstatus, C.size_t(unsafe.Sizeof(s))))
	return uint32(s), err
}

// load JIT-compiles the PTX to SASS for the current device.
func (k *Kernel) load() (C.CUfunction, C.CUmodule, error) {
	csrc := C.CString(k.src)
	defer C.free(unsafe.Pointer(csrc))
	var mod C.CUmodule
	if err := check(C.cuModuleLoadData(&mod, unsafe.Pointer(csrc))); err != nil {
		return nil, nil, err
	}

	cname := C.CString(k.name)
	defer C.free(unsafe.Pointer(cname))
	var fn C.CUfunction
	if err := check(C.cuModuleGetFunction(&fn, mod, cname)); err != nil {
		C.cuModuleUnload(mod)
		return nil, nil, err
	}
	return fn, mod, nil
}

// narrow keeps the low 32 bits of 4-byte params so the slot reads back
// as the right value regardless of the caller's upper bits.
func narrow(vt wasm.ValueType, v uint64) uint64 {
	switch vt {
	case wasm.ValueTypeI32, wasm.ValueTypeF32:
		return uint64(uint32(v))
	}
	return v
}

func check(r C.CUresult) error {
	if r == C.CUDA_SUCCESS {
		return nil
	}
	var s *C.char
	C.cuGetErrorString(r, &s)
	return fmt.Errorf("cuda: %s", C.GoString(s))
}
