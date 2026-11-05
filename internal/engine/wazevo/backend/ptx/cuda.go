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
)

// blockSize is threads per block; 256 is a safe default on all GPUs.
const blockSize = 256

// Run JIT-loads src through the CUDA driver, launches kernel name over
// n elements and copies the result into out.
//
// Each inputs[k] and out hold n elements, packed little-endian.
// Opt-in via `-tags cuda` so the default build stays cgo-free.
func Run(src, name string, inputs [][]byte, out []byte, n uint32) error {
	if err := check(C.cuInit(0)); err != nil {
		return err
	}

	// Context on device 0.
	var dev C.CUdevice
	if err := check(C.cuDeviceGet(&dev, 0)); err != nil {
		return err
	}
	var ctx C.CUcontext
	if err := check(C.cuCtxCreate(&ctx, 0, dev)); err != nil {
		return err
	}
	defer C.cuCtxDestroy(ctx)

	// The driver JIT-compiles PTX to SASS for the current device.
	csrc := C.CString(src)
	defer C.free(unsafe.Pointer(csrc))
	var mod C.CUmodule
	if err := check(C.cuModuleLoadData(&mod, unsafe.Pointer(csrc))); err != nil {
		return err
	}
	defer C.cuModuleUnload(mod)

	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var fn C.CUfunction
	if err := check(C.cuModuleGetFunction(&fn, mod, cname)); err != nil {
		return err
	}

	// One device buffer per input, plus out.
	bufs := make([]C.CUdeviceptr, len(inputs)+1)
	defer func() {
		for _, b := range bufs {
			if b != 0 {
				C.cuMemFree(b)
			}
		}
	}()
	for k, in := range inputs {
		if err := check(C.cuMemAlloc(&bufs[k], C.size_t(len(in)))); err != nil {
			return err
		}
		if err := check(C.cuMemcpyHtoD(bufs[k], unsafe.Pointer(&in[0]), C.size_t(len(in)))); err != nil {
			return err
		}
	}
	outBuf := &bufs[len(inputs)]
	if err := check(C.cuMemAlloc(outBuf, C.size_t(len(out)))); err != nil {
		return err
	}

	// Kernel params are pointers to each argument, in signature order.
	// They live in C memory: cgo forbids passing Go pointers to Go pointers.
	argc := len(bufs) + 1
	args := (*[1 << 16]unsafe.Pointer)(C.malloc(C.size_t(argc) * C.size_t(unsafe.Sizeof(uintptr(0)))))[:argc:argc]
	defer C.free(unsafe.Pointer(&args[0]))
	vals := (*[1 << 16]C.CUdeviceptr)(C.malloc(C.size_t(len(bufs)) * C.size_t(unsafe.Sizeof(C.CUdeviceptr(0)))))[:len(bufs):len(bufs)]
	defer C.free(unsafe.Pointer(&vals[0]))
	cn := (*C.uint)(C.malloc(C.size_t(unsafe.Sizeof(C.uint(0)))))
	defer C.free(unsafe.Pointer(cn))

	for k, b := range bufs {
		vals[k] = b
		args[k] = unsafe.Pointer(&vals[k])
	}
	*cn = C.uint(n)
	args[len(bufs)] = unsafe.Pointer(cn)

	grid := (n + blockSize - 1) / blockSize
	if err := check(C.cuLaunchKernel(fn, C.uint(grid), 1, 1, blockSize, 1, 1, 0, nil, &args[0], nil)); err != nil {
		return err
	}
	if err := check(C.cuCtxSynchronize()); err != nil {
		return err
	}
	return check(C.cuMemcpyDtoH(unsafe.Pointer(&out[0]), *outBuf, C.size_t(len(out))))
}

func check(r C.CUresult) error {
	if r == C.CUDA_SUCCESS {
		return nil
	}
	var s *C.char
	C.cuGetErrorString(r, &s)
	return fmt.Errorf("cuda: %s", C.GoString(s))
}
