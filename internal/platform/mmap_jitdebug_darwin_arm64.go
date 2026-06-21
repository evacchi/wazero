//go:build darwin && arm64 && jitdebug

package platform

import (
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func munmapCodeSegment(code []byte) error {
	return unix.Munmap(code)
}

func mmapCodeSegment(size int) ([]byte, error) {
	// MAP_JIT tells the kernel this is JIT memory. Combined with
	// pthread_jit_write_protect_np, this allows debuggers to set
	// software breakpoints via CS_DEBUGGED.
	b, err := unix.Mmap(
		-1,
		0,
		size,
		unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC,
		unix.MAP_ANON|unix.MAP_PRIVATE|unix.MAP_JIT,
	)
	if err != nil {
		return nil, err
	}
	// MAP_JIT pages default to execute-protected on the current thread.
	// Toggle to writable so the caller can copy code into the buffer.
	// We lock the OS thread because pthread_jit_write_protect_np is
	// per-thread state and Go may reschedule the goroutine.
	runtime.LockOSThread()
	pthreadJitWriteProtect(false)
	return b, nil
}

// MprotectCodeSegment transitions JIT code from writable to executable.
// Must be called on the same goroutine as MmapCodeSegment.
func MprotectCodeSegment(b []byte) (err error) {
	pthreadJitWriteProtect(true)
	sysIcacheInvalidate(unsafe.Pointer(&b[0]), uintptr(len(b)))
	runtime.UnlockOSThread()
	return nil
}

// MprotectCodeSegmentDebug keeps code pages writable so debuggers
// can set software breakpoints.
func MprotectCodeSegmentDebug(b []byte) (err error) {
	runtime.UnlockOSThread()
	return nil
}

func pthreadJitWriteProtect(protect bool) {
	var val uintptr
	if protect {
		val = 1
	}
	syscall_syscall6(libc_pthread_jit_write_protect_np_trampoline_addr, val, 0, 0, 0, 0, 0)
}

func sysIcacheInvalidate(start unsafe.Pointer, size uintptr) {
	syscall_syscall6(libc_sys_icache_invalidate_trampoline_addr, uintptr(start), size, 0, 0, 0, 0)
}

//go:linkname syscall_syscall6 syscall.syscall6
func syscall_syscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

var libc_pthread_jit_write_protect_np_trampoline_addr uintptr
var libc_sys_icache_invalidate_trampoline_addr uintptr

//go:cgo_import_dynamic libc_pthread_jit_write_protect_np pthread_jit_write_protect_np "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_sys_icache_invalidate sys_icache_invalidate "/usr/lib/libSystem.B.dylib"
