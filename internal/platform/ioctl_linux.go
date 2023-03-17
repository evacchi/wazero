package platform

import (
	"syscall"
	"unsafe"
)

const IOCTL_FIONREAD = 0x541B

func ioctlPtr(fd int, req uint, arg unsafe.Pointer) (err error) {
	_, _, e1 := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if e1 != 0 {
		err = (e1)
	}
	return
}

// libc_ioctl_trampoline_addr is the address of the
// `libc_ioctl_trampoline` symbol, defined in `ioctl_darwin.s`.
//
// We use this to invoke the syscall through syscall_syscall imported in platform_darwin.go.
var libc_ioctl_trampoline_addr uintptr

// Imports the ioctl symbol from libc as `libc_ioctl`.
//
// Note: CGO mechanisms are used in darwin regardless of the CGO_ENABLED value
// or the "cgo" build flag. See /RATIONALE.md for why.
//go:cgo_import_dynamic libc_ioctl ioctl "/usr/lib/libSystem.B.dylib"
