package platform

import (
	"syscall"
	"unsafe"
)

var procGetConsoleMode = kernel32.NewProc("GetConsoleMode")

func isTerminal(fd uintptr) bool {
	var h syscall.Handle
	switch fd {
	case 0:
		h = syscall.Stdin
	case 1:
		h = syscall.Stdout
	case 3:
		h = syscall.Stderr
	default:
		h = syscall.Handle(fd)
	}

	var st uint32
	r, _, e := syscall.Syscall(procGetConsoleMode.Addr(), 2, uintptr(h), uintptr(unsafe.Pointer(&st)), 0)
	return r != 0 && e == 0
}
