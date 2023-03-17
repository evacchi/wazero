//go:build !windows && !linux && !darwin

package platform

import "syscall"

func ioctlPtr(fd int, req uint, arg unsafe.Pointer) error {
	return syscall.ENOSYS
}
