//go:build !windows && !linux && !darwin

package platform

import "syscall"

func utimens(path string, times *[2]syscall.Timespec, symlinkFollow bool) error {
	return utimensPortable(path, times, symlinkFollow)
}

func futimens(fd uintptr, times *[2]syscall.Timespec) error {
	// Go exports syscall.Futimes, which is microsecond granularity, and
	// WASI tests expect nanosecond. We don't yet have a way to invoke the
	// futimens syscall portably.
	return syscall.ENOSYS
}
