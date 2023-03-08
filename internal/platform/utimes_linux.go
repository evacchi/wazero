package platform

import (
	"syscall"
	"unsafe"
	_ "unsafe" // for go:linkname
)

const (
	_AT_FDCWD            = -0x64
	_AT_SYMLINK_NOFOLLOW = 0x100
)

func utimensat(dirfd int, path *string, times *[2]syscall.Timespec, flags int) (err error) {
	var strPtr uintptr = 0 // NULL
	if path != nil {
		var _p0 *byte
		_p0, err = syscall.BytePtrFromString(*path)
		strPtr = uintptr(unsafe.Pointer(_p0))
		if err != nil {
			return
		}
	}
	_, _, e1 := syscall.Syscall6(syscall.SYS_UTIMENSAT, uintptr(dirfd), strPtr, uintptr(unsafe.Pointer(times)), uintptr(flags), 0, 0)
	if e1 != 0 {
		err = e1
	}
	return
}

func utimens(path string, times *[2]syscall.Timespec, symlinkFollow bool) error {
	flags := _AT_SYMLINK_NOFOLLOW
	if !symlinkFollow {
		flags = 0
	}
	return utimensat(_AT_FDCWD, &path, times, flags)
}

// On linux, implement futimens via utimensat with the empty path.
func futimens(fd uintptr, times *[2]syscall.Timespec) error {
	return utimensat(int(fd), nil, times, 0)
}
