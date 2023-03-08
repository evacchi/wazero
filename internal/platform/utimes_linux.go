package platform

import (
	"syscall"
	_ "unsafe" // for go:linkname
)

const (
	_AT_FDCWD            = -0x64
	_AT_SYMLINK_NOFOLLOW = 0x100
)

//go:noescape
//go:linkname utimensat syscall.utimensat
func utimensat(dirfd int, path string, times *[2]syscall.Timespec, flags int) error

func utimens(path string, times *[2]syscall.Timespec, symlinkFollow bool) error {
	flags := _AT_SYMLINK_NOFOLLOW
	if !symlinkFollow {
		flags = 0
	}
	return utimensat(_AT_FDCWD, path, times, flags)
}

// On linux, implement futimens via utimensat with the empty path.
func futimens(fd uintptr, times *[2]syscall.Timespec) error {
	return utimensat(int(fd), "", times, 0)
}
