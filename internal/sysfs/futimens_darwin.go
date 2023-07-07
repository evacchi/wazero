package sysfs

import (
	"syscall"
	"unsafe"
	_ "unsafe" // for go:linkname
)

const (
	_AT_FDCWD            = -0x2
	_AT_SYMLINK_NOFOLLOW = 0x0020

	_ATTR_BIT_MAP_COUNT = 5
	_ATTR_CMN_MODTIME   = 0x00000400
	_ATTR_CMN_ACCTIME   = 0x00001000

	_UTIME_NOW  = -1
	_UTIME_OMIT = -2

	SupportsSymlinkNoFollow = true
)

var timeSpecNow = [2]syscall.Timespec{
	{Nsec: _UTIME_NOW},
	{Nsec: _UTIME_NOW},
}

//go:noescape
//go:linkname utimensat syscall.utimensat
func utimensat(dirfd int, path string, times *[2]syscall.Timespec, flags int) error

func utimens(path string, times *[2]syscall.Timespec, symlinkFollow bool) error {
	var flags int
	if !symlinkFollow {
		flags = _AT_SYMLINK_NOFOLLOW
	}
	return utimensat(_AT_FDCWD, path, times, flags)
}

type attrlist struct {
	bitmapcount byte   // number of attr. bit sets in list (should be 5)
	reserved    uint16 // (to maintain 4-byte alignment)
	commonattr  uint32 // common attribute group
	volattr     uint32 // Volume attribute group
	dirattr     uint32 // directory attribute group
	fileattr    uint32 // file attribute group
	forkattr    uint32 // fork attribute group
}

func futimens(fd uintptr, times *[2]syscall.Timespec) error {
	commonattr, size, ts := prepareTimesAndAttrs(times)
	attrlist := attrlist{
		bitmapcount: _ATTR_BIT_MAP_COUNT,
		commonattr:  commonattr,
	}
	return fsetattrlist(fd, &attrlist, unsafe.Pointer(&ts), size, 0)
}

func prepareTimesAndAttrs(ts *[2]syscall.Timespec) (commonattr uint32, size int, times [2]syscall.Timespec) {
	const sizeOfTimespec = int(unsafe.Sizeof(times[0]))
	if ts == nil {
		ts = &timeSpecNow
	}
	i := 0
	if ts[1].Nsec != _UTIME_OMIT {
		commonattr |= _ATTR_CMN_MODTIME
		times[i] = ts[1]
		i++
	}
	if ts[0].Nsec != _UTIME_OMIT {
		commonattr |= _ATTR_CMN_ACCTIME
		times[i] = ts[0]
		i++
	}
	return commonattr, i * sizeOfTimespec, times
}

func fsetattrlist(fd uintptr, attrlist *attrlist, attrbuf unsafe.Pointer, attrbufsize int, options uint32) syscall.Errno {
	_, _, errno := syscall.Syscall6(
		uintptr(syscall.SYS_FSETATTRLIST),
		fd,
		uintptr(unsafe.Pointer(attrlist)),
		uintptr(attrbuf),
		uintptr(attrbufsize),
		uintptr(options),
		uintptr(0),
	)
	return errno
}
