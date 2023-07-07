package sysfs

import (
	"syscall"
	"unsafe"
	_ "unsafe" // for go:linkname
)

const (
	_AT_FDCWD               = -0x2
	_AT_SYMLINK_NOFOLLOW    = 0x0020
	_UTIME_NOW              = -1
	_UTIME_OMIT             = -2
	SupportsSymlinkNoFollow = true
)

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

func prepareTimesAndAttrs(ts *[2]syscall.Timespec) (attrs, size int, times [2]syscall.Timespec) {
	const sizeOfTimespec = int(unsafe.Sizeof(times[0]))
	i := 0
	if ts[1].Nsec != _UTIME_OMIT {
		attrs |= _ATTR_CMN_MODTIME
		times[i] = ts[1]
		i++
	}
	if ts[0].Nsec != _UTIME_OMIT {
		attrs |= _ATTR_CMN_ACCTIME
		times[i] = ts[0]
		i++
	}
	return attrs, i * sizeOfTimespec, times
}

type attrlist struct {
	bitmapcount byte   /* number of attr. bit sets in list (should be 5) */
	reserved    uint16 /* (to maintain 4-byte alignment) */
	commonattr  uint32 /* common attribute group */
	volattr     uint32 /* Volume attribute group */
	dirattr     uint32 /* directory attribute group */
	fileattr    uint32 /* file attribute group */
	forkattr    uint32 /* fork attribute group */
}

const _ATTR_BIT_MAP_COUNT = 5
const _ATTR_CMN_MODTIME = 0x00000400
const _ATTR_CMN_ACCTIME = 0x00001000

func futimens(fd uintptr, times *[2]syscall.Timespec) error {
	//if times == nil {
	//	times = &[2]syscall.Timespec{
	//		{
	//			Sec: _UTIME_NOW, Nsec: _UTIME_NOW,
	//		},
	//		{
	//			Sec: _UTIME_NOW, Nsec: _UTIME_NOW,
	//		},
	//	}
	//}
	//_p0 := timesToPtr(times)
	//
	//// Warning: futimens only exists since High Sierra (10.13).
	//e1 := fsetattrlist(fd, uintptr(_p0), 0, 0, 0, 0)
	//if e1 != 0 {
	//	return e1
	//}
	//return nil

	attrs, size, ts := prepareTimesAndAttrs(times)
	attrlist := attrlist{
		bitmapcount: _ATTR_BIT_MAP_COUNT,
		commonattr:  uint32(attrs),
	}
	return fsetattrlist(fd, &attrlist, unsafe.Pointer(&ts), size, 0)

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

// libc_futimens_trampoline_addr is the address of the
// `libc_futimens_trampoline` symbol, defined in `futimens_darwin.s`.
//
// We use this to invoke the syscall through syscall_syscall6 imported below.
var libc_futimens_trampoline_addr uintptr

// Imports the futimens symbol from libc as `libc_futimens`.
//
// Note: CGO mechanisms are used in darwin regardless of the CGO_ENABLED value
// or the "cgo" build flag. See /RATIONALE.md for why.
//go:cgo_import_dynamic libc_futimens futimens "/usr/lib/libSystem.B.dylib"
