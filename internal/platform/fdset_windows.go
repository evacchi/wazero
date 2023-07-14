package platform

import (
	"syscall"
	"unsafe"
)

var procGetNamedPipeInfo = kernel32.NewProc("GetNamedPipeInfo")

// Maximum number of fds in a WinSockFdSet.
const _FD_SETSIZE = 64

// WinSockFdSet implements the FdSet representation that is used internally by WinSock.
//
// Note: this representation is quite different from the one used in most POSIX implementations
// where a bitfield is usually implemented; instead on Windows we have a simpler array+count pair.
// Notice that because it keeps a count of the inserted handles, the first argument of select
// in WinSock is actually ignored.
//
// The implementation of the Set, Clear, IsSet, Zero, methods follows exactly
// the real implementation found in WinSock2.h, e.g. see:
// https://github.com/microsoft/win32metadata/blob/ef7725c75c6b39adfdc13ba26fb1d89ac954449a/generation/WinSDK/RecompiledIdlHeaders/um/WinSock2.h#L124-L175
type WinSockFdSet struct {
	// count is the number of used slots used in the handles slice.
	count uint64
	// handles is the array of handles. This is called "array" in the WinSock implementation
	// and it has a fixed length of _FD_SETSIZE.
	handles [_FD_SETSIZE]syscall.Handle
}

// FdSet implements the same methods provided on other plaforms.
//
// Note: the implementation is very different from POSIX; Windows provides
// POSIX select only for sockets. We emulate a select for other APIs in the sysfs
// package, but we still want to use the "real" select in the case of sockets.
// So, we keep a separate FdSet of sockets, so that we can pass it directly
// to the winsock select implementation
type FdSet struct {
	sockets WinSockFdSet
	regular WinSockFdSet
}

// Sockets returns a WinSockFdSet with only the handles in this FdSet that are sockets.
func (f *FdSet) Sockets() *WinSockFdSet {
	if f == nil {
		return nil
	}
	return &f.sockets
}

// Regular returns a WinSockFdSet with only the handles in this FdSet that are not sockets.
func (f *FdSet) Regular() *WinSockFdSet {
	if f == nil {
		return nil
	}
	return &f.regular
}

// Set adds the given fd to the set.
func (f *FdSet) Set(fd int) {
	if isSocket(syscall.Handle(fd)) {
		f.sockets.Set(fd)
	} else {
		f.regular.Set(fd)
	}
}

// Clear removes the given fd from the set.
func (f *FdSet) Clear(fd int) {
	if isSocket(syscall.Handle(fd)) {
		f.sockets.Clear(fd)
	} else {
		f.regular.Clear(fd)
	}
}

// IsSet returns true when fd is in the set.
func (f *FdSet) IsSet(fd int) bool {
	if isSocket(syscall.Handle(fd)) {
		return f.sockets.IsSet(fd)
	} else {
		return f.regular.IsSet(fd)
	}
}

// Zero clears the set.
func (f *FdSet) Zero() {
	f.sockets.Zero()
	f.regular.Zero()
}

// Set adds the given fd to the set.
func (f *WinSockFdSet) Set(fd int) {
	if f.count < _FD_SETSIZE {
		f.handles[f.count] = syscall.Handle(fd)
		f.count++
	}
}

// Clear removes the given fd from the set.
func (f *WinSockFdSet) Clear(fd int) {
	h := syscall.Handle(fd)
	if !isSocket(h) {
		return
	}

	for i := uint64(0); i < f.count; i++ {
		if f.handles[i] == h {
			for ; i < f.count-1; i++ {
				f.handles[i] = f.handles[i+1]
			}
			f.count--
			break
		}
	}
}

// IsSet returns true when fd is in the set.
func (f *WinSockFdSet) IsSet(fd int) bool {
	h := syscall.Handle(fd)
	if !isSocket(h) {
		return false
	}

	for i := uint64(0); i < f.count; i++ {
		if f.handles[i] == h {
			return true
		}
	}
	return false
}

// Zero clears the set.
func (f *WinSockFdSet) Zero() {
	f.count = 0
}

func (f *WinSockFdSet) Count() int {
	return int(f.count)
}

func (f *WinSockFdSet) Get(index int) syscall.Handle {
	return f.handles[index]
}

// isSocket returns true if the given file handle
// is a pipe.
func isSocket(fd syscall.Handle) bool {
	n, err := syscall.GetFileType(fd)
	if err != nil {
		return false
	}
	if n != syscall.FILE_TYPE_PIPE {
		return false
	}
	// If the call to GetNamedPipeInfo succeeds then
	// the handle is a pipe handle, otherwise it is a socket.
	r, _, errno := syscall.SyscallN(
		procGetNamedPipeInfo.Addr(),
		uintptr(unsafe.Pointer(nil)),
		uintptr(unsafe.Pointer(nil)),
		uintptr(unsafe.Pointer(nil)),
		uintptr(unsafe.Pointer(nil)))
	return r != 0 && errno == 0
}
