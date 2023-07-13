package platform

import (
	"syscall"
	"unsafe"
)

var procGetNamedPipeInfo = kernel32.NewProc("GetNamedPipeInfo")

const _FD_SETSIZE = 64

// WinSockFdSet implements the FdSet representation that is used internally by WinSock.
//
// Note that this representation is quite different from the one used in most POSIX implementations.
type WinSockFdSet struct {
	count uint64
	Array [_FD_SETSIZE]syscall.Handle
}

// FdSet re-exports syscall.FdSet with utility methods.
type FdSet struct {
	Sockets WinSockFdSet
	Regular WinSockFdSet
}

// Set adds the given fd to the set.
func (f *FdSet) Set(fd int) {
	if isSocket(syscall.Handle(fd)) {
		f.Sockets.Set(fd)
	} else {
		f.Regular.Set(fd)
	}
}

// Clear removes the given fd from the set.
func (f *FdSet) Clear(fd int) {
	if isSocket(syscall.Handle(fd)) {
		f.Sockets.Clear(fd)
	} else {
		f.Regular.Clear(fd)
	}
}

// IsSet returns true when fd is in the set.
func (f *FdSet) IsSet(fd int) bool {
	if isSocket(syscall.Handle(fd)) {
		return f.Sockets.IsSet(fd)
	} else {
		return f.Regular.IsSet(fd)
	}
}

// Zero clears the set.
func (f *FdSet) Zero() {
	f.Sockets.Zero()
	f.Regular.Zero()
}

// Set adds the given fd to the set.
func (f *WinSockFdSet) Set(fd int) {
	if f.count < _FD_SETSIZE {
		f.Array[f.count] = syscall.Handle(fd)
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
		if f.Array[i] == h {
			for ; i < f.count-1; i++ {
				f.Array[i] = f.Array[i+1]
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
		if f.Array[i] == h {
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
	return f.Array[index]
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
