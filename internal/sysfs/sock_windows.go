//go:build windows

package sysfs

import (
	"os"
	"syscall"
	"unsafe"

	"github.com/tetratelabs/wazero/internal/platform"
)

// MSG_PEEK is the flag PEEK for syscall.Recvfrom on Windows.
// This constant is not exported on this platform.
const MSG_PEEK = 0x2

type Sysfd = syscall.Handle

// recvfromPeek exposes syscall.Recvfrom with flag MSG_PEEK on Windows.
func recvfromPeek(fd Sysfd, p []byte) (n int, errno syscall.Errno) {
	return recvfrom(fd, p, MSG_PEEK)
}

var (
	// modws2_32 is WinSock.
	modws2_32 = syscall.NewLazyDLL("ws2_32.dll")
	// procrecvfrom exposes recvfrom from WinSock.
	procrecvfrom = modws2_32.NewProc("recvfrom")
)

// recvfrom exposes the underlying syscall in Windows.
//
// Note: since we are only using this to expose MSG_PEEK,
// we do not need really need all the parameters that are actually
// allowed in WinSock.
// We ignore `from *sockaddr` and `fromlen *int`.
func recvfrom(s syscall.Handle, buf []byte, flags int32) (n int, errno syscall.Errno) {
	var _p0 *byte
	if len(buf) > 0 {
		_p0 = &buf[0]
	}
	r0, _, e1 := syscall.SyscallN(
		procrecvfrom.Addr(),
		uintptr(s),
		uintptr(unsafe.Pointer(_p0)),
		uintptr(len(buf)),
		uintptr(flags),
		0, // from *sockaddr (optional)
		0) // fromlen *int (optional)
	return int(r0), e1
}

func getSysfd(conn *os.File) Sysfd {
	return Sysfd(conn.Fd())
}

func syscallAccept(fd Sysfd) (Sysfd, syscall.Errno) {
	nfd, _, err := syscall.Accept(fd)
	return nfd, platform.UnwrapOSError(err)
}

func syscallClose(fd Sysfd) error {
	return platform.UnwrapOSError(syscall.Close(fd))
}

func syscallRead(fd Sysfd, buf []byte) (n int, errno syscall.Errno) {
	n, err := syscall.Read(fd, buf)
	if err != nil {
		// Defer validation overhead until we've already had an error.
		errno = platform.UnwrapOSError(err)
	}
	return n, errno
}

func syscallWrite(fd Sysfd, buf []byte) (n int, errno syscall.Errno) {
	n, err := syscall.Write(fd, buf)
	if err != nil {
		// Defer validation overhead until we've already had an error.
		errno = platform.UnwrapOSError(err)
	}
	return n, errno
}

func syscallShutdown(fd Sysfd, how int) syscall.Errno {
	return platform.UnwrapOSError(syscall.Shutdown(fd, how))
}
