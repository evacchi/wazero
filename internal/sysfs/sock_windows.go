//go:build windows

package sysfs

import (
	"net"
	"syscall"
	"time"
	"unsafe"

	"github.com/tetratelabs/wazero/internal/platform"
	socketapi "github.com/tetratelabs/wazero/internal/sock"
)

// MSG_PEEK is the flag PEEK for syscall.Recvfrom on Windows.
// This constant is not exported on this platform.
const (
	MSG_PEEK       = 0x2
	_FIONBIO       = 0x8004667e
	_WASWOULDBLOCK = 10035
)

var (
	// modws2_32 is WinSock.
	modws2_32 = syscall.NewLazyDLL("ws2_32.dll")
	// procrecvfrom exposes recvfrom from WinSock.
	procrecvfrom = modws2_32.NewProc("recvfrom")
	// procaccept exposes accept from WinSock.
	procaccept = modws2_32.NewProc("accept")
	// procioctlsocket exposes ioctlsocket from WinSock.
	procioctlsocket = modws2_32.NewProc("ioctlsocket")
	// procselect exposes select from WinSock.
	procselect = modws2_32.NewProc("select")
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

func winsock_select(n int, r, w, e *platform.WinSockFdSet, timeout *time.Duration) (int, syscall.Errno) {
	if r == nil || r.Count() == 0 && w == nil || w.Count() == 0 && e == nil || e.Count() == 0 {
		return 0, 0
	}
	var t *syscall.Timeval
	if timeout != nil {
		tv := syscall.NsecToTimeval(timeout.Nanoseconds())
		t = &tv
	}
	r0, _, err := syscall.SyscallN(
		procselect.Addr(),
		uintptr(unsafe.Pointer(nil)),
		uintptr(unsafe.Pointer(r)),
		uintptr(unsafe.Pointer(w)),
		uintptr(unsafe.Pointer(e)),
		uintptr(unsafe.Pointer(t)))
	return int(r0), err
}

// newTCPListenerFile is a constructor for a socketapi.TCPSock.
//
// Note: currently the Windows implementation of socketapi.TCPSock
// returns a winTcpListenerFile, which is a specialized TCPSock
// that delegates to a .net.TCPListener.
// The current strategy is to delegate most behavior to the Go
// standard library, instead of invoke syscalls/Win32 APIs
// because they are sensibly different from Unix's.
func newTCPListenerFile(tl *net.TCPListener) socketapi.TCPSock {
	return &winTcpListenerFile{tl: tl}
}

var _ socketapi.TCPSock = (*winTcpListenerFile)(nil)

type winTcpListenerFile struct {
	baseSockFile

	tl       *net.TCPListener
	closed   bool
	nonblock bool
}

// Accept implements the same method as documented on socketapi.TCPSock
//
// If winTcpListenerFile is in nonblocking mode, it will always return
// a non-blocking connection; otherwise it will return a blocking connection.
//
// The (strong) assumption is that the property of being nonblocking should always
// be consistent with the listener that created the connection.
// This may not be always true, but it's a good strategy to get started.
func (f *winTcpListenerFile) Accept() (socketapi.TCPConn, syscall.Errno) {
	if f.IsNonblock() {
		rawConn, err := f.tl.SyscallConn()
		if err != nil {
			return nil, platform.UnwrapOSError(err)
		}

		var tcpFd syscall.Handle
		var errno syscall.Errno
		rawConn.Control(func(fd uintptr) {
			tcpFd, errno = accept(syscall.Handle(fd))
		})
		if errno == _WASWOULDBLOCK {
			errno = syscall.EAGAIN
		}
		if errno != 0 {
			return nil, errno
		}
		return &winNonblockingTcpConnFile{fd: tcpFd}, 0
	} else {
		if conn, err := f.tl.Accept(); err != nil {
			return nil, platform.UnwrapOSError(err)
		} else {
			return &winTcpConnFile{tc: conn.(*net.TCPConn)}, 0
		}
	}
}

// SOCKET WSAAPI accept(
// [in]      SOCKET   s,
// A descriptor that identifies a socket that has been placed in a listening state with the listen
// function. The connection is actually made with the socket that is returned by accept.
// [out]     sockaddr *addr,
// An optional pointer to a buffer that receives the address of the connecting entity,
// as known to the communications layer. The exact format of the addr parameter is determined by
// the address family that was established when the socket from the sockaddr structure was created.
// [in, out] int      *addrlen
// An optional pointer to an integer that contains the length of structure
// pointed to by the addr parameter.
// );
func accept(s syscall.Handle) (fd syscall.Handle, errno syscall.Errno) {
	r0, _, e1 := syscall.SyscallN(
		procaccept.Addr(),
		uintptr(s),
		uintptr(unsafe.Pointer(nil)),
		uintptr(unsafe.Pointer(nil)),
	) // fromlen *int (optional)
	return syscall.Handle(r0), e1
}

// IsNonblock implements File.IsNonblock
func (f *winTcpListenerFile) IsNonblock() bool {
	return f.nonblock
}

// SetNonblock implements the same method as documented on fsapi.File
func (f *winTcpListenerFile) SetNonblock(enabled bool) syscall.Errno {
	f.nonblock = enabled
	rawConn, err := f.tl.SyscallConn()
	if err != nil {
		return platform.UnwrapOSError(err)
	}
	var errno syscall.Errno
	err = rawConn.Control(func(fd uintptr) {
		errno = setNonblockSocket(syscall.Handle(fd), enabled)
	})
	if err != nil {
		return platform.UnwrapOSError(err)
	}
	return errno
}

func setNonblockSocket(fd syscall.Handle, enabled bool) syscall.Errno {
	opt := 0
	if enabled {
		opt = 1
	}
	_, _, e1 := syscall.SyscallN(
		procioctlsocket.Addr(),
		uintptr(fd),
		uintptr(_FIONBIO),
		uintptr(unsafe.Pointer(&opt)))

	return e1 // setNonblock() is a no-op on Windows
}

// Close implements the same method as documented on fsapi.File
func (f *winTcpListenerFile) Close() syscall.Errno {
	if !f.closed {
		return platform.UnwrapOSError(f.tl.Close())
	}
	return 0
}

// Addr is exposed for testing.
func (f *winTcpListenerFile) Addr() *net.TCPAddr {
	return f.tl.Addr().(*net.TCPAddr)
}

var _ socketapi.TCPConn = (*winTcpConnFile)(nil)

// winTcpConnFile is a blocking connection.
//
// It is a wrapper for an underlying net.TCPConn.
type winTcpConnFile struct {
	baseSockFile

	tc *net.TCPConn

	// closed is true when closed was called. This ensures proper syscall.EBADF
	closed bool
}

func newTcpConn(tc *net.TCPConn) socketapi.TCPConn {
	return &winTcpConnFile{tc: tc}
}

// SetNonblock implements the same method as documented on fsapi.File
func (f *winTcpConnFile) SetNonblock(enabled bool) (errno syscall.Errno) {
	syscallConn, err := f.tc.SyscallConn()
	if err != nil {
		return platform.UnwrapOSError(err)
	}

	// Prioritize the error from setNonblock over Control
	if controlErr := syscallConn.Control(func(fd uintptr) {
		errno = platform.UnwrapOSError(setNonblock(fd, enabled))
	}); errno == 0 {
		errno = platform.UnwrapOSError(controlErr)
	}
	return
}

// IsNonblock implements File.IsNonblock
func (f *winTcpConnFile) IsNonblock() bool {
	return false
}

// Read implements the same method as documented on fsapi.File
func (f *winTcpConnFile) Read(buf []byte) (n int, errno syscall.Errno) {
	if n, errno = read(f.tc, buf); errno != 0 {
		// Defer validation overhead until we've already had an error.
		errno = fileError(f, f.closed, errno)
	}
	return
}

// Write implements the same method as documented on fsapi.File
func (f *winTcpConnFile) Write(buf []byte) (n int, errno syscall.Errno) {
	if n, errno = write(f.tc, buf); errno != 0 {
		// Defer validation overhead until we've already had an error.
		errno = fileError(f, f.closed, errno)
	}
	return
}

// Recvfrom implements the same method as documented on socketapi.TCPConn
func (f *winTcpConnFile) Recvfrom(p []byte, flags int) (n int, errno syscall.Errno) {
	if flags != MSG_PEEK {
		errno = syscall.EINVAL
		return
	}
	conn := f.tc
	syscallConn, err := conn.SyscallConn()
	if err != nil {
		errno = platform.UnwrapOSError(err)
		return
	}

	// Prioritize the error from recvfrom over Control
	if controlErr := syscallConn.Control(func(fd uintptr) {
		var recvfromErr error
		n, recvfromErr = recvfrom(syscall.Handle(fd), p, MSG_PEEK)
		errno = platform.UnwrapOSError(recvfromErr)
	}); errno == 0 {
		errno = platform.UnwrapOSError(controlErr)
	}
	return
}

// Shutdown implements the same method as documented on fsapi.Conn
func (f *winTcpConnFile) Shutdown(how int) syscall.Errno {
	// FIXME: can userland shutdown listeners?
	var err error
	switch how {
	case syscall.SHUT_RD:
		err = f.tc.CloseRead()
	case syscall.SHUT_WR:
		err = f.tc.CloseWrite()
	case syscall.SHUT_RDWR:
		return f.close()
	default:
		return syscall.EINVAL
	}
	return platform.UnwrapOSError(err)
}

// Close implements the same method as documented on fsapi.File
func (f *winTcpConnFile) Close() syscall.Errno {
	return f.close()
}

func (f *winTcpConnFile) close() syscall.Errno {
	if f.closed {
		return 0
	}
	f.closed = true
	return f.Shutdown(syscall.SHUT_RDWR)
}

var _ socketapi.TCPConn = (*winNonblockingTcpConnFile)(nil)

// winNonblockingTcpConnFile is a nonblocking connection.
//
// It wraps a bare TCP handle, manipulated via WinSock APIs.
type winNonblockingTcpConnFile struct {
	baseSockFile

	fd syscall.Handle

	tc *net.TCPConn

	// closed is true when closed was called. This ensures proper syscall.EBADF
	closed bool
}

func newNonblockingTcpConn(tc *net.TCPConn) socketapi.TCPConn {
	// we cannot duplicate a file handle,
	// but we can get the raw value
	// and keep it valid by holding the
	// real underlying tc.
	rawConn, err := tc.SyscallConn()
	if err != nil {
		panic(err)
	}
	var fd syscall.Handle
	rawConn.Control(func(_fd uintptr) {
		fd = syscall.Handle(_fd)
	})
	return &winNonblockingTcpConnFile{tc: tc, fd: fd}
}

// IsNonblock implements File.IsNonblock
func (f *winNonblockingTcpConnFile) IsNonblock() bool {
	return true
}

// SetNonblock implements the same method as documented on fsapi.File
func (f *winNonblockingTcpConnFile) SetNonblock(enabled bool) (errno syscall.Errno) {
	err := setNonblockSocket(f.fd, enabled)
	return platform.UnwrapOSError(err)
}

// Read implements the same method as documented on fsapi.File
func (f *winNonblockingTcpConnFile) Read(buf []byte) (n int, errno syscall.Errno) {
	if n, errno = readSocket(f.fd, buf); errno != 0 {
		// Defer validation overhead until we've already had an error.
		errno = fileError(f, f.closed, errno)
	}
	return
}

// Write implements the same method as documented on fsapi.File
func (f *winNonblockingTcpConnFile) Write(buf []byte) (n int, errno syscall.Errno) {
	var done uint32
	var overlapped syscall.Overlapped
	err := syscall.WriteFile(f.fd, buf, &done, &overlapped)
	errno = platform.UnwrapOSError(err)
	n = int(done)
	if errno == syscall.ERROR_IO_PENDING {
		errno = syscall.EAGAIN
	}
	return
}

// Recvfrom implements the same method as documented on socketapi.TCPConn
func (f *winNonblockingTcpConnFile) Recvfrom(p []byte, flags int) (n int, errno syscall.Errno) {
	if flags != MSG_PEEK {
		errno = syscall.EINVAL
		return
	}
	var recvfromErr error
	n, recvfromErr = recvfrom(f.fd, p, MSG_PEEK)
	errno = platform.UnwrapOSError(recvfromErr)
	return
}

// Shutdown implements the same method as documented on fsapi.Conn
func (f *winNonblockingTcpConnFile) Shutdown(how int) syscall.Errno {
	// FIXME: can userland shutdown listeners?
	var err error
	switch how {
	case syscall.SHUT_RD:
		err = f.tc.CloseRead()
	case syscall.SHUT_WR:
		err = f.tc.CloseWrite()
	case syscall.SHUT_RDWR:
		err = f.tc.Close()
	default:
		return syscall.EINVAL
	}
	return platform.UnwrapOSError(err)
}
