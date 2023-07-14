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

const (
	// MSG_PEEK is the flag PEEK for syscall.Recvfrom on Windows.
	// This constant is not exported on this platform.
	MSG_PEEK = 0x2
	// _FIONBIO is the flag to set the O_NONBLOCK flag on socket handles using ioctlsocket.
	_FIONBIO = 0x8004667e
	// _WASWOULDBLOCK corresponds to syscall.EWOULDBLOCK in WinSock.
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
	if (r == nil || r.Count() == 0) && (w == nil || w.Count() == 0) && (e == nil || e.Count() == 0) {
		return 0, 0
	}
	var t *syscall.Timeval
	if timeout != nil {
		tv := syscall.NsecToTimeval(timeout.Nanoseconds())
		t = &tv
	}
	r0, _, err := syscall.SyscallN(
		procselect.Addr(),
		uintptr(unsafe.Pointer(nil)), // the first argument is ignored and exists only for compat with BSD sockets.
		uintptr(unsafe.Pointer(r)),
		uintptr(unsafe.Pointer(w)),
		uintptr(unsafe.Pointer(e)),
		uintptr(unsafe.Pointer(t)))
	return int(r0), err
}

func setNonblockSocket(fd syscall.Handle, enabled bool) syscall.Errno {
	opt := uint64(0)
	if enabled {
		opt = 1
	}
	// ioctlsocket(fd, FIONBIO, &opt)
	_, _, errno := syscall.SyscallN(
		procioctlsocket.Addr(),
		uintptr(fd),
		uintptr(_FIONBIO),
		uintptr(unsafe.Pointer(&opt)))
	return errno
}

// syscallConnControl extracts a syscall.RawConn from the given syscall.Conn and applies
// the given fn to a file descriptor, returning an integer or a nonzero syscall.Errno on failure.
//
// syscallConnControl streamlines the pattern of extracting the syscall.Rawconn,
// invoking its syscall.RawConn.Control method, then handling properly the errors that may occur
// within fn or returned by syscall.RawConn.Control itself.
func syscallConnControl(conn syscall.Conn, fn func(fd uintptr) (int, syscall.Errno)) (n int, errno syscall.Errno) {
	syscallConn, err := conn.SyscallConn()
	if err != nil {
		return 0, platform.UnwrapOSError(err)
	}
	// Prioritize the inner errno over Control
	if controlErr := syscallConn.Control(func(fd uintptr) {
		n, errno = fn(fd)
	}); errno == 0 {
		errno = platform.UnwrapOSError(controlErr)
	}
	return
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
	w := &winTcpListenerFile{tl: tl}
	_ = w.SetNonblock(true)
	return w
}

var _ socketapi.TCPSock = (*winTcpListenerFile)(nil)

type winTcpListenerFile struct {
	baseSockFile

	tl       *net.TCPListener
	closed   bool
	nonblock bool
}

// Accept implements the same method as documented on socketapi.TCPSock
func (f *winTcpListenerFile) Accept() (socketapi.TCPConn, syscall.Errno) {
	// Ensure we have an incoming connection using winsock_select.
	n, errno := syscallConnControl(f.tl, func(fd uintptr) (int, syscall.Errno) {
		fdSet := platform.WinSockFdSet{}
		fdSet.Set(int(fd))
		t := time.Duration(0)
		return winsock_select(1, &fdSet, nil, nil, &t)
	})

	// Otherwise return immediately.
	if n == 0 || errno != 0 {
		return nil, syscall.EAGAIN
	}

	// Accept normally blocks goroutines, but we
	// made sure that we have an incoming connection,
	// so we should be safe.
	if conn, err := f.tl.Accept(); err != nil {
		return nil, platform.UnwrapOSError(err)
	} else {
		return newTcpConn(conn.(*net.TCPConn)), 0
	}
}

// IsNonblock implements File.IsNonblock
func (f *winTcpListenerFile) IsNonblock() bool {
	return f.nonblock
}

// SetNonblock implements the same method as documented on fsapi.File
func (f *winTcpListenerFile) SetNonblock(enabled bool) syscall.Errno {
	f.nonblock = enabled
	_, errno := syscallConnControl(f.tl, func(fd uintptr) (int, syscall.Errno) {
		return 0, setNonblockSocket(syscall.Handle(fd), enabled)
	})
	return errno
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

	// nonblock is true when the underlying connection is flagged as non-blocking.
	// This ensures that reads and writes return EAGAIN without blocking the caller.
	nonblock bool
	// closed is true when closed was called. This ensures proper syscall.EBADF
	closed bool
}

func newTcpConn(tc *net.TCPConn) socketapi.TCPConn {
	return &winTcpConnFile{tc: tc}
}

// SetNonblock implements the same method as documented on fsapi.File
func (f *winTcpConnFile) SetNonblock(enabled bool) (errno syscall.Errno) {
	_, errno = syscallConnControl(f.tc, func(fd uintptr) (int, syscall.Errno) {
		return 0, platform.UnwrapOSError(setNonblockSocket(syscall.Handle(fd), enabled))
	})
	return
}

// IsNonblock implements File.IsNonblock
func (f *winTcpConnFile) IsNonblock() bool {
	return f.nonblock
}

// Read implements the same method as documented on fsapi.File
func (f *winTcpConnFile) Read(buf []byte) (n int, errno syscall.Errno) {
	if len(buf) == 0 {
		return 0, 0 // Short-circuit 0-len reads.
	}
	if NonBlockingFileIoSupported && f.IsNonblock() {
		n, errno = syscallConnControl(f.tc, func(fd uintptr) (int, syscall.Errno) {
			return readSocket(syscall.Handle(fd), buf)
		})
	} else {
		n, errno = read(f.tc, buf)
	}
	if errno != 0 {
		// Defer validation overhead until we've already had an error.
		errno = fileError(f, f.closed, errno)
	}
	return
}

// Write implements the same method as documented on fsapi.File
func (f *winTcpConnFile) Write(buf []byte) (n int, errno syscall.Errno) {
	if NonBlockingFileIoSupported && f.IsNonblock() {
		return syscallConnControl(f.tc, func(fd uintptr) (int, syscall.Errno) {
			return writeFd(fd, buf)
		})
	} else {
		n, errno = write(f.tc, buf)
	}
	if errno != 0 {
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
	return syscallConnControl(f.tc, func(fd uintptr) (int, syscall.Errno) {
		return recvfrom(syscall.Handle(fd), p, MSG_PEEK)
	})
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
