//go:build windows

package sysfs

import (
	"net"
	"os"
	"syscall"
	"unsafe"

	"github.com/tetratelabs/wazero/internal/fsapi"
	"github.com/tetratelabs/wazero/internal/platform"
	socketapi "github.com/tetratelabs/wazero/internal/sock"
)

// MSG_PEEK is the flag PEEK for syscall.Recvfrom on Windows.
// This constant is not exported on this platform.
const MSG_PEEK = 0x2

type Sysfd = syscall.Handle

// recvfromPeek exposes syscall.Recvfrom with flag MSG_PEEK on Windows.
func recvfromPeek(conn *net.TCPConn, p []byte) (n int, errno syscall.Errno) {
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

func NewTCPListenerFile(tl *net.TCPListener) socketapi.TCPSock {
	return &winTcpListenerFile{tl: tl}
}

var _ socketapi.TCPSock = (*winTcpListenerFile)(nil)

type winTcpListenerFile struct {
	fsapi.UnimplementedFile

	tl *net.TCPListener
}

// Accept implements the same method as documented on socketapi.TCPSock
func (f *winTcpListenerFile) Accept() (socketapi.TCPConn, syscall.Errno) {
	conn, err := f.tl.Accept()
	if err != nil {
		return nil, platform.UnwrapOSError(err)
	}
	return &winTcpConnFile{tc: conn.(*net.TCPConn)}, 0
}

// IsDir implements the same method as documented on File.IsDir
func (*winTcpListenerFile) IsDir() (bool, syscall.Errno) {
	// We need to override this method because WASI-libc prestats the FD
	// and the default impl returns ENOSYS otherwise.
	return false, 0
}

// Stat implements the same method as documented on File.Stat
func (f *winTcpListenerFile) Stat() (fs fsapi.Stat_t, errno syscall.Errno) {
	// The mode is not really important, but it should be neither a regular file nor a directory.
	fs.Mode = os.ModeIrregular
	return
}

// Close implements the same method as documented on fsapi.File
func (f *winTcpListenerFile) Close() syscall.Errno {
	return platform.UnwrapOSError(f.tl.Close())
}

// Addr is exposed for testing.
func (f *winTcpListenerFile) Addr() *net.TCPAddr {
	return f.tl.Addr().(*net.TCPAddr)
}

var _ socketapi.TCPConn = (*winTcpConnFile)(nil)

type winTcpConnFile struct {
	fsapi.UnimplementedFile

	tc *net.TCPConn

	// closed is true when closed was called. This ensures proper syscall.EBADF
	closed bool
}

func newTcpConn(conn *net.TCPConn) socketapi.TCPConn {
	return &winTcpConnFile{tc: conn}
}

// IsDir implements the same method as documented on File.IsDir
func (*winTcpConnFile) IsDir() (bool, syscall.Errno) {
	// We need to override this method because WASI-libc prestats the FD
	// and the default impl returns ENOSYS otherwise.
	return false, 0
}

// Stat implements the same method as documented on File.Stat
func (f *winTcpConnFile) Stat() (fs fsapi.Stat_t, errno syscall.Errno) {
	// The mode is not really important, but it should be neither a regular file nor a directory.
	fs.Mode = os.ModeIrregular
	return
}

// SetNonblock implements the same method as documented on fsapi.File
func (f *winTcpConnFile) SetNonblock(enabled bool) (errno syscall.Errno) {
	syscallConn, err := f.tc.SyscallConn()
	if err != nil {
		return platform.UnwrapOSError(err)
	}

	// Prioritize the error from setNonblock over Control
	if controlErr := syscallConn.Control(func(fd uintptr) {
		errno = platform.UnwrapOSError(setNonblock(Sysfd(fd), enabled))
	}); errno == 0 {
		errno = platform.UnwrapOSError(controlErr)
	}
	return
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
		// Defer validation overhead until we've alwritey had an error.
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
	return recvfromPeek(f.tc, p)
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
