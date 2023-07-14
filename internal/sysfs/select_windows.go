package sysfs

import (
	"context"
	"syscall"
	"time"

	"github.com/tetratelabs/wazero/internal/platform"
)

// wasiFdStdin is the constant value for stdin on Wasi.
// We need this constant because on Windows os.Stdin.Fd() != 0.
const wasiFdStdin = 0

// pollInterval is the interval between each calls to peekNamedPipe in pollNamedPipe
const pollInterval = 100 * time.Millisecond

// syscall_select emulates the select syscall on Windows for two, well-known cases, returns syscall.ENOSYS for all others.
// If r contains fd 0, and it is a regular file, then it immediately returns 1 (data ready on stdin)
// and r will have the fd 0 bit set.
// If r contains fd 0, and it is a FILE_TYPE_CHAR, then it invokes PeekNamedPipe to check the buffer for input;
// if there is data ready, then it returns 1 and r will have fd 0 bit set.
// If n==0 it will wait for the given timeout duration, but it will return syscall.ENOSYS if timeout is nil,
// i.e. it won't block indefinitely.
//
// Note: idea taken from https://stackoverflow.com/questions/6839508/test-if-stdin-has-input-for-c-windows-and-or-linux
// PeekNamedPipe: https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-peeknamedpipe
// "GetFileType can assist in determining what device type the handle refers to. A console handle presents as FILE_TYPE_CHAR."
// https://learn.microsoft.com/en-us/windows/console/console-handles
func syscall_select(n int, r, w, e *platform.FdSet, timeout *time.Duration) (int, error) {
	if n == 0 {
		// Don't block indefinitely.
		if timeout == nil {
			return -1, syscall.ENOSYS
		}
		time.Sleep(*timeout)
		return 0, nil
	}

	npipes, err := selectPipes(r.Regular(), timeout)
	if err != 0 {
		return npipes, err
	}

	nsocks, err := winsock_select(n, r.Sockets(), w.Sockets(), e.Sockets(), timeout)
	if err == syscall.Errno(0) {
		return npipes + nsocks, nil
	}
	return npipes + nsocks, err
}

func selectPipes(r *platform.WinSockFdSet, timeout *time.Duration) (int, syscall.Errno) {
	res, err := pollNamedPipes(context.TODO(), r, timeout)
	if err != 0 {
		return -1, err
	}
	if res != 0 {
		r.Zero()
		return 0, 0
	}
	return res, err
}

// pollNamedPipes polls the given named pipe handles for the given duration.
//
// The implementation actually polls every 100 milliseconds until it reaches the given duration.
// The duration may be nil, in which case it will wait undefinely. The given ctx is
// used to allow for cancellation. Currently used only in tests.
func pollNamedPipes(ctx context.Context, pipeHandles *platform.WinSockFdSet, duration *time.Duration) (int, syscall.Errno) {
	// Short circuit when the duration is zero.
	if duration != nil && *duration == time.Duration(0) {
		return peekAllPipes(pipeHandles)
	}

	// Ticker that emits at every pollInterval.
	tick := time.NewTicker(pollInterval)
	tickCh := tick.C
	defer tick.Stop()

	// Timer that expires after the given duration.
	// Initialize afterCh as nil: the select below will wait forever.
	var afterCh <-chan time.Time
	if duration != nil {
		// If duration is not nil, instantiate the timer.
		after := time.NewTimer(*duration)
		defer after.Stop()
		afterCh = after.C
	}

	for {
		select {
		case <-ctx.Done():
			return 0, 0
		case <-afterCh:
			return 0, 0
		case <-tickCh:
			return peekAllPipes(pipeHandles)
		}
	}
}

func peekAllPipes(pipeHandles *platform.WinSockFdSet) (int, syscall.Errno) {
	ready := 0
	for i := 0; i < pipeHandles.Count(); i++ {
		h := pipeHandles.Get(i)
		bytes, err := peekNamedPipe(h)
		if bytes > 0 {
			ready++
		}
		if err != 0 {
			return ready, err
		}
	}
	return ready, 0
}
