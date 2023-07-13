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

	n, err := selectPipe(&r.Regular, timeout)
	if err != nil {
		return n, err
	}

	var rs, ws, es *platform.WinSockFdSet
	if r != nil {
		rs = &r.Sockets
	}
	if w != nil {
		ws = &w.Sockets
	}
	if e != nil {
		es = &e.Sockets
	}

	n2, err := winsock_select(n, rs, ws, es, timeout)
	if err == syscall.Errno(0) {
		return n + n2, nil
	}
	return n + n2, err
}

func selectPipe(r *platform.WinSockFdSet, timeout *time.Duration) (int, error) {
	res, err := pollNamedPipe(context.TODO(), r, timeout)
	if err != nil {
		return -1, err
	}
	if !res {
		r.Zero()
		return 0, nil
	}
	return 1, nil
}

// pollNamedPipe polls the given named pipe handle for the given duration.
//
// The implementation actually polls every 100 milliseconds until it reaches the given duration.
// The duration may be nil, in which case it will wait undefinely. The given ctx is
// used to allow for cancellation. Currently used only in tests.
func pollNamedPipe(ctx context.Context, pipeHandles *platform.WinSockFdSet, duration *time.Duration) (bool, error) {
	// Short circuit when the duration is zero.
	if duration != nil && *duration == time.Duration(0) {
		return peekAllPipes(pipeHandles)
	}

	// Ticker that emits at every pollInterval.
	tick := time.NewTicker(pollInterval)
	tichCh := tick.C
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
			return false, nil
		case <-afterCh:
			return false, nil
		case <-tichCh:
			res, err := peekAllPipes(pipeHandles)
			if err != nil {
				return false, err
			}
			if res {
				return true, nil
			}
		}
	}
}

func peekAllPipes(pipeHandles *platform.WinSockFdSet) (bool, error) {
	for i := 0; i < pipeHandles.Count(); i++ {
		h := pipeHandles.Get(i)
		bytes, err := peekNamedPipe(h)
		if err != nil {
			return false, err
		}
		if bytes > 0 {
			return bytes > 0, err
		}
	}
	return false, nil
}

func wsastartup() error {
	var d syscall.WSAData
	e := syscall.WSAStartup(uint32(0x202), &d)
	if e != nil {
		return e
	}
	return nil
}
