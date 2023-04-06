package wasi_snapshot_preview1

import (
	"context"
	"io/fs"
	"syscall"
	"time"

	"github.com/tetratelabs/wazero/api"
	internalsys "github.com/tetratelabs/wazero/internal/sys"
	"github.com/tetratelabs/wazero/internal/wasip1"
	"github.com/tetratelabs/wazero/internal/wasm"
)

// pollOneoff is the WASI function named PollOneoffName that concurrently
// polls for the occurrence of a set of events.
//
// # Parameters
//
//   - in: pointer to the subscriptions (48 bytes each)
//   - out: pointer to the resulting events (32 bytes each)
//   - nsubscriptions: count of subscriptions, zero returns syscall.EINVAL.
//   - resultNevents: count of events.
//
// Result (Errno)
//
// The return value is 0 except the following error conditions:
//   - syscall.EINVAL: the parameters are invalid
//   - syscall.ENOTSUP: a parameters is valid, but not yet supported.
//   - syscall.EFAULT: there is not enough memory to read the subscriptions or
//     write results.
//
// # Notes
//
//   - Since the `out` pointer nests Errno, the result is always 0.
//   - This is similar to `poll` in POSIX.
//
// See https://github.com/WebAssembly/WASI/blob/snapshot-01/phases/snapshot/docs.md#poll_oneoff
// See https://linux.die.net/man/3/poll
var pollOneoff = newHostFunc(
	wasip1.PollOneoffName, pollOneoffFn,
	[]api.ValueType{i32, i32, i32, i32},
	"in", "out", "nsubscriptions", "result.nevents",
)

type pollValue = struct {
	eventType byte
	userData  []byte
	errno     byte
	outOffset uint32
}

func pollOneoffFn(ctx context.Context, mod api.Module, params []uint64) syscall.Errno {
	in := uint32(params[0])
	out := uint32(params[1])
	nsubscriptions := uint32(params[2])
	resultNevents := uint32(params[3])

	if nsubscriptions == 0 {
		return syscall.EINVAL
	}

	mem := mod.Memory()

	// Ensure capacity prior to the read loop to reduce error handling.
	inBuf, ok := mem.Read(in, nsubscriptions*48)
	if !ok {
		return syscall.EFAULT
	}
	outBuf, ok := mem.Read(out, nsubscriptions*32)
	if !ok {
		return syscall.EFAULT
	}

	// Eagerly write the number of events which will equal subscriptions unless
	// there's a fault in parsing (not processing).
	if !mod.Memory().WriteUint32Le(resultNevents, nsubscriptions) {
		return syscall.EFAULT
	}

	// Loop through all subscriptions and write their output.

	resultChannel := make(chan pollValue)

	// Layout is subscription_u: Union
	// https://github.com/WebAssembly/WASI/blob/snapshot-01/phases/snapshot/docs.md#subscription_u
	for i := uint32(0); i < nsubscriptions; i++ {
		inOffset := i * 48
		outOffset := i * 32

		eventType := inBuf[inOffset+8] // +8 past userdata
		argBuf := inBuf[inOffset+8+8:]
		userData := inBuf[inOffset : inOffset+8]

		v := pollValue{
			eventType: eventType,
			userData:  userData,
			errno:     0,
			outOffset: outOffset,
		}

		errno, done := processEvent(ctx, mod, argBuf, v, resultChannel)
		if done {
			return errno
		}
	}

	value := <-resultChannel

	write(outBuf, value)

	return 0
}

func write(outBuf []byte, value pollValue) {
	// Write the event corresponding to the processed subscription.
	// https://github.com/WebAssembly/WASI/blob/snapshot-01/phases/snapshot/docs.md#-event-struct
	copy(outBuf, value.userData) // userdata
	//if errno != 0 {
	outBuf[value.outOffset+8] = value.errno // uint16, but safe as < 255
	//} else { // special case ass ErrnoSuccess is zero
	//	outBuf[outOffset+8] = 0
	//}
	outBuf[value.outOffset+9] = 0
	le.PutUint32(outBuf[value.outOffset+10:], uint32(value.eventType))
	// TODO: When FD events are supported, write outOffset+16
}

func processEvent(ctx context.Context, mod api.Module, argBuf []byte, value pollValue, result chan pollValue) (syscall.Errno, bool) {
	var errno syscall.Errno // errno for this specific event (1-byte)
	switch value.eventType {
	case wasip1.EventTypeClock: // handle later
		// +8 past userdata +8 contents_offset
		processClockEvent(mod, argBuf, value, result)
	case wasip1.EventTypeFdRead, wasip1.EventTypeFdWrite:
		// +8 past userdata +8 contents_offset
		processFDEvent(mod, argBuf, value, result)
	default:
		return syscall.EINVAL, true
	}
	return errno, false
}

// processClockEvent supports only relative name events, as that's what's used
// to implement sleep in various compilers including Rust, Zig and TinyGo.
func processClockEvent(mod api.Module, inBuf []byte, value pollValue, result chan pollValue) {
	_ /* ID */ = le.Uint32(inBuf[0:8])          // See below
	timeout := le.Uint64(inBuf[8:16])           // nanos if relative
	_ /* precision */ = le.Uint64(inBuf[16:24]) // Unused
	flags := le.Uint16(inBuf[24:32])

	go func() {
		var err syscall.Errno
		// subclockflags has only one flag defined:  subscription_clock_abstime
		switch flags {
		case 0: // relative time
		case 1: // subscription_clock_abstime
			err = syscall.ENOTSUP
		default: // subclockflags has only one flag defined.
			err = syscall.EINVAL
		}

		if err != 0 {
			value.errno = byte(wasip1.ToErrno(err))
			result <- value
		} else {
			// https://linux.die.net/man/3/clock_settime says relative timers are
			// unaffected. Since this function only supports relative timeout, we can
			// skip name ID validation and use a single sleep function.
			_ = <-time.After(time.Duration(timeout))
			value.errno = 0
			result <- value
		}
	}()

}

// processFDEvent returns a validation error or syscall.ENOTSUP as file or socket
// subscriptions are not yet supported.
func processFDEvent(mod api.Module, inBuf []byte, value pollValue, result chan pollValue) {
	fd := le.Uint32(inBuf)
	fsc := mod.(*wasm.ModuleInstance).Sys.FS()

	go func() {
		// Choose the best error, which falls back to unsupported, until we support
		// files.
		errno := syscall.ENOTSUP
		if value.eventType == wasip1.EventTypeFdRead {
			// if we return this, we are inhibiting already the timer
			// because it returns right away
			if f, ok := fsc.LookupFile(fd); ok {
				st, _ := f.Stat()
				// if fd is a pipe, then it is not a char device (a tty)
				if st.Mode&fs.ModeCharDevice != 0 {
					if reader, ok := f.File.(*internalsys.StdioFileReader); ok {
						a, err := reader.BufferedReader.ReadByte()
						println(a)
						if err == nil {
							reader.BufferedReader.UnreadByte()
							errno = syscall.EBADF
						}
					}
				}
			} else {
				errno = syscall.EBADF
			}
			//alt:
			//if _, ok := fsc.LookupFile(fd); !ok {
			//	errno = syscall.EBADF
			//}
			//sy
		} else if value.eventType == wasip1.EventTypeFdWrite && internalsys.WriterForFile(fsc, fd) == nil {
			errno = syscall.EBADF
		}
		value.errno = byte(wasip1.ToErrno(errno))
		result <- value
	}()
}
