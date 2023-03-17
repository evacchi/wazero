package platform

import (
	"syscall"
	"unsafe"
)

func ioctlPtr(fd int, req uint, arg *uint32) (err error) {
	kernel32, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		panic(err)
	}
	defer syscall.FreeLibrary(kernel32)

	// Get a handle to the function
	proc, err := syscall.GetProcAddress(kernel32, "GetNumberOfConsoleInputEvents")
	if err != nil {
		panic(err)
	}

	// Convert the function pointer to the correct type
	var getNumberOfConsoleInputEvents func(syscall.Handle, *uint32) (bool, error)
	getNumberOfConsoleInputEvents = func(handle syscall.Handle, events *uint32) (bool, error) {
		ret, _, err := syscall.Syscall(proc, 2, uintptr(handle), uintptr(unsafe.Pointer(events)), 0)
		return ret != 0, err
	}

	// Use the function
	var numEvents uint32
	handle := syscall.Stdin
	ok, err := getNumberOfConsoleInputEvents(handle, &numEvents)
	if err != nil {
		panic(err)
	}
	if ok {
		println(numEvents)
	}
	*arg = numEvents

	return nil
}

func HasData(fd int) (bool, error) {
	kernel32, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		panic(err)
	}
	defer syscall.FreeLibrary(kernel32)

	var handle syscall.Handle
	switch fd {
	case 0:
		handle = syscall.Stdin
	case 1:
		handle = syscall.Stdout
	case 2:
		handle = syscall.Stderr
	default:
		handle = syscall.Handle(fd)
	}

	t, err := syscall.GetFileType(handle)
	if err != nil {
		return false, err
	}
	if t == syscall.FILE_TYPE_CHAR {
		return false, nil
	}
	if t == syscall.FILE_TYPE_PIPE {
		return true, nil
	}

	return false, nil
}

var (
	kernel32DLL       = syscall.NewLazyDLL("kernel32.dll")
	peekNamedPipeProc = kernel32DLL.NewProc("PeekNamedPipe")
)

func PeekNamedPipe(handle syscall.Handle, bytesAvailable *uint32) error {
	var bytesRead uint32

	// Call the PeekNamedPipe function
	r, _, err := peekNamedPipeProc.Call(
		uintptr(handle),
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&bytesRead)),
		uintptr(unsafe.Pointer(&bytesAvailable)),
		0,
	)

	if r == 0 {
		return err
	}

	return nil
}

func _main() {
	handle, err := syscall.Open("CONIN$", syscall.O_RDONLY, 0)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(handle)

	var bytesAvailable uint32
	err = PeekNamedPipe(handle, &bytesAvailable)
	if err != nil {
		panic(err)
	}

	if bytesAvailable > 0 {
		// read data from stdin
	} else {
		// do something else
	}
}
