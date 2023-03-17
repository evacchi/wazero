package platform

import (
	"syscall"
	"unsafe"
)

func ioctlPtr(fd int, req uint, arg unsafe.Pointer) (err error) {
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
