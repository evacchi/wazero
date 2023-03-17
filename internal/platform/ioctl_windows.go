package platform

import (
	"syscall"
)

func HasData(fd int) (bool, error) {
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
