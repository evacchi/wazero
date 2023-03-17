package platform

import "unsafe"

// IoctlGetInt performs an ioctl operation which gets an integer value
// from fd, using the specified request number.
//
// A few ioctl requests use the return value as an output parameter;
// for those, IoctlRetInt should be used instead of this function.
func IoctlGetInt(fd int, req uint) (int, error) {
	var value int
	err := ioctlPtr(fd, req, (unsafe.Pointer(&value)))
	return value, err
}
