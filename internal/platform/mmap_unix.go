//go:build unix

package platform

import "golang.org/x/sys/unix"

func munmapCodeSegment(code []byte) error {
	return unix.Munmap(code)
}

// MprotectCodeSegment is like unix.Mprotect with RX permission.
func MprotectCodeSegment(b []byte) (err error) {
	return unix.Mprotect(b, unix.PROT_READ|unix.PROT_EXEC)
}

// MprotectCodeSegmentDebug is like MprotectCodeSegment but keeps
// write permission so that debuggers can set software breakpoints.
func MprotectCodeSegmentDebug(b []byte) (err error) {
	return unix.Mprotect(b, unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC)
}
