//go:build darwin || linux || freebsd

package platform

import (
	"log"
	"syscall"
	"unsafe"
)

const (
	mmapProtAMD64 = syscall.PROT_READ | syscall.PROT_WRITE | syscall.PROT_EXEC
	mmapProtARM64 = syscall.PROT_READ | syscall.PROT_WRITE
)

const MmapSupported = true

func mmapMemory(size int) ([]byte, error) {
	return syscall.Mmap(
		-1,
		0,
		size,
		syscall.PROT_READ|syscall.PROT_WRITE,
		// Anonymous as this is not an actual file, but a memory,
		// Private as this is in-process memory region.
		syscall.MAP_ANON|syscall.MAP_PRIVATE,
	)
}

func munmapCodeSegment(code []byte) error {
	log.Printf("About to unmap: %v \n", unsafe.SliceData(code))
	err := syscall.Munmap(code)
	if err != nil {
		log.Printf("Unmapped with error=%v\n", err)
	}
	return err
}

// mmapCodeSegmentAMD64 gives all read-write-exec permission to the mmap region
// to enter the function. Otherwise, segmentation fault exception is raised.
func mmapCodeSegmentAMD64(size int) ([]byte, error) {
	// The region must be RWX: RW for writing native codes, X for executing the region.
	x, err := mmapCodeSegment(size, mmapProtAMD64)
	log.Printf("Mmapped code segment: len=%v, ptr=%x\n", size, unsafe.SliceData(x))
	return x, err
}

// mmapCodeSegmentARM64 cannot give all read-write-exec permission to the mmap region.
// Otherwise, the mmap systemcall would raise an error. Here we give read-write
// to the region so that we can write contents at call-sites. Callers are responsible to
// execute MprotectRX on the returned buffer.
func mmapCodeSegmentARM64(size int) ([]byte, error) {
	// The region must be RW: RW for writing native codes.
	return mmapCodeSegment(size, mmapProtARM64)
}

// MprotectRX is like syscall.Mprotect with RX permission, defined locally so that freebsd compiles.
func MprotectRX(b []byte) (err error) {
	var _p0 unsafe.Pointer
	if len(b) > 0 {
		_p0 = unsafe.Pointer(&b[0])
	}
	const prot = syscall.PROT_READ | syscall.PROT_EXEC
	_, _, e1 := syscall.Syscall(syscall.SYS_MPROTECT, uintptr(_p0), uintptr(len(b)), uintptr(prot))
	if e1 != 0 {
		err = syscall.Errno(e1)
	}
	return
}
