// Package platform includes runtime-specific code needed for the compiler or otherwise.
//
// Note: This is a dependency-free alternative to depending on parts of Go's x/sys.
// See /RATIONALE.md for more context.
package platform

import (
	"log"
	"runtime"
	"unsafe"
)

// archRequirementsVerified is set by platform-specific init to true if the platform is supported
var archRequirementsVerified bool

// CompilerSupported is exported for tests and includes constraints here and also the assembler.
func CompilerSupported() bool {
	switch runtime.GOOS {
	case "darwin", "windows", "linux", "freebsd":
	default:
		return false
	}

	return archRequirementsVerified
}

// MmapCodeSegment copies the code into the executable region and returns the byte slice of the region.
//
// See https://man7.org/linux/man-pages/man2/mmap.2.html for mmap API and flags.
func MmapCodeSegment(size int) ([]byte, error) {
	if size == 0 {
		panic("BUG: MmapCodeSegment with zero length")
	}
	if runtime.GOARCH == "amd64" {
		return mmapCodeSegmentAMD64(size)
	} else {
		return mmapCodeSegmentARM64(size)
	}
}

// MmapMemory allocates a buffer of the given size using mmap. A large size can be allocated at once
// without raising process memory usage, and physical pages will be allocated on access after calls to
// Grow.
func MmapMemory(size int) ([]byte, error) {
	if size == 0 {
		panic("BUG: MmapMemory with zero length")
	}
	return mmapMemory(size)
}

// RemapCodeSegment reallocates the memory mapping of an existing code segment
// to increase its size. The previous code mapping is unmapped and must not be
// reused after the function returns.
//
// This is similar to mremap(2) on linux, and emulated on platforms which do not
// have this syscall.
//
// See https://man7.org/linux/man-pages/man2/mremap.2.html
func RemapCodeSegment(code []byte, size int) ([]byte, error) {
	log.Printf("Remapping code segment: len=%v, ptr=%x\n", size, unsafe.SliceData(code))

	if size < len(code) {
		panic("BUG: RemapCodeSegment with size less than code")
	}
	if code == nil {
		return MmapCodeSegment(size)
	}
	if runtime.GOARCH == "amd64" {
		segm, err := remapCodeSegmentAMD64(code, size)
		log.Printf("Remapped code segment error: %v\n", err)
		log.Printf("Remapped code segment: len=%v, ptr=%x", size, unsafe.SliceData(segm))
		return segm, err
	} else {
		return remapCodeSegmentARM64(code, size)
	}
}

// MunmapCodeSegment unmaps the given memory region.
func MunmapCodeSegment(code []byte) error {
	if len(code) == 0 {
		panic("BUG: MunmapCodeSegment with zero length")
	}
	return munmapCodeSegment(code)
}

// mustMunmapCodeSegment panics instead of returning an error to the
// application.
//
// # Why panic?
//
// It is less disruptive to the application to leak the previous block if it
// could be unmapped than to leak the new block and return an error.
// Realistically, either scenarios are pretty hard to debug, so we panic.
func mustMunmapCodeSegment(code []byte) {
	if err := munmapCodeSegment(code); err != nil {
		panic(err)
	}
}
