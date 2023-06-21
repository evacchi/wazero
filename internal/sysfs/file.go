package sysfs

import (
	"io"
	"io/fs"
	"os"
	"syscall"

	"github.com/tetratelabs/wazero/internal/fsapi"
	"github.com/tetratelabs/wazero/internal/platform"
)

func NewStdioFile(stdin bool, f fs.File) (fsapi.File, error) {
	// Return constant stat, which has fake times, but keep the underlying
	// file mode. Fake times are needed to pass wasi-testsuite.
	// https://github.com/WebAssembly/wasi-testsuite/blob/af57727/tests/rust/src/bin/fd_filestat_get.rs#L1-L19
	var mode fs.FileMode
	if st, err := f.Stat(); err != nil {
		return nil, err
	} else {
		mode = st.Mode()
	}
	var flag int
	if stdin {
		flag = syscall.O_RDONLY
	} else {
		flag = syscall.O_WRONLY
	}
	var file fsapi.File
	if of, ok := f.(*os.File); ok {
		// This is ok because functions that need path aren't used by stdioFile
		file = newOsFile("", flag, 0, of)
	} else {
		file = &fsFile{file: f}
	}
	return &stdioFile{File: file, st: fsapi.Stat_t{Mode: mode, Nlink: 1}}, nil
}

func OpenFile(path string, flag int, perm fs.FileMode) (*os.File, syscall.Errno) {
	if flag&fsapi.O_DIRECTORY != 0 && flag&(syscall.O_WRONLY|syscall.O_RDWR) != 0 {
		return nil, syscall.EISDIR // invalid to open a directory writeable
	}
	return openFile(path, flag, perm)
}

func OpenOSFile(path string, flag int, perm fs.FileMode) (fsapi.File, syscall.Errno) {
	f, errno := OpenFile(path, flag, perm)
	if errno != 0 {
		return nil, errno
	}
	return newOsFile(path, flag, perm, f), 0
}

func OpenFSFile(fs fs.FS, path string, flag int, perm fs.FileMode) (fsapi.File, syscall.Errno) {
	if flag&fsapi.O_DIRECTORY != 0 && flag&(syscall.O_WRONLY|syscall.O_RDWR) != 0 {
		return nil, syscall.EISDIR // invalid to open a directory writeable
	}
	f, err := fs.Open(path)
	if errno := platform.UnwrapOSError(err); errno != 0 {
		return nil, errno
	}
	// Don't return an os.File because the path is not absolute. osFile needs
	// the path to be real and certain fs.File impls are subrooted.
	return &fsFile{fs: fs, name: path, file: f}, 0
}

type stdioFile struct {
	fsapi.File
	st fsapi.Stat_t
}

// IsDir implements File.IsDir
func (f *stdioFile) IsDir() (bool, syscall.Errno) {
	return false, 0
}

// Stat implements File.Stat
func (f *stdioFile) Stat() (fsapi.Stat_t, syscall.Errno) {
	return f.st, 0
}

// Close implements File.Close
func (f *stdioFile) Close() syscall.Errno {
	return 0
}

// fsFile is used for wrapped os.File, like os.Stdin or any fs.File
// implementation. Notably, this does not have access to the full file path.
// so certain operations can't be supported, such as inode lookups on Windows.
type fsFile struct {
	fsapi.UnimplementedFile

	// fs is the file-system that opened the file, or nil when wrapped for
	// pre-opens like stdio.
	fs fs.FS

	// name is what was used in fs for Open, so it may not be the actual path.
	name string

	// file is always set, possibly an os.File like os.Stdin.
	file fs.File

	// closed is true when closed was called. This ensures proper syscall.EBADF
	closed bool

	// cachedStat includes fields that won't change while a file is open.
	cachedSt *cachedStat
}

type cachedStat struct {
	// fileType is the same as what's documented on Dirent.
	fileType fs.FileMode

	// ino is the same as what's documented on Dirent.
	ino uint64
}

// cachedStat returns the cacheable parts of platform.sys.Stat_t or an error if
// they couldn't be retrieved.
func (f *fsFile) cachedStat() (fileType fs.FileMode, ino uint64, errno syscall.Errno) {
	if f.cachedSt == nil {
		if _, errno = f.Stat(); errno != 0 {
			return
		}
	}
	return f.cachedSt.fileType, f.cachedSt.ino, 0
}

// Ino implements File.Ino
func (f *fsFile) Ino() (uint64, syscall.Errno) {
	if _, ino, errno := f.cachedStat(); errno != 0 {
		return 0, errno
	} else {
		return ino, 0
	}
}

// IsAppend implements File.IsAppend
func (f *fsFile) IsAppend() bool {
	return false
}

// SetAppend implements File.SetAppend
func (f *fsFile) SetAppend(bool) (errno syscall.Errno) {
	return fileError(f, f.closed, syscall.ENOSYS)
}

// IsDir implements File.IsDir
func (f *fsFile) IsDir() (bool, syscall.Errno) {
	if ft, _, errno := f.cachedStat(); errno != 0 {
		return false, errno
	} else if ft.Type() == fs.ModeDir {
		return true, 0
	}
	return false, 0
}

// Stat implements File.Stat
func (f *fsFile) Stat() (st fsapi.Stat_t, errno syscall.Errno) {
	if f.closed {
		errno = syscall.EBADF
		return
	}

	// While some functions in fsapi.File need the full path, especially in
	// Windows, stat does not. Casting here allows os.DirFS to return inode
	// information.
	if of, ok := f.file.(*os.File); ok {
		if st, errno = statFile(of); errno != 0 {
			return
		}
		return f.cacheStat(st)
	} else if t, err := f.file.Stat(); err != nil {
		errno = platform.UnwrapOSError(err)
		return
	} else {
		st = StatFromDefaultFileInfo(t)
		return f.cacheStat(st)
	}
}

func (f *fsFile) cacheStat(st fsapi.Stat_t) (fsapi.Stat_t, syscall.Errno) {
	f.cachedSt = &cachedStat{fileType: st.Mode & fs.ModeType, ino: st.Ino}
	return st, 0
}

// Read implements File.Read
func (f *fsFile) Read(buf []byte) (n int, errno syscall.Errno) {
	if n, errno = read(f.file, buf); errno != 0 {
		// Defer validation overhead until we've already had an error.
		errno = fileError(f, f.closed, errno)
	}
	return
}

// Pread implements File.Pread
func (f *fsFile) Pread(buf []byte, off int64) (n int, errno syscall.Errno) {
	if ra, ok := f.file.(io.ReaderAt); ok {
		if n, errno = pread(ra, buf, off); errno != 0 {
			// Defer validation overhead until we've already had an error.
			errno = fileError(f, f.closed, errno)
		}
		return
	}

	// See /RATIONALE.md "fd_pread: io.Seeker fallback when io.ReaderAt is not supported"
	if rs, ok := f.file.(io.ReadSeeker); ok {
		// Determine the current position in the file, as we need to revert it.
		currentOffset, err := rs.Seek(0, io.SeekCurrent)
		if err != nil {
			return 0, fileError(f, f.closed, platform.UnwrapOSError(err))
		}

		// Put the read position back when complete.
		defer func() { _, _ = rs.Seek(currentOffset, io.SeekStart) }()

		// If the current offset isn't in sync with this reader, move it.
		if off != currentOffset {
			if _, err = rs.Seek(off, io.SeekStart); err != nil {
				return 0, fileError(f, f.closed, platform.UnwrapOSError(err))
			}
		}

		n, err = rs.Read(buf)
		if errno = platform.UnwrapOSError(err); errno != 0 {
			// Defer validation overhead until we've already had an error.
			errno = fileError(f, f.closed, errno)
		}
	} else {
		errno = syscall.ENOSYS // unsupported
	}
	return
}

// Seek implements File.Seek.
func (f *fsFile) Seek(offset int64, whence int) (newOffset int64, errno syscall.Errno) {
	// If this is a directory, and we're attempting to seek to position zero,
	// we have to re-open the file to ensure the directory state is reset.
	var isDir bool
	if offset == 0 && whence == io.SeekStart {
		if isDir, errno = f.IsDir(); errno != 0 {
			return
		} else if isDir {
			return 0, f.reopen() // It may return file not found if the file has been deleted in the meantime.
		}
	}

	if s, ok := f.file.(io.Seeker); ok {
		if newOffset, errno = seek(s, offset, whence); errno != 0 {
			// Defer validation overhead until we've already had an error.
			errno = fileError(f, f.closed, errno)
		}
	} else {
		errno = syscall.ENOSYS // unsupported
	}
	return
}

func (f *fsFile) reopen() syscall.Errno {
	_ = f.close()
	var err error
	f.file, err = f.fs.Open(f.name)
	return platform.UnwrapOSError(err)
}

// Readdir implements File.Readdir. Notably, this uses fs.ReadDirFile if
// available.
func (f *fsFile) Readdir() (dirs fsapi.Readdir, errno syscall.Errno) {
	if _, ok := f.file.(*os.File); ok {
		// We can't use f.name here because it is the path up to the fsapi.FS,
		// not necessarily the real path. For this reason, Windows may not be
		// able to populate inodes. However, Darwin and Linux will.
		if dirs, errno = readdirFS(f); errno != 0 {
			errno = adjustReaddirErr(f, f.closed, errno)
		}
		return
	}

	// Try with fs.ReadDirFile which is available on api.FS implementations
	// like embed:fs.
	if rdf, ok := f.file.(fs.ReadDirFile); ok {
		entries, e := rdf.ReadDir(-1)
		if errno = adjustReaddirErr(f, f.closed, e); errno != 0 {
			return
		}
		dirents := make([]fsapi.Dirent, 0, 2+len(entries))
		// fixme just checking a theory; reads that are >1 require . and ..
		//if n > 0 {
		//	result, _ := synthesizeDotEntries(f)
		//	dirents = append(dirents, result...)
		//}
		for _, e := range entries {
			// By default, we don't attempt to read inode data
			dirents = append(dirents, fsapi.Dirent{Name: e.Name(), Type: e.Type()})
		}
		return NewReaddirFromSlice(dirents), 0
	} else {
		return nil, syscall.ENOTDIR
	}
}

// Write implements File.Write
func (f *fsFile) Write(buf []byte) (n int, errno syscall.Errno) {
	if w, ok := f.file.(io.Writer); ok {
		if n, errno = write(w, buf); errno != 0 {
			// Defer validation overhead until we've already had an error.
			errno = fileError(f, f.closed, errno)
		}
	} else {
		errno = syscall.ENOSYS // unsupported
	}
	return
}

// Pwrite implements File.Pwrite
func (f *fsFile) Pwrite(buf []byte, off int64) (n int, errno syscall.Errno) {
	if wa, ok := f.file.(io.WriterAt); ok {
		if n, errno = pwrite(wa, buf, off); errno != 0 {
			// Defer validation overhead until we've already had an error.
			errno = fileError(f, f.closed, errno)
		}
	} else {
		errno = syscall.ENOSYS // unsupported
	}
	return
}

// Close implements File.Close
func (f *fsFile) Close() syscall.Errno {
	if f.closed {
		return 0
	}
	f.closed = true
	return f.close()
}

func (f *fsFile) close() syscall.Errno {
	if f.file == nil {
		return 0
	}
	return platform.UnwrapOSError(f.file.Close())
}

// dirError is used for commands that work against a directory, but not a file.
func dirError(f fsapi.File, isClosed bool, errno syscall.Errno) syscall.Errno {
	if vErrno := validate(f, isClosed, false, true); vErrno != 0 {
		return vErrno
	}
	return errno
}

// fileError is used for commands that work against a file, but not a directory.
func fileError(f fsapi.File, isClosed bool, errno syscall.Errno) syscall.Errno {
	if vErrno := validate(f, isClosed, true, false); vErrno != 0 {
		return vErrno
	}
	return errno
}

// validate is used to making syscalls which will fail.
func validate(f fsapi.File, isClosed, wantFile, wantDir bool) syscall.Errno {
	if isClosed {
		return syscall.EBADF
	}

	isDir, errno := f.IsDir()
	if errno != 0 {
		return errno
	}

	if wantFile && isDir {
		return syscall.EISDIR
	} else if wantDir && !isDir {
		return syscall.ENOTDIR
	}
	return 0
}

func read(r io.Reader, buf []byte) (n int, errno syscall.Errno) {
	if len(buf) == 0 {
		return 0, 0 // less overhead on zero-length reads.
	}

	n, err := r.Read(buf)
	return n, platform.UnwrapOSError(err)
}

func pread(ra io.ReaderAt, buf []byte, off int64) (n int, errno syscall.Errno) {
	if len(buf) == 0 {
		return 0, 0 // less overhead on zero-length reads.
	}

	n, err := ra.ReadAt(buf, off)
	return n, platform.UnwrapOSError(err)
}

func seek(s io.Seeker, offset int64, whence int) (int64, syscall.Errno) {
	if uint(whence) > io.SeekEnd {
		return 0, syscall.EINVAL // negative or exceeds the largest valid whence
	}

	newOffset, err := s.Seek(offset, whence)
	return newOffset, platform.UnwrapOSError(err)
}

type rawOsFile interface {
	fsapi.File
	rawOsFile() *os.File
}

func (f *fsFile) rawOsFile() *os.File {
	return f.file.(*os.File)
}

func (f *osFile) rawOsFile() *os.File {
	return f.file
}

func readdirFS(f *fsFile) (dirs fsapi.Readdir, errno syscall.Errno) {
	return NewWindowedReaddir(
		func() syscall.Errno {
			return reset(f)
		},
		func(n uint64) (fsapi.Readdir, syscall.Errno) {
			return fetch(f, "", int(n))

			// fis, err := ff.Readdir(int(n))
			// if errno = platform.UnwrapOSError(err); errno != 0 {
			// 	return nil, errno
			// }
			// dirents := make([]fsapi.Dirent, 0, len(fis))

			// // linux/darwin won't have to fan out to lstat, but windows will.
			// var ino uint64
			// for fi := range fis {
			// 	t := fis[fi]
			// 	if ino, errno = inoFromFileInfo("", t); errno != 0 {
			// 		return nil, errno
			// 	}
			// 	dirents = append(dirents, fsapi.Dirent{Name: t.Name(), Ino: ino, Type: t.Mode().Type()})
			// }
			// return NewReaddirFromSlice(dirents), 0
		})
}

func readdir0(f *osFile, path string) (dirs fsapi.Readdir, errno syscall.Errno) {
	return NewWindowedReaddir(
		func() syscall.Errno {
			return reset(f)
		},
		func(n uint64) (fsapi.Readdir, syscall.Errno) {
			return fetch(f, path, int(n))
		})
}

func fetch(f rawOsFile, path string, n int) (fsapi.Readdir, syscall.Errno) {
	fis, err := f.rawOsFile().Readdir(int(n))
	if errno := platform.UnwrapOSError(err); errno != 0 {
		return nil, errno
	}
	dirents := make([]fsapi.Dirent, 0, len(fis))

	// linux/darwin won't have to fan out to lstat, but windows will.
	// var ino uint64
	for fi := range fis {
		t := fis[fi]
		if ino, errno := inoFromFileInfo(path, t); errno != 0 {
			return nil, errno
		} else {
			dirents = append(dirents, fsapi.Dirent{Name: t.Name(), Ino: ino, Type: t.Mode().Type()})
		}
	}
	return NewReaddirFromSlice(dirents), 0
}

func reset(f fsapi.File) syscall.Errno {
	// Ensure we always rewind to the beginning when we re-init.
	if _, errno := f.Seek(0, io.SeekStart); errno != 0 {
		return errno
	}
	return 0
}

//func readdir(f *os.File, path string) (dirs fsapi.Readdir, errno syscall.Errno) {
//	return NewWindowedReaddir(
//		func() syscall.Errno {
//			// Ensure we always rewind to the beginning when we re-init.
//			if _, errno := f.Seek(0, io.SeekStart); errno != nil {
//				return platform.UnwrapOSError(errno)
//			}
//			return 0
//		},
//		func(n uint64) (fsapi.Readdir, syscall.Errno) {
//			fis, err := f.Readdir(int(n))
//			if errno = platform.UnwrapOSError(err); errno != 0 {
//				return nil, errno
//			}
//			dirents := make([]fsapi.Dirent, 0, len(fis))
//
//			// linux/darwin won't have to fan out to lstat, but windows will.
//			var ino uint64
//			for fi := range fis {
//				t := fis[fi]
//				if ino, errno = inoFromFileInfo(path, t); errno != 0 {
//					return nil, errno
//				}
//				dirents = append(dirents, fsapi.Dirent{Name: t.Name(), Ino: ino, Type: t.Mode().Type()})
//			}
//			return NewReaddirFromSlice(dirents), 0
//		})
//}

func write(w io.Writer, buf []byte) (n int, errno syscall.Errno) {
	if len(buf) == 0 {
		return 0, 0 // less overhead on zero-length writes.
	}

	n, err := w.Write(buf)
	return n, platform.UnwrapOSError(err)
}

func pwrite(w io.WriterAt, buf []byte, off int64) (n int, errno syscall.Errno) {
	if len(buf) == 0 {
		return 0, 0 // less overhead on zero-length writes.
	}

	n, err := w.WriteAt(buf, off)
	return n, platform.UnwrapOSError(err)
}

// emptyReaddir implements fsapi.Readdir
//
// emptyReaddir is an empty fsapi.Readdir.
type emptyReaddir struct{}

// Reset implements the method of the same name in fsapi.Readdir.
func (e emptyReaddir) Reset() syscall.Errno { return 0 }

// Skip implements the method of the same name in fsapi.Readdir.
func (e emptyReaddir) Skip(uint64) {}

// Cookie implements the method of the same name in fsapi.Readdir.
func (e emptyReaddir) Cookie() uint64 { return 0 }

// Rewind implements the method of the same name in fsapi.Readdir.
func (e emptyReaddir) Rewind(int64) syscall.Errno { return 0 }

// Peek implements the method of the same name in fsapi.Readdir.
func (e emptyReaddir) Peek() (*fsapi.Dirent, syscall.Errno) { return nil, syscall.ENOENT }

// Advance implements the method of the same name in fsapi.Readdir.
func (e emptyReaddir) Advance() syscall.Errno { return syscall.ENOENT }

// NewReaddirFromSlice is a constructor for fsapi.Readdir that only takes a []fsapi.Dirent.
func NewReaddirFromSlice(dirents []fsapi.Dirent) fsapi.Readdir {
	return &sliceReaddir{dirents: dirents}
}

// sliceReaddir implements fsapi.Readdir
//
// sliceReaddir iterates a given slice of fsapi.Dirent
type sliceReaddir struct {
	// cursor is the current position in the buffer.
	cursor  uint64
	dirents []fsapi.Dirent
}

// Reset implements the method of the same name in fsapi.Readdir.
func (s *sliceReaddir) Reset() syscall.Errno {
	s.cursor = 0
	return 0
}

// Skip implements the method of the same name in fsapi.Readdir.
func (s *sliceReaddir) Skip(n uint64) {
	s.cursor += n
}

// Cookie implements the method of the same name in fsapi.Readdir.
func (s *sliceReaddir) Cookie() uint64 {
	return s.cursor
}

// Rewind implements the method of the same name in fsapi.Readdir.
func (s *sliceReaddir) Rewind(cookie int64) syscall.Errno {
	unsignedCookie := uint64(cookie)
	switch {
	case cookie < 0 || unsignedCookie > s.cursor:
		// the cookie can neither be negative nor can it be larger than cursor.
		return syscall.EINVAL
	case cookie == 0 && s.cursor == 0:
		return 0
	case cookie == 0 && s.cursor != 0:
		// This means that there was a previous call to the dir, but cookie is reset.
		// This happens when the program calls rewinddir, for example:
		// https://github.com/WebAssembly/wasi-libc/blob/659ff414560721b1660a19685110e484a081c3d4/libc-bottom-half/cloudlibc/src/libc/dirent/rewinddir.c#L10-L12
		return s.Reset()
	case unsignedCookie < s.cursor:
		// We are allowed to rewind back to a previous offset within the current window.
		s.cursor = unsignedCookie
		return 0
	default:
		// The cookie is valid.
		return 0
	}
}

// Peek implements the method of the same name in fsapi.Readdir.
func (s *sliceReaddir) Peek() (*fsapi.Dirent, syscall.Errno) {
	if s.cursor >= uint64(len(s.dirents)) {
		return nil, syscall.ENOENT
	}
	return &s.dirents[s.cursor], 0
}

// Advance implements the method of the same name in fsapi.Readdir.
func (s *sliceReaddir) Advance() syscall.Errno {
	if s.cursor == uint64(len(s.dirents)) {
		return syscall.ENOENT
	}
	s.cursor++
	return 0
}

// concatReaddir implements fsapi.Readdir
//
// concatReaddir concatenates two fsapi.Readdir instances.
type concatReaddir struct {
	first, second, current fsapi.Readdir
}

// NewConcatReaddir is a constructor for an fsapi.Readdir that concatenates
// two fsapi.Readdir.
func NewConcatReaddir(first fsapi.Readdir, second fsapi.Readdir) fsapi.Readdir {
	return &concatReaddir{first: first, second: second, current: first}
}

// Reset implements the method of the same name in fsapi.Readdir.
func (c *concatReaddir) Reset() syscall.Errno {
	errno := c.first.Reset()
	if errno != 0 {
		return errno
	}
	errno = c.second.Reset()
	if errno != 0 {
		return errno
	}
	return 0
}

// Skip implements the method of the same name in fsapi.Readdir.
func (c *concatReaddir) Skip(n uint64) {
	for i := uint64(0); i < n; i++ {
		_ = c.Advance()
	}
}

// Cookie implements the method of the same name in fsapi.Readdir.
func (c *concatReaddir) Cookie() uint64 {
	return c.first.Cookie() + c.second.Cookie()
}

// Rewind implements the method of the same name in fsapi.Readdir.
func (c *concatReaddir) Rewind(cookie int64) syscall.Errno {
	ck := cookie - int64(c.first.Cookie())
	if ck > 0 {
		return c.second.Rewind(ck)
	} else {
		c.current = c.first
		if errno := c.second.Rewind(0); errno != 0 {
			return errno
		}
		return c.first.Rewind(cookie)
	}
}

// Peek implements the method of the same name in fsapi.Readdir.
func (c *concatReaddir) Peek() (*fsapi.Dirent, syscall.Errno) {
	el, errno := c.current.Peek()
	if errno != 0 {
		if c.current != c.second {
			c.current = c.second
			el, errno = c.current.Peek()
		}
		return el, errno
	}
	return el, 0
}

// Advance implements the method of the same name in fsapi.Readdir.
func (c *concatReaddir) Advance() syscall.Errno {
	errno := c.current.Advance()
	if errno != 0 {
		if c.current != c.second {
			c.current = c.second
			errno = c.current.Advance()
		}
		return errno
	}
	return 0
}

const direntBufSize = 16

// windowedReaddir implements fsapi.Readdir
//
// windowedReaddir iterates over the contents of a directory
// lazily fetching data over a sliding window.
type windowedReaddir struct {
	// cursor is the total count of files read including Dirents.
	//
	// Notes:
	//
	// * cursor is the index of the next file in the list. This is
	//   also the value that Cookie returns, so it should always be
	//   higher or equal than the cookie given in Rewind.
	//
	// * this can overflow to negative, which means our implementation
	//   doesn't support writing greater than max int64 entries.
	//   cursor uint64
	cursor uint64

	init func() syscall.Errno

	// window is an fsapi.Readdir over a fixed buffer of size direntBufSize.
	// Notably, directory listing are not rewindable, so we keep entries around
	// in case the caller mis-estimated their buffer and needs a few still cached.
	//
	// Note: This is wasi-specific and needs to be refactored.
	// In wasi preview1, dot and dot-dot entries are required to exist, but the
	// reverse is true for preview2. More importantly, preview2 holds separate
	// stateful dir-entry-streams per file.
	window fsapi.Readdir

	// fetch fetches a new batch of direntBufSize elements.
	fetch func(n uint64) (fsapi.Readdir, syscall.Errno)
}

// NewWindowedReaddir is a constructor for Readdir. It takes a dirInit
func NewWindowedReaddir(
	init func() syscall.Errno,
	fetch func(n uint64) (fsapi.Readdir, syscall.Errno),
) (fsapi.Readdir, syscall.Errno) {
	d := &windowedReaddir{init: init, fetch: fetch, window: emptyReaddir{}}
	errno := d.Reset()
	if errno != 0 {
		return nil, errno
	} else {
		return d, 0
	}
}

// init resets the cursor and invokes the fetch method to reset
// the internal state of the Readdir struct.
//
// Note: this is different from Reset, because it will not short-circuit
// when cursor is already 0, but it will force an unconditional reload.

// Reset implements the method of the same name in fsapi.Readdir.
func (d *windowedReaddir) Reset() syscall.Errno {
	errno := d.init()
	if errno != 0 {
		return errno
	}
	d.cursor = 0
	dir, errno := d.fetch(uint64(direntBufSize))
	if errno != 0 {
		return errno
	}
	d.window = dir
	return 0
}

// Skip implements the method of the same name in fsapi.Readdir.
func (d *windowedReaddir) Skip(n uint64) {
	end := d.cursor + n
	var err syscall.Errno = 0
	for d.cursor < end && err == 0 {
		err = d.Advance()
	}
}

// Cookie implements the method of the same name in fsapi.Readdir.
//
// Note: this returns the cursor field, but it is an implementation detail.
func (d *windowedReaddir) Cookie() uint64 {
	return d.cursor
}

// Rewind implements the method of the same name in fsapi.Readdir.
func (d *windowedReaddir) Rewind(cookie int64) syscall.Errno {
	unsignedCookie := uint64(cookie)
	switch {
	case cookie < 0 || unsignedCookie > d.cursor:
		// the cookie can neither be negative nor can it be larger than cursor.
		return syscall.EINVAL
	// case cookie == 0 && d.cursor == 0:
	//	return 0
	case cookie == 0: // && d.cursor != 0:
		// This means that there was a previous call to the dir, but cookie is reset.
		// This happens when the program calls rewinddir, for example:
		// https://github.com/WebAssembly/wasi-libc/blob/659ff414560721b1660a19685110e484a081c3d4/libc-bottom-half/cloudlibc/src/libc/dirent/rewinddir.c#L10-L12
		return d.Reset()
	case unsignedCookie < d.cursor:
		if cookie/direntBufSize != int64(d.cursor)/direntBufSize {
			// The cookie is not 0, but it points into a window before the current one.
			return syscall.ENOSYS
		}
		// We are allowed to rewind back to a previous offset within the current window.
		d.cursor = unsignedCookie
		// d.cursor = d.cursor % direntBufSize
		return d.window.Rewind(int64(d.cursor % direntBufSize))
	default:
		// The cookie is valid.
		return 0
	}
}

// Peek implements the method of the same name in fsapi.Readdir.
func (d *windowedReaddir) Peek() (*fsapi.Dirent, syscall.Errno) {
	if dirent, errno := d.window.Peek(); errno == syscall.ENOENT {
		dir, errno := d.fetch(direntBufSize)
		if errno != 0 {
			return nil, errno
		}
		d.window = dir
		return d.window.Peek()
	} else {
		return dirent, errno
	}
}

// Advance implements the method of the same name in fsapi.Readdir.
func (d *windowedReaddir) Advance() syscall.Errno {
	if errno := d.window.Advance(); errno == syscall.ENOENT {
		d.window, errno = d.fetch(direntBufSize)
		return errno
	} else if errno != 0 {
		return errno
	}
	d.cursor++
	return 0
}
