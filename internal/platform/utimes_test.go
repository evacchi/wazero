package platform

import (
	"io/fs"
	"os"
	"path"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/tetratelabs/wazero/internal/testing/require"
)

func TestUtimesns(t *testing.T) {
	tmpDir := t.TempDir()
	file := path.Join(tmpDir, "file")
	err := os.WriteFile(file, []byte{}, 0o700)
	require.NoError(t, err)

	dir := path.Join(tmpDir, "dir")
	err = os.Mkdir(dir, 0o700)
	require.NoError(t, err)

	t.Run("doesn't exist", func(t *testing.T) {
		err := Utimesns("nope", nil, true)
		require.EqualErrno(t, syscall.ENOENT, err)
		err = Utimesns("nope", nil, false)
		require.EqualErrno(t, syscall.ENOENT, err)
	})

	type test struct {
		name          string
		path          string
		times         *[2]syscall.Timespec
		symlinkFollow bool
	}

	// Note: This sets microsecond granularity because Windows doesn't support
	// nanosecond.
	//
	// Negative isn't tested as most platforms don't return consistent results.
	tests := []test{
		{
			name: "file positive",
			path: file,
			times: &[2]syscall.Timespec{
				{Sec: 123, Nsec: 4 * 1e3},
				{Sec: 123, Nsec: 4 * 1e3},
			},
		},
		{
			name: "dir positive",
			path: dir,
			times: &[2]syscall.Timespec{
				{Sec: 123, Nsec: 4 * 1e3},
				{Sec: 123, Nsec: 4 * 1e3},
			},
		},
		{name: "file nil", path: file},
		{name: "dir nil", path: dir},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			err := Utimesns(tc.path, tc.times, tc.symlinkFollow)
			require.NoError(t, err)

			var stat Stat_t
			require.NoError(t, Stat(tc.path, &stat))
			requireStatTimes(t, tc.times, stat)
		})
	}
}

func requireStatTimes(t *testing.T, times *[2]syscall.Timespec, stat Stat_t) {
	if CompilerSupported() {
		if times != nil && times[0].Nano() != UTIME_NOW {
			require.Equal(t, stat.Atim, times[0].Nano())
		} else {
			require.True(t, stat.Atim < time.Now().UnixNano())
		}
	} // else only mtimes will return.
	if times != nil && times[1].Nano() != UTIME_NOW {
		require.Equal(t, stat.Mtim, times[1].Nano())
	} else {
		require.True(t, stat.Mtim < time.Now().UnixNano())
	}
}

func TestUtimesnsFile(t *testing.T) {
	switch runtime.GOOS {
	case "linux", "darwin": // supported
	case "freebsd": // TODO: support freebsd w/o CGO
	case "windows":
		if !IsGo120 {
			t.Skip("windows only works after Go 1.20") // TODO: possibly 1.19 ;)
		}
	default: // expect ENOSYS and callers need to fall back to Utimesns
		t.Skip("unsupported GOOS", runtime.GOOS)
	}

	tmpDir := t.TempDir()

	file := path.Join(tmpDir, "file")
	err := os.WriteFile(file, []byte{}, 0o700)
	require.NoError(t, err)
	fileF, err := OpenFile(file, syscall.O_RDWR, 0)
	require.NoError(t, err)
	defer fileF.Close()

	dir := path.Join(tmpDir, "dir")
	err = os.Mkdir(dir, 0o700)
	require.NoError(t, err)
	dirF, err := OpenFile(dir, syscall.O_RDONLY, 0)
	require.NoError(t, err)
	defer fileF.Close()

	type test struct {
		name        string
		file        fs.File
		times       *[2]syscall.Timespec
		expectedErr error
	}

	// Note: This sets microsecond granularity because Windows doesn't support
	// nanosecond.
	//
	// Negative isn't tested as most platforms don't return consistent results.
	tests := []*test{
		{
			name: "file positive",
			file: fileF,
			times: &[2]syscall.Timespec{
				{Sec: 123, Nsec: 4 * 1e3},
				{Sec: 123, Nsec: 4 * 1e3},
			},
		},
		{name: "file nil", file: fileF},
		{
			name: "dir positive",
			file: dirF,
			times: &[2]syscall.Timespec{
				{Sec: 123, Nsec: 4 * 1e3},
				{Sec: 123, Nsec: 4 * 1e3},
			},
		},
		{name: "dir nil", file: dirF},
	}

	// In windows, trying to update the time of a directory fails, as it is
	// addressed by path, not by file descriptor.
	if runtime.GOOS == "windows" {
		for _, tt := range tests {
			if tt.file == dirF {
				tt.expectedErr = syscall.EPERM
			}
		}
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			err := UtimesnsFile(tc.file, tc.times)
			if tc.expectedErr != nil {
				require.EqualErrno(t, tc.expectedErr.(syscall.Errno), err)
				return
			}

			var stat Stat_t
			require.NoError(t, StatFile(tc.file, &stat))
			requireStatTimes(t, tc.times, stat)
		})
	}

	require.NoError(t, fileF.Close())
	t.Run("closed file", func(t *testing.T) {
		err := UtimesnsFile(fileF, nil)
		require.EqualErrno(t, syscall.EBADF, err)
	})

	require.NoError(t, dirF.Close())
	t.Run("closed dir", func(t *testing.T) {
		err := UtimesnsFile(dirF, nil)
		require.EqualErrno(t, syscall.EBADF, err)
	})
}
