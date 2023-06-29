package wasi_snapshot_preview1_test

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"testing/fstest"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/internal/testing/require"
	"github.com/tetratelabs/wazero/sys"
)

func _TestPythonRace(t *testing.T) {
	pyWASM, err := New()
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		require.NoError(t, pyWASM.Run())
		close(done)
	}()

	pyWASM.stdin.Write([]byte("Hello python!"))
	time.Sleep(5 * time.Second)

	pyWASM.Close(context.Background())
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Errorf("should not timeout")
	}
}

// TODO: editor is goimports-ing out the embed package but it's required for
// using the embed build tags
var _ = embed.FS{}

//go:embed testdata/python-3.11.1.wasm
var pythonWasm []byte

const helloPython = `#!/usr/bin/env python
import sys
import os

def hello():
    with os.fdopen(sys.stdin.fileno(), "rb", closefd=False) as stdin:
        with os.fdopen(sys.stdout.fileno(), "wb", closefd=False) as stdout:
            while True:
                line = stdin.readline()
                print(line, file=sys.stderr)

if __name__ == "__main__":
    hello()
`

type WASM struct {
	module  wazero.CompiledModule
	runtime wazero.Runtime
	config  wazero.ModuleConfig
	stdin   *io.PipeWriter
	stdout  *io.PipeReader
	// modCtx is how we close the module on termination
	modCtx    context.Context
	modCancel func()
}

type PyModule struct {
	Name    string
	Content []byte
}

func New(mfiles ...PyModule) (*WASM, error) {
	ctx, cancel := context.WithCancel(context.Background())
	// ctx = context.WithValue(
	//	ctx, experimental.FunctionListenerFactoryKey{},
	//	logging.NewHostLoggingListenerFactory(os.Stderr, logging.LogScopeFilesystem))

	// Create a new WebAssembly Runtime.
	// Allocate max pages at start, and limit to 2G (32768 * 64KiB pages)
	rConfig := wazero.NewRuntimeConfig().
		WithMemoryLimitPages(32768).
		WithMemoryCapacityFromMax(true).
		WithCloseOnContextDone(true)
	r := wazero.NewRuntimeWithConfig(ctx, rConfig)

	// Instantiate WASI, which implements host functions needed for various guest
	// environments.  Think libc+syscall interfaces
	_, err := wasi_snapshot_preview1.Instantiate(ctx, r)
	if err != nil {
		panic(err)
	}

	inPR, inPW := io.Pipe()
	outPR, outPW := io.Pipe()

	mfs := fstest.MapFS{}

	mfs["hello.py"] = &fstest.MapFile{
		Data: []byte(helloPython),
	}

	for _, f := range mfiles {
		if _, ok := mfs[f.Name]; ok {
			fmt.Printf("warn: caller attempted to add duplicate file to WASM fs context: %s\n", f.Name)
			continue
		}
		mfs[f.Name] = &fstest.MapFile{
			Data: f.Content,
		}
	}

	// Combine the above into our baseline config, overriding defaults.
	config := wazero.NewModuleConfig().
		WithStdout(outPW).WithStderr(os.Stderr).WithStdin(inPR).
		WithFSConfig(wazero.NewFSConfig().WithFSMount(mfs, "/")).
		WithArgs("-m", "/hello.py")

	mod, err := r.CompileModule(ctx, pythonWasm)
	if err != nil {
		panic(err)
	}

	return &WASM{
		stdin:     inPW,
		stdout:    outPR,
		runtime:   r,
		module:    mod,
		config:    config,
		modCtx:    ctx,
		modCancel: cancel,
	}, nil
}

func (w *WASM) Run() error {
	var err error
	_, err = w.runtime.InstantiateModule(w.modCtx, w.module, w.config)
	if errors.Is(err, sys.NewExitError(sys.ExitCodeContextCanceled)) {
		return nil
	}
	return err
}

func (w *WASM) Close(ctx context.Context) error {
	w.modCancel()
	w.stdin.Close()
	w.stdout.Close()
	return w.runtime.Close(ctx)
}
