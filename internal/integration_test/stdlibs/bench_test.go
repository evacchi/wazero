package wazevo_test

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/experimental/opt"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/internal/testing/require"
	"github.com/tetratelabs/wazero/sys"
)

func BenchmarkStdlibs(b *testing.B) {
	type testConfig struct {
		name   string
		config wazero.RuntimeConfig
	}
	configs := []testConfig{
		{name: "baseline", config: wazero.NewRuntimeConfigCompiler()},
	}
	if runtime.GOARCH == "arm64" {
		configs = append(configs, testConfig{name: "optimizing", config: opt.NewRuntimeConfigOptimizingCompiler()})
	}

	cwd, _ := os.Getwd()
	defer os.Chdir(cwd) //nolint
	ctx := context.Background()

	testCases := []struct {
		name, dir    string
		readTestCase func(fpath string, fname string) ([]byte, wazero.ModuleConfig, error)
	}{
		{
			name: "zig",
			dir:  "testdata/zig/",
			readTestCase: func(fpath string, fname string) ([]byte, wazero.ModuleConfig, error) {
				bin, err := os.ReadFile(fpath)
				modCfg := defaultModuleConfig().
					WithFSConfig(wazero.NewFSConfig().WithDirMount(".", "/")).
					WithArgs("test.wasm")

				return bin, modCfg, err
			},
		},
		{
			name: "tinygo",
			dir:  "testdata/tinygo/",
			readTestCase: func(fpath string, fname string) ([]byte, wazero.ModuleConfig, error) {
				if !strings.HasSuffix(fname, ".test") {
					return nil, nil, nil
				}
				bin, err := os.ReadFile(fpath)
				fsconfig := wazero.NewFSConfig().
					WithDirMount(".", "/").
					WithDirMount("/tmp", "/tmp")
				modCfg := defaultModuleConfig().
					WithFSConfig(fsconfig).
					WithArgs(fname, "-test.v")

				return bin, modCfg, err
			},
		},
		{
			name: "wasip1",
			dir:  "testdata/go/",
			readTestCase: func(fpath string, fname string) ([]byte, wazero.ModuleConfig, error) {
				if !strings.HasSuffix(fname, ".test") {
					return nil, nil, nil
				}
				bin, err := os.ReadFile(fpath)
				if err != nil {
					return nil, nil, err
				}
				fsuffixstripped := strings.ReplaceAll(fname, ".test", "")
				inferredpath := strings.ReplaceAll(fsuffixstripped, "_", "/")
				testdir := filepath.Join(runtime.GOROOT(), inferredpath)

				err = os.Chdir(testdir)
				modCfg := defaultModuleConfig().
					WithFSConfig(
						wazero.NewFSConfig().
							WithDirMount("/", "/")).
					WithEnv("PWD", testdir).
					WithArgs(fname, "-test.short", "-test.v")
				return bin, modCfg, err
			},
		},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			files, err := os.ReadDir(tc.dir)
			require.NoError(b, err)
			for _, f := range files {
				fname := f.Name()
				// Ensure we are on root dir.
				err = os.Chdir(cwd)
				require.NoError(b, err)

				fpath := filepath.Join(cwd, tc.dir, fname)
				bin, modCfg, err := tc.readTestCase(fpath, fname)
				require.NoError(b, err)
				if bin == nil {
					// skip
					continue
				}

				b.Run(fname, func(b *testing.B) {
					for _, cfg := range configs {
						r := wazero.NewRuntimeWithConfig(ctx, cfg.config)
						wasi_snapshot_preview1.MustInstantiate(ctx, r)
						b.Cleanup(func() { r.Close(ctx) })

						m, err := r.CompileModule(ctx, bin)
						require.NoError(b, err)

						b.Run(cfg.name, func(b *testing.B) {
							b.Run("Compile", func(b *testing.B) {
								_, err := r.CompileModule(ctx, bin)
								require.NoError(b, err)
							})
							im, err := r.InstantiateModule(ctx, m, modCfg)
							require.NoError(b, err)
							b.Run("Run", func(b *testing.B) {
								_, err := im.ExportedFunction("_start").Call(ctx)
								requireZeroExitCode(b, err)
							})
						})
					}
				})
			}
		})
	}
}

func defaultModuleConfig() wazero.ModuleConfig {
	return wazero.NewModuleConfig().
		WithSysNanosleep().
		WithSysNanotime().
		WithSysWalltime().
		WithRandSource(rand.Reader).
		// Some tests require Stdout and Stderr to be present.
		WithStdout(os.Stdout).
		WithStderr(os.Stderr).
		WithStartFunctions()
}

func requireZeroExitCode(b *testing.B, err error) {
	b.Helper()
	if se, ok := err.(*sys.ExitError); ok {
		if se.ExitCode() != 0 { // Don't err on success.
			require.NoError(b, err)
		}
	}
}
