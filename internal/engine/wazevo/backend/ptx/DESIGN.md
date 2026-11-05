# PTX backend: design notes

Experimental. Goal: a Wasm subset plus `gpu.*` intrinsic imports as a
portable, sandboxed GPU kernel language. Not a way to run arbitrary
existing Wasm on GPUs.

```
 kernel.wasm ──► wazevo frontend ──► SSA ──► ptx backend ──► PTX ──► CUDA driver JIT
      │          (unchanged)                 gpu.* calls → %tid/%ctaid/…
      │                                      ctx loads   → kernel params
      └──► wazero on CPU, gpu.* as host functions (reference + debugging)
```

## Why not `backend.Machine`

PTX is a virtual ISA with unlimited typed registers. SSA values map 1:1 to
PTX registers; regalloc, ABI, prologue and encoding are skipped. ptxas does
the rest. PTX has no phis: block args are copied through temps.

## Decisions

### Execution model
- Kernel = exported Wasm function, no results. Params become uniform
  `.param` scalars (same for every thread).
- Thread/block geometry comes from intrinsics, not from params.
- Traps (OOB, div by zero, unreachable) store the exit code to a status
  word and exit the thread. Host turns status != 0 into a trap.

### Intrinsics (`gpu` import module)
Recognized by the backend and lowered inline; anything else, or a wrong
signature, is rejected.

| import                          | PTX                          | status  |
|---------------------------------|------------------------------|---------|
| `thread_idx(dim i32) i32`       | `%tid.{x,y,z}`               | done    |
| `block_idx(dim i32) i32`        | `%ctaid.{x,y,z}`             | done    |
| `block_dim(dim i32) i32`        | `%ntid.{x,y,z}`              | done    |
| `grid_dim(dim i32) i32`         | `%nctaid.{x,y,z}`            | done    |
| `barrier()`                     | `bar.sync 0`                 | done    |
| `lane_id`, `shfl_xor_*`, `ballot` | `%laneid`, `shfl.sync`, `vote.sync` | planned |
| atomics                         | `atom.*` (or threads opcodes)| planned |

`dim` must be a constant 0..2.

The frontend is untouched: an import call is SSA `CallIndirect` through a
function pointer loaded from `module_ctx`. The backend matches the load
offset (`ImportedFunctionOffset`) to the import. Same for memory base and
length (`LocalMemoryBase/Len`), which become kernel params. Trade-off:
coupled to frontend lowering patterns, but contained in this package.

### Memory spaces: multi-memory
Wasm memory index selects the PTX state space.

| memidx | PTX space | scope              |
|--------|-----------|--------------------|
| 0      | `.global` | grid               |
| 1      | `.shared` | block              |
| 2      | `.const`  | grid, read-only    |
| 3      | `.local`  | thread (scratch)   |

Blocker: wazero does not support multi-memory yet
(`internal/wasm/memory_definition_test.go`). Only memory 0 for now.
No `memory.grow`: memory size is fixed at launch.

### Bounds checks
`BoundsCheck` compile mode:
- `Checked`: frontend's check kept; OOB sets status and exits.
- `Unchecked`: checks dropped. Opt-in, unsafe.
- Planned default: guard reservation. Reserve 4 GiB (8 GiB with offsets)
  of device VA via `cuMemAddressReserve`, map only the real size with
  `cuMemMap`. i32 addresses can't escape, no checks emitted, OOB faults
  instead of corrupting other buffers. Cost: the fault is sticky and
  kills the CUDA context.

### Shadow stack
Only an LLVM concern (`__stack_pointer` in linear memory). A purpose-built
language keeps scalars in Wasm locals (registers) and per-thread arrays in
memory 3 (`.local`). Kernels writing a stack-pointer global may be
rejected.

### Half precision
Prefer the Wasm FP16 proposal (`f16x8`) if mature. Fallback: v128 as
opaque storage plus intrinsics (`gpu.f16x8_add(v128, v128) v128`).
Rejected: reinterpreting existing SIMD opcodes via a custom section; it
silently changes semantics and breaks CPU/GPU parity.

### Deferred
- Barrier uniformity validation: reject `barrier` control-dependent on
  non-uniform values (thread id, lane id, global loads). Needs
  post-dominators in SSA.
- i32 addressing caps memories at 4 GiB; memory64 later.
- Tensor cores, f16/bf16 arithmetic.

## Supported Wasm subset (today)
i32/i64/f32/f64 scalars; integer/float arithmetic; bitwise ops; compares;
select; block/loop/br/br_if; i32/i64/f32/f64 load/store on memory 0;
`gpu` geometry intrinsics. Everything else is a compile error.

## Testing
- `go test ./`: compiles kernels, validates with `ptxas` when available,
  runs each kernel on CPU via wazero host functions. Blocks run in
  sequence, a block's threads as goroutines with a real barrier; exited
  threads leave the barrier (Volta+ semantics), so traps don't deadlock.
- `reduce` is a tree reduction with a per-block tile in memory 0 until
  multi-memory gives `.shared`. Correct: `bar.sync` orders global memory
  within the block too.
- `go test -tags cuda ./` on a CUDA host: runs on GPU, compares to CPU.
