+++
title = "How the Optimizing Compiler Works: Back-End"
layout = "single"
+++

In this section we will discuss the phases in the back-end of the optimizing compiler:

- [Instruction Selection](#instruction-selection)
- [Register Allocation](#register-allocation)
- [Finalization and Encoding](#finalization-and-encoding)

Each section will include a brief explanation of the phase, references to the code that implements the phase,
and a description of the debug flags that can be used to inspect that phase. Please notice that,
since the implementation of the back-end is architecture-specific, the code might be different for each architecture.

### Code

The higher-level entry-point to the back-end is the `backend.Compiler.Compile(context.Context)` method.
This method executes, in turn, the following methods in the same type:

- `backend.Compiler.Lower()` (instruction selection)
- `backend.Compiler.RegAlloc()` (register allocation)
- `backend.Compiler.Finalize(context.Context)` (finalization and encoding)

## Instruction Selection

The instruction selection phase is responsible for mapping the higher-level SSA instructions
to arch-specific instructions. Each SSA instruction is translated to one or more machine instructions.

Each target architecture comes with a different number of registers, some of them are general purpose,
others might be specific to certain instructions. In general, we can expect to have a set of registers
for integer computations, another set for floating point computations, a set for vector (SIMD) computations,
and some specific special-purpose registers (e.g. stack pointers, program counters, status flags, etc.)

In addition, some registers might be reserved by the Go runtime or the Operating System for specific purposes,
so they should be handled with special care.

At this point in the compilation process we do not want to deal with all that. Instead, we assume
that we have a potentially infinite number of *virtual registers* of each type at our disposal.
The next phase, the register allocation phase, will map these virtual registers to the actual
registers of the target architecture.

### Operands and Addressing Modes

As a rule of thumb, we want to map each `ssa.Value` to a virtual register, and then use that virtual register
as one of the arguments of the machine instruction that we will generate. However, usually instructions
are able to address more than just registers: an *operand* might be able to represent a memory address,
or an immediate value (i.e. a constant value that is encoded as part of the instruction itself).

For these reasons, instead of mapping each `ssa.Value` to a virtual register (`regalloc.VReg`),
we map each `ssa.Value` to an architecture-specific `operand` type.

During lowering of an `ssa.Instruction`, for each `ssa.Value` that is used as an argument of the instruction,
in the simplest case, the `operand` might be mapped to a virtual register, in other cases, the
`operand` might be mapped to a memory address, or an immediate value. Sometimes this makes it possible to
replace several SSA instructions with a single machine instruction, by folding the addressing mode into the
instruction itself.

For instance, consider the following SSA instructions:

```
    v4:i32 = Const 0x9
    v6:i32 = Load v5, 0x4
    v7:i32 = Iadd v6, v4
```

In the `amd64` architecture, the `add` instruction adds the second operand to the first operand,
and assigns the result to the second operand. So assuming that `r4`, `v5`, `v6`, and `v7` are mapped
respectively to the virtual registers `r4?`, `r5?`, `r6?`, and `r7?`, the lowering of the `Iadd`
instruction on `amd64` might look like this:

```asm
    ;; AT&T syntax
    add $4(%r5?), %r4? ;; add the value at memory address [`r5?` + 4] to `r4?`
    mov %r4?, %r7?     ;; move the result from `r4?` to `r7?`
```

Notice how the load from memory has been folded into an operand of the `add` instruction. This transformation
is possible when the value produced by the instruction being folded is not referenced by other instructions
and the instructions belong to the same `InstructionGroupID` (see [Front-End: Optimization](../frontend/#optimization)).

### Code

`backend.Machine` is the interface to the backend. It has a methods to translate (lower) the IR to machine code.
Again, as seen earlier in the front-end, the term *lowering* is used to indicate translation from a higher-level
representation to a lower-level representation.

`backend.Machine.LowerInstr(*ssa.Instruction)` is the method that translates an SSA instruction to machine code.
Machine-specific implementations of this method can be found in package `backend/isa/<arch>`
where `<arch>` is either `amd64` or `arm64`.

### Debug Flags

`wazevoapi.PrintSSAToBackendIRLowering` prints the basic blocks with the lowered arch-specific instructions.

## Register Allocation

**TODO: Not finished.**

The register allocation phase is responsible for mapping the potentially infinite number of virtual registers
to the actual registers of the target architecture. Because the number of real registers is limited,
the register allocation phase might need to "spill" some of the virtual registers to memory; that is, it might
store their content, and then load them back into a register when they are needed.

The register allocation procedure is implemented in sub-phases:

- `livenessAnalysis(f)` collects the liveness information for each virtual register. The algorithm is described
  in [Chapter 9.2 of The SSA Book](https://pfalcon.github.io/ssabook/latest/book-full.pdf).

- `alloc(f)` allocates registers for the given function. The algorithm is derived from
  [the Go compiler's allocator](https://github.com/golang/go/blob/release-branch.go1.21/src/cmd/compile/internal/ssa/regalloc.go)

  - In short, this is just a linear scan register allocation procedure, where each block inherits the
    register allocation state from one of its predecessors. Each block inherits the selected state and
    starts allocation from there.

  - If there's a discrepancy in the end states between predecessors, adjustments are made to ensure consistency after
    allocation is done (which we call "fixing merge state").

  - The spill instructions (store into the dedicated slots) are inserted after all the allocations and fixing
    merge states. That is because at the point, we all know where the reloads happen, and therefore we can
    know the best place to spill the values. More precisely, the spill happens in the block that is
    the lowest common ancestor of all the blocks that reloads the value.

  All of these logics are almost the same as Go's compiler which has a dedicated description in the source file ^^.

#### References

- https://web.stanford.edu/class/archive/cs/cs143/cs143.1128/lectures/17/Slides17.pdf
- https://en.wikipedia.org/wiki/Chaitin%27s_algorithm
- https://llvm.org/ProjectsWithLLVM/2004-Fall-CS426-LS.pdf
- https://pfalcon.github.io/ssabook/latest/book-full.pdf: Chapter 9. for liveness analysis.
- https://github.com/golang/go/blob/release-branch.go1.21/src/cmd/compile/internal/ssa/regalloc.go


### Code

The algorithm (`regalloc/regalloc.go`) can work on any ISA by implementing the interfaces in `regalloc/api.go`.

### Debug Flags

- `wazevoapi.RegAllocLoggingEnabled` logs detailed logging of the register allocation procedure.
- `wazevoapi.PrintRegisterAllocated` prints the basic blocks with the register allocation result.

## Finalization and Encoding

**TODO: Not finished.**

### PostRegAlloc:

* setup prologue of the function
* inserts epilogue of the function
* machine-specific custom logic (e.g. post-regalloc lowering)

### Encoding:

* encodes the low-level instructions into bytes

### Other

- MMap code segment
- resolve relocations

### Code

...

### Debug Flags

- `wazevoapi.PrintFinalizedMachineCode`
- `wazevoapi.PrintMachineCodeHexPerFunction`
- `wazevoapi.printMachineCodeHexPerFunctionUnmodified`
- `wazevoapi.PrintMachineCodeHexPerFunctionDisassemblable`

<hr>

* Previous Section: [Front-End](../frontend/)
