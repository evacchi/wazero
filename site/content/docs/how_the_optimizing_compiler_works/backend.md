+++
title = "How the Optimizing Compiler Works: Back-End"
layout = "single"
+++

## Back-End: Instruction Selection

- Mapping between higher-level SSA IR and machine instructions.
- Mention virtual registers.
- Note about "peephole" optimizations happening e.g. when mapping a Value
to a register (e.g. use address modes instead of loading a pointed value
into a register).

### Code

...

### Debug Flags

- `wazevoapi.PrintSSAToBackendIRLowering`

## Back-End: Register Allocation

Partially architecture independent. Explain the algorithm etc.

### Code

...

### Debug Flags

- `wazevoapi.RegAllocLoggingEnabled`
- `wazevoapi.PrintRegisterAllocated`

## Back-End: Finalization and Encoding

...

### Code

...

### Debug Flags

- `wazevoapi.PrintFinalizedMachineCode`
- `wazevoapi.PrintMachineCodeHexPerFunction`
- `wazevoapi.printMachineCodeHexPerFunctionUnmodified`
- `wazevoapi.PrintMachineCodeHexPerFunctionDisassemblable`

<hr>

* Previous Section: [Front-End](../frontend/)
