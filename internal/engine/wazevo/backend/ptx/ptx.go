// Package ptx is an experimental wazevo backend that emits NVIDIA PTX.
// See DESIGN.md for the model and the decisions behind it.
//
// An exported Wasm function becomes a kernel. Params are uniform
// scalars; thread geometry comes from `gpu.*` intrinsic imports; memory 0
// is a device buffer shared by the whole grid:
//
//	 host                                  device, every thread
//	┌───────────────────────┐  launch   ┌──────────────────────────────┐
//	│ mem0 []byte           │ ────────► │ i := block_idx*block_dim+tid │
//	│ params (uniform)      │           │ mem0[...] = f(mem0[...])     │
//	│ status (trap code)    │ ◄──────── │ trap: status = code; exit    │
//	└───────────────────────┘           └──────────────────────────────┘
//
// It does not implement backend.Machine: PTX has unlimited typed
// registers, so SSA values map 1:1 to PTX registers and regalloc, ABI
// and encoding are skipped. ptxas does the rest.
package ptx

import (
	"fmt"
	"strings"

	"github.com/tetratelabs/wazero/internal/engine/wazevo/frontend"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/wazevoapi"
	"github.com/tetratelabs/wazero/internal/wasm"
)

// BoundsCheck selects how memory accesses are guarded.
type BoundsCheck int

const (
	// Checked keeps the frontend's bounds checks; OOB sets status.
	Checked BoundsCheck = iota
	// Unchecked drops bounds checks. Unsafe: OOB corrupts device memory.
	Unchecked
)

const (
	// ptxVersion and ptxTarget are conservative: any CUDA >= 11 driver
	// accepts them and JIT-compiles to the actual device.
	ptxVersion = "7.0"
	ptxTarget  = "sm_52"

	// numCtxParams is the count of wazevo's implicit leading params
	// (exec_ctx, module_ctx).
	numCtxParams = 2

	// intrinsicModule is the import module recognized as intrinsics.
	intrinsicModule = "gpu"

	labelExit = "$Lexit"
	labelTrap = "$Ltrap"

	// barrierName is `gpu.barrier()`: block-wide barrier, also ordering
	// the block's memory accesses (bar.sync has CTA fence semantics).
	barrierName = "barrier"
)

// Intrinsic signatures.
var (
	geometrySig = wasm.FunctionType{Params: []wasm.ValueType{wasm.ValueTypeI32}, Results: []wasm.ValueType{wasm.ValueTypeI32}}
	barrierSig  = wasm.FunctionType{}
)

// intrinsics maps `gpu.<name>(dim i32) i32` to its PTX special register.
var intrinsics = map[string]string{
	"thread_idx": "%tid",
	"block_idx":  "%ctaid",
	"block_dim":  "%ntid",
	"grid_dim":   "%nctaid",
}

// dims are the PTX suffixes for dim 0..2.
var dims = [...]string{"x", "y", "z"}

// shiftOps maps SSA shifts to PTX mnemonic prefixes.
var shiftOps = map[ssa.Opcode]string{
	ssa.OpcodeIshl: "shl.b",
	ssa.OpcodeUshr: "shr.u",
	ssa.OpcodeSshr: "shr.s",
}

// Kernel is a compiled PTX module holding one entry point.
type Kernel struct {
	name   string
	src    string
	params []wasm.ValueType
}

// String returns the PTX source.
func (k *Kernel) String() string {
	return k.src
}

// Compile lowers the exported function export of m into a kernel with
// the same name and signature:
//
//	.entry export(.param .u64 mem0, .param .u64 mem0_len,
//	              .param .u64 status, .param <p0>, …)
func Compile(m *wasm.Module, export string, bc BoundsCheck) (*Kernel, error) {
	fnIdx, err := exportedFunc(m, export)
	if err != nil {
		return nil, err
	}
	imports, err := intrinsicImports(m)
	if err != nil {
		return nil, err
	}

	local := fnIdx - m.ImportFunctionCount
	typIdx := m.FunctionSection[local]
	typ := &m.TypeSection[typIdx]
	if len(typ.Results) != 0 {
		return nil, fmt.Errorf("ptx: kernel %q must not return values", export)
	}
	for _, vt := range typ.Params {
		if !scalar(vt) {
			return nil, fmt.Errorf("ptx: unsupported param type %s", wasm.ValueTypeName(vt))
		}
	}

	// Wasm -> optimized SSA, as the native backends do.
	b := ssa.NewBuilder()
	offset := wazevoapi.NewModuleContextOffsetData(m, false)
	fe := frontend.NewFrontendCompiler(m, b, &offset, false, false, false)
	code := &m.CodeSection[local]
	fe.Init(local, typIdx, typ, code.LocalTypes, code.Body, false, 0)
	fe.LowerToSSA()
	b.RunPasses()

	e := &emitter{
		b: b, name: export, bc: bc, offset: &offset, imports: imports,
		regs: map[ssa.Type]int{}, intrinsicPtrs: map[ssa.ValueID]string{},
	}
	src, err := e.emit()
	if err != nil {
		return nil, err
	}
	return &Kernel{name: export, src: src, params: typ.Params}, nil
}

// exportedFunc resolves an exported function to its function index.
func exportedFunc(m *wasm.Module, name string) (wasm.Index, error) {
	for i := range m.ExportSection {
		exp := &m.ExportSection[i]
		if exp.Type == wasm.ExternTypeFunc && exp.Name == name {
			return exp.Index, nil
		}
	}
	return 0, fmt.Errorf("ptx: no exported function %q", name)
}

// intrinsicImports checks every import is a known `gpu.*` intrinsic with
// the right signature, and returns their names by function index.
func intrinsicImports(m *wasm.Module) ([]string, error) {
	var names []string
	for i := range m.ImportSection {
		imp := &m.ImportSection[i]
		if imp.Type != wasm.ExternTypeFunc {
			return nil, fmt.Errorf("ptx: unsupported import %s.%s", imp.Module, imp.Name)
		}

		sig, ok := intrinsicSig(imp.Name)
		if imp.Module != intrinsicModule || !ok {
			return nil, fmt.Errorf("ptx: unknown intrinsic %s.%s", imp.Module, imp.Name)
		}
		if typ := &m.TypeSection[imp.DescFunc]; !typ.EqualsSignature(sig.Params, sig.Results) {
			return nil, fmt.Errorf("ptx: gpu.%s has signature %s, want %s", imp.Name, typ, sig)
		}
		names = append(names, imp.Name)
	}
	return names, nil
}

// intrinsicSig returns the expected signature of intrinsic name.
func intrinsicSig(name string) (*wasm.FunctionType, bool) {
	if name == barrierName {
		return &barrierSig, true
	}
	if _, ok := intrinsics[name]; ok {
		return &geometrySig, true
	}
	return nil, false
}

func scalar(vt wasm.ValueType) bool {
	switch vt {
	case wasm.ValueTypeI32, wasm.ValueTypeI64, wasm.ValueTypeF32, wasm.ValueTypeF64:
		return true
	}
	return false
}

// emitter translates one ssa.Builder into PTX text.
type emitter struct {
	b       ssa.Builder
	name    string
	bc      BoundsCheck
	offset  *wazevoapi.ModuleContextOffsetData
	imports []string
	body    strings.Builder
	err     error

	// execCtx, moduleCtx are wazevo's context params. They have no PTX
	// register: only recognized access patterns are lowered.
	execCtx, moduleCtx ssa.Value
	// intrinsicPtrs maps an imported function pointer to its name.
	intrinsicPtrs map[ssa.ValueID]string

	// regs is the register count per type, i.e. `.reg .b32 %r<N>`.
	regs map[ssa.Type]int
	// preds is the predicate register count.
	preds int
	// tmps is the next temp ID; IDs start after the last SSA value so
	// they never collide.
	tmps int
	// params are the kernel's Wasm params.
	params []ssa.Value
	// usesTrap is set when any trap path is emitted.
	usesTrap bool
}

func (e *emitter) emit() (string, error) {
	e.tmps = len(e.b.ValuesInfo())

	entry := e.b.EntryBlock()
	e.execCtx, e.moduleCtx = entry.Param(0), entry.Param(1)
	for k := numCtxParams; k < entry.Params(); k++ {
		e.params = append(e.params, entry.Param(k))
	}

	// Wasm params come in as uniform kernel params.
	for k, v := range e.params {
		e.ins(fmt.Sprintf("ld.param.%s %s, [p%d];", memKind(v.Type()), e.reg(v), k))
	}

	for blk := e.b.BlockIteratorReversePostOrderBegin(); blk != nil; blk = e.b.BlockIteratorReversePostOrderNext() {
		if err := e.block(blk); err != nil {
			return "", err
		}
	}
	if e.err != nil {
		return "", e.err
	}

	e.line(labelExit + ":")
	e.ins("ret;")
	if e.usesTrap {
		e.trapStub()
	}
	return e.module(), nil
}

// trapStub stores the exit code in %code to *status and exits.
func (e *emitter) trapStub() {
	e.line(labelTrap + ":")
	e.ins("ld.param.u64 %base, [status];")
	e.ins("cvta.to.global.u64 %base, %base;")
	e.ins("st.global.u32 [%base], %code;")
	e.ins("ret;")
}

// module assembles header, kernel signature, declarations and body.
// Declarations are generated last since counts are only known after
// the body is emitted.
func (e *emitter) module() string {
	var s strings.Builder
	fmt.Fprintf(&s, ".version %s\n.target %s\n.address_size 64\n\n", ptxVersion, ptxTarget)

	fmt.Fprintf(&s, ".visible .entry %s(\n", e.name)
	s.WriteString("\t.param .u64 mem0,\n\t.param .u64 mem0_len,\n\t.param .u64 status")
	for k, v := range e.params {
		fmt.Fprintf(&s, ",\n\t.param .%s p%d", memKind(v.Type()), k)
	}
	s.WriteString("\n)\n{\n")

	// Fixed registers for trap reporting.
	s.WriteString("\t.reg .b32 %code;\n")
	s.WriteString("\t.reg .b64 %base;\n")
	for _, t := range []ssa.Type{ssa.TypeI32, ssa.TypeI64, ssa.TypeF32, ssa.TypeF64} {
		n := e.regs[t]
		if n == 0 {
			continue
		}
		fmt.Fprintf(&s, "\t.reg .%s %%%s<%d>;\n", regKind(t), regPrefix(t), n)
	}
	if e.preds > 0 {
		fmt.Fprintf(&s, "\t.reg .pred %%p<%d>;\n", e.preds)
	}

	s.WriteString("\n")
	s.WriteString(e.body.String())
	s.WriteString("}\n")
	return s.String()
}

func (e *emitter) block(blk ssa.BasicBlock) error {
	e.line(blockLabel(blk.ID()) + ":")
	for cur := blk.Root(); cur != nil; cur = cur.Next() {
		if err := e.instr(cur); err != nil {
			return err
		}
	}
	return nil
}

func (e *emitter) instr(i *ssa.Instruction) error {
	switch op := i.Opcode(); op {
	case ssa.OpcodeIconst, ssa.OpcodeF32const, ssa.OpcodeF64const:
		r := i.Return()
		e.ins(fmt.Sprintf("mov.%s %s, %s;", regKind(r.Type()), e.reg(r), constLit(r.Type(), i.ConstantVal())))

	case ssa.OpcodeIadd, ssa.OpcodeIsub, ssa.OpcodeImul,
		ssa.OpcodeFadd, ssa.OpcodeFsub, ssa.OpcodeFmul, ssa.OpcodeFdiv,
		ssa.OpcodeBand, ssa.OpcodeBor, ssa.OpcodeBxor:
		x, y := i.Arg2()
		r := i.Return()
		e.ins(fmt.Sprintf("%s %s, %s, %s;", binOp(op, r.Type()), e.reg(r), e.reg(x), e.reg(y)))

	case ssa.OpcodeIshl, ssa.OpcodeUshr, ssa.OpcodeSshr:
		e.shift(i)

	case ssa.OpcodeUExtend, ssa.OpcodeSExtend:
		return e.extend(i)

	case ssa.OpcodeIcmp:
		x, y, c := i.IcmpData()
		e.setBool(i.Return(), fmt.Sprintf("setp.%s.%s", icmpCond(c), cmpKind(c, x.Type())), x, y)

	case ssa.OpcodeFcmp:
		x, y, c := i.FcmpData()
		e.setBool(i.Return(), fmt.Sprintf("setp.%s.%s", fcmpCond(c), regKind(x.Type())), x, y)

	case ssa.OpcodeSelect:
		c, x, y := i.SelectData()
		p := e.nonZero(c)
		r := i.Return()
		e.ins(fmt.Sprintf("selp.%s %s, %s, %s, %s;", regKind(r.Type()), e.reg(r), e.reg(x), e.reg(y), p))

	case ssa.OpcodeLoad, ssa.OpcodeUload32:
		return e.load(i)

	case ssa.OpcodeStore:
		return e.store(i)

	case ssa.OpcodeCallIndirect:
		return e.intrinsic(i)

	case ssa.OpcodeExitIfTrueWithCode:
		e.exitIf(i)

	case ssa.OpcodeExitWithCode:
		_, code := i.ExitWithCodeData()
		e.trap("", code)

	case ssa.OpcodeBrz, ssa.OpcodeBrnz:
		return e.condBranch(i)

	case ssa.OpcodeJump:
		e.jump(i)

	case ssa.OpcodeReturn:
		e.ins("bra " + labelExit + ";")

	default:
		return fmt.Errorf("ptx: unsupported instruction %s", op)
	}
	return nil
}

// load lowers module_ctx field reads to kernel params, and any other
// load to a global memory load.
func (e *emitter) load(i *ssa.Instruction) error {
	ptr, off, typ := i.LoadData()
	r := i.Return()
	if ptr != e.moduleCtx {
		if i.Opcode() != ssa.OpcodeLoad {
			return fmt.Errorf("ptx: unsupported instruction %s", i.Opcode())
		}
		e.ins(fmt.Sprintf("ld.global.%s %s, [%s+%d];", memKind(typ), e.reg(r), e.reg(ptr), off))
		return nil
	}

	// Memory 0 base and length are kernel params.
	o := wazevoapi.Offset(off)
	switch o {
	case e.offset.LocalMemoryBase():
		e.ins(fmt.Sprintf("ld.param.u64 %s, [mem0];", e.reg(r)))
		e.ins(fmt.Sprintf("cvta.to.global.u64 %s, %s;", e.reg(r), e.reg(r)))
		return nil
	case e.offset.LocalMemoryLen():
		e.ins(fmt.Sprintf("ld.param.u64 %s, [mem0_len];", e.reg(r)))
		return nil
	}

	// Imported function pointer: remember it for the CallIndirect.
	// The paired callee module_ctx load has no use on the device.
	for k, name := range e.imports {
		fnPtr, modCtx, _ := e.offset.ImportedFunctionOffset(wasm.Index(k))
		switch o {
		case fnPtr:
			e.intrinsicPtrs[r.ID()] = name
			return nil
		case modCtx:
			return nil
		}
	}
	return fmt.Errorf("ptx: unsupported module context access at offset %#x", off)
}

// store lowers global memory stores. The frontend's caller-module-ctx
// store before import calls is dropped.
func (e *emitter) store(i *ssa.Instruction) error {
	v, ptr, off, _ := i.StoreData()
	if ptr == e.execCtx && wazevoapi.Offset(off) == wazevoapi.ExecutionContextOffsetCallerModuleContextPtr {
		return nil
	}
	e.ins(fmt.Sprintf("st.global.%s [%s+%d], %s;", memKind(v.Type()), e.reg(ptr), off, e.reg(v)))
	return nil
}

// intrinsic lowers a call to a `gpu.*` import inline: a barrier, or a
// special register read.
func (e *emitter) intrinsic(i *ssa.Instruction) error {
	fnPtr, _, args, _ := i.CallIndirectData()
	name, ok := e.intrinsicPtrs[fnPtr.ID()]
	if !ok {
		return fmt.Errorf("ptx: unsupported indirect call")
	}
	if name == barrierName {
		e.ins("bar.sync 0;")
		return nil
	}

	// args = exec_ctx, callee module_ctx, dim.
	dim := e.b.InstructionOfValue(args[numCtxParams])
	if dim == nil || dim.Opcode() != ssa.OpcodeIconst || dim.ConstantVal() >= uint64(len(dims)) {
		return fmt.Errorf("ptx: gpu.%s needs a constant dim in 0..%d", name, len(dims)-1)
	}
	e.ins(fmt.Sprintf("mov.u32 %s, %s.%s;", e.reg(i.Return()), intrinsics[name], dims[dim.ConstantVal()]))
	return nil
}

// exitIf lowers a conditional trap. Unchecked drops bounds checks.
func (e *emitter) exitIf(i *ssa.Instruction) {
	_, c, code := i.ExitIfTrueWithCodeData()
	if e.bc == Unchecked && code == wazevoapi.ExitCodeMemoryOutOfBounds {
		return
	}
	e.trap(e.nonZero(c), code)
}

// trap jumps to the trap stub with code, guarded by predicate p
// (unconditional when p is empty).
func (e *emitter) trap(p string, code wazevoapi.ExitCode) {
	guard := ""
	if p != "" {
		guard = "@" + p + " "
	}
	e.usesTrap = true
	e.ins(fmt.Sprintf("%smov.u32 %%code, %d;", guard, code))
	e.ins(fmt.Sprintf("%sbra %s;", guard, labelTrap))
}

// shift masks the amount like Wasm (x << (y mod bits)); PTX clamps
// instead, and always takes a u32 amount.
func (e *emitter) shift(i *ssa.Instruction) {
	x, y := i.Arg2()
	r := i.Return()
	t := r.Type()

	amt := e.tmp(ssa.TypeI32)
	src := e.reg(y)
	if t == ssa.TypeI64 {
		e.ins(fmt.Sprintf("cvt.u32.u64 %s, %s;", amt, src))
		src = amt
	}
	e.ins(fmt.Sprintf("and.b32 %s, %s, %d;", amt, src, t.Bits()-1))
	e.ins(fmt.Sprintf("%s%d %s, %s, %s;", shiftOps[i.Opcode()], t.Bits(), e.reg(r), e.reg(x), amt))
}

// extend supports 32->64 only, which covers address computation.
func (e *emitter) extend(i *ssa.Instruction) error {
	from, to, signed := i.ExtendData()
	if from != 32 || to != 64 {
		return fmt.Errorf("ptx: unsupported extend %d->%d", from, to)
	}
	kind := "u"
	if signed {
		kind = "s"
	}
	e.ins(fmt.Sprintf("cvt.%s64.%s32 %s, %s;", kind, kind, e.reg(i.Return()), e.reg(i.Arg())))
	return nil
}

// setBool lowers a compare: PTX writes a predicate, wazevo wants i32 0/1.
func (e *emitter) setBool(r ssa.Value, setp string, x, y ssa.Value) {
	p := e.pred()
	e.ins(fmt.Sprintf("%s %s, %s, %s;", setp, p, e.reg(x), e.reg(y)))
	e.ins(fmt.Sprintf("selp.b32 %s, 1, 0, %s;", e.reg(r), p))
}

// nonZero returns a predicate holding v != 0.
func (e *emitter) nonZero(v ssa.Value) string {
	p := e.pred()
	e.ins(fmt.Sprintf("setp.ne.%s %s, %s, 0;", cmpKind(ssa.IntegerCmpCondEqual, v.Type()), p, e.reg(v)))
	return p
}

// condBranch lowers Brz/Brnz. Critical edges are split by the SSA
// passes, so conditional branches never carry block args.
func (e *emitter) condBranch(i *ssa.Instruction) error {
	c, args, target := i.BranchData()
	if len(args) != 0 {
		return fmt.Errorf("ptx: BUG: conditional branch with block args")
	}

	p := e.nonZero(c)
	guard := "@" + p
	if i.Opcode() == ssa.OpcodeBrz {
		guard = "@!" + p
	}
	e.ins(fmt.Sprintf("%s bra %s;", guard, blockLabel(target)))
	return nil
}

// jump lowers an unconditional branch. PTX has no phis: args are
// copied into the target's param registers. Copies go through temps
// so swaps like `jump blk1(v2, v1)` inside loops stay correct.
func (e *emitter) jump(i *ssa.Instruction) {
	_, args, targetID := i.BranchData()
	target := e.b.BasicBlock(targetID)
	if target.ReturnBlock() {
		e.ins("bra " + labelExit + ";")
		return
	}

	tmps := make([]string, len(args))
	for k, a := range args {
		tmps[k] = e.tmp(a.Type())
		e.mov(a.Type(), tmps[k], e.reg(a))
	}
	for k, a := range args {
		e.mov(a.Type(), e.reg(target.Param(k)), tmps[k])
	}
	e.ins(fmt.Sprintf("bra %s;", blockLabel(targetID)))
}

func (e *emitter) mov(t ssa.Type, dst, src string) {
	e.ins(fmt.Sprintf("mov.%s %s, %s;", regKind(t), dst, src))
}

// reg names the register of v, e.g. v12:i32 -> %r12. Context params
// have no register: reaching here means an unsupported access pattern.
func (e *emitter) reg(v ssa.Value) string {
	if (v == e.execCtx || v == e.moduleCtx) && e.err == nil {
		e.err = fmt.Errorf("ptx: unsupported use of execution or module context")
	}
	return e.named(v.Type(), int(v.ID()))
}

// tmp allocates a fresh register of type t.
func (e *emitter) tmp(t ssa.Type) string {
	id := e.tmps
	e.tmps++
	return e.named(t, id)
}

func (e *emitter) named(t ssa.Type, id int) string {
	if id >= e.regs[t] {
		e.regs[t] = id + 1
	}
	return fmt.Sprintf("%%%s%d", regPrefix(t), id)
}

func (e *emitter) pred() string {
	p := fmt.Sprintf("%%p%d", e.preds)
	e.preds++
	return p
}

func (e *emitter) ins(s string) {
	e.body.WriteString("\t")
	e.body.WriteString(s)
	e.body.WriteString("\n")
}

func (e *emitter) line(s string) {
	e.body.WriteString(s)
	e.body.WriteString("\n")
}

func blockLabel(id ssa.BasicBlockID) string {
	return fmt.Sprintf("$Lblk%d", id)
}

// regPrefix gives each type its own register namespace; PTX requires
// one type per `%name<N>` declaration.
func regPrefix(t ssa.Type) string {
	switch t {
	case ssa.TypeI32:
		return "r"
	case ssa.TypeI64:
		return "rd"
	case ssa.TypeF32:
		return "f"
	case ssa.TypeF64:
		return "fd"
	}
	panic("ptx: unsupported type " + t.String())
}

// regKind is the type used in register declarations and moves.
func regKind(t ssa.Type) string {
	switch t {
	case ssa.TypeI32:
		return "b32"
	case ssa.TypeI64:
		return "b64"
	case ssa.TypeF32:
		return "f32"
	case ssa.TypeF64:
		return "f64"
	}
	panic("ptx: unsupported type " + t.String())
}

// memKind is the type used in ld/st and params.
func memKind(t ssa.Type) string {
	switch t {
	case ssa.TypeI32:
		return "u32"
	case ssa.TypeI64:
		return "u64"
	}
	return regKind(t)
}

// constLit formats raw constant bits, e.g. f32 1.0 -> 0f3F800000.
func constLit(t ssa.Type, bits uint64) string {
	switch t {
	case ssa.TypeF32:
		return fmt.Sprintf("0f%08X", uint32(bits))
	case ssa.TypeF64:
		return fmt.Sprintf("0d%016X", bits)
	case ssa.TypeI32:
		return fmt.Sprintf("%d", int32(bits))
	}
	return fmt.Sprintf("%d", int64(bits))
}

// binOp maps an SSA binary opcode to a typed PTX mnemonic.
// Integer ops wrap, matching Wasm; f32/f64 use IEEE round-to-nearest,
// which also forbids FMA contraction.
func binOp(op ssa.Opcode, t ssa.Type) string {
	bits := fmt.Sprintf("%d", t.Bits())
	switch op {
	case ssa.OpcodeIadd:
		return "add.s" + bits
	case ssa.OpcodeIsub:
		return "sub.s" + bits
	case ssa.OpcodeImul:
		return "mul.lo.s" + bits
	case ssa.OpcodeBand:
		return "and.b" + bits
	case ssa.OpcodeBor:
		return "or.b" + bits
	case ssa.OpcodeBxor:
		return "xor.b" + bits
	case ssa.OpcodeFadd:
		return "add.rn.f" + bits
	case ssa.OpcodeFsub:
		return "sub.rn.f" + bits
	case ssa.OpcodeFmul:
		return "mul.rn.f" + bits
	case ssa.OpcodeFdiv:
		return "div.rn.f" + bits
	}
	panic("ptx: unsupported binop " + op.String())
}

// icmpCond maps to PTX compare ops; unsigned ones use lo/ls/hi/hs.
func icmpCond(c ssa.IntegerCmpCond) string {
	switch c {
	case ssa.IntegerCmpCondEqual:
		return "eq"
	case ssa.IntegerCmpCondNotEqual:
		return "ne"
	case ssa.IntegerCmpCondSignedLessThan:
		return "lt"
	case ssa.IntegerCmpCondSignedLessThanOrEqual:
		return "le"
	case ssa.IntegerCmpCondSignedGreaterThan:
		return "gt"
	case ssa.IntegerCmpCondSignedGreaterThanOrEqual:
		return "ge"
	case ssa.IntegerCmpCondUnsignedLessThan:
		return "lo"
	case ssa.IntegerCmpCondUnsignedLessThanOrEqual:
		return "ls"
	case ssa.IntegerCmpCondUnsignedGreaterThan:
		return "hi"
	case ssa.IntegerCmpCondUnsignedGreaterThanOrEqual:
		return "hs"
	}
	panic("ptx: unsupported icmp cond")
}

// cmpKind picks the operand type of an integer setp.
func cmpKind(c ssa.IntegerCmpCond, t ssa.Type) string {
	bits := fmt.Sprintf("%d", t.Bits())
	switch c {
	case ssa.IntegerCmpCondSignedLessThan, ssa.IntegerCmpCondSignedLessThanOrEqual,
		ssa.IntegerCmpCondSignedGreaterThan, ssa.IntegerCmpCondSignedGreaterThanOrEqual:
		return "s" + bits
	}
	return "u" + bits
}

// fcmpCond maps Wasm float compares. All are ordered (false on NaN)
// except ne, which Wasm defines as true on NaN: PTX `neu`.
func fcmpCond(c ssa.FloatCmpCond) string {
	switch c {
	case ssa.FloatCmpCondEqual:
		return "eq"
	case ssa.FloatCmpCondNotEqual:
		return "neu"
	case ssa.FloatCmpCondLessThan:
		return "lt"
	case ssa.FloatCmpCondLessThanOrEqual:
		return "le"
	case ssa.FloatCmpCondGreaterThan:
		return "gt"
	case ssa.FloatCmpCondGreaterThanOrEqual:
		return "ge"
	}
	panic("ptx: unsupported fcmp cond")
}
