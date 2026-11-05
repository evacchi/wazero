// Package ptx is an experimental wazevo backend that emits NVIDIA PTX.
//
// It does not implement backend.Machine: PTX is a virtual ISA with
// unlimited typed registers, so SSA values map 1:1 to PTX registers and
// regalloc, ABI and encoding are skipped. ptxas does the rest.
//
// One Wasm function becomes one "map" kernel. Thread i reads param k
// from in_k[i], runs the body, writes the result to out[i]:
//
//	       host                         device, thread i
//	┌─────────────────┐   launch   ┌────────────────────────────┐
//	│ in_0[] in_1[] … │ ─────────► │ v = f(in_0[i], in_1[i], …) │
//	│ out[]           │ ◄───────── │ out[i] = v                 │
//	└─────────────────┘            └────────────────────────────┘
//
// Supported subset: i32/i64/f32/f64 scalars, one result, integer and
// float arithmetic, compares, select, and control flow (block, loop,
// if, br, br_if). Memory, globals, tables, calls and traps are rejected.
package ptx

import (
	"fmt"
	"slices"
	"strings"

	"github.com/tetratelabs/wazero/internal/engine/wazevo/frontend"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/wazevoapi"
	"github.com/tetratelabs/wazero/internal/wasm"
)

const (
	// ptxVersion and ptxTarget are conservative: any CUDA >= 11 driver
	// accepts them and JIT-compiles to the actual device.
	ptxVersion = "7.0"
	ptxTarget  = "sm_52"

	// numCtxParams is the count of wazevo's implicit leading params
	// (exec_ctx, module_ctx). Kernels ignore them.
	numCtxParams = 2

	// labelExit is the shared exit label of every kernel.
	labelExit = "$Lexit"
)

// Compile lowers the local function fnIdx of m into a PTX module
// exposing one kernel named name with signature:
//
//	.entry name(.param .u64 in_0, …, .param .u64 out, .param .u32 n)
//
// fnIdx indexes the code section, i.e. imports are not counted.
func Compile(m *wasm.Module, fnIdx wasm.Index, name string) (string, error) {
	typIdx := m.FunctionSection[fnIdx]
	typ := &m.TypeSection[typIdx]
	if len(typ.Results) != 1 {
		return "", fmt.Errorf("ptx: want 1 result, got %d", len(typ.Results))
	}
	for _, vt := range slices.Concat(typ.Params, typ.Results) {
		switch vt {
		case wasm.ValueTypeI32, wasm.ValueTypeI64, wasm.ValueTypeF32, wasm.ValueTypeF64:
			continue
		}
		return "", fmt.Errorf("ptx: unsupported type %s", wasm.ValueTypeName(vt))
	}

	// Wasm -> optimized SSA, as the native backends do.
	b := ssa.NewBuilder()
	offset := wazevoapi.NewModuleContextOffsetData(m, false)
	fe := frontend.NewFrontendCompiler(m, b, &offset, false, false, false)
	code := &m.CodeSection[fnIdx]
	fe.Init(fnIdx, typIdx, typ, code.LocalTypes, code.Body, false, 0)
	fe.LowerToSSA()
	b.RunPasses()

	e := &emitter{b: b, name: name, regs: map[ssa.Type]int{}}
	return e.emit()
}

// emitter translates one ssa.Builder into PTX text.
type emitter struct {
	b    ssa.Builder
	name string
	body strings.Builder

	// regs is the register count per type, i.e. `.reg .b32 %r<N>`.
	regs map[ssa.Type]int
	// preds is the predicate register count.
	preds int
	// tmps is the next temp ID for block-argument copies; IDs start
	// after the last SSA value so they never collide.
	tmps int
	// numParams is the count of kernel input arrays.
	numParams int
	// result is the type stored to out[].
	result ssa.Type
}

func (e *emitter) emit() (string, error) {
	e.tmps = len(e.b.ValuesInfo())
	e.result = e.b.Signature().Results[0]

	entry := e.b.EntryBlock()
	e.numParams = entry.Params() - numCtxParams
	e.prologue(entry)

	for blk := e.b.BlockIteratorReversePostOrderBegin(); blk != nil; blk = e.b.BlockIteratorReversePostOrderNext() {
		if err := e.block(blk); err != nil {
			return "", err
		}
	}

	e.line(labelExit + ":")
	e.ins("ret;")
	return e.module(), nil
}

// module assembles header, kernel signature, declarations and body.
// Declarations come last in generation since counts are only known
// after the body is emitted.
func (e *emitter) module() string {
	var s strings.Builder
	fmt.Fprintf(&s, ".version %s\n.target %s\n.address_size 64\n\n", ptxVersion, ptxTarget)

	fmt.Fprintf(&s, ".visible .entry %s(\n", e.name)
	for k := 0; k < e.numParams; k++ {
		fmt.Fprintf(&s, "\t.param .u64 in_%d,\n", k)
	}
	s.WriteString("\t.param .u64 out,\n\t.param .u32 n\n)\n{\n")

	// Fixed registers used by the prologue and by loads/stores.
	s.WriteString("\t.reg .b32 %gid, %t0, %t1;\n")
	s.WriteString("\t.reg .b64 %base, %off, %addr;\n")
	s.WriteString("\t.reg .pred %oob;\n")
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

// prologue computes the global thread index, exits out-of-range
// threads, and loads each Wasm param from its input array.
func (e *emitter) prologue(entry ssa.BasicBlock) {
	// gid = ctaid.x * ntid.x + tid.x
	e.ins("mov.u32 %t0, %ctaid.x;")
	e.ins("mov.u32 %t1, %ntid.x;")
	e.ins("mov.u32 %gid, %tid.x;")
	e.ins("mad.lo.s32 %gid, %t0, %t1, %gid;")

	// Grid may overshoot n.
	e.ins("ld.param.u32 %t0, [n];")
	e.ins("setp.ge.u32 %oob, %gid, %t0;")
	e.ins("@%oob bra " + labelExit + ";")

	for k := 0; k < e.numParams; k++ {
		v := entry.Param(numCtxParams + k)
		e.addr(fmt.Sprintf("in_%d", k), v.Type())
		e.ins(fmt.Sprintf("ld.global.%s %s, [%%addr];", memKind(v.Type()), e.reg(v)))
	}
}

// addr sets %addr = &param[gid] for an array of elements of type t.
func (e *emitter) addr(param string, t ssa.Type) {
	e.ins(fmt.Sprintf("ld.param.u64 %%base, [%s];", param))
	e.ins("cvta.to.global.u64 %base, %base;")
	e.ins(fmt.Sprintf("mul.wide.u32 %%off, %%gid, %d;", t.Size()))
	e.ins("add.s64 %addr, %base, %off;")
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

	case ssa.OpcodeBrz, ssa.OpcodeBrnz:
		return e.condBranch(i)

	case ssa.OpcodeJump:
		e.jump(i)

	case ssa.OpcodeReturn:
		e.ret(i.ReturnVals())

	default:
		return fmt.Errorf("ptx: unsupported instruction %s", op)
	}
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
		e.ret(args)
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

// ret stores the single result to out[gid] and exits.
func (e *emitter) ret(vals []ssa.Value) {
	v := vals[0]
	e.addr("out", e.result)
	e.ins(fmt.Sprintf("st.global.%s [%%addr], %s;", memKind(v.Type()), e.reg(v)))
	e.ins("bra " + labelExit + ";")
}

func (e *emitter) mov(t ssa.Type, dst, src string) {
	e.ins(fmt.Sprintf("mov.%s %s, %s;", regKind(t), dst, src))
}

// reg names the register of v, e.g. v12:i32 -> %r12.
func (e *emitter) reg(v ssa.Value) string {
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
	e.body.WriteString("\t" + s + "\n")
}

func (e *emitter) line(s string) {
	e.body.WriteString(s + "\n")
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

// memKind is the type used in ld/st.
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
// Integer ops wrap, matching Wasm; f32/f64 use IEEE round-to-nearest.
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
