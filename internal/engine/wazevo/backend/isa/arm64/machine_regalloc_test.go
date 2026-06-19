package arm64

import (
	"testing"

	"github.com/tetratelabs/wazero/internal/engine/wazevo/backend/regalloc"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa"
	"github.com/tetratelabs/wazero/internal/testing/require"
)

func TestRegAllocFunctionImpl_ReloadRegisterAfter(t *testing.T) {
	ctx, _, m := newSetupWithMockContext()

	ctx.typeOf = map[regalloc.VRegID]ssa.Type{x1VReg.ID(): ssa.TypeI64, v1VReg.ID(): ssa.TypeF64}
	i1, i2 := m.allocateNop(), m.allocateNop()
	i1.next = i2
	i2.prev = i1

	m.insertReloadRegisterAt(x1VReg, i1, true)
	m.insertReloadRegisterAt(v1VReg, i1, true)

	require.NotEqual(t, i1, i2.prev)
	require.NotEqual(t, i1.next, i2)
	fload, iload := i1.next, i1.next.next
	require.Equal(t, fload.prev, i1)
	require.Equal(t, i1, fload.prev)
	require.Equal(t, iload.next, i2)
	require.Equal(t, iload, i2.prev)

	require.Equal(t, iload.kind, uLoad64)
	require.Equal(t, fload.kind, fpuLoad64)

	m.rootInstr = i1
	require.Equal(t, `
	ldr d1, [sp, #0x18]
	ldr x1, [sp, #0x10]
`, m.Format())
}

func TestRegAllocFunctionImpl_StoreRegisterBefore(t *testing.T) {
	ctx, _, m := newSetupWithMockContext()

	ctx.typeOf = map[regalloc.VRegID]ssa.Type{x1VReg.ID(): ssa.TypeI64, v1VReg.ID(): ssa.TypeF64}
	i1, i2 := m.allocateNop(), m.allocateNop()
	i1.next = i2
	i2.prev = i1

	m.insertStoreRegisterAt(x1VReg, i2, false)
	m.insertStoreRegisterAt(v1VReg, i2, false)

	require.NotEqual(t, i1, i2.prev)
	require.NotEqual(t, i1.next, i2)
	iload, fload := i1.next, i1.next.next
	require.Equal(t, iload.prev, i1)
	require.Equal(t, i1, iload.prev)
	require.Equal(t, fload.next, i2)
	require.Equal(t, fload, i2.prev)

	require.Equal(t, iload.kind, store64)
	require.Equal(t, fload.kind, fpuStore64)

	m.rootInstr = i1
	require.Equal(t, `
	str x1, [sp, #0x10]
	str d1, [sp, #0x18]
`, m.Format())
}

func TestMachine_insertStoreRegisterAt(t *testing.T) {
	for _, tc := range []struct {
		spillSlotSize int64
		expected      string
	}{
		{
			spillSlotSize: 0,
			expected: `
	udf
	str x1, [sp, #0x10]
	str d1, [sp, #0x18]
	exit_sequence x30
`,
		},
		{
			spillSlotSize: 0xffff,
			expected: `
	udf
	movz x27, #0xf, lsl 0
	movk x27, #0x1, lsl 16
	str x1, [sp, x27]
	movz x27, #0x17, lsl 0
	movk x27, #0x1, lsl 16
	str d1, [sp, x27]
	exit_sequence x30
`,
		},
		{
			spillSlotSize: 0xffff_00,
			expected: `
	udf
	movz x27, #0xff10, lsl 0
	movk x27, #0xff, lsl 16
	str x1, [sp, x27]
	movz x27, #0xff18, lsl 0
	movk x27, #0xff, lsl 16
	str d1, [sp, x27]
	exit_sequence x30
`,
		},
	} {
		t.Run(tc.expected, func(t *testing.T) {
			ctx, _, m := newSetupWithMockContext()
			m.spillSlotSize = tc.spillSlotSize

			for _, after := range []bool{false, true} {
				var name string
				if after {
					name = "after"
				} else {
					name = "before"
				}
				t.Run(name, func(t *testing.T) {
					ctx.typeOf = map[regalloc.VRegID]ssa.Type{x1VReg.ID(): ssa.TypeI64, v1VReg.ID(): ssa.TypeF64}
					i1, i2 := m.allocateInstr().asUDF(), m.allocateInstr().asExitSequence(x30VReg)
					i1.next = i2
					i2.prev = i1

					if after {
						m.insertStoreRegisterAt(v1VReg, i1, after)
						m.insertStoreRegisterAt(x1VReg, i1, after)
					} else {
						m.insertStoreRegisterAt(x1VReg, i2, after)
						m.insertStoreRegisterAt(v1VReg, i2, after)
					}
					m.rootInstr = i1
					require.Equal(t, tc.expected, m.Format())
				})
			}
		})
	}
}

func TestMachine_insertReloadRegisterAt(t *testing.T) {
	for _, tc := range []struct {
		spillSlotSize int64
		expected      string
	}{
		{
			spillSlotSize: 0,
			expected: `
	udf
	ldr x1, [sp, #0x10]
	ldr d1, [sp, #0x18]
	exit_sequence x30
`,
		},
		{
			spillSlotSize: 0xffff,
			expected: `
	udf
	movz x27, #0xf, lsl 0
	movk x27, #0x1, lsl 16
	ldr x1, [sp, x27]
	movz x27, #0x17, lsl 0
	movk x27, #0x1, lsl 16
	ldr d1, [sp, x27]
	exit_sequence x30
`,
		},
		{
			spillSlotSize: 0xffff_00,
			expected: `
	udf
	movz x27, #0xff10, lsl 0
	movk x27, #0xff, lsl 16
	ldr x1, [sp, x27]
	movz x27, #0xff18, lsl 0
	movk x27, #0xff, lsl 16
	ldr d1, [sp, x27]
	exit_sequence x30
`,
		},
	} {
		t.Run(tc.expected, func(t *testing.T) {
			ctx, _, m := newSetupWithMockContext()
			m.spillSlotSize = tc.spillSlotSize

			for _, after := range []bool{false, true} {
				var name string
				if after {
					name = "after"
				} else {
					name = "before"
				}
				t.Run(name, func(t *testing.T) {
					ctx.typeOf = map[regalloc.VRegID]ssa.Type{x1VReg.ID(): ssa.TypeI64, v1VReg.ID(): ssa.TypeF64}
					i1, i2 := m.allocateInstr().asUDF(), m.allocateInstr().asExitSequence(x30VReg)
					i1.next = i2
					i2.prev = i1

					if after {
						m.insertReloadRegisterAt(v1VReg, i1, after)
						m.insertReloadRegisterAt(x1VReg, i1, after)
					} else {
						m.insertReloadRegisterAt(x1VReg, i2, after)
						m.insertReloadRegisterAt(v1VReg, i2, after)
					}
					m.rootInstr = i1

					require.Equal(t, tc.expected, m.Format())
				})
			}
		})
	}
}

// TestMergeStateLikeSequence_swapStoreReload exercises the exact instruction
// insertion sequence that fixMergeState produces for the argon2id fill_blocks
// regression (ARM64-specific). The reconciliation for block 35 does:
//
//  1. SwapBefore(vB@r1, vA@r5, tmp, lastInstr)     — Case 2: swap r1↔r5
//  2. StoreRegisterBefore(vB@r5, lastInstr)          — Case 1 part 1: save displaced vB
//  3. ReloadRegisterBefore(vC@r5, lastInstr)         — Case 1 part 2: load desired vC
//  4. StoreRegisterBefore(vX@r3, lastInstr)          — Case 1 for another register
//  5. ReloadRegisterBefore(vD@r3, lastInstr)         — Case 1 part 2
//  6. ReloadRegisterBefore(vE@r8, lastInstr)         — Case 4: reload from stack
//
// All operations insert before the same lastInstr (the branch at end of pred).
// The test verifies the emitted instructions are in the correct order so that:
//   - The swap completes before any store reads from the swapped registers
//   - Stores happen before their corresponding reloads
//   - No x27 (tmp register) conflicts between swap and large-offset spills
func TestMergeStateLikeSequence_swapStoreReload(t *testing.T) {
	for _, tc := range []struct {
		name          string
		spillSlotSize int64 // 0 = small offsets (imm12), large = uses x27 for address
		expected      string
	}{
		{
			name:          "small offsets",
			spillSlotSize: 0,
			expected: `
	udf
	mov x9, x1
	mov x1, x5
	mov x5, x9
	str w5, [sp, #0x10]
	ldr w5, [sp, #0x14]
	str w3, [sp, #0x18]
	ldr w3, [sp, #0x1c]
	ldr w8, [sp, #0x20]
	b L1
`,
		},
		{
			name:          "large offsets (x27 used for address computation)",
			spillSlotSize: 0xffff,
			expected: `
	udf
	mov x9, x1
	mov x1, x5
	mov x5, x9
	movz x27, #0xf, lsl 0
	movk x27, #0x1, lsl 16
	str w5, [sp, x27]
	movz x27, #0x13, lsl 0
	movk x27, #0x1, lsl 16
	ldr w5, [sp, x27]
	movz x27, #0x17, lsl 0
	movk x27, #0x1, lsl 16
	str w3, [sp, x27]
	movz x27, #0x1b, lsl 0
	movk x27, #0x1, lsl 16
	ldr w3, [sp, x27]
	movz x27, #0x1f, lsl 0
	movk x27, #0x1, lsl 16
	ldr w8, [sp, x27]
	b L1
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, _, m := newSetupWithMockContext()
			m.spillSlotSize = tc.spillSlotSize

			// VReg IDs — each needs a unique ID for distinct spill slots.
			vA := regalloc.VReg(100).SetRealReg(x5).SetRegType(regalloc.RegTypeInt)  // desired at r1, currently at r5
			vB := regalloc.VReg(200).SetRealReg(x1).SetRegType(regalloc.RegTypeInt)  // currently at r1, displaced by swap
			vC := regalloc.VReg(300).SetRealReg(x5).SetRegType(regalloc.RegTypeInt)  // desired at r5, on stack
			vX := regalloc.VReg(400).SetRealReg(x3).SetRegType(regalloc.RegTypeInt)  // currently at r3
			vD := regalloc.VReg(500).SetRealReg(x3).SetRegType(regalloc.RegTypeInt)  // desired at r3, on stack
			vE := regalloc.VReg(600).SetRealReg(x8).SetRegType(regalloc.RegTypeInt)  // desired at r8, on stack
			tmpReg := regalloc.VReg(0).SetRealReg(x9).SetRegType(regalloc.RegTypeInt) // free register for swap

			ctx.typeOf = map[regalloc.VRegID]ssa.Type{
				vA.ID(): ssa.TypeI32,
				vB.ID(): ssa.TypeI32,
				vC.ID(): ssa.TypeI32,
				vX.ID(): ssa.TypeI32,
				vD.ID(): ssa.TypeI32,
				vE.ID(): ssa.TypeI32,
			}

			// Build the instruction list: [udf] ... [branch] (lastInstr)
			// The reconciliation inserts everything before the branch.
			head := m.allocateInstr().asUDF()
			lastInstr := m.allocateInstr()
			lastInstr.asBr(label(1))
			head.next = lastInstr
			lastInstr.prev = head

			f := &regAllocFn{m: m}

			// Simulate exactly what fixMergeState/reconcileEdge does:
			// Step 1: Case 2 — swap r1 and r5 (vB@r1 ↔ vA@r5)
			f.SwapBefore(
				vB.SetRealReg(x1), // currentVReg@r
				vA.SetRealReg(x5), // desiredVReg@er
				tmpReg,
				lastInstr,
			)

			// Step 2: Case 1 — r5 now has vB (from swap), but we want vC there
			// Store vB from r5, then reload vC to r5
			f.StoreRegisterBefore(vB.SetRealReg(x5), lastInstr)
			f.ReloadRegisterBefore(vC.SetRealReg(x5), lastInstr)

			// Step 3: Case 1 — r3 has vX, but we want vD there
			f.StoreRegisterBefore(vX.SetRealReg(x3), lastInstr)
			f.ReloadRegisterBefore(vD.SetRealReg(x3), lastInstr)

			// Step 4: Case 4 — r8 is free, reload vE from stack
			f.ReloadRegisterBefore(vE.SetRealReg(x8), lastInstr)

			m.rootInstr = head
			actual := m.Format()
			require.Equal(t, tc.expected, actual)
		})
	}
}

// TestMergeStateLikeSequence_swapWithTmpRegConflict tests the case where
// no free register is available for the swap temp, so x27 (tmpRegVReg) is used.
// With large spill offsets, both the swap AND the store/reload use x27.
// This verifies there's no x27 conflict between the swap and address computation.
func TestMergeStateLikeSequence_swapWithTmpRegConflict(t *testing.T) {
	ctx, _, m := newSetupWithMockContext()
	m.spillSlotSize = 0xffff // Large offsets → x27 used for address computation

	vA := regalloc.VReg(100).SetRealReg(x5).SetRegType(regalloc.RegTypeInt)
	vB := regalloc.VReg(200).SetRealReg(x1).SetRegType(regalloc.RegTypeInt)
	vC := regalloc.VReg(300).SetRealReg(x5).SetRegType(regalloc.RegTypeInt)

	ctx.typeOf = map[regalloc.VRegID]ssa.Type{
		vA.ID(): ssa.TypeI32,
		vB.ID(): ssa.TypeI32,
		vC.ID(): ssa.TypeI32,
	}

	head := m.allocateInstr().asUDF()
	lastInstr := m.allocateInstr()
	lastInstr.asBr(label(1))
	head.next = lastInstr
	lastInstr.prev = head

	f := &regAllocFn{m: m}

	// Swap with NO free tmp → uses x27 (tmpRegVReg)
	f.SwapBefore(
		vB.SetRealReg(x1),
		vA.SetRealReg(x5),
		regalloc.VRegInvalid, // no free register → will use x27
		lastInstr,
	)

	// Case 1: store vB from r5 (now has vB after swap), reload vC
	f.StoreRegisterBefore(vB.SetRealReg(x5), lastInstr)
	f.ReloadRegisterBefore(vC.SetRealReg(x5), lastInstr)

	m.rootInstr = head

	// The swap uses x27 as temp: mov x27,x1; mov x1,x5; mov x5,x27
	// Then the store with large offset also uses x27: movz x27,#offset; str w5,[sp,x27]
	// This is safe because the swap's x27 use is complete before the store starts.
	expected := `
	udf
	mov x27, x1
	mov x1, x5
	mov x5, x27
	movz x27, #0xf, lsl 0
	movk x27, #0x1, lsl 16
	str w5, [sp, x27]
	movz x27, #0x13, lsl 0
	movk x27, #0x1, lsl 16
	ldr w5, [sp, x27]
	b L1
`
	require.Equal(t, expected, m.Format())
}

func TestRegMachine_ClobberedRegisters(t *testing.T) {
	_, _, m := newSetupWithMockContext()
	m.regAllocFn.ClobberedRegisters([]regalloc.VReg{v19VReg, v19VReg, v19VReg, v19VReg})
	require.Equal(t, []regalloc.VReg{v19VReg, v19VReg, v19VReg, v19VReg}, m.clobberedRegs)
}

func TestMachineMachineswap(t *testing.T) {
	for _, tc := range []struct {
		x1, x2, tmp regalloc.VReg
		expected    string
	}{
		{
			x1:  x18VReg,
			x2:  x19VReg,
			tmp: x20VReg,
			expected: `
	udf
	mov x20, x18
	mov x18, x19
	mov x19, x20
	exit_sequence x30
`,
		},
		{
			x1: x18VReg,
			x2: x19VReg,
			// Tmp not given.
			expected: `
	udf
	mov x27, x18
	mov x18, x19
	mov x19, x27
	exit_sequence x30
`,
		},
		{
			x1:  v18VReg,
			x2:  v19VReg,
			tmp: v11VReg,
			expected: `
	udf
	mov v11.16b, v18.16b
	mov v18.16b, v19.16b
	mov v19.16b, v11.16b
	exit_sequence x30
`,
		},
		{
			x1: v18VReg,
			x2: v19VReg,
			// Tmp not given.
			expected: `
	udf
	str d18, [sp, #0x10]
	mov v18.16b, v19.16b
	ldr d19, [sp, #0x10]
	exit_sequence x30
`,
		},
	} {
		t.Run(tc.expected, func(t *testing.T) {
			ctx, _, m := newSetupWithMockContext()

			ctx.typeOf = map[regalloc.VRegID]ssa.Type{
				x18VReg.ID(): ssa.TypeI64, x19VReg.ID(): ssa.TypeI64,
				v18VReg.ID(): ssa.TypeF64, v19VReg.ID(): ssa.TypeF64,
			}
			cur, i2 := m.allocateInstr().asUDF(), m.allocateInstr().asExitSequence(x30VReg)
			cur.next = i2
			i2.prev = cur

			m.swap(cur, tc.x1, tc.x2, tc.tmp)
			m.rootInstr = cur

			require.Equal(t, tc.expected, m.Format())
		})
	}
}
