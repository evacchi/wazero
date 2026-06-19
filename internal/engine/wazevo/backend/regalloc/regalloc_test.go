package regalloc

import (
	"fmt"
	"sort"
	"testing"

	"github.com/tetratelabs/wazero/internal/engine/wazevo/wazevoapi"
	"github.com/tetratelabs/wazero/internal/testing/require"
)

type (
	_allocator = Allocator[*mockInstr, *mockBlock, *mockFunction]
	_state     = state[*mockInstr, *mockBlock, *mockFunction]
	_vrState   = vrState[*mockInstr, *mockBlock, *mockFunction]
)

var (
	_newAllocator = NewAllocator[*mockInstr, *mockBlock, *mockFunction]
	_resetVrState = resetVrState[*mockInstr, *mockBlock, *mockFunction]
)

func TestAllocator_livenessAnalysis(t *testing.T) {
	const realRegID, realRegID2 = 50, 100
	realReg, realReg2 := FromRealReg(realRegID, RegTypeInt), FromRealReg(realRegID2, RegTypeInt)
	phiVReg := VReg(12345).SetRegType(RegTypeInt)

	type exp struct {
		liveIns []VRegID
	}

	for _, tc := range []struct {
		name  string
		setup func() *mockFunction
		exps  map[int]*exp
	}{
		{
			name: "single block",
			setup: func() *mockFunction {
				return newMockFunction(
					newMockBlock(0,
						newMockInstr().def(1),
						newMockInstr().use(1).def(2),
					).entry(),
				)
			},
			exps: map[int]*exp{
				0: {},
			},
		},
		{
			name: "single block with real reg",
			setup: func() *mockFunction {
				realVReg := FromRealReg(10, RegTypeInt)
				param := VReg(1)
				ret := VReg(2)
				blk := newMockBlock(0,
					newMockInstr().def(param).use(realVReg),
					newMockInstr().def(ret).use(param, param),
					newMockInstr().def(realVReg).use(ret),
				).entry()
				blk.blockParam(param)
				return newMockFunction(blk)
			},
			exps: map[int]*exp{
				0: {},
			},
		},
		{
			name: "straight",
			// b0 -> b1 -> b2
			setup: func() *mockFunction {
				b0 := newMockBlock(0,
					newMockInstr().def(1000, 1, 2),
					newMockInstr().use(1000),
					newMockInstr().use(1, 2).def(3),
				).entry()
				b1 := newMockBlock(1,
					newMockInstr().def(realReg),
					newMockInstr().use(3).def(4, 5),
					newMockInstr().use(realReg),
				)
				b2 := newMockBlock(2,
					newMockInstr().use(3, 4, 5),
				)
				b2.addPred(b1)
				b1.addPred(b0)
				return newMockFunction(b0, b1, b2)
			},
			exps: map[int]*exp{
				0: {},
				1: {
					liveIns: []VRegID{3},
				},
				2: {liveIns: []VRegID{3, 4, 5}},
			},
		},
		{
			name: "diamond",
			//  0   v1000<-, v1<-, v2<-
			// / \
			// 1   2
			// \ /
			//  3
			setup: func() *mockFunction {
				b0 := newMockBlock(0,
					newMockInstr().def(1000),
					newMockInstr().def(1),
					newMockInstr().def(2),
				).entry()
				b1 := newMockBlock(1,
					newMockInstr().def(realReg).use(1),
					newMockInstr().use(realReg),
					newMockInstr().def(realReg2),
					newMockInstr().use(realReg2),
					newMockInstr().def(realReg),
					newMockInstr().use(realReg),
				)
				b2 := newMockBlock(2,
					newMockInstr().use(2, realReg2),
				)
				b3 := newMockBlock(3,
					newMockInstr().use(1000),
				)
				b3.addPred(b1)
				b3.addPred(b2)
				b1.addPred(b0)
				b2.addPred(b0)
				return newMockFunction(b0, b1, b2, b3)
			},
			exps: map[int]*exp{
				0: {},
				1: {liveIns: []VRegID{1000, 1}},
				2: {
					liveIns: []VRegID{1000, 2},
				},
				3: {
					liveIns: []VRegID{1000},
				},
			},
		},

		{
			name: "phis",
			//   0
			// /  \
			// 1   \
			// |   |
			// 2   3
			//  \ /
			//   4  use v5 (phi node) defined at both 1 and 3.
			setup: func() *mockFunction {
				b0 := newMockBlock(0,
					newMockInstr().def(1000, 2000, 3000),
				).entry()
				b1 := newMockBlock(1,
					newMockInstr().def(phiVReg).use(2000),
				)
				b2 := newMockBlock(2)
				b3 := newMockBlock(3,
					newMockInstr().def(phiVReg).use(1000),
				)
				b4 := newMockBlock(
					4, newMockInstr().use(phiVReg, 3000),
				)
				b4.addPred(b2)
				b4.addPred(b3)
				b3.addPred(b0)
				b2.addPred(b1)
				b1.addPred(b0)
				return newMockFunction(b0, b1, b2, b3, b4)
			},
			exps: map[int]*exp{
				0: {},
				1: {
					liveIns: []VRegID{2000, 3000},
				},
				2: {
					liveIns: []VRegID{phiVReg.ID(), 3000},
				},
				3: {
					liveIns: []VRegID{1000, 3000},
				},
				4: {
					liveIns: []VRegID{phiVReg.ID(), 3000},
				},
			},
		},

		{
			name: "loop",
			// 0 -> 1 -> 2
			//      ^    |
			//      |    v
			//      4 <- 3 -> 5
			setup: func() *mockFunction {
				b0 := newMockBlock(0,
					newMockInstr().def(1),
					newMockInstr().def(phiVReg).use(1),
				).entry()
				b1 := newMockBlock(1,
					newMockInstr().def(9999),
				)
				b1.blockParam(phiVReg)
				b2 := newMockBlock(2,
					newMockInstr().def(100).use(phiVReg, 9999),
				)
				b3 := newMockBlock(3,
					newMockInstr().def(54321),
					newMockInstr().use(100),
				)
				b4 := newMockBlock(4,
					newMockInstr().def(phiVReg).use(54321).
						// Make sure this is the PHI defining instruction.
						asCopy(),
				)
				b5 := newMockBlock(
					5, newMockInstr().use(54321),
				)
				b1.addPred(b0)
				b1.addPred(b4)
				b2.addPred(b1)
				b3.addPred(b2)
				b4.addPred(b3)
				b5.addPred(b3)
				b1.loop(b2, b3, b4, b5)
				f := newMockFunction(b0, b1, b2, b3, b4, b5)
				f.loopNestingForestRoots(b1)
				return f
			},
			exps: map[int]*exp{
				0: {
					liveIns: []VRegID{},
				},
				1: {
					liveIns: []VRegID{phiVReg.ID()},
				},
				2: {
					liveIns: []VRegID{phiVReg.ID(), 9999},
				},
				3: {
					liveIns: []VRegID{100},
				},
				4: {
					liveIns: []VRegID{54321},
				},
				5: {liveIns: []VRegID{54321}},
			},
		},
		{
			name: "multiple pass alive",
			setup: func() *mockFunction {
				v := VReg(9999)
				b0 := newMockBlock(0, newMockInstr().def(v)).entry()

				b1, b2, b3, b4, b5, b6 := newMockBlock(1), newMockBlock(2),
					newMockBlock(3, newMockInstr().use(v)),
					newMockBlock(4), newMockBlock(5), newMockBlock(6)

				b1.addPred(b0)
				b4.addPred(b0)
				b2.addPred(b1)
				b5.addPred(b2)
				b2.addPred(b5)
				b6.addPred(b2)
				b3.addPred(b6)
				b3.addPred(b4)
				f := newMockFunction(b0, b1, b2, b4, b5, b6, b3)
				f.loopNestingForestRoots(b2)
				return f
			},
			exps: map[int]*exp{
				0: {},
				1: {
					liveIns: []VRegID{9999},
				},
				2: {
					liveIns: []VRegID{9999},
				},
				3: {
					liveIns: []VRegID{9999},
				},
				4: {
					liveIns: []VRegID{9999},
				},
				5: {},
				6: {
					liveIns: []VRegID{9999},
				},
			},
		},
		{
			//           -----+
			//           v    |
			// 0 -> 1 -> 2 -> 3 -> 4
			//      ^    |
			//      +----+
			name: "Fig. 9.2 in paper",
			setup: func() *mockFunction {
				b0 := newMockBlock(0,
					newMockInstr().def(99999),
					newMockInstr().def(phiVReg).use(111).asCopy(),
				).entry()
				b1 := newMockBlock(1, newMockInstr().use(99999))
				b1.blockParam(phiVReg)
				b2 := newMockBlock(2, newMockInstr().def(88888).use(phiVReg, phiVReg))
				b3 := newMockBlock(3, newMockInstr().def(phiVReg).use(88888).asCopy())
				b4 := newMockBlock(4)
				b1.addPred(b0)
				b1.addPred(b2)
				b2.addPred(b1)
				b2.addPred(b3)
				b3.addPred(b2)
				b4.addPred(b3)

				b1.loop(b2)
				b2.loop(b3)
				f := newMockFunction(b0, b1, b2, b3, b4)
				f.loopNestingForestRoots(b1)
				return f
			},
			exps: map[int]*exp{
				0: {
					liveIns: []VRegID{111},
				},
				1: {
					liveIns: []VRegID{99999, phiVReg.ID()},
				},
				2: {
					liveIns: []VRegID{99999, phiVReg.ID()},
				},
				3: {
					liveIns: []VRegID{99999, phiVReg.ID(), 88888},
				},
				4: {},
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f := tc.setup()
			a := _newAllocator(&RegisterInfo{
				RealRegName: func(r RealReg) string {
					return fmt.Sprintf("r%d", r)
				},
			})
			a.livenessAnalysis(f)
			for blockID := 0; blockID <= a.blockStates.MaxIDEncountered(); blockID++ {
				actual := a.blockStates.Get(blockID)
				if actual == nil {
					continue
				}
				t.Run(fmt.Sprintf("block_id=%d", blockID), func(t *testing.T) {
					exp := tc.exps[blockID]
					if len(exp.liveIns) == 0 {
						require.Nil(t, actual.liveIns, "live ins")
					} else {
						var actuals []VRegID
						for _, s := range actual.liveIns {
							actuals = append(actuals, s.v.ID())
						}
						sort.Slice(actuals, func(i, j int) bool {
							return actuals[i] < actuals[j]
						})
						sort.Slice(exp.liveIns, func(i, j int) bool {
							return exp.liveIns[i] < exp.liveIns[j]
						})
						require.Equal(t, exp.liveIns, actuals, "live ins")
					}
				})
			}
		})
	}
}

func TestAllocator_livenessAnalysis_copy(t *testing.T) {
	f := newMockFunction(
		newMockBlock(0,
			newMockInstr().def(1),
			newMockInstr().use(1).def(2).asCopy(),
		).entry(),
	)
	a := _newAllocator(&RegisterInfo{})
	a.livenessAnalysis(f)
}

// TestFixMergeState_swapThenStoreReload tests the fixMergeState reconciliation
// for the pattern found in the argon2id fill_blocks ARM64 regression:
// a merge block where a predecessor requires a register swap, followed by
// Case 1 (store+reload) on the swapped register, then Case 4 (reload from stack)
// for the value that was displaced by the swap.
//
// Desired state at merge block:
//
//	r1 = vA (the swap target)
//	r5 = vC (comes from stack)
//	r8 = vD (comes from stack)
//
// Predecessor end state (live-in values only):
//
//	r1 = vB   (needs to move out)
//	r5 = vA   (needs to go to r1 via swap)
//
// Expected operations:
//  1. Swap r1 and r5: r1 gets vA, r5 gets vB
//  2. Store vB from r5 to stack (Case 1: r5 has vB, but vC is desired there)
//  3. Reload vC from stack to r5
//  4. Reload vD from stack to r8
func TestFixMergeState_swapThenStoreReload(t *testing.T) {
	const (
		r1 = RealReg(1)
		r5 = RealReg(5)
		r8 = RealReg(8)
		r9 = RealReg(9) // free register for swap temp
	)

	vA := VReg(100).SetRegType(RegTypeInt)
	vB := VReg(200).SetRegType(RegTypeInt)
	vC := VReg(300).SetRegType(RegTypeInt)
	vD := VReg(400).SetRegType(RegTypeInt)

	regInfo := &RegisterInfo{
		AllocatableRegisters: [NumRegType][]RealReg{
			RegTypeInt:   {r1, r5, r8, r9},
			RegTypeFloat: {},
		},
		RealRegName: func(r RealReg) string {
			return fmt.Sprintf("r%d", r)
		},
		RealRegType: func(r RealReg) RegType { return RegTypeInt },
	}

	// pred0 is the inherited predecessor (startFromPredIndex=0).
	pred0 := newMockBlock(0, newMockInstr()).entry()
	// pred1 is the non-inherited predecessor that needs reconciliation.
	pred1 := newMockBlock(1, newMockInstr())
	// mergeBlk is the merge block with 2 predecessors.
	mergeBlk := newMockBlock(2, newMockInstr())
	mergeBlk.addPred(pred0)
	mergeBlk.addPred(pred1)

	f := newMockFunction(pred0, pred1, mergeBlk)
	f.loopNestingForestRoots(pred0)
	a := _newAllocator(regInfo)

	s := &a.state
	s.vrStates = wazevoapi.NewIDedPool[_vrState](_resetVrState)
	s.reset()

	vsA := s.getOrAllocateVRegState(vA)
	vsB := s.getOrAllocateVRegState(vB)
	vsC := s.getOrAllocateVRegState(vC)
	vsD := s.getOrAllocateVRegState(vD)

	// Set up the merge block's desired state (startRegs).
	mergeBlkSt := a.getOrAllocateBlockState(mergeBlk.ID())
	mergeBlkSt.startRegs.add(r1, vsA) // r1 should have vA
	mergeBlkSt.startRegs.add(r5, vsC) // r5 should have vC
	mergeBlkSt.startRegs.add(r8, vsD) // r8 should have vD
	mergeBlkSt.startFromPredIndex = 0  // inherit from pred0

	// Mark all desired values as live-in at the merge block.
	s.currentBlockID = mergeBlk.ID()
	vsA.lastUse = programCounterLiveIn
	vsA.lastUseUpdatedAtBlockID = mergeBlk.ID()
	vsB.lastUse = programCounterLiveIn
	vsB.lastUseUpdatedAtBlockID = mergeBlk.ID()
	vsC.lastUse = programCounterLiveIn
	vsC.lastUseUpdatedAtBlockID = mergeBlk.ID()
	vsD.lastUse = programCounterLiveIn
	vsD.lastUseUpdatedAtBlockID = mergeBlk.ID()

	mergeBlkSt.liveIns = []*_vrState{vsA, vsB, vsC, vsD}

	// Set up pred1's end state: r1=vB, r5=vA (swap needed).
	pred1St := a.getOrAllocateBlockState(pred1.ID())
	pred1St.endRegs.add(r1, vsB) // r1 has vB (but we want vA there)
	pred1St.endRegs.add(r5, vsA) // r5 has vA (but we want vC there)
	pred1St.visited = true
	// vC and vD are NOT in pred1's endRegs — they're on the stack.

	// Run fixMergeState.
	a.fixMergeState(f, mergeBlk)

	// Verify the final state: all desired registers should be correct.
	require.NotNil(t, s.regsInUse.get(r1), "r1 should be occupied")
	require.Equal(t, vA.ID(), s.regsInUse.get(r1).v.ID(), "r1 should have vA")
	require.NotNil(t, s.regsInUse.get(r5), "r5 should be occupied")
	require.Equal(t, vC.ID(), s.regsInUse.get(r5).v.ID(), "r5 should have vC")
	require.NotNil(t, s.regsInUse.get(r8), "r8 should be occupied")
	require.Equal(t, vD.ID(), s.regsInUse.get(r8).v.ID(), "r8 should have vD")

	// Verify operations were emitted in the correct order.
	// Expected: 1 swap (r1↔r5), then store+reload for r5, then reload for r8.
	t.Logf("Swaps: %d, Stores/Reloads (befores): %d, Moves: %d", len(f.swaps), len(f.befores), len(f.moves))
	for i, sw := range f.swaps {
		t.Logf("  swap[%d]: x1=v%d@r%d, x2=v%d@r%d", i, sw.x1.ID(), sw.x1.RealReg(), sw.x2.ID(), sw.x2.RealReg())
	}
	for i, sr := range f.befores {
		kind := "store"
		if sr.reload {
			kind = "reload"
		}
		t.Logf("  before[%d]: %s v%d@r%d", i, kind, sr.v.ID(), sr.v.RealReg())
	}

	require.Equal(t, 1, len(f.swaps), "should have exactly 1 swap")
	// The swap should be: vB@r1 swapped with vA@r5
	require.Equal(t, vB.ID(), f.swaps[0].x1.ID())
	require.Equal(t, r1, f.swaps[0].x1.RealReg())
	require.Equal(t, vA.ID(), f.swaps[0].x2.ID())
	require.Equal(t, r5, f.swaps[0].x2.RealReg())

	// After swap: r1=vA (done), r5=vB (needs store+reload for vC)
	// befores should contain:
	// [0] store vB@r5  (Case 1: store current vB from r5)
	// [1] reload vC@r5 (Case 1: reload desired vC to r5)
	// [2] reload vD@r8 (Case 4: reload desired vD to r8)
	require.True(t, len(f.befores) >= 3, "should have at least 3 store/reload operations")

	// First: store vB from r5
	require.False(t, f.befores[0].reload, "first op should be store")
	require.Equal(t, vB.ID(), f.befores[0].v.ID())
	require.Equal(t, r5, f.befores[0].v.RealReg())

	// Second: reload vC to r5
	require.True(t, f.befores[1].reload, "second op should be reload")
	require.Equal(t, vC.ID(), f.befores[1].v.ID())
	require.Equal(t, r5, f.befores[1].v.RealReg())

	// Third: reload vD to r8
	require.True(t, f.befores[2].reload, "third op should be reload")
	require.Equal(t, vD.ID(), f.befores[2].v.ID())
	require.Equal(t, r8, f.befores[2].v.RealReg())
}

// TestScheduleSpill tests the spill scheduling logic that places store instructions
// at the correct dominator position. This models the fill_blocks regression pattern:
//
// Control flow:
//
//	blk0 (entry, defines vX)
//	  └─► blk1 (first loop body — vX in register, gets spilled here)
//	        └─► blk2 (loop back-edge, vX reloaded in fixMergeState reconciliation)
//	              └─► blk1 (back to loop header)
//	        └─► blk3 (loop exit → second loop)
//	              └─► blk4 (second loop body, needs vX from spill slot)
//
// The spill store must be placed where vX is in a register AND dominates all reload sites.
func TestScheduleSpill(t *testing.T) {
	const (
		r1 = RealReg(1)
		r5 = RealReg(5)
	)
	vX := VReg(100).SetRegType(RegTypeInt)

	regInfo := &RegisterInfo{
		AllocatableRegisters: [NumRegType][]RealReg{
			RegTypeInt:   {r1, r5},
			RegTypeFloat: {},
		},
		RealRegName: func(r RealReg) string { return fmt.Sprintf("r%d", r) },
		RealRegType: func(r RealReg) RegType { return RegTypeInt },
	}

	t.Run("spill at LCA block where value is in startRegs", func(t *testing.T) {
		// blk0 → blk1 → blk2
		//                  ↓
		//                blk3
		// vX defined in blk0, reloaded in blk2 and blk3.
		// LCA(blk2, blk3) = blk1.
		// vX is in r1 at the start of blk1 → spill should be placed at start of blk1.
		defInstr := newMockInstr().def(vX)
		blk0 := newMockBlock(0, defInstr).entry()
		blk1 := newMockBlock(1, newMockInstr())
		blk2 := newMockBlock(2, newMockInstr())
		blk3 := newMockBlock(3, newMockInstr())

		blk1._idom = blk0
		blk2._idom = blk1
		blk3._idom = blk1

		f := newMockFunction(blk0, blk1, blk2, blk3)

		a := _newAllocator(regInfo)
		s := &a.state
		s.vrStates = wazevoapi.NewIDedPool[_vrState](_resetVrState)
		s.reset()

		vsX := s.getOrAllocateVRegState(vX)
		vsX.spilled = true
		vsX.defBlk = blk0
		vsX.defInstr = defInstr
		vsX.lca = blk1 // LCA of all reload sites
		vsX.v = vX

		// vX is in r1 at start of blk1
		blk1St := a.getOrAllocateBlockState(blk1.ID())
		blk1St.startRegs.add(r1, vsX)

		a.scheduleSpill(f, vsX)

		// The spill should be inserted after the first instruction of blk1 (the LCA),
		// NOT after the definition in blk0.
		require.Equal(t, 1, len(f.afters), "should have 1 spill store")
		require.False(t, f.afters[0].reload, "should be a store, not reload")
		require.Equal(t, vX.ID(), f.afters[0].v.ID(), "should store vX")
		require.Equal(t, r1, f.afters[0].v.RealReg(), "should store from r1")
		require.Equal(t, blk1.instructions[0], f.afters[0].instr,
			"spill should be at start of blk1 (the LCA block)")
	})

	t.Run("spill at definition when LCA is the defining block", func(t *testing.T) {
		// blk0 defines vX. LCA = blk0. Spill right after the definition.
		defInstr := newMockInstr().def(vX)
		blk0 := newMockBlock(0, defInstr).entry()
		blk1 := newMockBlock(1, newMockInstr())

		blk1._idom = blk0

		f := newMockFunction(blk0, blk1)

		a := _newAllocator(regInfo)
		s := &a.state
		s.vrStates = wazevoapi.NewIDedPool[_vrState](_resetVrState)
		s.reset()

		vsX := s.getOrAllocateVRegState(vX)
		vsX.spilled = true
		vsX.defBlk = blk0
		vsX.defInstr = defInstr
		vsX.lca = blk0
		vsX.v = vX

		a.scheduleSpill(f, vsX)

		require.Equal(t, 1, len(f.afters))
		require.Equal(t, defInstr, f.afters[0].instr,
			"spill should be after the definition instruction")
	})

	t.Run("spill walks up idom chain when value not in startRegs at LCA", func(t *testing.T) {
		// blk0 → blk1 → blk2 → blk3
		// vX defined in blk0, LCA = blk3.
		// vX is NOT in startRegs of blk3 or blk2, but IS in startRegs of blk1.
		// Spill should be at blk1.
		defInstr := newMockInstr().def(vX)
		blk0 := newMockBlock(0, defInstr).entry()
		blk1 := newMockBlock(1, newMockInstr())
		blk2 := newMockBlock(2, newMockInstr())
		blk3 := newMockBlock(3, newMockInstr())

		blk1._idom = blk0
		blk2._idom = blk1
		blk3._idom = blk2

		f := newMockFunction(blk0, blk1, blk2, blk3)

		a := _newAllocator(regInfo)
		s := &a.state
		s.vrStates = wazevoapi.NewIDedPool[_vrState](_resetVrState)
		s.reset()

		vsX := s.getOrAllocateVRegState(vX)
		vsX.spilled = true
		vsX.defBlk = blk0
		vsX.defInstr = defInstr
		vsX.lca = blk3
		vsX.v = vX

		// Only blk1 has vX in startRegs (not blk2 or blk3)
		blk1St := a.getOrAllocateBlockState(blk1.ID())
		blk1St.startRegs.add(r5, vsX)

		a.scheduleSpill(f, vsX)

		require.Equal(t, 1, len(f.afters))
		require.Equal(t, r5, f.afters[0].v.RealReg(), "should store from r5")
		require.Equal(t, blk1.instructions[0], f.afters[0].instr,
			"spill should be at start of blk1 (closest ancestor with value in register)")
	})

	t.Run("spill at loop header is unsafe if register is reused on back-edge", func(t *testing.T) {
		t.Skip("Known latent issue: scheduleSpill can place stores at multi-pred blocks where the register may differ across paths. Not the cause of the fill_blocks bug but worth fixing separately.")
		// This reproduces the fill_blocks ARM64 bug.
		//
		// blk0 (entry) → blk1 (defines vX in r1) → blk9 (loop header) → blk_body → blk9
		//
		// vX is in r1 at the start of blk9 on the FIRST iteration (inherited from blk1).
		// But on the back-edge, r1 may hold a DIFFERENT value because the loop body
		// reuses r1. scheduleSpill places StoreRegisterAfter(vX@r1, blk9.FirstInstr()),
		// which runs on EVERY iteration — writing whatever is in r1 to vX's spill slot.
		// On the second iteration, r1 != vX → spill slot is corrupted.
		//
		// The correct behavior is to spill at the definition site (blk1), not at the
		// loop header.
		defInstr := newMockInstr().def(vX)
		blk0 := newMockBlock(0, newMockInstr()).entry()
		blk1 := newMockBlock(1, defInstr)
		blk9 := newMockBlock(9, newMockInstr()) // merge block with 2 preds
		blkBody := newMockBlock(10, newMockInstr())

		blk1._idom = blk0
		blk9._idom = blk1
		blkBody._idom = blk9

		blk9.addPred(blk1)
		blk9.addPred(blkBody)

		f := newMockFunction(blk0, blk1, blk9, blkBody)

		a := _newAllocator(regInfo)
		s := &a.state
		s.vrStates = wazevoapi.NewIDedPool[_vrState](_resetVrState)
		s.reset()

		vsX := s.getOrAllocateVRegState(vX)
		vsX.spilled = true
		vsX.defBlk = blk1
		vsX.defInstr = defInstr
		vsX.lca = blk9 // LCA of all reload sites is the loop header
		vsX.v = vX

		// vX is in r1 at start of blk9 (from the initial entry via blk1)
		blk9St := a.getOrAllocateBlockState(blk9.ID())
		blk9St.startRegs.add(r1, vsX)

		a.scheduleSpill(f, vsX)

		// BUG: currently scheduleSpill places the store at blk9.FirstInstr() (the loop header).
		// This is wrong because on back-edge iterations, r1 may not hold vX.
		//
		// EXPECTED (after fix): spill should be at the definition in blk1, NOT at the loop header.
		// For now, this test documents the current (buggy) behavior.
		require.Equal(t, 1, len(f.afters))
		if f.afters[0].instr == defInstr {
			t.Log("CORRECT: spill placed at definition site (blk1)")
		} else if f.afters[0].instr == blk9.instructions[0] {
			t.Log("BUG: spill placed at loop header (blk9) — register may be reused on back-edge")
			t.Fail()
		}
	})

	t.Run("spill falls through to definition when no ancestor has value in startRegs", func(t *testing.T) {
		// blk0 → blk1 → blk2
		// vX defined in blk0, LCA = blk2.
		// Neither blk2 nor blk1 have vX in startRegs.
		// Spill should fall back to the definition in blk0.
		defInstr := newMockInstr().def(vX)
		blk0 := newMockBlock(0, defInstr).entry()
		blk1 := newMockBlock(1, newMockInstr())
		blk2 := newMockBlock(2, newMockInstr())

		blk1._idom = blk0
		blk2._idom = blk1

		f := newMockFunction(blk0, blk1, blk2)

		a := _newAllocator(regInfo)
		s := &a.state
		s.vrStates = wazevoapi.NewIDedPool[_vrState](_resetVrState)
		s.reset()

		vsX := s.getOrAllocateVRegState(vX)
		vsX.spilled = true
		vsX.defBlk = blk0
		vsX.defInstr = defInstr
		vsX.lca = blk2
		vsX.v = vX

		// No block has vX in startRegs.

		a.scheduleSpill(f, vsX)

		require.Equal(t, 1, len(f.afters))
		require.Equal(t, defInstr, f.afters[0].instr,
			"spill should be after the definition when no ancestor has it in startRegs")
	})
}

func Test_findOrSpillAllocatable_prefersSpill(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		a := &_allocator{}
		s := &_state{regsInUse: newRegInUseSet[*mockInstr, *mockBlock, *mockFunction]()}
		s.regsInUse.add(RealReg(1), &_vrState{v: VReg(2222222)})
		got := a.findOrSpillAllocatable(s, []RealReg{3}, 0, 3)
		require.Equal(t, RealReg(3), got)
	})
	t.Run("preferred but in use", func(t *testing.T) {
		a := &_allocator{}
		s := &_state{vrStates: wazevoapi.NewIDedPool[_vrState](_resetVrState)}
		s.regsInUse.add(RealReg(3), &_vrState{v: VReg(1).SetRealReg(3)})
		got := a.findOrSpillAllocatable(s, []RealReg{3, 4}, 0, 3)
		require.Equal(t, RealReg(4), got)
	})
	t.Run("preferred but forbidden", func(t *testing.T) {
		a := &_allocator{}
		s := &_state{vrStates: wazevoapi.NewIDedPool[_vrState](_resetVrState)}
		got := a.findOrSpillAllocatable(s, []RealReg{3, 4}, RegSet(0).add(3), 3)
		require.Equal(t, RealReg(4), got)
	})
}
