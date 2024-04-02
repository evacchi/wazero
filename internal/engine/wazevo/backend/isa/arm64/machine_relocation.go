package arm64

import (
	"github.com/tetratelabs/wazero/internal/engine/wazevo/backend"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa"
	"unsafe"
)

// ResolveRelocations implements backend.Machine ResolveRelocations.
//
// TODO: unit test!
func (m *machine) ResolveRelocations(refToBinaryOffset map[ssa.FuncRef]int, binary []byte, relocations []backend.RelocationInfo) {
	base := uintptr(unsafe.Pointer(&binary[0]))
	for _, r := range relocations {
		instrOffset := r.Offset
		calleeFnOffset := refToBinaryOffset[r.FuncRef]
		brInstr := binary[instrOffset : instrOffset+4]
		diff := int64(calleeFnOffset) - (instrOffset)
		// Check if the diff is within the range of the branch instruction.
		if true || diff < -(1<<25)*4 || diff > ((1<<25)-1)*4 {
			diff = int64(r.TrampolineOffset) - instrOffset
			absoluteCalleeFnAddress := uint(base) + uint(calleeFnOffset)
			m.encodeTrampoline(absoluteCalleeFnAddress, binary, r.TrampolineOffset, -diff+8)
		}
		// https://developer.arm.com/documentation/ddi0596/2020-12/Base-Instructions/BL--Branch-with-Link-
		imm26 := diff / 4
		brInstr[0] = byte(imm26)
		brInstr[1] = byte(imm26 >> 8)
		brInstr[2] = byte(imm26 >> 16)
		if diff < 0 {
			brInstr[3] = (byte(imm26 >> 24 & 0b000000_01)) | 0b100101_10 // Set sign bit.
		} else {
			brInstr[3] = (byte(imm26 >> 24 & 0b000000_01)) | 0b100101_00 // No sign bit.
		}
	}
}

func (m *machine) encodeTrampoline(addr uint, binary []byte, instrOffset int, jumpBack int64) {
	tmpReg := regNumberInEncoding[tmp]

	const movzOp = uint32(0b10)
	const movkOp = uint32(0b11)

	instrs := []uint32{
		encodeMoveWideImmediate(movzOp, tmpReg, uint64(uint16(addr)), 0, 1),
		encodeMoveWideImmediate(movkOp, tmpReg, uint64(uint16(addr>>16)), 1, 1),
		encodeMoveWideImmediate(movkOp, tmpReg, uint64(uint16(addr>>32)), 2, 1),
		encodeMoveWideImmediate(movkOp, tmpReg, uint64(uint16(addr>>48)), 3, 1),
		encodeUnconditionalBranchReg(tmpReg, true),
		encodeMov64(tmpReg, tmpReg, false, false),
		encodeUnconditionalBranch(false, jumpBack-7*4),
	}

	for i, inst := range instrs {
		writeInst(binary[instrOffset+i*4:instrOffset+(i+1)*4], inst)
	}
}

func writeInst(binary []byte, inst uint32) {
	binary[0] = byte(inst)
	binary[1] = byte(inst >> 8)
	binary[2] = byte(inst >> 16)
	binary[3] = byte(inst >> 24)
}
