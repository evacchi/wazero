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
		if diff < -(1<<25)*4 || diff > ((1<<25)-1)*4 {
			//panic(fmt.Sprintf("TODO: too large binary where branch target is out of the supported range +/-128MB: %#x", diff))
			m.encodeTrampoline(base, calleeFnOffset, binary, instrOffset)
			continue
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

		// movz

		//fmt.Printf("base: %#x, calleeFnOffset: %#x\n", base, calleeFnOffset)
	}
}

func (m *machine) encodeTrampoline(base uintptr, calleeFnOffset int, binary []byte, instrOffset int64) {
	tmpReg := regNumberInEncoding[tmp]

	const movzOp = uint32(0b10)
	const movkOp = uint32(0b11)

	addr := uint(base) + uint(calleeFnOffset)

	movInst := binary[instrOffset : instrOffset+4]
	w := encodeMoveWideImmediate(movzOp, tmpReg, uint64(uint16(addr)), 0, 1)
	writeInst(movInst, w)

	movInst = binary[instrOffset+4 : instrOffset+8]
	w = encodeMoveWideImmediate(movkOp, tmpReg, uint64(uint16(addr>>16)), 1, 1)
	writeInst(movInst, w)

	movInst = binary[instrOffset+8 : instrOffset+12]
	w = encodeMoveWideImmediate(movkOp, tmpReg, uint64(uint16(addr>>32)), 2, 1)
	writeInst(movInst, w)

	movInst = binary[instrOffset+12 : instrOffset+16]
	w = encodeMoveWideImmediate(movkOp, tmpReg, uint64(uint16(addr>>48)), 3, 1)
	writeInst(movInst, w)

	movInst = binary[instrOffset+16 : instrOffset+20]
	w = encodeUnconditionalBranchReg(tmpReg, true)
	writeInst(movInst, w)
}

func writeInst(binary []byte, inst uint32) {
	binary[0] = byte(inst)
	binary[1] = byte(inst >> 8)
	binary[2] = byte(inst >> 16)
	binary[3] = byte(inst >> 24)
}
