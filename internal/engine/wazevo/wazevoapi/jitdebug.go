package wazevoapi

import (
	"encoding/binary"
	"runtime"
	"unsafe"
)

// GDB/LLDB JIT debug interface.
//
// When enabled via -tags jitdebug, wazero registers JIT-compiled code with
// the debugger using the GDB JIT Compilation Interface. The debugger can then
// show wasm bytecode offsets as "line numbers" in disassembly and backtraces.
//
// In lldb, enable with: settings set plugin.jit-loader.gdb.enable on
//
// References:
//   - https://llvm.org/docs/DebuggingJITedCode.html
//   - https://sourceware.org/gdb/current/onlinedocs/gdb.html/JIT-Interface.html

// jitCodeEntry is a node in the linked list read by the debugger.
// The layout must match the C struct expected by GDB/LLDB.
type jitCodeEntry struct {
	next        *jitCodeEntry
	prev        *jitCodeEntry
	symfileAddr *byte
	symfileSize uint64
}

// jitDescriptor is the root descriptor read by the debugger.
type jitDescriptor struct {
	version       uint32
	actionFlag    uint32
	relevantEntry *jitCodeEntry
	firstEntry    *jitCodeEntry
}

// jitDebugDescriptor is the global descriptor that the debugger looks for
// via the __jit_debug_descriptor symbol (see go:linkname below).
//
//go:linkname jitDebugDescriptor __jit_debug_descriptor
var jitDebugDescriptor jitDescriptor

// jitDebugRegisterCode calls __jit_debug_register_code, which is the
// function the debugger sets a breakpoint on.
// Implemented in jitdebug_asm_{arch}.s when jitdebug is enabled,
// or as a no-op stub in jitdebug_stub.go when disabled.

// jitEntries keeps references to all registered entries so the GC doesn't collect them.
var jitEntries []*jitCodeEntry

// jitELFBuffers keeps references to the ELF byte slices so the GC doesn't collect them.
var jitELFBuffers [][]byte

const (
	jitRegisterAction   = 1
	jitUnregisterAction = 2
)

// SourceLineResolver resolves a wasm bytecode offset to a source file and line.
// Returns empty file if no source info is available for that offset.
type SourceLineResolver func(wasmOffset uint64) (file string, line int)

// RegisterJITCode constructs a minimal ELF with DWARF .debug_line info
// and registers it with the debugger via the GDB JIT interface.
// If resolver is non-nil, it maps wasm offsets to real source file/line.
// Otherwise, wasm bytecode offsets are used as line numbers with file "<jit>".
func RegisterJITCode(textAddr uintptr, textSize int, sourceOffsets []uintptr, wasmOffsets []uint64, resolver SourceLineResolver) {
	if !JITDebugEnabled {
		return
	}

	debugLine := buildDebugLine(textAddr, sourceOffsets, wasmOffsets, resolver)
	elfBytes := buildELF64(textAddr, uint64(textSize), debugLine)


	// Keep a reference so GC doesn't collect it.
	jitELFBuffers = append(jitELFBuffers, elfBytes)

	entry := &jitCodeEntry{
		symfileAddr: &elfBytes[0],
		symfileSize: uint64(len(elfBytes)),
	}
	jitEntries = append(jitEntries, entry)

	// Insert at the head of the linked list.
	entry.next = jitDebugDescriptor.firstEntry
	if jitDebugDescriptor.firstEntry != nil {
		jitDebugDescriptor.firstEntry.prev = entry
	}
	jitDebugDescriptor.firstEntry = entry
	jitDebugDescriptor.version = 1
	jitDebugDescriptor.actionFlag = jitRegisterAction
	jitDebugDescriptor.relevantEntry = entry

	// Signal the debugger. After this call returns, the debugger has
	// processed the JIT ELF. Then jitDebugBreak traps (BRK/INT3) so the
	// user can set source breakpoints before execution continues.
	// Under a debugger, skip the BRK with: register write pc `$pc+4`
	// Note: will crash if not run under a debugger.
	jitDebugRegisterCode()
	jitDebugBreak()

	// Ensure the ELF buffer and entry stay alive past the call.
	runtime.KeepAlive(elfBytes)
	runtime.KeepAlive(entry)
}

// --- ELF builder ---

const (
	elfClass64    = 2
	elfData2LSB   = 1
	elfEvCurrent  = 1
	elfOSABINone  = 0
	elfETExec     = 2
	elfEMAarch64  = 183
	elfEMX86_64   = 62
	elfSHTNull     = 0
	elfSHTProgbits = 1
	elfSHTStrtab   = 3
	elfSHTNobits   = 8
	elfSHFAlloc    = 0x2
	elfSHFExec     = 0x4

	elf64HdrSize = 64
	elf64ShdrSize = 64
)

func elfMachine() uint16 {
	switch runtime.GOARCH {
	case "arm64":
		return elfEMAarch64
	default:
		return elfEMX86_64
	}
}

func buildELF64(textAddr uintptr, textSize uint64, debugLine []byte) []byte {
	shstrtab := buildShstrtab()
	debugAbbrev := buildDebugAbbrev()
	debugInfo := buildDebugInfo(textAddr, textSize)

	// Layout:
	//   [ELF header]           64 bytes
	//   [.debug_line data]
	//   [.debug_abbrev data]
	//   [.debug_info data]
	//   [.shstrtab data]
	//   [section headers]      6 * 64 bytes (null + .text + .debug_line + .debug_abbrev + .debug_info + .shstrtab)

	debugLineOff := uint64(elf64HdrSize)
	debugAbbrevOff := debugLineOff + uint64(len(debugLine))
	debugInfoOff := debugAbbrevOff + uint64(len(debugAbbrev))
	shstrtabOff := debugInfoOff + uint64(len(debugInfo))
	shdrOff := shstrtabOff + uint64(len(shstrtab))
	if shdrOff%8 != 0 {
		shdrOff = (shdrOff + 7) &^ 7
	}
	numSections := uint16(6)
	totalSize := shdrOff + uint64(numSections)*elf64ShdrSize

	buf := make([]byte, totalSize)
	le := binary.LittleEndian

	// --- ELF Header ---
	copy(buf[0:4], "\x7fELF")
	buf[4] = elfClass64
	buf[5] = elfData2LSB
	buf[6] = elfEvCurrent
	buf[7] = elfOSABINone
	le.PutUint16(buf[16:], elfETExec)
	le.PutUint16(buf[18:], elfMachine())
	le.PutUint32(buf[20:], elfEvCurrent)
	le.PutUint64(buf[40:], shdrOff)       // e_shoff
	le.PutUint16(buf[52:], elf64HdrSize)  // e_ehsize
	le.PutUint16(buf[58:], elf64ShdrSize) // e_shentsize
	le.PutUint16(buf[60:], numSections)   // e_shnum
	le.PutUint16(buf[62:], 5)             // e_shstrndx (index of .shstrtab)

	// --- Section data ---
	copy(buf[debugLineOff:], debugLine)
	copy(buf[debugAbbrevOff:], debugAbbrev)
	copy(buf[debugInfoOff:], debugInfo)
	copy(buf[shstrtabOff:], shstrtab)

	// --- Section headers ---
	sh := buf[shdrOff:]

	// [0] SHT_NULL

	// [1] .text
	s := elf64ShdrSize
	le.PutUint32(sh[s:], shstrtabIndex(".text"))
	le.PutUint32(sh[s+4:], elfSHTNobits)
	le.PutUint64(sh[s+8:], elfSHFAlloc|elfSHFExec)
	le.PutUint64(sh[s+16:], uint64(textAddr))
	le.PutUint64(sh[s+32:], textSize)

	// [2] .debug_line
	s = 2 * elf64ShdrSize
	le.PutUint32(sh[s:], shstrtabIndex(".debug_line"))
	le.PutUint32(sh[s+4:], elfSHTProgbits)
	le.PutUint64(sh[s+24:], debugLineOff)
	le.PutUint64(sh[s+32:], uint64(len(debugLine)))
	le.PutUint64(sh[s+48:], 1)

	// [3] .debug_abbrev
	s = 3 * elf64ShdrSize
	le.PutUint32(sh[s:], shstrtabIndex(".debug_abbrev"))
	le.PutUint32(sh[s+4:], elfSHTProgbits)
	le.PutUint64(sh[s+24:], debugAbbrevOff)
	le.PutUint64(sh[s+32:], uint64(len(debugAbbrev)))
	le.PutUint64(sh[s+48:], 1)

	// [4] .debug_info
	s = 4 * elf64ShdrSize
	le.PutUint32(sh[s:], shstrtabIndex(".debug_info"))
	le.PutUint32(sh[s+4:], elfSHTProgbits)
	le.PutUint64(sh[s+24:], debugInfoOff)
	le.PutUint64(sh[s+32:], uint64(len(debugInfo)))
	le.PutUint64(sh[s+48:], 1)

	// [5] .shstrtab
	s = 5 * elf64ShdrSize
	le.PutUint32(sh[s:], shstrtabIndex(".shstrtab"))
	le.PutUint32(sh[s+4:], elfSHTStrtab)
	le.PutUint64(sh[s+24:], shstrtabOff)
	le.PutUint64(sh[s+32:], uint64(len(shstrtab)))
	le.PutUint64(sh[s+48:], 1)

	return buf
}

// shstrtab layout: \0 .text\0 .debug_line\0 .debug_abbrev\0 .debug_info\0 .shstrtab\0
var shstrtabData = "\x00.text\x00.debug_line\x00.debug_abbrev\x00.debug_info\x00.shstrtab\x00"

func buildShstrtab() []byte {
	return []byte(shstrtabData)
}

func shstrtabIndex(name string) uint32 {
	// Indices into shstrtabData.
	switch name {
	case ".text":
		return 1
	case ".debug_line":
		return 7
	case ".debug_abbrev":
		return 19
	case ".debug_info":
		return 33
	case ".shstrtab":
		return 45
	default:
		panic("unknown section name: " + name)
	}
}

// --- DWARF .debug_abbrev ---

func buildDebugAbbrev() []byte {
	// Minimal abbreviation table: one entry for DW_TAG_compile_unit.
	var buf []byte
	// Abbreviation code 1.
	buf = appendULEB128(buf, 1)
	// DW_TAG_compile_unit
	buf = appendULEB128(buf, 0x11)
	// DW_CHILDREN_no
	buf = append(buf, 0)
	// DW_AT_low_pc, DW_FORM_addr
	buf = appendULEB128(buf, 0x11)
	buf = appendULEB128(buf, 0x01)
	// DW_AT_high_pc, DW_FORM_addr
	buf = appendULEB128(buf, 0x12)
	buf = appendULEB128(buf, 0x01)
	// DW_AT_stmt_list, DW_FORM_data4 (offset into .debug_line)
	buf = appendULEB128(buf, 0x10)
	buf = appendULEB128(buf, 0x06)
	// End of attributes.
	buf = append(buf, 0, 0)
	// End of abbreviation table.
	buf = append(buf, 0)
	return buf
}

// --- DWARF .debug_info ---

func buildDebugInfo(textAddr uintptr, textSize uint64) []byte {
	addrSize := byte(unsafe.Sizeof(textAddr))

	// Compilation unit header + one DIE (compile_unit).
	var buf []byte
	buf = append(buf, 0, 0, 0, 0) // unit_length placeholder
	buf = appendU16(buf, 4)       // DWARF version 4
	buf = append(buf, 0, 0, 0, 0) // debug_abbrev_offset = 0
	buf = append(buf, addrSize)   // address_size

	// DIE: abbreviation code 1 (compile_unit)
	buf = appendULEB128(buf, 1)
	// DW_AT_low_pc (DW_FORM_addr)
	var addrBytes [8]byte
	binary.LittleEndian.PutUint64(addrBytes[:], uint64(textAddr))
	buf = append(buf, addrBytes[:addrSize]...)
	// DW_AT_high_pc (DW_FORM_addr)
	binary.LittleEndian.PutUint64(addrBytes[:], uint64(textAddr)+textSize)
	buf = append(buf, addrBytes[:addrSize]...)
	// DW_AT_stmt_list (DW_FORM_data4) — offset 0 into .debug_line
	buf = append(buf, 0, 0, 0, 0)

	// Patch unit_length.
	binary.LittleEndian.PutUint32(buf[0:], uint32(len(buf)-4))
	return buf
}

// --- DWARF .debug_line builder ---

// sourceEntry holds a resolved source location for one mapping.
type sourceEntry struct {
	fileIdx uint64 // 1-based index into the file table
	line    int
}

func buildDebugLine(textAddr uintptr, execOffsets []uintptr, wasmOffsets []uint64, resolver SourceLineResolver) []byte {
	if len(execOffsets) == 0 {
		return nil
	}

	// Resolve source locations. If resolver is nil or returns no info,
	// fall back to wasm offsets as line numbers with file "<jit>".
	files := []string{"<jit>"} // file index 1 = fallback
	fileMap := map[string]uint64{"<jit>": 1}
	entries := make([]sourceEntry, len(execOffsets))

	for i := range execOffsets {
		var file string
		var line int
		if resolver != nil {
			file, line = resolver(wasmOffsets[i])
		}
		if file == "" {
			// Fallback: use wasm offset as line number.
			entries[i] = sourceEntry{fileIdx: 1, line: int(wasmOffsets[i])}
		} else {
			idx, ok := fileMap[file]
			if !ok {
				files = append(files, file)
				idx = uint64(len(files))
				fileMap[file] = idx
			}
			entries[i] = sourceEntry{fileIdx: idx, line: line}
		}
	}

	const (
		dwarfVersion   = 4
		minInstrLen    = 1
		maxOpsPerInstr = 1
		defaultIsStmt  = 1
		lineBase       = 0
		lineRange      = 1
		opcodeBase     = 13
	)

	stdOpcodeLens := []byte{0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1}

	// Build the header.
	var hdr []byte
	hdr = append(hdr, 0, 0, 0, 0) // unit_length placeholder
	hdr = appendU16(hdr, dwarfVersion)
	hdr = append(hdr, 0, 0, 0, 0) // header_length placeholder
	headerLenOffset := len(hdr) - 4
	hdr = append(hdr, minInstrLen, maxOpsPerInstr, defaultIsStmt)
	hdr = append(hdr, byte(int8(lineBase)))
	hdr = append(hdr, lineRange, opcodeBase)
	hdr = append(hdr, stdOpcodeLens...)
	// Include directories (empty list).
	hdr = append(hdr, 0)
	// File names.
	for _, f := range files {
		hdr = append(hdr, []byte(f)...)
		hdr = append(hdr, 0)        // null-terminated name
		hdr = appendULEB128(hdr, 0) // directory index
		hdr = appendULEB128(hdr, 0) // modification time
		hdr = appendULEB128(hdr, 0) // file length
	}
	hdr = append(hdr, 0) // end of file names

	headerLen := uint32(len(hdr) - headerLenOffset - 4)
	binary.LittleEndian.PutUint32(hdr[headerLenOffset:], headerLen)

	// Build the line number program.
	var prog []byte
	prog = append(prog, 4) // DW_LNS_set_file
	prog = appendULEB128(prog, 1)
	prog = appendExtendedOp(prog, 2, textAddr) // DW_LNE_set_address

	currentLine := int64(0)
	currentFile := uint64(1)
	currentAddr := textAddr

	for i, e := range entries {
		addr := execOffsets[i]
		addrDelta := int64(addr - currentAddr)

		if e.fileIdx != currentFile {
			prog = append(prog, 4) // DW_LNS_set_file
			prog = appendULEB128(prog, e.fileIdx)
			currentFile = e.fileIdx
		}

		lineDelta := int64(e.line) - currentLine
		if addrDelta > 0 || lineDelta != 0 {
			if lineDelta != 0 {
				prog = append(prog, 3) // DW_LNS_advance_line
				prog = appendSLEB128(prog, lineDelta)
			}
			if addrDelta > 0 {
				prog = append(prog, 2) // DW_LNS_advance_pc
				prog = appendULEB128(prog, uint64(addrDelta))
			}
			prog = append(prog, 1) // DW_LNS_copy
		}

		currentAddr = addr
		currentLine = int64(e.line)
	}

	prog = append(prog, 0, 1, 1) // DW_LNE_end_sequence

	result := append(hdr, prog...)
	binary.LittleEndian.PutUint32(result[0:], uint32(len(result)-4))
	return result
}

// --- LEB128 encoding ---

func appendULEB128(buf []byte, val uint64) []byte {
	for {
		b := byte(val & 0x7f)
		val >>= 7
		if val != 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if val == 0 {
			break
		}
	}
	return buf
}

func appendSLEB128(buf []byte, val int64) []byte {
	for {
		b := byte(val & 0x7f)
		val >>= 7
		if (val == 0 && b&0x40 == 0) || (val == -1 && b&0x40 != 0) {
			buf = append(buf, b)
			break
		}
		buf = append(buf, b|0x80)
	}
	return buf
}

func appendU16(buf []byte, val uint16) []byte {
	return append(buf, byte(val), byte(val>>8))
}

func appendExtendedOp(buf []byte, opcode byte, addr uintptr) []byte {
	buf = append(buf, 0) // extended opcode marker
	addrSize := uint64(unsafe.Sizeof(addr))
	buf = appendULEB128(buf, addrSize+1) // length = sizeof(addr) + 1 for opcode
	buf = append(buf, opcode)
	var addrBytes [8]byte
	binary.LittleEndian.PutUint64(addrBytes[:], uint64(addr))
	buf = append(buf, addrBytes[:addrSize]...)
	return buf
}
