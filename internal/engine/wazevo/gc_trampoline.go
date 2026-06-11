package wazevo

import (
	"encoding/binary"
	"fmt"
	"math"
	"unsafe"

	"github.com/tetratelabs/wazero/internal/engine/wazevo/wazevoapi"
	"github.com/tetratelabs/wazero/internal/wasm"
	"github.com/tetratelabs/wazero/internal/wasmruntime"
)

// gcEncodeFieldValue converts a uint64 operand-stack slot into the Go typed
// value that WasmStruct.Fields / WasmArray.Elements stores.
func gcEncodeFieldValue(f wasm.FieldType, raw uint64) any {
	switch f.Kind() {
	case wasm.ValueTypeI8.Kind():
		return wasm.NarrowI8(int32(uint32(raw)))
	case wasm.ValueTypeI16.Kind():
		return wasm.NarrowI16(int32(uint32(raw)))
	}
	switch f.AsImmutable() {
	case wasm.ValueTypeI32:
		return int32(uint32(raw))
	case wasm.ValueTypeI64:
		return int64(raw)
	case wasm.ValueTypeF32:
		return math.Float32frombits(uint32(raw))
	case wasm.ValueTypeF64:
		return math.Float64frombits(raw)
	}
	if f.IsRef() {
		if raw == 0 {
			return nil
		}
		if wasm.IsGCRef(raw) {
			if wasm.IsGCStructRef(raw) {
				return gcStruct(raw)
			}
			return gcArray(raw)
		}
		return raw
	}
	panic(fmt.Sprintf("unsupported struct/array field type %#x", f.Kind()))
}

const (
	gcFieldReadDefault = 0 // unsigned / non-packed
	gcFieldReadSigned  = 1
)

// gcDecodeFieldValue reads a stored field value and converts it to the
// operand-stack uint64 representation.
func gcDecodeFieldValue(f wasm.FieldType, stored any, signed int) uint64 {
	switch f.Kind() {
	case wasm.ValueTypeI8.Kind():
		v := stored.(uint8)
		if signed == gcFieldReadSigned {
			return uint64(uint32(wasm.SignExtendI8(v)))
		}
		return uint64(wasm.ZeroExtendI8(v))
	case wasm.ValueTypeI16.Kind():
		v := stored.(uint16)
		if signed == gcFieldReadSigned {
			return uint64(uint32(wasm.SignExtendI16(v)))
		}
		return uint64(wasm.ZeroExtendI16(v))
	}
	switch f.AsImmutable() {
	case wasm.ValueTypeI32:
		return uint64(uint32(stored.(int32)))
	case wasm.ValueTypeI64:
		return uint64(stored.(int64))
	case wasm.ValueTypeF32:
		return uint64(math.Float32bits(stored.(float32)))
	case wasm.ValueTypeF64:
		return math.Float64bits(stored.(float64))
	}
	if f.IsRef() {
		switch v := stored.(type) {
		case *wasm.WasmStruct:
			return wasm.TagGCStructPointer(unsafe.Pointer(v))
		case *wasm.WasmArray:
			return wasm.TagGCArrayPointer(unsafe.Pointer(v))
		case uint64:
			return v
		case nil:
			return 0
		}
	}
	panic(fmt.Sprintf("unsupported struct/array field type %#x", f.Kind()))
}

func gcStruct(v uint64) *wasm.WasmStruct {
	return (*wasm.WasmStruct)(wasm.UntagGCPointer(v))
}

func gcArray(v uint64) *wasm.WasmArray {
	return (*wasm.WasmArray)(wasm.UntagGCPointer(v))
}

// gcRefMatches reports whether a ref value matches a target heap type.
// Used by ref.test / ref.cast / br_on_cast(_fail).
func gcRefMatches(v uint64, kindByte byte, nullable, isConcrete bool, typeIdx uint32, mi *wasm.ModuleInstance) bool {
	if v == 0 {
		return nullable
	}
	if !isConcrete && wasm.ValueType(kindByte) == wasm.ValueTypeExternref {
		return true
	}
	if !isConcrete {
		switch wasm.ValueType(kindByte) {
		case wasm.ValueTypeNoExternref, wasm.ValueTypeNoExnref, wasm.ValueTypeNullref:
			return false
		}
	}
	if wasm.IsTaggedExternAsAny(v) {
		if isConcrete {
			return false
		}
		return wasm.ValueType(kindByte) == wasm.ValueTypeAnyref
	}
	if wasm.IsTaggedI31(v) {
		if isConcrete {
			return false
		}
		switch wasm.ValueType(kindByte) {
		case wasm.ValueTypeI31ref, wasm.ValueTypeEqref, wasm.ValueTypeAnyref:
			return true
		}
		return false
	}
	store := mi.GetStore()
	if wasm.IsGCRef(v) {
		var objTypeID wasm.FunctionTypeID
		var objForm wasm.CompositeForm
		if wasm.IsGCStructRef(v) {
			objTypeID, objForm = gcStruct(v).TypeID, wasm.CompositeFormStruct
		} else {
			objTypeID, objForm = gcArray(v).TypeID, wasm.CompositeFormArray
		}
		if isConcrete {
			if int(typeIdx) >= len(mi.TypeIDs) {
				return false
			}
			return store.IsSubtype(objTypeID, mi.TypeIDs[typeIdx])
		}
		if !store.IsResolvedType(objTypeID) {
			return false
		}
		switch wasm.ValueType(kindByte) {
		case wasm.ValueTypeAnyref, wasm.ValueTypeEqref:
			return objForm == wasm.CompositeFormStruct || objForm == wasm.CompositeFormArray
		case wasm.ValueTypeStructref:
			return objForm == wasm.CompositeFormStruct
		case wasm.ValueTypeArrayref:
			return objForm == wasm.CompositeFormArray
		}
		return false
	}
	// Function pointer: in wazevo, function refs are *functionInstance.
	tf := wazevoapi.PtrFromUintptr[functionInstance](uintptr(v))
	if isConcrete {
		if int(typeIdx) >= len(mi.TypeIDs) || tf == nil {
			return false
		}
		return store.IsSubtype(tf.typeID, mi.TypeIDs[typeIdx])
	}
	switch wasm.ValueType(kindByte) {
	case wasm.ValueTypeFuncref:
		return tf != nil
	case wasm.ValueTypeNoFuncref:
		return false
	}
	return false
}

// handleGCAlloc handles ExitCodeGCAlloc — all GC heap allocations.
func (c *callEngine) handleGCAlloc() {
	s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
	subOp := int(s[0])
	typeIdx := uint32(s[1])
	mod := c.callerModuleInstance()
	schema := &mod.Source.TypeSection[typeIdx]
	gcTypeID := mod.TypeIDs[typeIdx]

	var result uint64
	switch subOp {
	case wazevoapi.GCAllocStructNew:
		fieldCount := len(schema.Fields)
		if fieldCount > wazevoapi.ExecutionContextOffsetGCScratchBufferSize {
			panic(fmt.Errorf("struct.new: %d fields exceeds scratch buffer size %d", fieldCount, wazevoapi.ExecutionContextOffsetGCScratchBufferSize))
		}
		fields := make([]any, fieldCount)
		for i := 0; i < fieldCount; i++ {
			fields[i] = gcEncodeFieldValue(schema.Fields[i], c.execCtx.gcScratchBuffer[i])
		}
		obj := wasm.NewWasmStructWith(gcTypeID, fields)
		result = mod.GCRegister(obj)
	case wazevoapi.GCAllocStructNewDefault:
		fieldCount := len(schema.Fields)
		fields := make([]any, fieldCount)
		for i := 0; i < fieldCount; i++ {
			fields[i] = wasm.DefaultFieldValue(schema.Fields[i])
		}
		obj := wasm.NewWasmStructWith(gcTypeID, fields)
		result = mod.GCRegister(obj)
	case wazevoapi.GCAllocArrayNew:
		rawVal := c.execCtx.gcScratchBuffer[0]
		length := uint32(c.execCtx.gcScratchBuffer[1])
		stored := gcEncodeFieldValue(schema.ArrayField, rawVal)
		elems := make([]any, length)
		for i := range elems {
			elems[i] = stored
		}
		obj := wasm.NewWasmArrayWith(gcTypeID, elems)
		result = mod.GCRegister(obj)
	case wazevoapi.GCAllocArrayNewDefault:
		length := uint32(c.execCtx.gcScratchBuffer[0])
		def := wasm.DefaultFieldValue(schema.ArrayField)
		elems := make([]any, length)
		for i := range elems {
			elems[i] = def
		}
		obj := wasm.NewWasmArrayWith(gcTypeID, elems)
		result = mod.GCRegister(obj)
	case wazevoapi.GCAllocArrayNewFixed:
		count := int(c.execCtx.gcScratchBuffer[0])
		if 1+count > wazevoapi.ExecutionContextOffsetGCScratchBufferSize {
			panic(fmt.Errorf("array.new_fixed: %d elements exceeds scratch buffer size %d", count, wazevoapi.ExecutionContextOffsetGCScratchBufferSize-1))
		}
		elems := make([]any, count)
		for i := 0; i < count; i++ {
			elems[i] = gcEncodeFieldValue(schema.ArrayField, c.execCtx.gcScratchBuffer[1+i])
		}
		obj := wasm.NewWasmArrayWith(gcTypeID, elems)
		result = mod.GCRegister(obj)
	case wazevoapi.GCAllocArrayNewData:
		segIdx := uint32(c.execCtx.gcScratchBuffer[0])
		srcOff := uint32(c.execCtx.gcScratchBuffer[1])
		count := uint32(c.execCtx.gcScratchBuffer[2])
		data := mod.DataInstances[segIdx]
		elemSize, ok := gcArrayDataElemSize(schema.ArrayField)
		if !ok {
			panic(fmt.Errorf("array.new_data on unsupported element type"))
		}
		totalBytes := uint64(count) * uint64(elemSize)
		if uint64(srcOff)+totalBytes > uint64(len(data)) {
			panic(wasmruntime.ErrRuntimeOutOfBoundsMemoryAccess)
		}
		elems := make([]any, count)
		for i := uint32(0); i < count; i++ {
			off := srcOff + i*elemSize
			elems[i] = gcReadDataElement(schema.ArrayField, data, off)
		}
		obj := wasm.NewWasmArrayWith(gcTypeID, elems)
		result = mod.GCRegister(obj)
	case wazevoapi.GCAllocArrayNewElem:
		segIdx := uint32(c.execCtx.gcScratchBuffer[0])
		srcOff := uint32(c.execCtx.gcScratchBuffer[1])
		count := uint32(c.execCtx.gcScratchBuffer[2])
		elem := mod.ElementInstances[segIdx]
		if uint64(srcOff)+uint64(count) > uint64(len(elem)) {
			panic(wasmruntime.ErrRuntimeInvalidTableAccess)
		}
		elems := make([]any, count)
		for i := uint32(0); i < count; i++ {
			elems[i] = gcEncodeFieldValue(schema.ArrayField, uint64(elem[srcOff+i]))
		}
		obj := wasm.NewWasmArrayWith(gcTypeID, elems)
		result = mod.GCRegister(obj)
	default:
		panic("BUG: unknown GCAlloc sub-opcode")
	}
	s[0] = result
}

// handleGCFieldOp handles ExitCodeGCFieldOp — single-field read/write ops.
func (c *callEngine) handleGCFieldOp() {
	s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
	subOp := int(s[0])
	ref := s[1]
	typeIdx := uint32(s[2])
	fieldIdx := int(s[3])
	value := s[4]
	mod := c.callerModuleInstance()
	schema := &mod.Source.TypeSection[typeIdx]

	switch subOp {
	case wazevoapi.GCFieldOpStructGet, wazevoapi.GCFieldOpStructGetS, wazevoapi.GCFieldOpStructGetU:
		if ref == 0 {
			panic(wasmruntime.ErrRuntimeNullReference)
		}
		st := gcStruct(ref)
		fieldSchema := schema.Fields[fieldIdx]
		signed := gcFieldReadDefault
		if subOp == wazevoapi.GCFieldOpStructGetS {
			signed = gcFieldReadSigned
		}
		s[0] = gcDecodeFieldValue(fieldSchema, st.Get(fieldIdx), signed)
	case wazevoapi.GCFieldOpStructSet:
		if ref == 0 {
			panic(wasmruntime.ErrRuntimeNullReference)
		}
		st := gcStruct(ref)
		fieldSchema := schema.Fields[fieldIdx]
		if err := st.Set(fieldIdx, gcEncodeFieldValue(fieldSchema, value)); err != nil {
			panic(err)
		}
		s[0] = 0
	case wazevoapi.GCFieldOpArrayGet, wazevoapi.GCFieldOpArrayGetS, wazevoapi.GCFieldOpArrayGetU:
		if ref == 0 {
			panic(wasmruntime.ErrRuntimeNullReference)
		}
		a := gcArray(ref)
		idx := uint32(fieldIdx)
		if idx >= a.Len() {
			panic(wasmruntime.ErrRuntimeOutOfBoundsMemoryAccess)
		}
		signed := gcFieldReadDefault
		if subOp == wazevoapi.GCFieldOpArrayGetS {
			signed = gcFieldReadSigned
		}
		s[0] = gcDecodeFieldValue(schema.ArrayField, a.Get(idx), signed)
	case wazevoapi.GCFieldOpArraySet:
		if ref == 0 {
			panic(wasmruntime.ErrRuntimeNullReference)
		}
		a := gcArray(ref)
		idx := uint32(fieldIdx)
		if idx >= a.Len() {
			panic(wasmruntime.ErrRuntimeOutOfBoundsMemoryAccess)
		}
		if err := a.Set(idx, gcEncodeFieldValue(schema.ArrayField, value)); err != nil {
			panic(err)
		}
		s[0] = 0
	default:
		panic("BUG: unknown GCFieldOp sub-opcode")
	}
}

// handleGCArrayBulk handles ExitCodeGCArrayBulk — bulk array operations.
// All params come from the scratch buffer.
func (c *callEngine) handleGCArrayBulk() {
	s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
	subOp := int(s[0])
	mod := c.callerModuleInstance()
	scratch := &c.execCtx.gcScratchBuffer

	switch subOp {
	case wazevoapi.GCArrayBulkFill:
		ref := scratch[0]
		typeIdx := uint32(scratch[1])
		idx := uint32(scratch[2])
		rawVal := scratch[3]
		count := uint32(scratch[4])
		if ref == 0 {
			panic(wasmruntime.ErrRuntimeNullReference)
		}
		a := gcArray(ref)
		if uint64(idx)+uint64(count) > uint64(a.Len()) {
			panic(wasmruntime.ErrRuntimeOutOfBoundsMemoryAccess)
		}
		schema := mod.Source.TypeSection[typeIdx].ArrayField
		stored := gcEncodeFieldValue(schema, rawVal)
		for i := uint32(0); i < count; i++ {
			if err := a.Set(idx+i, stored); err != nil {
				panic(err)
			}
		}
	case wazevoapi.GCArrayBulkCopy:
		dstRef := scratch[0]
		dstIdx := uint32(scratch[1])
		srcRef := scratch[2]
		srcIdx := uint32(scratch[3])
		count := uint32(scratch[4])
		if srcRef == 0 || dstRef == 0 {
			panic(wasmruntime.ErrRuntimeNullReference)
		}
		src := gcArray(srcRef)
		dst := gcArray(dstRef)
		if uint64(srcIdx)+uint64(count) > uint64(src.Len()) ||
			uint64(dstIdx)+uint64(count) > uint64(dst.Len()) {
			panic(wasmruntime.ErrRuntimeOutOfBoundsMemoryAccess)
		}
		if src == dst && srcIdx < dstIdx {
			for i := count; i > 0; i-- {
				if err := dst.Set(dstIdx+i-1, src.Get(srcIdx+i-1)); err != nil {
					panic(err)
				}
			}
		} else {
			for i := uint32(0); i < count; i++ {
				if err := dst.Set(dstIdx+i, src.Get(srcIdx+i)); err != nil {
					panic(err)
				}
			}
		}
	case wazevoapi.GCArrayBulkInitData:
		ref := scratch[0]
		typeIdx := uint32(scratch[1])
		segIdx := uint32(scratch[2])
		dstOff := uint32(scratch[3])
		srcOff := uint32(scratch[4])
		count := uint32(scratch[5])
		if ref == 0 {
			panic(wasmruntime.ErrRuntimeNullReference)
		}
		a := gcArray(ref)
		schema := mod.Source.TypeSection[typeIdx].ArrayField
		data := mod.DataInstances[segIdx]
		elemSize, ok := gcArrayDataElemSize(schema)
		if !ok {
			panic(fmt.Errorf("array.init_data on unsupported element type"))
		}
		if uint64(dstOff)+uint64(count) > uint64(a.Len()) ||
			uint64(srcOff)+uint64(count)*uint64(elemSize) > uint64(len(data)) {
			panic(wasmruntime.ErrRuntimeOutOfBoundsMemoryAccess)
		}
		for i := uint32(0); i < count; i++ {
			off := srcOff + i*elemSize
			v := gcReadDataElement(schema, data, off)
			if err := a.Set(dstOff+i, v); err != nil {
				panic(err)
			}
		}
	case wazevoapi.GCArrayBulkInitElem:
		ref := scratch[0]
		typeIdx := uint32(scratch[1])
		segIdx := uint32(scratch[2])
		dstOff := uint32(scratch[3])
		srcOff := uint32(scratch[4])
		count := uint32(scratch[5])
		if ref == 0 {
			panic(wasmruntime.ErrRuntimeNullReference)
		}
		a := gcArray(ref)
		elem := mod.ElementInstances[segIdx]
		if uint64(dstOff)+uint64(count) > uint64(a.Len()) {
			panic(wasmruntime.ErrRuntimeOutOfBoundsMemoryAccess)
		}
		if uint64(srcOff)+uint64(count) > uint64(len(elem)) {
			panic(wasmruntime.ErrRuntimeInvalidTableAccess)
		}
		schema := mod.Source.TypeSection[typeIdx].ArrayField
		for i := uint32(0); i < count; i++ {
			if err := a.Set(dstOff+i, gcEncodeFieldValue(schema, uint64(elem[srcOff+i]))); err != nil {
				panic(err)
			}
		}
	default:
		panic("BUG: unknown GCArrayBulk sub-opcode")
	}
}

// handleGCRefCast handles ExitCodeGCRefCast — runtime type checks.
func (c *callEngine) handleGCRefCast() {
	s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
	subOp := int(s[0])
	ref := s[1]
	kindByte := byte(s[2])
	typeIdx := uint32(s[3])
	mod := c.callerModuleInstance()

	// Encode nullable + isConcrete into the kindByte as passed from the frontend.
	// The frontend packs: kindByte in bits 0-7, nullable in bit 8, isConcrete in bit 9.
	nullable := (s[2] >> 8 & 1) != 0
	isConcrete := (s[2] >> 9 & 1) != 0

	matches := gcRefMatches(ref, kindByte, nullable, isConcrete, typeIdx, mod)

	switch subOp {
	case wazevoapi.GCRefCastRefTest, wazevoapi.GCRefCastRefTestNull:
		if matches {
			s[0] = 1
		} else {
			s[0] = 0
		}
	case wazevoapi.GCRefCastRefCast, wazevoapi.GCRefCastRefCastNull:
		if !matches {
			panic(wasmruntime.ErrRuntimeInvalidConversionToInteger)
		}
		s[0] = ref
	default:
		panic("BUG: unknown GCRefCast sub-opcode")
	}
}

func gcArrayDataElemSize(f wasm.FieldType) (uint32, bool) {
	switch f.Kind() {
	case wasm.ValueTypeI8.Kind():
		return 1, true
	case wasm.ValueTypeI16.Kind():
		return 2, true
	}
	switch f.AsImmutable() {
	case wasm.ValueTypeI32, wasm.ValueTypeF32:
		return 4, true
	case wasm.ValueTypeI64, wasm.ValueTypeF64:
		return 8, true
	case wasm.ValueTypeV128:
		return 16, true
	}
	return 0, false
}

func gcReadDataElement(f wasm.FieldType, data []byte, off uint32) any {
	switch f.Kind() {
	case wasm.ValueTypeI8.Kind():
		return uint8(data[off])
	case wasm.ValueTypeI16.Kind():
		return binary.LittleEndian.Uint16(data[off:])
	}
	switch f.AsImmutable() {
	case wasm.ValueTypeI32:
		return int32(binary.LittleEndian.Uint32(data[off:]))
	case wasm.ValueTypeI64:
		return int64(binary.LittleEndian.Uint64(data[off:]))
	case wasm.ValueTypeF32:
		return math.Float32frombits(binary.LittleEndian.Uint32(data[off:]))
	case wasm.ValueTypeF64:
		return math.Float64frombits(binary.LittleEndian.Uint64(data[off:]))
	}
	panic(fmt.Sprintf("unsupported element type for array.new_data: %#x", f.Kind()))
}
