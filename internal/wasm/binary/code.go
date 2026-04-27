package binary

import (
	"bytes"
	"fmt"
	"io"
	"math"

	"github.com/tetratelabs/wazero/internal/leb128"
	"github.com/tetratelabs/wazero/internal/wasm"
)

func decodeCode(r *bytes.Reader, codeSectionStart uint64, ret *wasm.Code) (err error) {
	ss, _, err := leb128.DecodeUint32(r)
	if err != nil {
		return fmt.Errorf("get the size of code: %w", err)
	}
	remaining := int64(ss)

	// Parse #locals.
	ls, bytesRead, err := leb128.DecodeUint32(r)
	remaining -= int64(bytesRead)
	if err != nil {
		return fmt.Errorf("get the size locals: %v", err)
	} else if remaining < 0 {
		return io.EOF
	}

	// Validate the locals.
	bytesRead = 0
	var sum uint64
	for i := uint32(0); i < ls; i++ {
		num, n, err := leb128.DecodeUint32(r)
		if err != nil {
			return fmt.Errorf("read n of locals: %v", err)
		} else if remaining < 0 {
			return io.EOF
		}

		sum += uint64(num)

		b, err := r.ReadByte()
		if err != nil {
			return fmt.Errorf("read type of local: %v", err)
		}

		bytesRead += n + 1
		switch b {
		case wasm.ValueTypeI32.Kind(), wasm.ValueTypeF32.Kind(), wasm.ValueTypeI64.Kind(), wasm.ValueTypeF64.Kind(),
			wasm.ValueTypeFuncref.Kind(), wasm.ValueTypeExternref.Kind(), wasm.ValueTypeV128.Kind(),
			wasm.ValueTypeExnref.Kind():
		case wasm.RefPrefixNullable, wasm.RefPrefixNonNullable:
			// Read and skip the heap type.
			_, htNum, err := leb128.DecodeInt33AsInt64(r)
			if err != nil {
				return fmt.Errorf("read local ref heap type: %v", err)
			}
			bytesRead += htNum
		default:
			return fmt.Errorf("invalid local type: 0x%x", b)
		}
	}

	if sum > math.MaxUint32 {
		return fmt.Errorf("too many locals: %d", sum)
	}

	// Rewind the buffer.
	_, err = r.Seek(-int64(bytesRead), io.SeekCurrent)
	if err != nil {
		return err
	}

	localTypes := make([]wasm.ValueType, 0, sum)
	for i := uint32(0); i < ls; i++ {
		num, bytesRead, err := leb128.DecodeUint32(r)
		remaining -= int64(bytesRead) + 1 // +1 for the subsequent ReadByte
		if err != nil {
			return fmt.Errorf("read n of locals: %v", err)
		} else if remaining < 0 {
			return io.EOF
		}

		b, err := r.ReadByte()
		if err != nil {
			return fmt.Errorf("read type of local: %v", err)
		}

		var vt wasm.ValueType
		switch b {
		case wasm.RefPrefixNullable, wasm.RefPrefixNonNullable:
			nullable := b == wasm.RefPrefixNullable
			ht, htNum, err := leb128.DecodeInt33AsInt64(r)
			if err != nil {
				return fmt.Errorf("read local ref heap type: %v", err)
			}
			remaining -= int64(htNum)
			switch ht {
			case wasm.HeapTypeFunc:
				vt = wasm.ValueTypeFuncref
			case wasm.HeapTypeExtern:
				vt = wasm.ValueTypeExternref
			case wasm.HeapTypeExn:
				vt = wasm.ValueTypeExnref
			default:
				vt = wasm.ConcreteRef(uint32(ht), nullable)
			}
			if !nullable {
				vt = vt.AsNonNullable()
			}
		default:
			vt = wasm.ValueType(b)
		}

		for j := uint32(0); j < num; j++ {
			localTypes = append(localTypes, vt)
		}
	}

	bodyOffsetInCodeSection := codeSectionStart - uint64(r.Len())
	body := make([]byte, remaining)
	if _, err = io.ReadFull(r, body); err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	if endIndex := len(body) - 1; endIndex < 0 || body[endIndex] != wasm.OpcodeEnd {
		return fmt.Errorf("expr not end with OpcodeEnd")
	}

	ret.BodyOffsetInCodeSection = bodyOffsetInCodeSection
	ret.LocalTypes = localTypes
	ret.Body = body
	return nil
}
