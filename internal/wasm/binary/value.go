package binary

import (
	"bytes"
	"fmt"
	"io"
	"unicode/utf8"
	"unsafe"

	"github.com/tetratelabs/wazero/internal/leb128"
	"github.com/tetratelabs/wazero/internal/wasm"
)

func decodeValueTypes(r *bytes.Reader, num uint32) ([]wasm.ValueType, error) {
	if num == 0 {
		return nil, nil
	}

	ret := make([]wasm.ValueType, 0, num)
	for i := uint32(0); i < num; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		switch b {
		case wasm.ValueTypeI32, wasm.ValueTypeF32, wasm.ValueTypeI64, wasm.ValueTypeF64,
			wasm.ValueTypeExternref, wasm.ValueTypeFuncref, wasm.ValueTypeV128,
			wasm.ValueTypeExnref:
			ret = append(ret, b)
		case wasm.RefPrefixNullable: // (ref null <heaptype>) — nullable.
			ht, _, err := leb128.DecodeInt33AsInt64(r)
			if err != nil {
				return nil, fmt.Errorf("read ref heap type: %w", err)
			}
			// The following nullable refs are an alternative representation of the corresponding ref types:
			// - (ref null exn) is equivalent to exnref
			// - (ref null func) is equivalent to funcref
			// - (ref null extern) is equivalent to externref
			// See https://webassembly.github.io/gc/core/syntax/types.html#reference-types
			switch ht {
			case wasm.HeapTypeExn:
				ret = append(ret, wasm.ValueTypeExnref)
			case wasm.HeapTypeFunc:
				ret = append(ret, wasm.ValueTypeFuncref)
			case wasm.HeapTypeExtern:
				ret = append(ret, wasm.ValueTypeExternref)
			default: // concrete type index — treat as nullable funcref
				ret = append(ret, wasm.ValueTypeFuncref)
			}
		case wasm.RefPrefixNonNullable: // (ref <heaptype>) — non-nullable.
			ht, _, err := leb128.DecodeInt33AsInt64(r)
			if err != nil {
				return nil, fmt.Errorf("read ref heap type: %w", err)
			}
			// The following non-nullable refs do not have alternative representations:
			// - (ref exn) is a non-nullable exnref (currently desugared into a nullable exnref)
			// - (ref func) is a non-nullable funcref
			// - (ref extern) is a non-nullable externref (unsupported)
			// See https://webassembly.github.io/gc/core/syntax/types.html#reference-types
			switch ht {
			case wasm.HeapTypeExn:
				ret = append(ret, wasm.ValueTypeExnref)
			case wasm.HeapTypeFunc:
				ret = append(ret, wasm.ValueTypeNonNullFuncref)
			case wasm.HeapTypeExtern:
				return nil, fmt.Errorf("unsupported non-nullable ref heap type: extern")
			default: // concrete type index — treat as non-nullable funcref
				ret = append(ret, wasm.ValueTypeNonNullFuncref)
			}
		default:
			return nil, fmt.Errorf("invalid value type: %d", b)
		}
	}
	return ret, nil
}

// decodeUTF8 decodes a size prefixed string from the reader, returning it and the count of bytes read.
// contextFormat and contextArgs apply an error format when present
func decodeUTF8(r *bytes.Reader, contextFormat string, contextArgs ...interface{}) (string, uint32, error) {
	size, sizeOfSize, err := leb128.DecodeUint32(r)
	if err != nil {
		return "", 0, fmt.Errorf("failed to read %s size: %w", fmt.Sprintf(contextFormat, contextArgs...), err)
	}

	if size == 0 {
		return "", uint32(sizeOfSize), nil
	}

	buf := make([]byte, size)
	if _, err = io.ReadFull(r, buf); err != nil {
		return "", 0, fmt.Errorf("failed to read %s: %w", fmt.Sprintf(contextFormat, contextArgs...), err)
	}

	if !utf8.Valid(buf) {
		return "", 0, fmt.Errorf("%s is not valid UTF-8", fmt.Sprintf(contextFormat, contextArgs...))
	}

	ret := unsafe.String(&buf[0], int(size))
	return ret, size + uint32(sizeOfSize), nil
}
