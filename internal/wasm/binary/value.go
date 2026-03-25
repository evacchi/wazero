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
		case 0x63, 0x64:
			// GC proposal: (ref <heaptype>) or (ref null <heaptype>).
			// heaptype is an s33: negative = abstract heap type, non-negative = type index.
			ht, _, err := leb128.DecodeInt33AsInt64(r)
			if err != nil {
				return nil, fmt.Errorf("read ref heap type: %w", err)
			}
			// Map to existing value types for interpreter-level representation.
			switch ht {
			case -23: // 0x69 = exn
				ret = append(ret, wasm.ValueTypeExnref)
			case -16: // 0x70 = func
				ret = append(ret, wasm.ValueTypeFuncref)
			case -17: // 0x6f = extern
				ret = append(ret, wasm.ValueTypeExternref)
			default:
				// Concrete type index or other abstract type — treat as funcref.
				ret = append(ret, wasm.ValueTypeFuncref)
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
