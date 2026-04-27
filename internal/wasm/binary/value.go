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
		case wasm.ValueTypeI32.Kind(), wasm.ValueTypeF32.Kind(), wasm.ValueTypeI64.Kind(), wasm.ValueTypeF64.Kind(),
			wasm.ValueTypeExternref.Kind(), wasm.ValueTypeFuncref.Kind(), wasm.ValueTypeV128.Kind(),
			wasm.ValueTypeExnref.Kind():
			ret = append(ret, wasm.ValueType(b))
		case wasm.RefPrefixNullable, wasm.RefPrefixNonNullable:
			nullable := b == wasm.RefPrefixNullable
			ht, _, err := leb128.DecodeInt33AsInt64(r)
			if err != nil {
				return nil, fmt.Errorf("read ref heap type: %w", err)
			}
			switch ht {
			case wasm.HeapTypeExn:
				v := wasm.ValueTypeExnref
				if !nullable {
					v = v.AsNonNullable()
				}
				ret = append(ret, v)
			case wasm.HeapTypeFunc:
				v := wasm.ValueTypeFuncref
				if !nullable {
					v = v.AsNonNullable()
				}
				ret = append(ret, v)
			case wasm.HeapTypeExtern:
				v := wasm.ValueTypeExternref
				if !nullable {
					v = v.AsNonNullable()
				}
				ret = append(ret, v)
			default:
				if ht < 0 {
					return nil, fmt.Errorf("unknown abstract heap type: %d", ht)
				}
				ret = append(ret, wasm.ConcreteRef(uint32(ht), nullable))
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
