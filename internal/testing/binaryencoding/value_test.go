package binaryencoding

import (
	"testing"

	"github.com/tetratelabs/wazero/internal/testing/require"
	"github.com/tetratelabs/wazero/internal/wasm"
)

func TestEncodeValTypes(t *testing.T) {
	i32, i64, f32, f64, ext, fref := wasm.ValueTypeI32, wasm.ValueTypeI64, wasm.ValueTypeF32, wasm.ValueTypeF64, wasm.ValueTypeExternref, wasm.ValueTypeFuncref
	i32b, i64b, f32b, f64b, extb, frefb := i32.Kind(), i64.Kind(), f32.Kind(), f64.Kind(), ext.Kind(), fref.Kind()
	tests := []struct {
		name     string
		input    []wasm.ValueType
		expected []byte
	}{
		{
			name:     "empty",
			input:    []wasm.ValueType{},
			expected: []byte{0},
		},
		{
			name:     "undefined", // ensure future spec changes don't panic
			input:    []wasm.ValueType{0x6f},
			expected: []byte{1, 0x6f},
		},
		{
			name:     "funcref",
			input:    []wasm.ValueType{fref},
			expected: []byte{1, frefb},
		},
		{
			name:     "externref",
			input:    []wasm.ValueType{ext},
			expected: []byte{1, extb},
		},
		{
			name:     "i32",
			input:    []wasm.ValueType{i32},
			expected: []byte{1, i32b},
		},
		{
			name:     "i64",
			input:    []wasm.ValueType{i64},
			expected: []byte{1, i64b},
		},
		{
			name:     "f32",
			input:    []wasm.ValueType{f32},
			expected: []byte{1, f32b},
		},
		{
			name:     "f64",
			input:    []wasm.ValueType{f64},
			expected: []byte{1, f64b},
		},
		{
			name:     "i32i64",
			input:    []wasm.ValueType{i32, i64},
			expected: []byte{2, i32b, i64b},
		},
		{
			name:     "i32i64f32",
			input:    []wasm.ValueType{i32, i64, f32},
			expected: []byte{3, i32b, i64b, f32b},
		},
		{
			name:     "i32i64f32f64",
			input:    []wasm.ValueType{i32, i64, f32, f64},
			expected: []byte{4, i32b, i64b, f32b, f64b},
		},
		{
			name:     "i32i64f32f64i32",
			input:    []wasm.ValueType{i32, i64, f32, f64, i32},
			expected: []byte{5, i32b, i64b, f32b, f64b, i32b},
		},
		{
			name:     "i32i64f32f64i32i64",
			input:    []wasm.ValueType{i32, i64, f32, f64, i32, i64},
			expected: []byte{6, i32b, i64b, f32b, f64b, i32b, i64b},
		},
		{
			name:     "i32i64f32f64i32i64f32",
			input:    []wasm.ValueType{i32, i64, f32, f64, i32, i64, f32},
			expected: []byte{7, i32b, i64b, f32b, f64b, i32b, i64b, f32b},
		},
		{
			name:     "i32i64f32f64i32i64f32f64",
			input:    []wasm.ValueType{i32, i64, f32, f64, i32, i64, f32, f64},
			expected: []byte{8, i32b, i64b, f32b, f64b, i32b, i64b, f32b, f64b},
		},
		{
			name:     "i32i64f32f64i32i64f32f64i32",
			input:    []wasm.ValueType{i32, i64, f32, f64, i32, i64, f32, f64, i32},
			expected: []byte{9, i32b, i64b, f32b, f64b, i32b, i64b, f32b, f64b, i32b},
		},
		{
			name:     "i32i64f32f64i32i64f32f64i32i64",
			input:    []wasm.ValueType{i32, i64, f32, f64, i32, i64, f32, f64, i32, i64},
			expected: []byte{10, i32b, i64b, f32b, f64b, i32b, i64b, f32b, f64b, i32b, i64b},
		},
	}

	for _, tt := range tests {
		tc := tt

		t.Run(tc.name, func(t *testing.T) {
			bytes := EncodeValTypes(tc.input)
			require.Equal(t, tc.expected, bytes)
		})
	}
}
