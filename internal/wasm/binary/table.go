package binary

import (
	"bytes"
	"fmt"

	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/internal/leb128"
	"github.com/tetratelabs/wazero/internal/wasm"
)

// decodeTable returns the wasm.Table decoded with the WebAssembly 1.0 (20191205) Binary Format.
//
// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#binary-table
func decodeTable(r *bytes.Reader, enabledFeatures api.CoreFeatures, ret *wasm.Table) (err error) {
	b, err := r.ReadByte()
	if err != nil {
		return fmt.Errorf("read leading byte: %v", err)
	}

	hasInitExpr := false
	if b == 0x40 {
		// Table with initializer expression: 0x40 0x00 tabletype expr
		reserved, err := r.ReadByte()
		if err != nil {
			return fmt.Errorf("read reserved byte after 0x40: %v", err)
		}
		if reserved != 0x00 {
			return fmt.Errorf("expected 0x00 after 0x40 table prefix, got 0x%02x", reserved)
		}
		hasInitExpr = true
		b, err = r.ReadByte()
		if err != nil {
			return fmt.Errorf("read table ref type: %v", err)
		}
	}

	switch b {
	case wasm.RefPrefixNullable, wasm.RefPrefixNonNullable:
		nullable := b == wasm.RefPrefixNullable
		ht, _, err := leb128.DecodeInt33AsInt64(r)
		if err != nil {
			return fmt.Errorf("read table ref heap type: %v", err)
		}
		switch ht {
		case wasm.HeapTypeFunc:
			ret.Type = wasm.ValueTypeFuncref
		case wasm.HeapTypeExtern:
			ret.Type = wasm.ValueTypeExternref
		case wasm.HeapTypeExn:
			ret.Type = wasm.ValueTypeExnref
		default:
			if ht < 0 {
				return fmt.Errorf("unknown abstract heap type for table: %d", ht)
			}
			ret.Type = wasm.ValueTypeConcreteRef(uint32(ht), nullable)
		}
		if !nullable {
			ret.Type = ret.Type.AsNonNullable()
		}
	default:
		ret.Type = wasm.ValueType(b)
	}

	if ret.Type != wasm.RefTypeFuncref {
		if err = enabledFeatures.RequireEnabled(api.CoreFeatureReferenceTypes); err != nil {
			return fmt.Errorf("table type funcref is invalid: %w", err)
		}
	}

	var shared bool
	ret.Min, ret.Max, shared, err = decodeLimitsType(r)
	if err != nil {
		return fmt.Errorf("read limits: %v", err)
	}
	if ret.Min > wasm.MaximumFunctionIndex {
		return fmt.Errorf("table min must be at most %d", wasm.MaximumFunctionIndex)
	}
	if ret.Max != nil {
		if *ret.Max < ret.Min {
			return fmt.Errorf("table size minimum must not be greater than maximum")
		}
	}
	if shared {
		return fmt.Errorf("tables cannot be marked as shared")
	}

	if hasInitExpr {
		var initExpr wasm.ConstantExpression
		if err := decodeConstantExpression(r, enabledFeatures, &initExpr); err != nil {
			return fmt.Errorf("read table init expr: %v", err)
		}
		ret.InitExpr = &initExpr
	}
	return
}
