(module
  (type $fn (func (result i32)))

  (func $f (type $fn) (i32.const 42))

  (table 1 funcref)

  ;; ref.func produces a concrete ref type (ref $fn) which is a subtype
  ;; of funcref. The element init type checker must accept this.
  (elem (table 0) (i32.const 0) funcref (ref.func $f))

  (func (export "call_indirect") (result i32)
    i32.const 0
    call_indirect (type $fn)
  )
)
