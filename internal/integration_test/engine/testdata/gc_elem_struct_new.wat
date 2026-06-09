(module
  (rec
    (type $point (struct (field (mut i32)) (field (mut i32))))
    (type $fn (func (result (ref null $point))))
  )

  (table 2 (ref null $point))

  ;; Element segment with struct.new in a const expression.
  ;; This exercises the const expression evaluator's ability to pop
  ;; the right number of fields for struct.new during validation.
  (elem (table 0) (i32.const 0) (ref null $point)
    (item struct.new_default $point)
    (item i32.const 10 i32.const 20 struct.new $point)
  )

  (func (export "get_x") (result i32)
    i32.const 1
    table.get 0
    struct.get $point 0
  )
)
