(module
  (type $fn (func (result i32)))
  (type $holder (struct (field (mut funcref))))

  (func $f (type $fn) (i32.const 42))

  ;; Declare $f so ref.func is valid.
  (elem declare funcref (ref.func $f))

  (func (export "test") (result i32)
    (struct.new $holder (ref.func $f))
    (struct.get $holder 0)
    (ref.cast (ref $fn))
    (call_ref $fn)
  )
)
