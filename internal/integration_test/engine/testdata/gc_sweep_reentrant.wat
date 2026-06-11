(module
  (type $s (struct (field i32)))

  ;; Host function that will call back into wasm, triggering a nested
  ;; Call() whose GCSweep scans only the inner stack.
  (import "host" "callback" (func $callback))

  ;; Trivial export called by the host callback to create a re-entrant call.
  (func (export "nop"))

  ;; Main test: allocate a struct, store in a local, call the host
  ;; callback (which re-enters wasm and triggers GCSweep on its inner
  ;; stack), then read the struct. If GCSweep incorrectly removed the
  ;; struct from GCRoots during the inner call, Go's GC may have
  ;; collected it, and this read returns garbage or traps.
  (func (export "test") (result i32)
    (local $s (ref null $s))
    (local.set $s (struct.new $s (i32.const 42)))
    (call $callback)
    (struct.get $s 0 (local.get $s))))
