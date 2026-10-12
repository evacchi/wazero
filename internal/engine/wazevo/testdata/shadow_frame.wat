;; Exercises the shadow-frame accounting. A raise skips the epilogue of every
;; frame it unwinds, so those frames never release the slots they reserved;
;; the depth has to come back from the try_table checkpoint instead.
(module
  (tag $a (param i32))
  (tag $b)

  ;; deep recurses and then throws, so a catch above unwinds several frames.
  ;; the exnref local makes each frame reserve a slot, so an unwind that skips
  ;; the epilogues leaves them reserved.
  (func $deep (param $d i32) (local $e exnref)
    (if (i32.gt_u (local.get $d) (i32.const 0))
      (then (call $deep (i32.sub (local.get $d) (i32.const 1)))))
    (throw $b))

  ;; holds an exnref in a local across a catch, so the frame reserves slots.
  (func $catching (result i32)
    (local $x exnref)
    (block $h (result exnref)
      (try_table (catch_all_ref $h) (throw $a (i32.const 1)))
      (unreachable))
    (local.set $x)
    (block $h2
      (try_table (catch $b $h2) (call $deep (i32.const 8))))
    (i32.const 1))

  (func (export "unwind_once") (result i32)
    (call $catching))

  (func (export "unwind_many") (result i32)
    (local $i i32) (local $n i32)
    (loop $l
      (local.set $n (i32.add (local.get $n) (call $catching)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $l (i32.lt_u (local.get $i) (i32.const 100))))
    (local.get $n))

  ;; many takes more params than fit in registers on amd64 or arm64, so a
  ;; return_call to it falls back to a plain call. See internal/engine/RATIONALE.md.
  (func $many (param i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64) (result i32)
    (i32.const 1))

  ;; tail_call reserves a slot for its exnref local, then tail-calls many. On
  ;; the fallback path its frame survives the call, so it must release its
  ;; slots exactly once.
  (func $tail_call (result i32)
    (local $e exnref)
    (block $h (result exnref)
      (try_table (catch_all_ref $h) (throw $b))
      (unreachable))
    (local.set $e)
    (return_call $many (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0)))

  (func (export "tail_call_stack_args") (result i32)
    (call $tail_call))

  ;; few takes its params in registers, so a return_call to it is a real tail
  ;; call that frees the caller's frame.
  (func $few (param i64) (result i32)
    (i32.const 1))

  ;; tail_call_regs reserves a slot for its exnref local, then tail-calls few.
  ;; Its frame is gone by the time few returns, so it must release its slots
  ;; before the jump.
  (func $tail_call_regs (result i32)
    (local $e exnref)
    (block $h (result exnref)
      (try_table (catch_all_ref $h) (throw $b))
      (unreachable))
    (local.set $e)
    (return_call $few (i64.const 0)))

  (func (export "tail_call_regs") (result i32)
    (call $tail_call_regs))

  ;; take_second rethrows its second param and returns the i32 it carries.
  (func $take_second (param $x exnref) (param $y exnref) (result i32)
    (block $h (result i32)
      (try_table (catch $a $h) (throw_ref (local.get $y)))
      (unreachable)))

  ;; tail_call_overlap catches A, B and Z, one slot each, numbered downward:
  ;; A at top-1, B at top-2, Z at top-3. It drops Z and tail-calls
  ;; take_second(A, B), whose frame is one slot smaller, so take_second roots
  ;; A at top-2: over B's only root, before B itself is rooted.
  (func $tail_call_overlap (result i32)
    (block $ha (result exnref)
      (try_table (catch_all_ref $ha) (throw $a (i32.const 21)))
      (unreachable))
    (block $hb (result exnref)
      (try_table (catch_all_ref $hb) (throw $a (i32.const 22)))
      (unreachable))
    (block $hz (result exnref)
      (try_table (catch_all_ref $hz) (throw $a (i32.const 23)))
      (unreachable))
    (drop)
    (return_call $take_second))

  (func (export "tail_call_overlap") (result i32)
    (call $tail_call_overlap))
)
