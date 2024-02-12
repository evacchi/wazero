(module
  (type (;0;) (func (param f64 f64 i64)))
  (func (;0;) (type 0) (param f64 f64 i64)
    (local f32 f32 f32 f32 f32 f32 f32)
    global.get 4
    i32.eqz
    if  ;; label = @1
      unreachable
    end
    global.get 4
    i32.const 1
    i32.sub
    global.set 4
    memory.size
    f32.load offset=205086 align=1
    i64.const 2387432411842552282
    i64.eqz
    f32.load offset=205086 align=1
    f32.max
    local.tee 3
    f32.const nan (;=nan;)
    local.get 3
    local.get 3
    f32.eq
    select
    f32.abs
    f32.abs
    f32.abs
    f32.abs
    f32.abs
    f32.abs
    f32.const -0x1.a1a1ap+34 (;=-2.80268e+10;)
    f32.eq
    f32.load offset=205086 align=1
    f32.abs
    f32.abs
    f32.abs
    br 0 (;@0;)
    f32.sqrt
    local.tee 4
    f32.const nan (;=nan;)
    local.get 4
    local.get 4
    f32.eq
    select
    f32.sqrt
    local.tee 5
    f32.const nan (;=nan;)
    local.get 5
    local.get 5
    f32.eq
    select
    f32.sqrt
    local.tee 6
    f32.const nan (;=nan;)
    local.get 6
    local.get 6
    f32.eq
    select
    f32.sqrt
    local.tee 7
    f32.const nan (;=nan;)
    local.get 7
    local.get 7
    f32.eq
    select
    f32.sqrt
    local.tee 8
    f32.const nan (;=nan;)
    local.get 8
    local.get 8
    f32.eq
    select
    f32.sqrt
    local.tee 9
    f32.const nan (;=nan;)
    local.get 9
    local.get 9
    f32.eq
    select
    f32.abs
    i32.const 0
    global.get 2
    i32.xor
    global.set 2
    i32.reinterpret_f32
    global.get 3
    i32.xor
    global.set 3)
  (memory (;0;) 10 10)
  (global (;0;) f64 (f64.const 0x1.f0600fff7ff06p-880 (;=2.40533e-265;)))
  (global (;1;) (mut i64) (i64.const 4598370596298883327))
  (global (;2;) (mut i32) (i32.const 0))
  (global (;3;) (mut i32) (i32.const 0))
  (global (;4;) (mut i32) (i32.const 1000))
  (export "" (func 0))
  (export "1" (memory 0))
  (export "2" (global 0))
  (export "3" (global 1))
  (export "4" (global 2))
  (export "5" (global 3)))
