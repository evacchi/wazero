;; Regression test for a wazevo bug where ShadowFrameEnter shared one address
;; mode between the load and the store of execCtx.shadowRefsTop. The register
;; allocator rewrote the shared base register when allocating the load, so the
;; store no longer counted as a use of the execution context, and under register
;; pressure the counter was allocated to the same register: the store then went
;; through the counter value instead of the execution context.
;;
;; $many takes 26 params to exhaust the argument registers, so most arrive on
;; the stack and stay live across the entry block. It holds no exnref; it gets a
;; shadow frame only because offset=31 encodes the try_table opcode byte (0x1f),
;; which the frame gate searches for in modules that declare a tag.
(module
  (tag $t)
  (memory 1)

  (func $alloc (param i32) (result i32) (i32.const 1024))

  (func $many (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
    (local i32)
    i32.const 26
    call $alloc
    local.set 26
    local.get 26
    local.get 0
    i32.store8 offset=16
    local.get 26
    local.get 1
    i32.store8 offset=17
    local.get 26
    local.get 2
    i32.store8 offset=18
    local.get 26
    local.get 3
    i32.store8 offset=19
    local.get 26
    local.get 4
    i32.store8 offset=20
    local.get 26
    local.get 5
    i32.store8 offset=21
    local.get 26
    local.get 6
    i32.store8 offset=22
    local.get 26
    local.get 7
    i32.store8 offset=23
    local.get 26
    local.get 8
    i32.store8 offset=24
    local.get 26
    local.get 9
    i32.store8 offset=25
    local.get 26
    local.get 10
    i32.store8 offset=26
    local.get 26
    local.get 11
    i32.store8 offset=27
    local.get 26
    local.get 12
    i32.store8 offset=28
    local.get 26
    local.get 13
    i32.store8 offset=29
    local.get 26
    local.get 14
    i32.store8 offset=30
    local.get 26
    local.get 15
    i32.store8 offset=31
    local.get 26
    local.get 16
    i32.store8 offset=32
    local.get 26
    local.get 17
    i32.store8 offset=33
    local.get 26
    local.get 18
    i32.store8 offset=34
    local.get 26
    local.get 19
    i32.store8 offset=35
    local.get 26
    local.get 20
    i32.store8 offset=36
    local.get 26
    local.get 21
    i32.store8 offset=37
    local.get 26
    local.get 22
    i32.store8 offset=38
    local.get 26
    local.get 23
    i32.store8 offset=39
    local.get 26
    local.get 24
    i32.store8 offset=40
    local.get 26
    local.get 25
    i32.store8 offset=41
    local.get 26)

  (func (export "entry") (result i32)
    (call $many (i32.const 1) (i32.const 2) (i32.const 3) (i32.const 4) (i32.const 5) (i32.const 6) (i32.const 7) (i32.const 8) (i32.const 9) (i32.const 10) (i32.const 11) (i32.const 12) (i32.const 13) (i32.const 14) (i32.const 15) (i32.const 16) (i32.const 17) (i32.const 18) (i32.const 19) (i32.const 20) (i32.const 21) (i32.const 22) (i32.const 23) (i32.const 24) (i32.const 25) (i32.const 26))
    i32.load8_u offset=41)
)
