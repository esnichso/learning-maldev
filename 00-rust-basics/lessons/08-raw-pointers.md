# Lesson 08 — Raw Pointers

## What you learned

### What raw pointers are

`*const T` and `*mut T` are Rust's equivalent of C's `const T*` and `T*`. They are memory addresses with no safety guarantees — the compiler does not track their validity, lifetimes, or aliasing.

```rust
let x: u32 = 42;
let ptr: *const u32 = &x;     // immutable raw pointer
let mut y: u32 = 99;
let ptr_mut: *mut u32 = &mut y; // mutable raw pointer
```

### Creating a raw pointer is safe. Using it is not.

The *creation* of a raw pointer is always safe — you're just recording an address. The *dereference* (reading or writing the value at that address) is `unsafe` because:
- The pointer might be null
- The pointer might be dangling (pointing to freed memory)
- Multiple `*mut` pointers might alias the same location

```rust
// Safe — just takes the address
let ptr: *mut u8 = buffer.as_mut_ptr();

// Unsafe — reads/writes through the pointer
unsafe {
    *ptr = 0xAB;        // write
    let v = *ptr;       // read
}
```

### Pointer arithmetic

`.add(n)` advances a pointer by `n` elements (not bytes — by elements of type T):

```rust
let arr = [10u8, 20, 30, 40];
let p = arr.as_ptr();   // *const u8, points at arr[0]

unsafe {
    let a = *p;          // 10 — arr[0]
    let b = *p.add(1);   // 20 — arr[1]
    let c = *p.add(3);   // 40 — arr[3]
}
```

For `*const u8` / `*mut u8`, `.add(1)` moves 1 byte forward. For `*const u32`, `.add(1)` moves 4 bytes forward. The type determines the step size.

### Casting between pointer types

Win32 APIs use `*mut c_void` (a void pointer — no type information). You must cast to a typed pointer before you can read bytes through it:

```rust
use core::ffi::c_void;

let raw: *mut c_void = /* VirtualAlloc result */;

// Cast to *mut u8 so you can copy bytes into it
let byte_ptr: *mut u8 = raw as *mut u8;

unsafe {
    ptr::copy_nonoverlapping(src.as_ptr(), byte_ptr, src.len());
}
```

### Null check

```rust
if ptr.is_null() {
    // handle error
}
```

Always check raw pointers from Win32 APIs before using them.

### Array initialization syntax

```rust
let buffer = [0u8; 8];
//            ^^^  ^
//            |    └── count: 8 elements
//            └─────── initial value: 0, type u8
// Result: [0, 0, 0, 0, 0, 0, 0, 0]
```

The `0u8` suffix means "integer literal 0 with type u8". You could also write `[0_u8; 8]` — the underscore is a visual separator.

### Maldev connection

Almost every Win32 memory API works with raw pointers:

```rust
// VirtualAlloc returns *mut c_void
let mem = VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

// Copy shellcode in
ptr::copy_nonoverlapping(shellcode.as_ptr(), mem as *mut u8, shellcode.len());

// Change permissions
VirtualProtect(mem, size, PAGE_EXECUTE_READ, &mut old);

// Execute — transmute *mut c_void into a function pointer (ex09)
let f: unsafe extern "system" fn() = transmute(mem);
f();
```

Every step involves raw pointer casts. Getting the types right is most of the work.

## Key rules

- `*const T` = read-only raw pointer. `*mut T` = read-write raw pointer.
- Creating a raw pointer is safe. Dereferencing requires `unsafe`.
- `.add(n)` = pointer arithmetic, moves by n elements of type T.
- `.is_null()` checks for null — always check pointers from external APIs.
- Cast with `as`: `ptr as *mut u8`, `ptr as *const c_void`, etc.
- `[value; count]` initializes an array of `count` elements all set to `value`.
