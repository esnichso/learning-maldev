# Lesson 09 — unsafe & transmute

## What you learned

### What `unsafe` means

`unsafe` is not "dangerous code" — it's a contract. It tells the compiler: "I've checked the invariants you can't verify; trust me here." Rust still compiles and runs the code; it just stops guaranteeing memory safety within the block.

`unsafe` unlocks exactly four capabilities:

1. **Dereference raw pointers** (`*ptr`)
2. **Call `unsafe` functions** — all Win32 FFI, and functions explicitly marked `unsafe fn`
3. **Read/write mutable statics** (`static mut`)
4. **Implement `unsafe` traits**

Everything else in Rust remains fully checked even inside an `unsafe` block. The borrow checker, type checker, and the rest of the compiler still apply.

### Minimise unsafe scope

The smaller your `unsafe` block, the easier it is to reason about correctness. Don't wrap an entire function in `unsafe` when only one line needs it:

```rust
// Bad — entire function is unchecked
unsafe fn do_thing(ptr: *mut u8, size: usize) {
    let v = Vec::from_raw_parts(ptr, size, size);
    process(v);  // process() is safe — no reason it needs to be in unsafe
}

// Better — only the genuinely unsafe operation is marked
fn do_thing(ptr: *mut u8, size: usize) {
    let v = unsafe { Vec::from_raw_parts(ptr, size, size) };
    process(v);
}
```

### `std::mem::transmute`

`transmute::<A, B>(value)` reinterprets the bits of `A` as `B`. It's the most powerful (and most dangerous) tool in Rust — it completely bypasses the type system.

**Requirements**: `A` and `B` must be the same size in bytes. If they're not, it's a compile-time error.

```rust
// Reinterpret 4 bytes as a u32 (little-endian)
let bytes: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
let value: u32 = unsafe { std::mem::transmute(bytes) };
// value = 1  (0x00000001 in little-endian)
```

### Turning a pointer into a function pointer

This is the critical use case for Module 01. A function pointer is just an address. `VirtualAlloc` returns `*mut c_void` — also just an address. `transmute` bridges them:

```rust
let mem: *mut c_void = unsafe { VirtualAlloc(...) };

// transmute the raw address into a callable function pointer
let f: unsafe extern "system" fn() = unsafe { std::mem::transmute(mem) };

// call the shellcode
unsafe { f() };
```

`extern "system"` specifies the **calling convention** — the contract for how arguments and return values are passed between caller and callee. On x64 Windows, `"system"` and `"C"` are identical (both use the Microsoft x64 ABI), but being explicit documents intent.

### Why transmute is dangerous

- No runtime checks. If `mem` is null, `f()` crashes.
- If the shellcode uses a different calling convention, the stack will be corrupted.
- If `A` and `B` have different alignments, you get undefined behaviour.

Always verify the pointer is non-null and the memory is executable before calling.

### Maldev connection

The full Module 01 execution step:

```rust
unsafe {
    // Verify memory was allocated
    assert!(!mem.is_null(), "VirtualAlloc failed");

    // Reinterpret the allocation address as a function pointer
    let shellcode_fn: unsafe extern "system" fn() = std::mem::transmute(mem);

    // Jump to shellcode
    shellcode_fn();
}
```

Or via `CreateThread`, which takes the same type:
```rust
CreateThread(None, 0, Some(std::mem::transmute(mem)), None, 0, None)
```

## Key rules

- `unsafe` blocks allow: pointer dereference, unsafe fn calls, mutable statics, unsafe traits.
- Everything else (types, borrows, lifetimes) is still checked inside `unsafe`.
- Keep `unsafe` blocks as small as possible — easier to audit.
- `transmute` reinterprets bits. Same size is required; validity is your responsibility.
- `extern "system"` = Windows calling convention. Required on function pointers passed to Win32 APIs.
