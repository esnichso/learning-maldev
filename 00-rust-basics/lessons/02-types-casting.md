# Lesson 02 — Types & Casting

## What you learned

### Rust never converts between numeric types silently

In C, assigning a `uint64_t` to a `uint32_t` just truncates — no warning, no error, silent data loss. Rust refuses. Every conversion between numeric types must be written explicitly.

```rust
let a: usize = 1024;
let b: u32   = a;         // ERROR: mismatched types
let b: u32   = a as u32;  // OK — explicit cast
```

This catches a huge category of bugs where you pass the wrong width to a Win32 API.

### The numeric types

| Type | Size | Range | Notes |
|------|------|-------|-------|
| `u8` | 1 byte | 0..=255 | raw byte, shellcode element |
| `i8` | 1 byte | -128..=127 | |
| `u32` | 4 bytes | 0..=4 billion | most Win32 flags and sizes |
| `i32` | 4 bytes | ±2 billion | signed, some API return codes |
| `u64` | 8 bytes | 0..=18e18 | handles, addresses on x64 |
| `i64` | 8 bytes | ±9e18 | |
| `usize` | pointer-sized | platform-dependent | memory sizes, indices |
| `isize` | pointer-sized | platform-dependent | signed pointer arithmetic |

On x64 Windows, `usize` = 8 bytes. On x86, it would be 4 bytes.

### Casting with `as`

`as` performs the conversion. It never fails — but it can truncate or wrap:

```rust
let big: u64 = 300;
let small: u8 = big as u8;  // 300 % 256 = 44 — wraps, no panic
```

If you need a *checked* conversion that returns an error on overflow, use `.try_into()` from the standard library.

### Maldev connection

Win32 APIs are extremely strict about parameter widths. For example:

```rust
VirtualAlloc(
    None,
    shellcode.len(),               // usize — correct
    MEM_COMMIT | MEM_RESERVE,      // VIRTUAL_ALLOCATION_TYPE (wraps u32)
    PAGE_READWRITE,                // PAGE_PROTECTION_FLAGS (wraps u32)
)
```

`shellcode.len()` returns `usize`. The API expects `usize` for the size parameter — a match. If you tried to pass a `u32` there you'd get a type error and have to cast. Getting these widths right is one of the most common sources of friction when porting C malware to Rust.

## Key rules

- No implicit numeric conversions. Use `as` for explicit casts.
- `as` wraps on overflow — it never panics.
- Use `usize` for sizes and indices; `u32`/`u64` for Win32 values.
- `.try_into()` for safe conversions that can signal overflow.
