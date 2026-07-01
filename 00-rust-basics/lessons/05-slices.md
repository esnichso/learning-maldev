# Lesson 05 — Slices

## What you learned

### What a slice is

A slice `&[T]` is a **view** into a contiguous block of memory. It does not own the data — it just describes where the data lives and how many elements there are.

Internally it's a **fat pointer**: two words of memory.
1. A pointer to the first element
2. The number of elements (the length)

```
&[u8] layout in memory:
┌──────────────┬────────┐
│  *const u8   │  usize │
│  (address)   │  (len) │
└──────────────┴────────┘
```

### Creating slices

```rust
let arr = [0x90u8, 0x90, 0x48, 0x31, 0xc0]; // array — fixed size, lives on stack
let slice: &[u8] = &arr;                      // slice of the whole array
let part:  &[u8] = &arr[1..3];               // slice of elements 1 and 2 (not 3)
```

Slice ranges: `start..end` is exclusive on the right (does not include `end`).

### Working with slices

```rust
let sc: &[u8] = &[0xfc, 0xe8, 0x90, 0x90];

sc.len()          // number of elements: 4
sc[0]             // first element: 0xfc  (panics if out of bounds)
sc.get(0)         // returns Option<&u8> — safe indexing, never panics
sc.is_empty()     // true if len == 0
sc.first()        // Option<&u8> — first element or None
sc.iter()         // iterator over &u8 references
sc.as_ptr()       // *const u8 raw pointer to first element
```

### Iterating

```rust
// By index — explicit, C-style
for i in 0..sc.len() {
    println!("byte {i}: 0x{:02x}", sc[i]);
}

// By element — idiomatic Rust, preferred
for byte in sc {
    println!("byte: 0x{byte:02x}");
}

// Iterator chain
let nop_count = sc.iter().filter(|&&b| b == 0x90).count();
```

The double `&&` in `|&&b|` is a pattern: `.iter()` yields `&u8` references, and the closure pattern `&&b` destructures through both the reference from the iterator (`&`) and the reference in the element (`&`) to bind `b` directly as `u8`.

### Maldev connection

Shellcode is always `&[u8]`. You need `.len()` to pass the size to `VirtualAlloc` and `.as_ptr()` to pass the address to `ptr::copy_nonoverlapping`:

```rust
let shellcode: &[u8] = &[0xfc, 0xe8, ...];

let alloc = VirtualAlloc(None, shellcode.len(), ...);
ptr::copy_nonoverlapping(
    shellcode.as_ptr(),           // *const u8 source
    alloc as *mut u8,             // *mut u8 destination
    shellcode.len(),              // byte count
);
```

## Key rules

- `&[T]` is a borrowed view — fat pointer (address + length).
- Does not own the data; lives only as long as the source array/vec lives.
- Index with `[i]` (panics on OOB) or `.get(i)` (returns Option).
- `.as_ptr()` gives the raw `*const T` pointer for FFI calls.
- Ranges are exclusive on the right: `1..3` means indices 1 and 2.
