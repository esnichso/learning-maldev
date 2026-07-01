# Lesson 10 — Structs

## What you learned

### Defining a struct

A struct groups named fields into a single type:

```rust
struct Region {
    base:    *mut u8,
    size:    usize,
    protect: u32,
}
```

Create an instance by naming each field:

```rust
let r = Region {
    base:    std::ptr::null_mut(),
    size:    4096,
    protect: 0x20,
};
```

Access fields with `.`:

```rust
println!("size: {}", r.size);
println!("protect: 0x{:02x}", r.protect);
```

### Methods with `impl`

Methods are functions attached to a type, defined in an `impl` block:

```rust
impl Region {
    // &self = immutable reference to the instance
    fn is_executable(&self) -> bool {
        self.protect == 0x20 || self.protect == 0x40
    }

    // &mut self = mutable reference — can modify the instance
    fn set_protect(&mut self, flags: u32) {
        self.protect = flags;
    }
}
```

- `&self` — read-only access to the instance's fields. Call with `r.is_executable()`.
- `&mut self` — read-write access. Requires `let mut r = Region { ... }` at the call site.
- `self` (no `&`) — takes ownership of the instance. The value is consumed after the call.

### `#[repr(C)]` — the FFI attribute

By default, Rust may reorder struct fields and add padding differently from C. For any struct you pass across an FFI boundary (to or from a Win32 API), you must opt in to C-compatible layout:

```rust
#[repr(C)]
struct POINT {
    x: i32,
    y: i32,
}
```

Without `#[repr(C)]`, Rust might lay out the fields in a different order, add unexpected padding, or use different alignment — making the struct incompatible with the C code on the other side. The result is silent data corruption or crashes.

### Common Win32 structs

In Module 04 (process hollowing) and beyond, you'll use structs like these — all require `#[repr(C)]`:

```rust
#[repr(C)]
struct STARTUPINFOW {
    cb:          u32,
    // ... many more fields
}

#[repr(C)]
struct PROCESS_INFORMATION {
    h_process:    HANDLE,
    h_thread:     HANDLE,
    dw_process_id: u32,
    dw_thread_id:  u32,
}
```

The `windows` crate provides all the standard Win32 structs already defined with `#[repr(C)]` — you'll rarely need to define them yourself. But you need to understand the attribute to know why it's there.

### Default values

The `Default` trait provides a zero/empty initial value. Many Win32 APIs require you to zero-initialize a struct before passing it:

```rust
let mut si = STARTUPINFOW::default(); // all fields zeroed
si.cb = std::mem::size_of::<STARTUPINFOW>() as u32; // then set cb
```

You used `Default::default()` in Module 01 for `PAGE_PROTECTION_FLAGS` — same pattern.

### Maldev connection

Structs are everywhere in Win32 code. Every process creation, thread context manipulation, and memory query involves passing structs to APIs. The pattern is always:

1. Declare with `#[repr(C)]`
2. Zero-initialize with `Default::default()` or `std::mem::zeroed()`
3. Fill in required fields
4. Pass a reference (`&struct` or `&mut struct`) to the API

## Key rules

- `struct Name { field: Type, ... }` — defines the struct.
- `impl Name { fn method(&self) ... }` — attaches methods.
- `&self` = immutable access, `&mut self` = mutable access, `self` = consumes.
- `#[repr(C)]` is mandatory for any struct crossing an FFI boundary.
- `Default::default()` zero-initializes — use it for Win32 out-param structs.
