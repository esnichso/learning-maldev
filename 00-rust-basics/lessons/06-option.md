# Lesson 06 — Option\<T\>

## What you learned

### Null doesn't exist in safe Rust

In C, any pointer can be NULL. There's no way to tell from a function's type signature whether it might return NULL — you just have to know to check. Forgotten null checks are a major source of crashes.

In safe Rust, there are no null references. Instead, "this might be absent" is encoded in the type: `Option<T>`.

```rust
// C equivalent: int* might_be_null;
// Rust:
let might_be_absent: Option<u32> = None;
let definitely_here: Option<u32> = Some(42);
```

The type system forces you to handle the absent case — the compiler will not let you use an `Option<T>` as if it were a `T` directly.

### Pattern matching

The clean way to extract the value:

```rust
match value {
    Some(n) => println!("got {n}"),
    None    => println!("was empty"),
}
```

`match` must cover all variants. If you forget `None`, the compiler errors. This is exactly what prevents forgotten null checks.

### Common shortcuts

```rust
let opt: Option<u8> = Some(0xfc);

opt.unwrap()              // extract value, PANIC if None — only for tests/prototypes
opt.expect("reason")      // same, but with a custom panic message
opt.unwrap_or(0)           // extract value, or use default 0 if None
opt.is_some()              // bool: true if Some
opt.is_none()              // bool: true if None
opt.map(|b| b as u32)      // transform the inner value if Some, pass None through
opt?                       // in functions returning Option: propagate None early (like Result's ?)
```

### The `?` operator

In a function that returns `Option<T>`, you can use `?` to short-circuit on `None`:

```rust
fn second_byte(data: &[u8]) -> Option<u8> {
    let first = data.first()?; // if None, return None immediately from the function
    data.get(1).copied()       // return the second element
}
```

### Maldev connection

Raw pointers can still be null in unsafe code. The pattern for checking them mirrors `Option`:

```rust
let alloc = unsafe { VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

if alloc.is_null() {
    // handle failure
}
```

Some `windows` crate APIs return `Option<HANDLE>` or `windows::core::Result<T>` instead of a raw nullable pointer, giving you the type-safe version of this check. Knowing `Option` means you already understand the pattern.

## Key rules

- `Option<T>` = `Some(value)` or `None`. Never null.
- The compiler forces you to handle both cases before using the value.
- `unwrap()` extracts the value but panics on `None` — use only in tests or when you've already confirmed it's `Some`.
- `match` is the safest and most explicit way to handle `Option`.
- `?` propagates `None` upward in functions that return `Option`.
