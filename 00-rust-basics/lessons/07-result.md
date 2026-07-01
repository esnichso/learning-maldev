# Lesson 07 — Result\<T, E\>

## What you learned

### Errors are values

In C, errors are typically signalled via return codes (0 / -1 / nonzero) or by setting `errno`. You can ignore them. Rust makes errors impossible to ignore at the type level: if a function can fail, it returns `Result<T, E>`, and you must deal with it before getting at the value.

```rust
// Either success with a value:
let ok:  Result<u8, String> = Ok(0xfc);
// Or failure with an error:
let err: Result<u8, String> = Err("invalid hex digit".to_string());
```

### Pattern matching

```rust
match parse_hex_byte("fc") {
    Ok(byte) => println!("parsed: 0x{byte:02x}"),
    Err(e)   => println!("failed: {e}"),
}
```

Just like `Option`, `match` on `Result` must cover both arms — the compiler ensures you never silently swallow an error.

### Common shortcuts

```rust
let res: Result<u8, String> = Ok(42);

res.unwrap()              // extract Ok value, PANIC on Err — prototypes only
res.expect("message")     // panic with a message on Err
res.unwrap_or(0)           // Ok value, or 0 if Err
res.is_ok()                // bool
res.is_err()               // bool
res.ok()                   // converts Result<T,E> → Option<T>, discards the error
res.map(|v| v as u32)      // transform the Ok value, pass Err through unchanged
res.map_err(|e| ...)       // transform the Err value, pass Ok through unchanged
```

### `map_err` and closures

`map_err` converts the error type of a `Result` without touching the success side:

```rust
// from_str_radix returns Result<u8, ParseIntError>
// We need                Result<u8, String>
u8::from_str_radix(s, 16).map_err(|e| e.to_string())
//                                 ^^^^^^^^^^^^^^^^
//                                 closure: takes ParseIntError, returns String
```

A **closure** is an anonymous function written inline:

```rust
|parameter| expression
|param1, param2| { statement; result }
```

Rust infers the types. `|e| e.to_string()` means: "take one argument `e`, call `.to_string()` on it, return the result."

### The `?` operator

In a function returning `Result`, `?` propagates errors automatically:

```rust
fn load_shellcode(path: &str) -> Result<Vec<u8>, std::io::Error> {
    let bytes = std::fs::read(path)?; // if Err, return Err immediately
    Ok(bytes)
}
```

`?` is equivalent to `match result { Ok(v) => v, Err(e) => return Err(e.into()) }`. It eliminates a lot of boilerplate.

### Maldev connection

The `windows` crate uses `windows::core::Result<T>` everywhere. Win32 `BOOL` values have an `.ok()` method:

```rust
// VirtualProtect returns BOOL (1 = success, 0 = failure)
VirtualProtect(ptr, size, PAGE_EXECUTE_READ, &mut old)
    .ok()  // converts BOOL → windows::core::Result<()>
    .expect("VirtualProtect failed");
```

You can also use `?` if your function returns `windows::core::Result<T>`:
```rust
fn setup_memory(ptr: *mut c_void, size: usize) -> windows::core::Result<()> {
    let mut old = PAGE_PROTECTION_FLAGS::default();
    unsafe { VirtualProtect(ptr, size, PAGE_EXECUTE_READ, &mut old).ok()? };
    Ok(())
}
```

## Key rules

- `Result<T, E>` = `Ok(T)` on success or `Err(E)` on failure.
- The compiler requires handling both cases before you can use the value.
- `map_err` converts the error type; `map` converts the success type.
- Closures: `|param| expression` — anonymous inline functions.
- `?` propagates errors upward from functions that return `Result`.
- `unwrap()` panics on `Err` — avoid in production paths.
