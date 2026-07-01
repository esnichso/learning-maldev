# Module 00 — Rust Basics

This module teaches the Rust concepts you'll use in every subsequent module. It's not a full Rust course — it covers exactly the subset needed for systems programming and Win32 FFI.

Run your code with:
```bash
cargo run -p rust-basics
```

---

## 1. Variables & Mutability

```rust
let x = 5;        // immutable — cannot be changed
let mut y = 5;    // mutable
y += 1;           // fine
```

Rust defaults to immutable because mutation is a common source of bugs. You must explicitly opt in with `mut`. The compiler enforces this.

**Shadowing** — you can re-declare a variable with the same name:
```rust
let x = 5;
let x = x + 1; // new variable, shadows the old one
```

---

## 2. Types & Casting

Rust never silently converts between numeric types. Every conversion is explicit.

```rust
let a: u32 = 100;
let b: usize = a as usize; // explicit cast with `as`
```

Types you'll use constantly in Win32 code:

| Type | Size | Notes |
|------|------|-------|
| `u8` | 1 byte | raw byte, shellcode element |
| `u32` | 4 bytes | most Win32 flags and return values |
| `u64` | 8 bytes | handles, addresses on x64 |
| `usize` | pointer-sized | memory sizes, array indices |
| `i32` | 4 bytes | signed, used for some API return codes |

Casting to a smaller type **truncates** — it doesn't panic:
```rust
let x: u64 = 300;
let y: u8 = x as u8; // y = 44  (300 % 256)
```

---

## 3. Ownership

Rust's most distinctive feature. Every value has exactly **one owner** at a time. When the owner goes out of scope, the value is freed — no garbage collector needed.

```rust
let s1 = String::from("hello"); // s1 owns the string
let s2 = s1;                    // ownership MOVES to s2; s1 is gone
println!("{s1}");               // ERROR: s1 was moved
```

**Copy types** (all primitives: `u8`, `u32`, `bool`, raw pointers) are copied on assignment, not moved:
```rust
let a: u32 = 5;
let b = a;           // b is a copy; a still valid
println!("{a} {b}"); // fine
```

If you need two owned copies of a heap value, use `.clone()`:
```rust
let s1 = String::from("hello");
let s2 = s1.clone(); // explicit deep copy
println!("{s1} {s2}"); // both valid
```

---

## 4. References & Borrowing

You can *borrow* a value without taking ownership using references.

```rust
fn print_len(s: &String) {      // borrows s, doesn't own it
    println!("{}", s.len());
}

let s = String::from("hello");
print_len(&s);                  // pass a reference
println!("{s}");                // s still valid — we only borrowed it
```

Mutable borrow — lets you modify through the reference:
```rust
fn add_one(n: &mut u32) {
    *n += 1;   // dereference to access the value
}

let mut x = 5;
add_one(&mut x);
println!("{x}"); // 6
```

**The borrow rules** (enforced at compile time):
- Many immutable borrows at once — fine
- Exactly one mutable borrow — fine
- Mixing mutable and immutable borrows — **not allowed**

---

## 5. Slices

A slice `&[T]` is a borrowed view into a contiguous sequence. It's a **fat pointer**: address + length. No allocation, no ownership.

```rust
let arr = [1u8, 2, 3, 4, 5];
let slice: &[u8] = &arr[1..3]; // bytes at index 1 and 2
println!("{:?}", slice);        // [2, 3]
```

Shellcode is always `&[u8]`. Iterating:
```rust
for byte in shellcode {
    print!("0x{byte:02x} ");
}
```

`shellcode.len()` gives the byte count. `shellcode.as_ptr()` gives a `*const u8` raw pointer — needed to pass it to `ptr::copy_nonoverlapping`.

---

## 6. Option\<T\>

Rust has no `null`. "This value might be absent" is expressed as `Option<T>`:

```rust
let some: Option<u32> = Some(42);
let none: Option<u32> = None;
```

Pattern match to unwrap:
```rust
match value {
    Some(n) => println!("got {n}"),
    None    => println!("nothing"),
}
```

Common shortcuts:
```rust
value.unwrap()           // panics if None — only use in examples/tests
value.expect("message")  // panics with a message
value.unwrap_or(0)        // returns 0 if None
value.is_some()           // bool check
```

In Win32 code: `VirtualAlloc` returns a raw pointer that will be null on failure. You check it manually (`ptr.is_null()`) or the `windows` crate wraps it for you.

---

## 7. Result\<T, E\>

For operations that can fail with an error value:

```rust
let ok: Result<u32, String> = Ok(42);
let err: Result<u32, String> = Err("something went wrong".into());
```

Pattern match:
```rust
match result {
    Ok(value) => println!("success: {value}"),
    Err(e)    => println!("failed: {e}"),
}
```

The `?` operator — propagate errors upward automatically (only in functions that return `Result`):
```rust
fn read_byte(data: &[u8]) -> Result<u8, String> {
    let b = data.first().ok_or("empty")?; // returns Err early if None
    Ok(*b)
}
```

The `windows` crate uses `windows::core::Result<T>` everywhere. Win32 `BOOL` return values have a `.ok()` method that converts `TRUE` → `Ok(())` and `FALSE` → `Err(last_win32_error)`.

---

## 8. Raw Pointers

`*const T` (immutable) and `*mut T` (mutable) are Rust's C-style pointers. They exist for FFI.

Creating one is safe. Dereferencing one requires `unsafe`.

```rust
let mut x: u32 = 5;
let ptr: *mut u32 = &mut x;    // safe — just taking an address

unsafe {
    *ptr = 10;                  // unsafe — dereferencing
}
println!("{x}");                // 10
```

Pointer arithmetic uses `.add(n)` (moves forward n elements):
```rust
let arr = [1u8, 2, 3];
let p = arr.as_ptr();
unsafe {
    let third = *p.add(2); // reads arr[2]
    println!("{third}");   // 3
}
```

Common casts in Win32 code:
```rust
let p: *mut c_void = VirtualAlloc(...);
let p: *mut u8     = p as *mut u8;      // cast to byte pointer for copy
```

---

## 9. unsafe & transmute

The `unsafe` keyword unlocks operations the compiler can't verify:
1. Dereference raw pointers
2. Call `unsafe` functions (all Win32/FFI)
3. Read/write mutable statics
4. Implement `unsafe` traits

```rust
unsafe {
    // everything inside here is your responsibility
    let val = *some_raw_pointer;
    some_ffi_function(args);
}
```

`std::mem::transmute::<A, B>(value)` — reinterpret the bits of `A` as `B`. Both types must be the same size. This is how you turn a `*mut c_void` into a function pointer:

```rust
let exec_ptr: *mut c_void = VirtualAlloc(...);

unsafe {
    let f: unsafe extern "system" fn() = std::mem::transmute(exec_ptr);
    f(); // jump to shellcode
}
```

`extern "system"` specifies the calling convention. On x64 Windows this is the same as `extern "C"`, but being explicit is good practice.

---

## 10. Structs

```rust
struct Point {
    x: f64,
    y: f64,
}

impl Point {
    fn distance_from_origin(&self) -> f64 {
        (self.x * self.x + self.y * self.y).sqrt()
    }
}

let p = Point { x: 3.0, y: 4.0 };
println!("{}", p.distance_from_origin()); // 5.0
```

For Win32 FFI you must use `#[repr(C)]` to match C's struct layout:
```rust
#[repr(C)]
struct POINT {
    x: i32,
    y: i32,
}
```

Without `#[repr(C)]`, Rust may reorder or pad fields differently than C, causing UB when you pass the struct to a Win32 API.

---

## Exercises

The file `src/main.rs` has 10 exercises (`ex01` through `ex10`), one per section above. Each has a `todo!()` marking what to implement.

Work through them in order. The earlier ones are one-liners; the later ones (08, 09) are directly applicable to Module 01.

## Submission

Paste your completed `main.rs` in the chat when you're done.
