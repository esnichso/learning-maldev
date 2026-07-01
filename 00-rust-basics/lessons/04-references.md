# Lesson 04 — References & Borrowing

## What you learned

### Borrowing without moving

A reference lets you use a value without taking ownership. The original owner keeps the value; you just borrow access to it temporarily.

```rust
fn print_len(s: &String) {    // `s` is a reference — borrows the String
    println!("{}", s.len());  // can read through it
}                             // borrow ends here, String is NOT dropped

let name = String::from("hello");
print_len(&name);             // lend a reference to the function
println!("{name}");           // name still valid — we only borrowed it
```

### Immutable vs mutable references

`&T` — immutable reference. You can read, not write.  
`&mut T` — mutable reference. You can read AND write through it.

```rust
fn zero_out(n: &mut u32) {
    *n = 0;   // `*` dereferences the reference to get at the value
}

let mut x = 42;
zero_out(&mut x);
println!("{x}"); // 0
```

The `*` before a reference is the **dereference operator** — it means "go to the value this reference points at". Without it, you're working with the reference itself (a memory address), not the value.

### The borrow rules

The compiler enforces these at compile time:

1. You can have **any number** of immutable references (`&T`) at the same time.
2. You can have **exactly one** mutable reference (`&mut T`) at a time.
3. You cannot have a mutable reference and an immutable reference **at the same time**.

```rust
let mut v = vec![1, 2, 3];

let r1 = &v;     // immutable borrow
let r2 = &v;     // another immutable borrow — fine, both coexist
println!("{r1:?} {r2:?}");

let r3 = &mut v; // mutable borrow — fine, r1/r2 are no longer used above
r3.push(4);
```

These rules exist to eliminate data races at compile time.

### Dereference in practice

When you have `n: &mut u32`:

```rust
*n          // the u32 value at the other end of the reference
*n = 99     // write 99 through the reference
*n * 2      // read the value and multiply
*n *= 2     // shorthand: read, multiply, write back
```

Note: for structs, Rust often auto-dereferences for you so you can write `n.field` instead of `(*n).field`. But for plain numeric types you need the explicit `*`.

### Maldev connection

Win32 API out-parameters are mutable references in disguise. In C:
```c
DWORD old_protect;
VirtualProtect(ptr, size, PAGE_EXECUTE_READ, &old_protect);
```
In Rust:
```rust
let mut old_protect = PAGE_PROTECTION_FLAGS::default();
VirtualProtect(ptr, size, PAGE_EXECUTE_READ, &mut old_protect);
```

The pattern is identical. Anywhere a C function takes a pointer to write a result back, Rust uses `&mut`.

## Key rules

- `&T` borrows without taking ownership.
- `&mut T` borrows mutably — lets you write through the reference.
- `*ref` dereferences to get the value.
- Multiple `&T` at once — fine. One `&mut T` at a time — fine. Both at the same time — not allowed.
- The borrow rules are enforced at compile time; violations are errors, not runtime crashes.
