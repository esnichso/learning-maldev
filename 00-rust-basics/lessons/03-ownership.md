# Lesson 03 — Ownership

## What you learned

### The ownership rule

Every value in Rust has exactly **one owner** at a time. When the owner goes out of scope, the value is dropped — its memory is freed. No garbage collector, no `free()` call needed.

```rust
{
    let s = String::from("hello"); // s owns the String
    // ... use s ...
}  // s goes out of scope here — String is automatically freed
```

### Move semantics

When you assign a heap-allocated value to another variable, ownership **moves**. The original variable becomes invalid.

```rust
let s1 = String::from("hello");
let s2 = s1;   // ownership moved from s1 to s2

println!("{s1}"); // ERROR: s1 was moved — the compiler won't let you use it
println!("{s2}"); // fine — s2 is the owner now
```

This is NOT like C where both pointers would just point at the same memory. After the move, `s1` is gone at the language level. The compiler enforces this — there's no runtime cost.

### Copy types

Types that are trivially copyable (live entirely on the stack) implement the `Copy` trait. Assignment copies the value instead of moving it.

**Copy types**: all integer types, `bool`, `char`, `f32`/`f64`, tuples of Copy types, **raw pointers**.

```rust
let a: u32 = 5;
let b = a;          // b is an independent copy; a is still valid
println!("{a} {b}"); // both fine
```

**Raw pointers are Copy** — this matters in maldev. You can pass `*mut u8` to multiple places freely. But the compiler won't stop you from having two mutable raw pointers to the same memory; that's your responsibility.

### Clone

If you need two independent owned copies of a non-Copy type, call `.clone()`:

```rust
let s1 = String::from("hello");
let s2 = s1.clone(); // explicit deep copy — allocates new heap memory
println!("{s1} {s2}"); // both valid
```

Clone is always explicit — Rust will never silently make a deep copy. If an operation seems like it would be expensive, Rust makes you say so.

### Maldev connection

You mostly deal with raw pointers in Win32 code, and raw pointers are Copy. But when you store Win32 handles or `Vec<u8>` payloads in a struct, the ownership rules apply — you need to think about who owns the data and when it gets freed.

The ownership model also means there's **no use-after-free** in safe Rust. The compiler tracks lifetimes and refuses programs where a reference might outlive its owner.

## Key rules

- One owner at a time. Assignment of heap types = move.
- After a move, the original variable is gone.
- Copy types (primitives, raw pointers) copy on assignment.
- `.clone()` for explicit deep copy.
- When the owner's scope ends, the value is dropped automatically.
