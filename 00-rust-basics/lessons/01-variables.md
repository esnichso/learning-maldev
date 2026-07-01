# Lesson 01 — Variables & Mutability

## What you learned

### Immutability is the default

In Rust, every variable is immutable unless you say otherwise. This is the opposite of C.

```rust
let x = 5;     // immutable — the compiler will refuse any attempt to change x
let mut y = 5; // mutable — you can reassign y freely
y += 1;        // fine
```

If you try to mutate an immutable variable, the compiler rejects it at compile time with a clear error: `cannot assign twice to immutable variable`. This prevents a large class of bugs before your code ever runs.

### Why immutability by default?

Mutation is one of the most common sources of bugs in systems code — a value changes unexpectedly, a second thread writes while you're reading, a loop modifies something it shouldn't. By making immutability the default, Rust forces you to be *explicit* about every place where state can change. In a malware codebase, this matters: you want to know exactly which allocations change and when.

### Shadowing

You can declare a new variable with the same name as an existing one. The new variable *shadows* the old one from that point onward.

```rust
let size = 1024;           // usize
let size = size * 2;       // new variable, shadows the old one — still immutable
let size = size.to_string(); // can even change the type
```

Shadowing is different from `mut`: each `let` creates a brand-new variable. The old one is not changed — it's just hidden.

### Maldev connection

Win32 API out-parameters require `mut`:
```rust
let mut old_protect: PAGE_PROTECTION_FLAGS = Default::default();
VirtualProtect(ptr, size, PAGE_EXECUTE_READ, &mut old_protect);
//                                           ^^^^ requires mut
```
Without `mut` on `old_protect`, the compiler refuses to let you pass `&mut old_protect`.

## Key rules

- `let x` = immutable. Period.
- `let mut x` = mutable.
- Shadowing (`let x = ...` again) creates a new variable, does not mutate the old one.
- The compiler catches immutability violations at compile time, not runtime.
