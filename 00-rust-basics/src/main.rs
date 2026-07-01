// Module 00 — Rust Basics
// Run with: cargo run -p rust-basics
// Each exercise is a function. Uncomment them one at a time in main().

fn main() {
    ex01_variables();
    ex02_types_and_casting();
    ex03_ownership();
    ex04_references();
    ex05_slices();
    ex06_option();
    ex07_result();
    ex08_raw_pointers();
    ex09_unsafe_blocks();
    ex10_structs();
    
}

// ─── Exercise 01: Variables & Mutability ─────────────────────────────────────
//
// In Rust, all variables are immutable by default.
// You must explicitly opt into mutability with `mut`.
//
// Task: fix the code so it compiles and prints "counter is 3".
fn ex01_variables() {
    let mut counter = 0;          // BUG: this should be mutable
    counter += 1;
    counter += 1;
    counter += 1;
    println!("ex01: counter is {counter}");
}

// ─── Exercise 02: Types & Casting ────────────────────────────────────────────
//
// Rust never implicitly converts between numeric types. You must cast with `as`.
// This matters a lot in Win32 code: API parameters are specific widths (u32, usize, i32).
//
// Key types:
//   u8  / i8   — 8-bit  (byte)
//   u32 / i32  — 32-bit
//   u64 / i64  — 64-bit
//   usize      — pointer-sized unsigned (use for sizes and array indices)
//
// Task: fill in the casts so all three prints work without compiler errors.
fn ex02_types_and_casting() {
    let size: usize = 1024;
    let size_u32: u32 = size as u32;
    let size_u64: u64 = size as u64;

    println!("ex02: size={size}  as u32={size_u32}  as u64={size_u64}");

    // Bonus: what happens when you cast a large value to a smaller type?
    let big: u64 = 300;
    let small: u8 = big as u8; // 300 % 256 = 44 — truncation, not an error
    println!("ex02: 300u64 as u8 = {small}");
}

// ─── Exercise 03: Ownership ───────────────────────────────────────────────────
//
// Rust's ownership model: every value has exactly ONE owner.
// When the owner goes out of scope, the value is dropped (freed).
// Assigning a heap value to another variable MOVES ownership — the original is gone.
//
// For types that implement Copy (all primitives: u8, u32, bool, raw pointers...),
// assignment copies the value instead of moving it.
//
// Task: explain in a comment WHY line A compiles but line B would not.
// Then fix ex03 so it prints both messages without cloning.
fn ex03_ownership() {
    let s1 = String::from("hello"); // String is heap-allocated, NOT Copy
    let s2 = s1;                    // ownership MOVED to s2; s1 is now invalid

    // Line A — this works:
    println!("ex03: s2 = {s2}");
    // s2 = s1 has moved ownership over the String, so s2 references it without error

    // Line B — uncomment to see the error, then re-comment it:
    //println!("ex03: s1 = {s1}");  // error: s1 was moved
    // string has no copy, so s2 = s1 droppes s1

    // Fix: if you need both, use .clone() to make a deep copy:
    let s3 = String::from("world");
    let s4 = s3.clone();
    println!("ex03: s3={s3}  s4={s4}");
}

// ─── Exercise 04: References & Borrowing ─────────────────────────────────────
//
// Instead of moving, you can BORROW a value with a reference (&T or &mut T).
// Rules:
//   - Any number of immutable borrows (&T) at once, OR
//   - Exactly ONE mutable borrow (&mut T) — never both simultaneously.
//
// This is how you pass values to functions without giving up ownership.
//
// Task: implement `double` so it modifies `n` in-place via a mutable reference.
fn double(n: &mut u32) {
    // `n` is a *reference* to a u32 — it's not the value itself, it's a pointer to it.
    // To get at the actual number, we must *dereference* the reference with `*`.
    //
    //   n        — the reference (memory address)
    //   *n       — the value sitting at that address
    //   *n = ... — write a new value through the reference back to the caller's variable
    //
    // Without the `*`, you'd be trying to reassign the reference itself (not allowed).
    // This is the same mental model as C's pointer dereference: `*ptr = value`.
    *n = *n * 2
    // Idiomatic shorthand: `*n *= 2;` — same thing, just terser.
}

fn ex04_references() {
    let mut value: u32 = 21;
    double(&mut value);
    println!("ex04: doubled = {value}"); // should print 42
}

// ─── Exercise 05: Slices ──────────────────────────────────────────────────────
//
// A slice (&[T]) is a view into a contiguous sequence — an array, a Vec, etc.
// It's a fat pointer: (pointer to first element, length).
//
// &[u8] is how shellcode is represented: a borrowed view of raw bytes.
//
// Task: write `count_nops` — count how many 0x90 bytes are in a shellcode slice.
fn count_nops(shellcode: &[u8]) -> usize {
    let mut counter = 0;

    // `0..shellcode.len()` is a *range* — it produces the integers 0, 1, 2, ...
    // up to but NOT including shellcode.len() (exclusive upper bound).
    // `for i in range` then iterates over those integers one at a time.
    //
    // `shellcode[i]` indexes into the slice by position. Rust will panic at runtime
    // if i >= shellcode.len(), but because we drive i from the range 0..len(),
    // that can never happen here.
    for i in 0..shellcode.len() {
        if shellcode[i] == 0x90 {
            counter += 1;
        }
    }

    // In Rust, `return` on the last line is optional — the last expression in a
    // function is automatically its return value if there's no semicolon.
    // Both styles below are equivalent to `return counter;`:
    //   counter          ← idiomatic (expression, no semicolon)
    //   return counter;  ← explicit return (fine, just less common at end of fn)
    //
    // Idiomatic one-liner alternative using iterators:
    //   shellcode.iter().filter(|&&b| b == 0x90).count()
    return counter;
}

fn ex05_slices() {
    let stub: &[u8] = &[0x90, 0x90, 0x48, 0x31, 0xc0, 0x90];
    let nops = count_nops(stub);
    println!("ex05: {nops} NOPs found"); // should print 3
}

// ─── Exercise 06: Option<T> ───────────────────────────────────────────────────
//
// Rust has no null pointers in safe code. Instead, "might be absent" is modelled
// as Option<T>, which is either Some(value) or None.
//
// Win32 functions that return pointers often return NULL on failure.
// The `windows` crate maps this to Option or to a raw pointer you must check.
//
// Task: implement `first_byte` — return the first byte of a slice, or None if empty.
fn first_byte(data: &[u8]) -> Option<u8> {
    if data.is_empty() {
        return None
    }
    else {
        return Some(data[0]); // return Some
    }
    // Hint: check data.is_empty() or use data.first().copied()
}

fn ex06_option() {
    let bytes: &[u8] = &[0xfc, 0xe8, 0x00];
    let empty: &[u8] = &[];

    match first_byte(bytes) {
        Some(b) => println!("ex06: first byte = 0x{b:02x}"),
        None    => println!("ex06: empty slice"),
    }
    match first_byte(empty) {
        Some(b) => println!("ex06: first byte = 0x{b:02x}"),
        None    => println!("ex06: empty slice"),
    }
}

// ─── Exercise 07: Result<T, E> ────────────────────────────────────────────────
//
// Result<T, E> is for operations that can fail with an error.
// Either Ok(value) or Err(error).
//
// Win32 API errors: many return BOOL (0 = fail, nonzero = success).
// The `windows` crate wraps this as windows::core::Result<T>.
// Calling .ok() on a windows BOOL converts it to Result.
//
// Task: implement `parse_hex_byte` — parse a two-char hex string ("fc") into a u8.
// Return Err with a descriptive string if parsing fails.
fn parse_hex_byte(s: &str) -> Result<u8, String> {
    // Breaking this line apart:
    //
    // 1. `u8::from_str_radix(s, 16)`
    //    A standard library function that parses a string as an integer in a given base.
    //    Base 16 = hexadecimal. Returns `Result<u8, ParseIntError>`.
    //    - "fc"  → Ok(252)
    //    - "zz"  → Err(ParseIntError { kind: InvalidDigit })
    //
    // 2. `.map_err(|e| e.to_string())`
    //    `map_err` transforms the *error* side of a Result, leaving Ok unchanged.
    //    It takes a *closure* — an anonymous function written inline as `|args| body`.
    //    `|e|` declares one parameter called `e` (the ParseIntError).
    //    `e.to_string()` converts it into a plain String.
    //    Why? Our return type is `Result<u8, String>`, but from_str_radix returns
    //    `Result<u8, ParseIntError>`. map_err bridges the gap.
    //
    // 3. The whole chain returns `Result<u8, String>`, which matches our signature.
    //
    // Closures in brief:
    //   |param1, param2| expression    ← single-expression closure
    //   |param| { statement; result }  ← multi-statement closure with braces
    //   Rust infers the types from context — you rarely need to annotate them.
    return u8::from_str_radix(s, 16).map_err(|e| e.to_string());
}

fn ex07_result() {
    for input in ["fc", "90", "zz", "1"] {
        match parse_hex_byte(input) {
            Ok(b)  => println!("ex07: '{input}' -> 0x{b:02x}"),
            Err(e) => println!("ex07: '{input}' -> error: {e}"),
        }
    }
}

// ─── Exercise 08: Raw Pointers ────────────────────────────────────────────────
//
// Raw pointers (*const T, *mut T) are the equivalent of C pointers.
// They bypass all of Rust's safety guarantees — you can:
//   - Have multiple mutable raw pointers to the same location
//   - Dereference a null or dangling pointer (instant crash / UB)
//
// You need them for Win32 FFI: VirtualAlloc returns *mut c_void,
// WriteProcessMemory takes *const c_void, etc.
//
// Creating a raw pointer is safe. DEREFERENCING it requires unsafe.
//
// Task: fill in the pointer arithmetic below.
fn ex08_raw_pointers() {
    // `[0u8; 8]` — array literal syntax: [initial_value; count]
    // Creates an array of 8 elements of type u8, every element initialized to 0.
    // `0u8` is a numeric literal with an explicit type suffix (u8).
    // You could also write `[0_u8; 8]` — the underscore is a visual separator, ignored by the compiler.
    let mut buffer = [0u8; 8];  // memory: [00, 00, 00, 00, 00, 00, 00, 00]

    // `buffer.as_mut_ptr()` returns a raw mutable pointer to the first element.
    // Type is `*mut u8` — a raw pointer to a single byte.
    // This does NOT borrow the buffer in the Rust sense; the compiler stops tracking it.
    // From here on, YOU are responsible for staying in bounds.
    let ptr: *mut u8 = buffer.as_mut_ptr();

    unsafe {
        // `*ptr = 0xAB` dereferences the raw pointer and writes a byte.
        // ptr points at buffer[0], so this sets buffer[0] = 0xAB.
        *ptr = 0xAB;

        // `ptr.add(1)` advances the pointer by 1 element (1 byte, since T = u8).
        // Equivalent to `ptr + 1` in C. Returns a new `*mut u8` pointing at buffer[1].
        // `*ptr.add(1) = 0xCD` writes 0xCD into buffer[1].
        // Note: .add() is unsafe because it can produce an out-of-bounds pointer —
        // that's why it must live inside an `unsafe` block.
        *ptr.add(1) = 0xCD;
    }
    // After the unsafe block: buffer = [AB, CD, 00, 00, 00, 00, 00, 00]

    println!("ex08: buffer[0]=0x{:02x}  buffer[1]=0x{:02x}", buffer[0], buffer[1]);
    // should print: buffer[0]=0xab  buffer[1]=0xcd
}

// ─── Exercise 09: unsafe Blocks & transmute ───────────────────────────────────
//
// `unsafe` unlocks four extra abilities:
//   1. Dereference raw pointers
//   2. Call unsafe functions (all Win32 FFI)
//   3. Access/modify mutable statics
//   4. Implement unsafe traits
//
// `std::mem::transmute::<A, B>(value)` reinterprets the bits of A as B.
// A and B must be the same size. This is how you turn a *mut c_void into
// a callable function pointer — which is exactly what Step 4 of Module 01 does.
//
// Task: use transmute to reinterpret four bytes as a u32, then print it.
fn ex09_unsafe_blocks() {
    let bytes: [u8; 4] = [0x01, 0x00, 0x00, 0x00]; // little-endian 1

    let value: u32 = unsafe {
        std::mem::transmute(bytes) 
        // std::mem::transmute(bytes)::<[u8; 4], u32>
        // Hint: std::mem::transmute(bytes)
    };

    println!("ex09: bytes as u32 = {value}"); // should print 1
}

// ─── Exercise 10: Structs ─────────────────────────────────────────────────────
//
// Structs are how Rust models C structs — important for Win32 types like
// PROCESS_INFORMATION, STARTUPINFOW, CONTEXT, etc.
//
// #[repr(C)] makes the struct layout match the C ABI (field order, padding).
// You MUST use #[repr(C)] on any struct you pass across FFI.
//
// Task: complete the Region struct and its `is_executable` method.
#[repr(C)]
struct Region {
    base: *mut u8,
    size: usize,
    protect: u32,
}

impl Region {
    // PAGE_EXECUTE_READ = 0x20, PAGE_EXECUTE_READWRITE = 0x40
    fn is_executable(&self) -> bool {
        if self.protect == 0x20 || self.protect == 0x40 {
            true
        }
        else { false }
    }
}

fn ex10_structs() {
    let r1 = Region { base: std::ptr::null_mut(), size: 4096, protect: 0x20 };
    let r2 = Region { base: std::ptr::null_mut(), size: 4096, protect: 0x04 };

    println!("ex10: r1 executable = {}", r1.is_executable()); // true
    println!("ex10: r2 executable = {}", r2.is_executable()); // false
}
