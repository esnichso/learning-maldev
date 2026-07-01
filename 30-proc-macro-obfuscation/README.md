# Module 30 — Proc Macro Obfuscation

## Concept

Module 05 showed compile-time string obfuscation using `const fn` XOR. That approach works for simple cases but has a hard limit: `const fn` runs inside the compiler and can only use a small subset of Rust. You can't generate random keys, do I/O, or produce complex token transformations.

**Procedural macros** remove that limit. A proc macro is a normal Rust binary that the compiler invokes at compile time. It receives a stream of tokens (your source code), transforms it, and outputs a new token stream. Because it runs as a full Rust program, it can:

- Generate a random encryption key on every build (different key each compilation)
- Encrypt string literals and emit the encrypted bytes as a `const` array
- Produce a runtime decode expression that reconstructs the string in memory

The result: the plaintext string is never present in the binary. Every build produces a different key and different ciphertext, defeating byte-signature matching.

### Why this beats `const fn` from module 05

| Property | `const fn` XOR (module 05) | Proc macro (module 30) |
|---|---|---|
| Random key per build | No — key is a literal in source | Yes — generated at compile time from `SystemTime` |
| Arbitrary computation | No — limited subset of Rust | Yes — full `std` available |
| Can read environment / filesystem | No | Yes |
| Complexity | Low | High — requires separate crate |
| Works in stable Rust | Yes (`const fn` is stable) | Yes (attribute macros are stable) |

### How proc macros work

```
your code
   │
   ▼
rustc parses tokens
   │
   ▼  invokes proc-macro binary (host architecture, not cross-compiled)
encrypt_macro::xor_string runs
   │  receives TokenStream for the `static` declaration
   │  encrypts the string, generates random key
   │  returns new TokenStream with encrypted bytes + decode expression
   ▼
rustc compiles the expanded code into the final binary
```

The proc macro crate (`30-encrypt-macro`) is compiled for the **host** machine (your Linux build machine), not the Windows target. Only the binary that *uses* the macro (`30-proc-macro-obfuscation`) is cross-compiled to Windows.

---

## This module has two crates

| Crate | Type | Role |
|---|---|---|
| `30-encrypt-macro` | `proc-macro = true` | Implements the `#[xor_string]` macro |
| `30-proc-macro-obfuscation` | binary | Uses the macro, calls `MessageBoxA` with the decoded secret |

**Build order:**

```bash
# The proc-macro crate is compiled for the host automatically by Cargo
# when the binary crate depends on it — no manual step needed.

cargo build --target x86_64-pc-windows-gnu -p proc-macro-obfuscation
```

Cargo automatically builds `encrypt-macro` for the host before building `proc-macro-obfuscation` for Windows.

---

## Task — Implement the `xor_string` Proc Macro (`30-encrypt-macro/src/lib.rs`)

The skeleton has four steps marked with `todo!()`. Work through them in order.

### Step 1 — Extract the string literal

The macro receives a `static NAME: &str = "some string";` declaration as a token stream. Parse it with `syn`:

```
parse_macro_input!(item as ItemStatic)
```

The initialiser is `input.expr`. Match it as `Expr::Lit` → `Lit::Str` → call `.value()` to get a `String`. Anything other than a string literal should `panic!` with a descriptive error message (proc macro panics become compile errors).

### Step 2 — Generate a random key

Proc macros run as host code, so `std::time::SystemTime` is available. Use the nanosecond component of the current time as a seed:

```
use std::time::{SystemTime, UNIX_EPOCH};
let nanos = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .subsec_nanos();
let key = ((nanos ^ (nanos >> 8) ^ (nanos >> 16)) & 0xFF) as u8;
```

Ensure `key != 0` — XOR with zero is identity (no encryption). If it's zero, use a fallback like `0x5A`.

### Step 3 — XOR-encrypt the string bytes

```
// Hint:
plaintext.bytes().map(|b| b ^ key).collect::<Vec<u8>>()
```

Every byte of the plaintext (including the null terminator if present) gets XOR'd with `key`.

### Step 4 — Emit the replacement token stream

Use `quote!` to generate the code that will replace the original `static` declaration. You have two design choices:

**Option A** (simpler — recommended for first attempt): emit a static `[u8; N]` holding the encrypted bytes, plus a `decode_NAME() -> [u8; N]` function that XOR-decrypts them at runtime. The caller must call `decode_NAME()` explicitly.

**Option B** (cleaner interface): emit a `static NAME: &str` where the value is an unsafe block that decodes the bytes and calls `std::str::from_utf8_unchecked`. This keeps the usage identical — you can use `NAME` directly as a `&str`.

For Option A, the emitted code looks like:
```rust
{vis} static {ident}_ENC: [u8; N] = [b0, b1, b2, ...];
{vis} const {ident}_KEY: u8 = {key};
{vis} fn decode_{ident}() -> [u8; N] {
    let mut buf = [{ident}_ENC; N]; // copy
    for b in buf.iter_mut() { *b ^= {ident}_KEY; }
    buf
}
```

Use `quote::quote!` to build this token stream:
```rust
let expanded = quote! {
    // ... your generated code here ...
};
expanded.into() // convert proc_macro2::TokenStream to proc_macro::TokenStream
```

To emit the encrypted byte literals, use:
```rust
let enc_bytes = encrypted.iter().map(|&b| quote! { #b });
// In the quote! block: &[ #(#enc_bytes),* ]
```

---

## Task — Use the Macro (`30-proc-macro-obfuscation/src/main.rs`)

### Step 3 — Get the decoded bytes

After implementing the macro, the static `SECRET` is replaced by encrypted bytes plus a decode function (or a runtime-decoded `&str` if you chose Option B). Either way, get a `*const u8` pointer to the decoded string to pass to `MessageBoxA`.

### Step 4 — Call `MessageBoxA`

```
MessageBoxA(
    hwnd: HWND,              // None — no owner window
    lptext: PCSTR,           // the body text — something like "Proc macro works!"
    lpcaption: PCSTR,        // the decoded SECRET bytes, cast to PCSTR
    utype: MESSAGEBOX_STYLE, // MB_OK
) -> MESSAGEBOX_RESULT
```

### Step 5 — Verify the plaintext is absent

Build in release mode and check with `strings`:

```bash
cargo build --target x86_64-pc-windows-gnu -p proc-macro-obfuscation --release
strings target/x86_64-pc-windows-gnu/release/proc-macro-obfuscation.exe | grep -i maldev
# Expected: no output
```

---

## Key Crates

- **`proc-macro2`** — a re-export of the compiler's proc_macro types that works outside proc-macro context (needed by `quote` and `syn`)
- **`syn`** — parse Rust source code into an AST; `ItemStatic`, `Expr`, `Lit`, `LitStr` are the types you'll use
- **`quote`** — the `quote!` macro for constructing token streams from Rust code templates; `#var` splices a variable, `#(#items),*` splices an iterator

---

## Key Types

**`TokenStream`** — the raw input and output of a proc macro. `proc_macro::TokenStream` is what the macro signature uses; `proc_macro2::TokenStream` is what `quote!` produces. Convert with `.into()`.

**`ItemStatic`** — `syn` type representing `static NAME: TYPE = EXPR;`. Key fields: `.ident` (the name), `.vis` (visibility), `.ty` (the type), `.expr` (the initialiser expression, boxed).

**`Expr::Lit` / `Lit::Str`** — the initialiser expression matched down to a string literal. `.value()` returns the string contents as a plain `String` (escape sequences decoded, quotes removed).

**`quote! { ... }`** — quasi-quoting macro. Inside it, `#variable` splices a variable into the token stream. `#(#iter),*` splices an iterator with commas between items.

---

## Hints

- The proc-macro crate has `[lib] proc-macro = true` in its Cargo.toml — it cannot have a `main.rs`. Don't confuse it with a normal library.
- Proc macros are compiled for the **host** (x86_64-unknown-linux-gnu), not the Windows cross-compilation target. Cargo handles this automatically when you have a `path = "..."` dependency.
- If your macro panics, `cargo build` shows the panic message as a compile error — this is the intended error-reporting mechanism.
- `quote!` needs imported symbols to be in scope. If you reference `Vec` in the generated code, the *generated* code must have it in scope. Use fully qualified paths (`::std::vec::Vec`) to avoid relying on the caller's imports.
- `syn::LitByte::new(byte, Span::call_site())` creates a byte literal token (`b'\xAB'`). Use it when emitting individual encrypted bytes in the `quote!` block.
- The `#[xor_string]` attribute in the binary (`30-proc-macro-obfuscation`) is imported with `use encrypt_macro::xor_string;`.
- If you see "can't use proc-macro crate when building for a non-host target" during cross-compilation — this is Cargo warning you that the proc-macro itself isn't being cross-compiled. That's correct. The binary crate is cross-compiled; the macro crate runs on the host.

---

## Acceptance Criteria

- [ ] `cargo build --target x86_64-pc-windows-gnu -p proc-macro-obfuscation` succeeds
- [ ] `30-encrypt-macro/src/lib.rs` — all four `todo!()` replaced with working code
- [ ] `30-proc-macro-obfuscation/src/main.rs` — all `todo!()` replaced
- [ ] Running `proc-macro-obfuscation.exe` on the VM shows a MessageBox with the decoded secret as the caption
- [ ] `strings proc-macro-obfuscation.exe | grep -i maldev` returns no output
- [ ] `strings proc-macro-obfuscation.exe | grep -i maldev` returns **different** results when comparing two builds (different encrypted bytes due to random key)
- [ ] The key is generated at runtime using `SystemTime` — not hardcoded

---

## Submission

Paste `30-encrypt-macro/src/lib.rs` and `30-proc-macro-obfuscation/src/main.rs` and ask for a review.
