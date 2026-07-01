# Module 13 — Payload Encoding & Staging

## Concept

Raw shellcode bytes in a binary are easy to detect with static signatures — AV vendors fingerprint known patterns. **Encoding** breaks those signatures by transforming the payload bytes so the recognizable pattern never appears in the file. A small **decoder stub** at runtime reverses the transformation and executes the original payload.

**Staging** separates the dropper from the payload: a small first-stage binary downloads, decodes, and executes a larger second stage — nothing but the stub ever touches disk.

This module covers both: you implement XOR encoding at compile time (Part A) and the in-memory staging pattern (Part B).

### The two parts

| Part | Payload source | How it arrives | Execution |
|---|---|---|---|
| A | Hardcoded shellcode | Embedded in binary, XOR-encoded | Decode → VirtualAlloc RX → transmute → call |
| B | `13-stage-two` PE | `include_bytes!` in the binary | VirtualAlloc RWX → copy → transmute → call |

Part B is pedagogically simplified — jumping directly to PE bytes without loading them is not reliable (import table, relocations). The point is to practice the alloc+copy+call pattern. Module 04 (hollowing) and Module 07 (reflective loading) cover reliable PE execution.

---

## This module has two crates

| Crate | Role |
|---|---|
| `13-stage-two` | Minimal PE payload — spawns calc.exe |
| `13-payload-staging` | Dropper — encodes at compile time, decodes + executes at runtime |

**Build order:**

```bash
cargo build --target x86_64-pc-windows-gnu -p stage-two
cargo build --target x86_64-pc-windows-gnu -p payload-staging
```

---

## Part A — XOR Encode / Decode

### Why XOR?

XOR is its own inverse: `(A XOR K) XOR K == A`. This means the same function encodes and decodes. A rolling key (cycling through a key array) avoids the obvious all-zero plaintext signature that a single-byte key produces.

### The compile-time trick

```rust
const fn xor_encode(input: &[u8], key: &[u8]) -> [u8; 64] { ... }
static ENCODED_SHELLCODE: [u8; 64] = xor_encode(SHELLCODE, KEY);
```

`const fn` runs at compile time. The binary contains `ENCODED_SHELLCODE` — the plaintext `SHELLCODE` bytes never appear in the output file. The decoder at runtime reapplies the same XOR to recover the original.

### Step 1 — Implement `xor_encode`

The const fn takes `input: &[u8]` and `key: &[u8]` and returns `[u8; 64]`.

Constraints of `const fn`:
- No heap allocation, no iterators with closures — use a `while` loop and index manually.
- Mutable local arrays are allowed: `let mut out = [0u8; 64];`.
- Return `out` at the end.

Logic: `out[i] = input[i] ^ key[i % key.len()]` for each `i` in `0..input.len()`.

### Step 2 — Allocate RW memory for the decoded shellcode

```
VirtualAlloc(
    lpaddress: Option<*const c_void>,          // None — let the OS choose the address
    dwsize: usize,                             // ENCODED_SHELLCODE.len()
    flallocationtype: VIRTUAL_ALLOCATION_TYPE, // MEM_COMMIT | MEM_RESERVE
    flprotect: PAGE_PROTECTION_FLAGS,          // PAGE_READWRITE — writable for the copy step
) -> *mut c_void                               // NULL on failure; check it
```

Start with `PAGE_READWRITE` — you cannot write into an `PAGE_EXECUTE_READ` region.

### Step 3 — Decode into the allocation

Iterate `0..ENCODED_SHELLCODE.len()` and write each decoded byte:

```
ptr::write(buf.add(i), ENCODED_SHELLCODE[i] ^ KEY[i % KEY.len()])
```

### Step 4 — Change protection to RX

W^X principle: a region should never be simultaneously writable and executable.

```
VirtualProtect(
    lpaddress: *const c_void,                      // buf as *const c_void
    dwsize: usize,                                 // ENCODED_SHELLCODE.len()
    flnewprotect: PAGE_PROTECTION_FLAGS,           // PAGE_EXECUTE_READ
    lpfloldprotect: *mut PAGE_PROTECTION_FLAGS,    // &mut old_protect — receives the old protection
) -> Result<()>
```

`old_protect` must be a valid pointer — pass a local variable.

### Step 5 — Execute

```rust
let f: unsafe extern "system" fn() = mem::transmute(buf);
f();
```

The placeholder shellcode is a NOP sled ending in `INT3` (0xCC). You will see a crash or a debugger trap — that confirms the shellcode ran. Swap `SHELLCODE` for real calc-spawning shellcode when you want a visible effect.

---

## Part B — Stage-two PE in memory

### Step 6 — Allocate RWX for the PE bytes

```
VirtualAlloc(
    lpaddress: Option<*const c_void>,          // None
    dwsize: usize,                             // STAGE_TWO.len()
    flallocationtype: VIRTUAL_ALLOCATION_TYPE, // MEM_COMMIT | MEM_RESERVE
    flprotect: PAGE_PROTECTION_FLAGS,          // PAGE_EXECUTE_READWRITE — RWX for simplicity
) -> *mut c_void                               // NULL on failure; check it
```

### Step 7 — Copy the PE bytes

```
ptr::copy_nonoverlapping(
    src: *const u8,   // STAGE_TWO.as_ptr()
    dst: *mut u8,     // stage_buf
    count: usize,     // STAGE_TWO.len()
)
```

### Step 8 — Jump to the allocation

```rust
let f: unsafe extern "system" fn() = mem::transmute(stage_buf);
f();
```

This jumps to offset 0 of the PE bytes (the DOS stub), which will likely crash. That is expected — PE headers are not executable directly. The value of this exercise is the **pattern**: you will use exactly this alloc + copy + call sequence in Module 26 (staged payloads), but with a reflective loader that handles the PE loading before jumping.

To observe a successful stage-two execution, use Module 04's hollowing technique with `STAGE_TWO` as the payload instead.

---

## Acceptance Criteria

- [ ] `xor_encode` implemented as a `const fn` (no heap, no closures)
- [ ] `static ENCODED_SHELLCODE` compiles — it is initialized with `xor_encode(SHELLCODE, KEY)` at compile time
- [ ] `VirtualAlloc` with `PAGE_READWRITE` for the shellcode buffer; null checked
- [ ] Shellcode decoded byte-by-byte with rolling XOR into the allocation
- [ ] `VirtualProtect` called to change protection to `PAGE_EXECUTE_READ` before executing
- [ ] `VirtualProtect` old-protect pointer is a valid local variable, not null
- [ ] `13-stage-two` built first; `include_bytes!` path resolves without error
- [ ] `VirtualAlloc` with `PAGE_EXECUTE_READWRITE` for the PE buffer; null checked
- [ ] `ptr::copy_nonoverlapping` used to copy PE bytes (not a manual loop)
- [ ] Both transmute+call steps present in `main`

---

## Key Types

**`PAGE_READWRITE`, `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`** — `PAGE_PROTECTION_FLAGS` constants. The W^X principle says use `PAGE_READWRITE` to write, then `VirtualProtect` to `PAGE_EXECUTE_READ` before executing. `PAGE_EXECUTE_READWRITE` skips the protection change but is more suspicious to scanners.

**`MEM_COMMIT | MEM_RESERVE`** — always pass both when allocating fresh memory. `MEM_RESERVE` claims the virtual address range; `MEM_COMMIT` backs it with physical pages.

**`mem::transmute`** — reinterprets bits without conversion. Turning a `*mut u8` into `unsafe extern "system" fn()` is undefined behavior if the pointer doesn't point to valid executable code — but that is exactly what malware does.

**`ptr::copy_nonoverlapping`** — equivalent to `memcpy`. Requires `src` and `dst` to not overlap. Safe to use here since `VirtualAlloc` returns a fresh region.

---

## Hints

- The `const fn` cannot use `for item in slice` iterator syntax — use `while i < input.len() { ... i += 1; }`.
- You need to declare `const KEY: &[u8] = b"maldev42";` alongside `const fn xor_encode`. A `const fn` can access `const` and `static` items in scope.
- If `xor_encode` fails to compile, add `#![feature(const_for)]` temporarily to debug, then rewrite to use `while`.
- The `old_protect` variable passed to `VirtualProtect` must be initialized (e.g. `let mut old_protect = PAGE_READWRITE;`). Passing `ptr::null_mut()` will crash.
- The NOP-sled shellcode in Part A will hit the INT3 and trap. Run under a debugger (`x64dbg`) or replace with real shellcode to see it spawn calc.exe.
- Compare Part B with Module 04: the difference is that Module 04 parses the PE headers and sets up the correct entry point; here you jump to offset 0, which skips all that setup. Module 26 builds the proper staging chain.

---

## Submission

Paste `13-payload-staging/src/main.rs` and ask for a review.
