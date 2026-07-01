# Module 01 — Shellcode Runner

## Concept

A **shellcode runner** is the most basic malware primitive: allocate memory, write raw machine code into it, make it executable, and jump to it. Every loader, injector, and implant is built on this foundation.

### Why not just allocate RWX memory directly?

You can (`PAGE_EXECUTE_READWRITE`), and many toy examples do. But modern EDRs flag RWX allocations immediately — it's a major IOC. The standard pattern is:

1. Allocate **RW** (readable/writable, not executable)
2. Write the shellcode
3. **Flip to RX** (readable/executable, not writable) via `VirtualProtect`
4. Execute

This two-step approach is harder to detect because the transition happens at runtime and the final allocation is RX, not RWX.

### Windows memory protection flags

| Constant | Read | Write | Execute |
|---|---|---|---|
| `PAGE_READWRITE` | ✓ | ✓ | ✗ |
| `PAGE_EXECUTE_READ` | ✓ | ✗ | ✓ |
| `PAGE_EXECUTE_READWRITE` | ✓ | ✓ | ✓ |

---

## Task

Implement a working shellcode runner in `src/main.rs` by completing all four `todo!()` steps.

### Step 1 — `VirtualAlloc`

```
VirtualAlloc(
    lpaddress: Option<*const c_void>,   // NULL = let OS choose base
    dwsize: usize,                       // bytes to allocate
    flallocationtype: VIRTUAL_ALLOCATION_TYPE,
    flprotect: PAGE_PROTECTION_FLAGS,
) -> *mut c_void
```

Returns `NULL` on failure. Check for it and handle the error (call `GetLastError` or use the `windows::core::Error::from_win32()` helper).

### Step 2 — Copy bytes

Use `ptr::copy_nonoverlapping`. The destination is the raw pointer from Step 1; cast it to `*mut u8`.

### Step 3 — `VirtualProtect`

```
VirtualProtect(
    lpaddress: *const c_void,
    dwsize: usize,
    flnewprotect: PAGE_PROTECTION_FLAGS,
    lpfloldprotect: *mut PAGE_PROTECTION_FLAGS,  // out-param, must point to valid memory
) -> BOOL
```

A `BOOL` return of `false` (0) means failure. The `windows` crate's `BOOL` type has an `.ok()` method that converts it to a `windows::core::Result<()>`.

### Step 4 — Execute

Try both approaches described in the comments and understand the difference:

- **Function pointer** — synchronous, simpler, crashes the current thread if the shellcode is buggy
- **`CreateThread`** — asynchronous; pair it with `WaitForSingleObject(handle, INFINITE)` to block until the shellcode finishes

---

## Acceptance Criteria

- [ ] Compiles: `cargo build --target x86_64-pc-windows-gnu`
- [ ] Runs calc.exe (or another payload) when executed on Windows
- [ ] No `NULL` pointer dereference — VirtualAlloc and VirtualProtect failures are handled
- [ ] Final allocation is **RX**, not RWX
- [ ] `unsafe` is used only where unavoidable

---

## Generating Shellcode

```bash
# Install msfvenom (part of Metasploit Framework)
# Then:
msfvenom -p windows/x64/exec CMD=calc.exe -f rust
```

Copy the output array into the `SHELLCODE` constant in `main.rs`.

Alternatively, for a self-contained test without Metasploit, use a hand-written NOP sled + `int3` (`\xcc`) to confirm execution reaches your shellcode at all:

```rust
const SHELLCODE: &[u8] = &[0x90, 0x90, 0x90, 0xcc]; // NOP NOP NOP INT3
```

Running this under a debugger (x64dbg) and seeing the breakpoint hit confirms your runner works.

---

## Hints

- The `windows` crate requires each Win32 API to be enabled via a feature flag — they're already set in `Cargo.toml` for this module.
- `VirtualAlloc` returns `*mut core::ffi::c_void`. You'll need to cast it to `*mut u8` for the copy step.
- If `CreateThread` gives you type errors on the function pointer, the signature it expects for the thread proc is `unsafe extern "system" fn(*mut c_void) -> u32`.
- The `todo!()` macro compiles fine but panics at runtime — replace each one before testing.

---

## Submission

Once you're happy with your implementation, paste your `main.rs` in the chat and ask for a review.
