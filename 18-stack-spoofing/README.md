# Module 18 — Call Stack Spoofing

## Concept

When an EDR intercepts a suspicious API call (via a userland hook in ntdll, or an ETW event), one of its first checks is to **walk the call stack** of the thread that made the call. It asks: *who called this function?*

If the return address on the stack points into an anonymous, executable memory region — a shellcode allocation with no backing module — that is a red flag. Legitimate code always has return addresses that trace back into mapped PE images: `kernel32.dll`, `ntdll.dll`, `clr.dll`, etc.

**Call stack spoofing** defeats this check by planting a fake return address on the stack before making the suspicious call. From the EDR's perspective, the call originated from a trusted module. Your actual code address never appears in the trace.

This module teaches the concept with a simplified implementation that demonstrates the principle. Production stack spoofing (e.g. as used in Cobalt Strike's `sleep_mask` or the Ekko technique) uses ROP gadgets and timer-based context switching that is significantly more complex — that complexity is noted but not required here.

---

## Prerequisites: the x64 call stack

You cannot spoof the stack without understanding how it works. This section is not optional.

### The call instruction

When the CPU executes `call target`:
1. It pushes the address of the **next instruction** (the return address) onto the stack.
2. It sets RIP to `target`.

When `target` executes `ret`:
1. It pops the top 8 bytes of the stack into RIP.
2. Execution continues at that address.

The stack is a contiguous region of memory that grows **downward**. RSP always points to the current top (the most recently pushed value). Pushing decrements RSP by 8, then writes; popping reads, then increments RSP by 8.

### Shadow space

The x64 Windows calling convention requires the **caller** to reserve 32 bytes of "shadow space" (also called "home space") above the return address before every call. This space belongs to the callee — it can spill its first four register arguments there. You must allocate this space even if you are not passing four arguments.

```
  [RSP + 40]  ... other stack ...
  [RSP + 32]  arg5 (if any, passed on stack)
  [RSP +  0]  return address  ← RSP at point of call (after shadow alloc)
              (shadow space: [RSP+8]..[RSP+32], 32 bytes, for callee to use)
```

In practice before a `call`:
```
sub rsp, 32   ; allocate shadow space
call target   ; pushes return address, jumps
add rsp, 40   ; after return: undo shadow (32) + return-address slot (8)
```

### Stack alignment

The x64 ABI requires RSP to be **16-byte aligned at the point of a call instruction** (i.e., aligned to 16 before the `call` pushes the return address, so RSP is 8-byte aligned *after* the push). If you violate this, certain SSE instructions inside the callee will fault with a misaligned access exception. Always account for alignment when manually manipulating RSP.

### RtlCaptureContext and RtlRestoreContext

Two undocumented-but-stable ntdll functions control full thread context:

- **`RtlCaptureContext(ContextRecord: *mut CONTEXT)`** — fills a `CONTEXT` with all register values (including RSP, RIP, all general-purpose registers) at the moment of the call. Equivalent to taking a CPU snapshot.

- **`RtlRestoreContext(ContextRecord: *const CONTEXT, ExceptionRecord: *mut c_void) -> !`** — restores all registers from a saved `CONTEXT` and jumps execution to `ContextRecord.Rip`. It never returns (hence `-> !`). This is how the Windows exception dispatcher resumes after handling a structured exception.

These functions are the mechanism behind the production stack-spoofing trick: save context → manipulate the saved RSP/RIP → call `RtlRestoreContext` to enter a gadget chain with a controlled stack.

---

## What stack spoofing actually changes

During a normal call to `VirtualAlloc`:

```
thread stack (top = RSP, grows downward):
  [RSP+0]  → return address pointing into *your code*  ← EDR sees this
  [RSP+8]  → your caller's return address
  ...
```

With stack spoofing:

```
  [RSP+0]  → fake address inside ntdll.dll             ← EDR sees this instead
  [RSP+8]  → another fake or real address
  ...
```

The suspicious function executes normally and returns successfully. The fake return address is cleaned off the stack by your code immediately after. The only window where the faked address is visible is during the suspicious call itself — which is exactly when EDR would walk the stack.

---

## Implementation approach

This module uses **inline assembly** (the `asm!` macro from `core::arch`) to manually manipulate RSP before calling `VirtualAlloc`. The steps:

1. Get a legitimate-looking return address from inside ntdll's `.text` section.
2. Save the current RSP (to restore later).
3. Subtract 8 from RSP and write the fake address to `[RSP]`.
4. Allocate shadow space (sub rsp, 32).
5. Call `VirtualAlloc` — it executes normally and returns in `rax`.
6. Add 40 to RSP to undo shadow + fake slot.
7. Read `rax` as the allocation result.

Verification: call `CaptureStackBackTrace` **during** the suspicious call is not possible from Rust without a hook. Instead, you verify by printing the fake address and confirming the ntdll PE header parse gave you a valid `.text` address. The principle is demonstrated; attaching WinDbg to observe the actual mid-call stack is the gold standard verification.

---

## Task

Implement the spoofed `VirtualAlloc` call in six steps. The skeleton in `src/main.rs` has a `todo!()` per step.

### Step 1 — Capture the baseline stack

Call `CaptureStackBackTrace` with no frames skipped to record the current call stack. Print each frame address. This is your "before" reference.

```
CaptureStackBackTrace(
    FramesToSkip: u32,            // 0 — start from the innermost frame
    FramesToCapture: u32,         // number of frames to capture (e.g. 16)
    BackTrace: *mut *mut c_void,  // pointer to an array you provide
    BackTraceHash: *mut u32,      // hash of the trace — None/null_mut() is fine
) -> u16                          // actual frames captured (may be < FramesToCapture)
```

Iterate and print each `frames[i]` as a hex address.

### Step 2 — Resolve RtlCaptureContext and RtlRestoreContext

These functions are in ntdll but not in the `windows` crate's safe API surface. Resolve them manually:

```
GetModuleHandleA(
    lpmodulename: PCSTR,  // b"ntdll.dll\0" — module already loaded, no disk hit
) -> HMODULE              // base address of ntdll in this process; null on failure
```

```
GetProcAddress(
    hmodule: HMODULE,     // ntdll handle from above
    lpprocname: PCSTR,    // b"RtlCaptureContext\0" or b"RtlRestoreContext\0"
) -> Option<unsafe extern "system" fn()>  // raw fn pointer; None if not found
```

Transmute the result to `FnRtlCaptureContext` / `FnRtlRestoreContext` (the type aliases defined at the top of the skeleton).

### Step 3 — Find a fake return address in ntdll's .text section

Parse ntdll's in-memory PE headers to find the `.text` section's RVA, then add an offset of `0x1000` to get a stable address well inside the section.

Start by casting the ntdll base to `*const IMAGE_DOS_HEADER` to read `e_lfanew`, then to `*const IMAGE_NT_HEADERS64` to reach the section headers.

The section headers immediately follow `IMAGE_NT_HEADERS64`. Each is an `IMAGE_SECTION_HEADER`. Iterate `FileHeader.NumberOfSections` of them. The section named `.text` has its `VirtualAddress` field containing the RVA you need.

```
fake_ret_addr = ntdll_base as usize + text_section.VirtualAddress as usize + 0x1000
```

This address will look like it belongs to ntdll when a stack-walker resolves it against the module list.

### Step 4 — Capture the current context for restoration

Call `rtl_capture(&mut saved_ctx)` where `saved_ctx` is a `CONTEXT` with `ContextFlags = CONTEXT_FULL` set first. This saves all register values so that (in a full implementation) `rtl_restore` could bring you back here cleanly. For this exercise, capture it and print `saved_ctx.Rsp` to confirm it captured a valid stack pointer.

### Step 5 — Make the spoofed VirtualAlloc call with inline assembly

This is the core step. Use `core::arch::asm!` to:

1. Subtract 8 from RSP to make room for the fake return address.
2. Write `fake_ret_addr` to `[RSP]` (the slot a real `call` instruction would use).
3. Subtract 32 from RSP for shadow space.
4. Load arguments into the correct registers (x64 calling convention: `rcx`, `rdx`, `r8`, `r9`).
5. Call `VirtualAlloc` (resolve its address first via `GetProcAddress` or use the windows crate import).
6. Add 40 to RSP (32 shadow + 8 fake-ret slot) to restore the stack.
7. Move `rax` into an output variable.

Skeleton asm structure (you fill in the blanks):

```rust
let alloc_fn = VirtualAlloc as usize;
let result: usize;
asm!(
    "sub rsp, 8",
    "mov qword ptr [rsp], {fake}",   // plant the fake return address
    "sub rsp, 32",                   // shadow space
    "xor rcx, rcx",                  // lpAddress = NULL
    "mov rdx, 0x1000",               // dwSize = 4096
    "mov r8d, 0x3000",               // MEM_COMMIT | MEM_RESERVE
    "mov r9d, 0x40",                 // PAGE_EXECUTE_READWRITE
    "call {fn}",                     // call VirtualAlloc
    "add rsp, 40",                   // undo shadow + fake-ret slot
    "mov {out}, rax",
    fake = in(reg) fake_ret_addr,
    fn   = in(reg) alloc_fn,
    out  = out(reg) result,
    // clobbers: rax, rcx, rdx, r8, r9, r10, r11 (caller-saved on x64)
    out("rax") _, out("rcx") _, out("rdx") _,
    out("r8") _,  out("r9") _,  out("r10") _, out("r11") _,
    options(nostack),
);
```

Note: `options(nostack)` tells LLVM the asm block doesn't touch RSP — but here we do touch it. This is a known tension; use it with care or use `options()` without `nostack` and manage alignment manually.

### Step 6 — Capture the stack again and compare

After the call returns, call `CaptureStackBackTrace` again with the same parameters. Print both traces side by side. Confirm that `alloc_ptr` is non-null (the allocation succeeded despite the spoofed frame).

Print the fake return address so you can visually compare it to the frames printed in step 1. In a real scenario, the frame at `[0]` during the VirtualAlloc call would have been `fake_ret_addr` rather than your actual caller.

---

## Production vs. this exercise

The simplified approach here has a limitation: we call `CaptureStackBackTrace` *after* the spoofed call returns, so the stack is already restored. The fake address is never visible to our Rust code because it only lives on the stack *during* the call. The educational value is:

- You manipulate RSP in assembly without crashing.
- You correctly set up shadow space.
- You find and use a legitimate module address as a fake frame.
- You understand why the EDR walk only matters during the suspicious call.

In production (Cobalt Strike Beacon style):
- A timer fires and calls a gadget that pivots the stack to a fake frame chain.
- The gadget calls the suspicious API with the fake frames visible.
- Another gadget restores the original RSP and returns.
- The entire sequence is indistinguishable from a normal ntdll call.

---

## Inline assembly in Rust

The `asm!` macro is in `core::arch`. On stable Rust since 1.59.

Key constraints syntax:
- `in(reg) value` — copy `value` into an unspecified register, tell the compiler which one.
- `out(reg) variable` — after the asm, write the output register into `variable`.
- `in("rax") x` — use specifically the `rax` register for input.
- `out("rax") _` — declare `rax` as clobbered (written but result discarded).
- `options(nostack)` — assert to LLVM that this block doesn't change RSP (omit if you change RSP).

LLVM will error if you write to a register without declaring it as an output or clobber.

---

## ntdll section header layout

`IMAGE_SECTION_HEADER` (from `Win32_System_Diagnostics_Debug`):

| Field | Type | Notes |
|---|---|---|
| `Name` | `[u8; 8]` | null-padded ASCII name, e.g. `.text\0\0\0` |
| `VirtualSize` | `u32` | size of section in memory |
| `VirtualAddress` | `u32` | RVA of section start |
| `SizeOfRawData` | `u32` | size in the file |
| `PointerToRawData` | `u32` | file offset |

The headers start immediately after `IMAGE_NT_HEADERS64`. Cast:
```rust
let sections = (nt_ptr as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>())
    as *const IMAGE_SECTION_HEADER;
```
Then index with `sections.add(i)` for `i` in `0..num_sections`.

---

## Acceptance Criteria

- [ ] `cargo build --target x86_64-pc-windows-gnu -p stack-spoofing` succeeds
- [ ] Step 1 prints a valid baseline stack trace (at least 3 frames)
- [ ] `GetModuleHandleA("ntdll.dll")` returns a non-null handle
- [ ] `RtlCaptureContext` and `RtlRestoreContext` resolve successfully via `GetProcAddress`
- [ ] The ntdll `.text` section is found by name; `fake_ret_addr` is non-null and above the ntdll base
- [ ] `saved_ctx.Rsp` is non-zero after `RtlCaptureContext`
- [ ] The inline `asm!` block executes without crashing (stack remains 16-byte aligned)
- [ ] `VirtualAlloc` returns a non-null pointer through the spoofed call
- [ ] Step 6 prints a post-call trace and confirms the allocation succeeded
- [ ] The program exits cleanly (no access violation or stack corruption)

---

## Key Types

**`CONTEXT`** — from `Win32_System_Diagnostics_Debug`. Must have `ContextFlags = CONTEXT_FULL` set before any call that fills it. On x64, general-purpose registers are direct fields: `Rax`, `Rbx`, `Rcx`, `Rdx`, `Rsp`, `Rbp`, `Rsi`, `Rdi`, `R8`–`R15`, `Rip`.

**`IMAGE_DOS_HEADER`** — first structure at any PE's base. Field `e_lfanew: i32` is the byte offset from the PE base to `IMAGE_NT_HEADERS64`.

**`IMAGE_NT_HEADERS64`** — contains `FileHeader: IMAGE_FILE_HEADER` and `OptionalHeader: IMAGE_OPTIONAL_HEADER64`. `FileHeader.NumberOfSections` is the section count. Section headers follow immediately after this structure.

**`IMAGE_SECTION_HEADER`** — 40-byte structure. `Name` is 8 bytes of null-padded ASCII. Compare with `b".text\0\0\0"` to identify the code section.

**`FnRtlCaptureContext`** / **`FnRtlRestoreContext`** — type aliases at the top of `main.rs`. Must match the actual calling convention (`extern "system"`) to avoid stack corruption.

---

## Hints

- The `.text` section name comparison: `§ion.Name == *b".text\0\0\0"` — note eight bytes, not five.
- Alignment before the `call`: after `sub rsp, 8` (fake ret) and `sub rsp, 32` (shadow), RSP has moved by 40. If RSP was 16-byte aligned before your asm block, it is now 8-byte aligned at the point of `call`. The `call` will push 8 more bytes, making it 16-byte aligned *inside* the callee. This is correct.
- If your program crashes with an access violation inside `VirtualAlloc`, the most common cause is stack misalignment. Double-check that RSP was 16-byte aligned before your `asm!` block (the Rust ABI guarantees this at function entry).
- To find the `VirtualAlloc` function pointer for the `call` operand: `let va_fn = VirtualAlloc as usize;` — Rust lets you coerce a function item to a pointer.
- `CaptureStackBackTrace` is in `dbghelp.dll` on older systems but is re-exported by `ntdll` on modern Windows. The `windows` crate feature `Win32_System_Diagnostics_Debug` exposes it.
- `RtlRestoreContext` is only needed if you implement the full save/restore round-trip. For this exercise, calling `rtl_capture` for the snapshot is sufficient — you do not need to call `rtl_restore`.

---

## Submission

Paste `18-stack-spoofing/src/main.rs` and ask for a review.
