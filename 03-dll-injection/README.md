# Module 03 — DLL Injection

## Concept

**DLL injection** loads a `.dll` you control into a running process. Instead of writing raw shellcode bytes, you write the *path* to your DLL into the target, then trick the target into calling `LoadLibraryA` on it. Windows' own loader maps the DLL, resolves its imports, and calls your `DllMain` — all inside the target process.

This module builds the classic **dropper + payload** pattern:

```
┌─────────────────────────────────────┐
│  dll-injection.exe                  │
│  ┌───────────────────────────────┐  │
│  │  DLL bytes (baked in)         │  │  ← include_bytes! at compile time
│  └───────────────────────────────┘  │
│  1. Drop DLL bytes → %TEMP%\x.dll  │  ← LoadLibraryA needs a file path
│  2. Inject %TEMP%\x.dll into target │
└─────────────────────────────────────┘
```

One binary to deliver. The DLL doesn't exist on disk until the injector runs.

### How it compares to Module 02

| | Module 02 | Module 03 |
|---|---|---|
| Payload | raw shellcode bytes | compiled DLL |
| Written into target | shellcode | path string only |
| Execution trigger | `CreateRemoteThread` at shellcode ptr | `CreateRemoteThread` at `LoadLibraryA` |
| Payload on disk | never | briefly in %TEMP% |
| Payload capabilities | position-independent code only | full DLL — imports, globals, exports |

### Why LoadLibraryA works remotely

`kernel32.dll` is loaded into every Windows process. Due to how ASLR works for system DLLs, it's mapped at the **same virtual address in all processes for a given boot session**. So `GetProcAddress(kernel32, "LoadLibraryA")` in your injector returns a pointer that's also valid inside notepad.exe. You hijack a function that's already there.

### DllMain

When `LoadLibraryA` finishes mapping your DLL, Windows calls `DllMain` with `reason = DLL_PROCESS_ATTACH`. That's where your payload runs.

**Loader lock warning**: DllMain holds the loader lock. Don't call `LoadLibrary`, `CoInitialize`, or blocking `WaitForSingleObject` directly. The safe pattern: spawn a thread and return immediately.

---

## This module has two crates

The DLL and the injector must be separate Cargo crates — Rust can't produce both a `.exe` and a `.dll` (`cdylib`) from one crate simultaneously.

| Crate | Output | Role |
|---|---|---|
| `03-dll-payload` | `dll_payload.dll` | Payload — implement `DllMain` here |
| `03-dll-injection` | `dll-injection.exe` | Dropper + injector |

**Build order matters.** The injector embeds the DLL via `include_bytes!`:

```
cargo build --target x86_64-pc-windows-gnu -p dll-payload   # first
cargo build --target x86_64-pc-windows-gnu -p dll-injection  # second
```

Only the `.exe` needs to go to the VM.

---

## Task A — Payload DLL (`03-dll-payload/src/lib.rs`)

Implement `DllMain`. On `DLL_PROCESS_ATTACH`, produce a visible effect.

### DllMain signature

```
DllMain(
    _hinstance: *mut c_void,  // this DLL's base address in memory — not needed here
    reason: u32,              // why we were called: 1 = first load into process
    _reserved: *mut c_void,   // NULL for dynamic loads; ignore
) -> BOOL                     // BOOL(1) = accept load; BOOL(0) = reject and unload
```

### MessageBoxA

```
MessageBoxA(
    hwnd: HWND,               // parent window — pass None for a standalone popup
    lptext: PCSTR,            // message body (null-terminated ANSI string)
    lpcaption: PCSTR,         // window title (null-terminated ANSI string)
    utype: MESSAGEBOX_STYLE,  // button/icon layout — MB_OK for a single OK button
) -> MESSAGEBOX_RESULT        // which button was clicked (you can ignore this)
```

Feature flag: `Win32_UI_WindowsAndMessaging`

### WinExec (alternative)

```
WinExec(
    lpcmdline: PCSTR,  // null-terminated command to run, e.g. b"calc.exe\0"
    ucmdshow: u32,     // window show state — SW_SHOW (5) makes it visible
) -> u32               // > 31 = success; ≤ 31 = Win32 error code
```

Feature flag: `Win32_System_WindowsProgramming`

---

## Task B — Injector (`03-dll-injection/src/main.rs`)

### Step 0 — Drop the embedded DLL to disk

`LoadLibraryA` requires a file path — the DLL must exist on disk. The injector carries the DLL as a byte array (baked in by `include_bytes!`) and writes it out at runtime.

```rust
// In Rust std — no Win32 needed for this step
std::env::temp_dir()   // returns %TEMP% as a PathBuf
std::fs::write(path, bytes)  // writes bytes to that path
CString::new(path_str)  // converts to null-terminated for Win32
```

`CString::new(...).unwrap().as_bytes_with_nul()` gives you a `&[u8]` with the null terminator included — use this wherever you need the path as raw bytes.

### Step 1 — Find notepad.exe PID

Reuse your Toolhelp32 code from Module 02 directly.

### Step 2 — Open the target process

```
OpenProcess(
    dwdesiredaccess: PROCESS_ACCESS_RIGHTS,  // rights needed — OR together what you'll use
    binherithandle: BOOL,                    // child process handle inheritance — use false
    dwprocessid: u32,                        // PID from Step 1
) -> Result<HANDLE>                          // process handle, or Err if access denied
```

Rights needed: `PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD`

### Step 3 — Write the path into the target

Allocate space for the path string:

```
VirtualAllocEx(
    hprocess: HANDLE,                          // target process handle
    lpaddress: Option<*const c_void>,          // desired base — None lets the OS choose
    dwsize: usize,                             // bytes to allocate — dll_path_bytes.len()
    flallocationtype: VIRTUAL_ALLOCATION_TYPE, // MEM_COMMIT | MEM_RESERVE
    flprotect: PAGE_PROTECTION_FLAGS,          // PAGE_READWRITE — path data, never executes
) -> *mut c_void                               // pointer in the target's address space; NULL on failure
```

Write the bytes there:

```
WriteProcessMemory(
    hprocess: HANDLE,                           // target process handle
    lpbaseaddress: *const c_void,               // where to write — remote_path cast to *const c_void
    lpbuffer: *const c_void,                    // local bytes to copy — dll_path_bytes.as_ptr() cast
    nsize: usize,                               // byte count — dll_path_bytes.len()
    lpnumberofbyteswritten: Option<*mut usize>, // out-param for written count — None
) -> BOOL                                       // nonzero = success
```

### Step 4 — Get LoadLibraryA's address

```
GetModuleHandleA(
    lpmodulename: PCSTR,  // null-terminated name of a DLL already in this process
) -> Result<HMODULE>      // the DLL's base address (same value in all processes this session)
```

```
GetProcAddress(
    hmodule: HMODULE,    // module to search — the kernel32 handle from above
    lpprocname: PCSTR,   // exported function name (null-terminated)
) -> Option<FARPROC>     // opaque function pointer — transmute to LPTHREAD_START_ROUTINE
```

`FARPROC` is `Option<unsafe extern "system" fn() -> isize>` — the return type is intentionally unspecified. Use `transmute` to get `LPTHREAD_START_ROUTINE`.

Feature flag: `Win32_System_LibraryLoader`

### Step 5 — Spawn the remote thread

```
CreateRemoteThread(
    hprocess: HANDLE,                                    // target process handle
    lpthreadattributes: Option<*const SECURITY_ATTRIBUTES>, // thread security — None for default
    dwstacksize: usize,                                  // stack size — 0 uses system default
    lpstartaddress: LPTHREAD_START_ROUTINE,              // LoadLibraryA's address
    lpparameter: Option<*const c_void>,                  // argument to pass — remote path pointer
    dwcreationflags: u32,                                // 0 = start immediately
    lpthreadid: Option<*mut u32>,                        // out-param for thread ID — None
) -> Result<HANDLE>                                      // handle to the created thread
```

`lpparameter` is `Some(remote_path as *const c_void)`. The target thread runs `LoadLibraryA(remote_path)` — your path string becomes its argument.

---

## Acceptance Criteria

- [ ] `cargo build --target x86_64-pc-windows-gnu -p dll-payload` produces a `.dll`
- [ ] `cargo build --target x86_64-pc-windows-gnu -p dll-injection` produces a `.exe`
- [ ] Only the `.exe` is needed on the VM — it drops and injects the DLL itself
- [ ] Injecting into `notepad.exe` produces a visible effect
- [ ] All Win32 errors checked
- [ ] `OpenProcess` requests only the three rights it actually uses
- [ ] No `VirtualProtectEx` — the path region stays `PAGE_READWRITE` (it's data, never executed)

---

## Key Types

**`HMODULE`** — handle to a loaded module; numerically its base address. Because kernel32 loads at the same address in all processes per session, a locally-obtained handle is valid everywhere.

**`FARPROC`** — `Option<unsafe extern "system" fn() -> isize>`. Returned by `GetProcAddress`. Type is deliberately opaque — `transmute` to whatever you need.

**`PCSTR`** — `*const u8` to a null-terminated ANSI string. Construct: `PCSTR(b"name\0".as_ptr())`. Lives in `windows::core`.

**`CString`** — Rust's owned null-terminated string (`std::ffi::CString`). Use `as_bytes_with_nul()` to get a `&[u8]` with the terminator included for passing to Win32.

---

## Hints

- Build order: `dll-payload` first, then `dll-injection`. The `include_bytes!` path points to the workspace target directory.
- `GetModuleHandleA` + `GetProcAddress` are in the `Win32_System_LibraryLoader` feature flag.
- `transmute` the `FARPROC` result directly to `LPTHREAD_START_ROUTINE` — same pattern as casting the shellcode pointer in Module 01.
- `dll_path_bytes` from `CString::as_bytes_with_nul()` already has the null terminator. Use its `.len()` for `VirtualAllocEx` and `WriteProcessMemory`.
- No `VirtualProtectEx` this time — you're not executing the remote allocation, only reading it.

---

## What's still missing (next modules)

The DLL touches disk, even briefly. Two techniques eliminate that:

- **Reflective DLL loading** — embed a custom loader inside the DLL; write the raw bytes into remote memory and jump to the loader instead of using `LoadLibraryA`. No file needed.
- **Process hollowing** — replace a suspended process's image in memory with your own PE. No injection at all.

Both are later modules.

---

## Submission

Paste both `03-dll-payload/src/lib.rs` and `03-dll-injection/src/main.rs` and ask for a review.
