# Module 02 — Process Injection

## Concept

**Process injection** writes and executes code inside a *different* process. Instead of running shellcode in your own process (Module 01), you target a process already running on the system — e.g. `notepad.exe`, `explorer.exe`, or any other.

Why? Your malicious code now runs under the identity of a legitimate process. Memory scanners see the host process, not yours. Network connections appear to come from the host. Basic AV/EDR solutions that only watch for suspicious new processes won't catch it.

### The classic injection sequence

```
OpenProcess          →  get a handle to the target
VirtualAllocEx       →  allocate memory inside the target's address space
WriteProcessMemory   →  copy shellcode into that allocation
CreateRemoteThread   →  make the target execute it
```

Each step crosses a process boundary — that's what makes this more complex than Module 01.

### Handle access rights

`OpenProcess` requires you to specify what you want to do with the handle:

| Right | Meaning |
|---|---|
| `PROCESS_VM_OPERATION` | Required for `VirtualAllocEx` |
| `PROCESS_VM_WRITE` | Required for `WriteProcessMemory` |
| `PROCESS_CREATE_THREAD` | Required for `CreateRemoteThread` |

You can OR these together: `PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD`.

### Finding a target PID

You need the Process ID (PID) of your target. Two options:

- **Hardcode it** — acceptable for this exercise; use Task Manager to find the PID of notepad.exe
- **Enumerate** — use the Toolhelp32 snapshot API to find a PID by process name (bonus task)

---

## Task

Implement classic remote process injection in `src/main.rs`.

The target process name is `notepad.exe` — launch it first in your VM.

### Step 1 — Find the target PID

**Option A (simple):** Hardcode the PID. Pass it as a command-line argument:
```
process-injection.exe <pid>
```
Parse it with `std::env::args()`.

**Option B (bonus):** Enumerate running processes using the Toolhelp32 API to find `notepad.exe` automatically:
```
CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
Process32First / Process32Next
PROCESSENTRY32W → szExeFile field
```

### Step 2 — Open the target process

```
OpenProcess(
    dwdesiredaccess: PROCESS_ACCESS_RIGHTS,
    binherithandle: BOOL,
    dwprocessid: u32,
) -> Result<HANDLE>
```

You need `PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD`.

### Step 3 — Allocate memory in the target

```
VirtualAllocEx(
    hprocess: HANDLE,
    lpaddress: Option<*const c_void>,
    dwsize: usize,
    flallocationtype: VIRTUAL_ALLOCATION_TYPE,
    flprotect: PAGE_PROTECTION_FLAGS,
) -> *mut c_void
```

Same pattern as `VirtualAlloc` from Module 01, but takes a process handle as the first argument.
Use `MEM_COMMIT | MEM_RESERVE` and `PAGE_READWRITE`.

### Step 4 — Write shellcode into the target

```
WriteProcessMemory(
    hprocess: HANDLE,
    lpbaseaddress: *const c_void,
    lpbuffer: *const c_void,
    nsize: usize,
    lpnumberofbyteswritten: Option<*mut usize>,
) -> BOOL
```

`lpbuffer` is a pointer to your local shellcode bytes. Cast `SHELLCODE.as_ptr()` to `*const c_void`.
Pass `None` for the bytes-written out-parameter unless you want to verify the count.

### Step 5 — Flip protection to RX

Use `VirtualProtectEx` (the cross-process variant of `VirtualProtect`):

```
VirtualProtectEx(
    hprocess: HANDLE,
    lpaddress: *const c_void,
    dwsize: usize,
    flnewprotect: PAGE_PROTECTION_FLAGS,
    lpfloldprotect: *mut PAGE_PROTECTION_FLAGS,
) -> BOOL
```

### Step 6 — Create a remote thread

```
CreateRemoteThread(
    hprocess: HANDLE,
    lpthreadattributes: Option<*const SECURITY_ATTRIBUTES>,
    dwstacksize: usize,
    lpstartaddress: LPTHREAD_START_ROUTINE,
    lpparameter: Option<*const c_void>,
    dwcreationflags: u32,
    lpthreadid: Option<*mut u32>,
) -> Result<HANDLE>
```

`lpstartaddress` is the remote address you got from `VirtualAllocEx`. Use `transmute` to cast it, same as `CreateThread` in Module 01.

Then `WaitForSingleObject(thread_handle, INFINITE)` to block until done.

---

## Acceptance Criteria

- [ ] Compiles: `cargo build --target x86_64-pc-windows-gnu`
- [ ] Injects into a running `notepad.exe` and executes calc.exe (or another payload)
- [ ] All Win32 errors are checked — no silent failures
- [ ] Final remote allocation is RX, not RWX
- [ ] `OpenProcess` asks for only the rights it actually needs

---

## Key types to know

**`HANDLE`** — an opaque pointer-sized value that refers to a kernel object (process, thread, file, etc). Most Win32 APIs return `Result<HANDLE>` in the `windows` crate. Handles must be closed with `CloseHandle` when done.

**`*const c_void` vs `*mut c_void`** — `c_void` is Rust's equivalent of C's `void*`. Many Win32 APIs take `*const c_void` for "pointer to something" and return `*mut c_void` for allocated memory. You cast between these and concrete types freely in `unsafe` code — the compiler won't stop you, so correctness is your responsibility.

**Cross-process pointers** — `VirtualAllocEx` returns a `*mut c_void` that is valid *in the target process's address space*, not yours. You cannot dereference it locally. You can only pass it back to cross-process APIs like `WriteProcessMemory` and `CreateRemoteThread`.

---

## Hints

- `PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD` — OR these together for `OpenProcess`.
- `WriteProcessMemory`'s `lpbuffer` parameter expects `*const c_void`. Cast with `SHELLCODE.as_ptr() as *const c_void`.
- The `VirtualProtectEx` feature flag is in `Win32_System_Memory`, same as `VirtualProtect`.
- If injection succeeds but the shellcode doesn't run, double-check that you flipped protection to `PAGE_EXECUTE_READ` *before* calling `CreateRemoteThread`.
- Use the same x64 shellcode from Module 01.

---

## Submission

Paste your completed `main.rs` in the chat and ask for a review.
