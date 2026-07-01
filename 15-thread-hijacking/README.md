# Module 15 — Thread Hijacking

## Concept

**Thread hijacking** (also called *thread context manipulation*) redirects a *running* thread in an existing process to execute your shellcode. The sequence is:

1. Suspend the thread so its register state is frozen and readable.
2. Write shellcode into the process's memory.
3. Read the thread's current register context.
4. Change the instruction pointer (`RIP`) to point at the shellcode.
5. Apply the modified context and resume the thread.

The thread wakes up at the shellcode address instead of where it was. No new thread is created. From an observer's perspective, the shellcode executes inside a thread that has been running since the process started.

### How it differs from prior injection techniques

| | Module 02 (shellcode injection) | Module 04 (process hollowing) | Module 14 (APC) | Module 15 (thread hijacking) |
|---|---|---|---|---|
| Target process state | Already running | We create it suspended | We create it suspended | Already running |
| Execution mechanism | New thread via CreateRemoteThread | Resume suspended main thread | APC on existing thread | Redirect RIP of existing thread |
| New thread created | Yes | No | No | No |
| Thread visible before shellcode | Yes (briefly) | No | No | No (same thread, no new thread) |
| Process enumeration needed | No | No | No | Yes — need to find a thread in the target |

The key challenge in thread hijacking is **timing**: if you redirect `RIP` while the thread is mid-instruction (inside a multi-byte x64 instruction), execution will start at the wrong byte and crash. Suspending the thread first puts it into a safe state — typically waiting in a kernel syscall — making the context snapshot reliable.

---

## The hijacking sequence

1. Spawn `notepad.exe` (not suspended — it will be running).
2. `CreateToolhelp32Snapshot` + `Thread32First`/`Thread32Next` — find a thread belonging to notepad.
3. `OpenProcess` — get a handle to the target process with memory read/write access.
4. `OpenThread` — get a handle to the target thread.
5. `SuspendThread` — freeze the thread; its register state is now stable.
6. `VirtualAllocEx` + `WriteProcessMemory` — inject shellcode into the target process.
7. `GetThreadContext` — read the thread's registers.
8. Modify `ctx.Rip` to point at the shellcode.
9. `SetThreadContext` — apply the modified registers.
10. `ResumeThread` — the thread wakes at the shellcode address.

---

## Task

Implement the hijacker in ten steps. The skeleton in `src/main.rs` has a `todo!()` for each step.

### Step 1 — Spawn the target process

```
CreateProcessA(
    lpapplicationname: PCSTR,                              // b"notepad.exe\0"
    lpcommandline: PSTR,                                   // None
    lpprocessattributes: Option<*const SECURITY_ATTRIBUTES>, // None
    lpthreadattributes: Option<*const SECURITY_ATTRIBUTES>,  // None
    binherithandles: BOOL,                                 // false
    dwcreationflags: PROCESS_CREATION_FLAGS,               // PROCESS_CREATION_FLAGS(0) — not suspended
    lpenvironment: Option<*const c_void>,                  // None
    lpcurrentdirectory: PCSTR,                             // None
    lpstartupinfo: *const STARTUPINFOA,                    // &si (cb must be set)
    lpprocessinformation: *mut PROCESS_INFORMATION,        // &mut pi — gives us dwProcessId
) -> Result<()>
```

After the call, `pi.dwProcessId` holds the PID of the new notepad process. Call `Sleep(200)` to give notepad time to initialize before you suspend one of its threads.

### Step 2 — Open the target process

```
OpenProcess(
    dwdesiredaccess: PROCESS_ACCESS_RIGHTS, // PROCESS_ALL_ACCESS — needed for VirtualAllocEx and WriteProcessMemory
    binherithandle: BOOL,                   // false
    dwprocessid: u32,                       // pi.dwProcessId
) -> Result<HANDLE>
```

### Step 3 — Enumerate threads to find one in the target process

Take a system-wide snapshot of all threads, then iterate to find one owned by the target process.

```
CreateToolhelp32Snapshot(
    dwflags: CREATE_TOOLHELP_SNAPSHOT_FLAGS, // TH32CS_SNAPTHREAD — snapshot all threads
    th32processid: u32,                      // 0 — system-wide (not filtered by process)
) -> Result<HANDLE>                          // snapshot handle; close with CloseHandle when done
```

Then iterate:

```
Thread32First(
    hsnapshot: HANDLE,       // snapshot handle
    lpte: *mut THREADENTRY32, // pointer to your THREADENTRY32 struct (dwSize must be pre-set)
) -> Result<()>              // Err if snapshot is empty

Thread32Next(
    hsnapshot: HANDLE,       // snapshot handle
    lpte: *mut THREADENTRY32, // same struct — updated on each call
) -> Result<()>              // Err when no more entries remain
```

`THREADENTRY32` must have `dwSize` set to `mem::size_of::<THREADENTRY32>() as u32` before the first call. Key fields: `th32OwnerProcessID` (compare to your target PID), `th32ThreadID` (save this when you find a match).

### Step 4 — Open the target thread

```
OpenThread(
    dwdesiredaccess: THREAD_ACCESS_RIGHTS, // THREAD_ALL_ACCESS
    binherithandle: BOOL,                  // false
    dwthreadid: u32,                       // target_tid found in step 3
) -> Result<HANDLE>
```

### Step 5 — Suspend the thread

```
SuspendThread(
    hthread: HANDLE, // the thread handle from step 4
) -> u32            // previous suspend count; 0xFFFFFFFF on failure
```

You must suspend before reading the context. A running thread's registers change continuously — `GetThreadContext` on a running thread produces a snapshot that may be mid-update.

### Step 6 — Allocate and write shellcode

```
VirtualAllocEx(
    hprocess: HANDLE,                          // h_process from step 2
    lpaddress: Option<*const c_void>,          // None — OS chooses
    dwsize: usize,                             // SHELLCODE.len()
    flallocationtype: VIRTUAL_ALLOCATION_TYPE, // MEM_COMMIT | MEM_RESERVE
    flprotect: PAGE_PROTECTION_FLAGS,          // PAGE_EXECUTE_READWRITE
) -> *mut c_void

WriteProcessMemory(
    hprocess: HANDLE,                           // h_process
    lpbaseaddress: *const c_void,               // remote_buf from VirtualAllocEx
    lpbuffer: *const c_void,                    // SHELLCODE.as_ptr() as *const c_void
    nsize: usize,                               // SHELLCODE.len()
    lpnumberofbyteswritten: Option<*mut usize>, // None
) -> Result<()>
```

### Step 7 — Read the thread's register context

```
GetThreadContext(
    hthread: HANDLE,         // h_thread — must be suspended
    lpcontext: *mut CONTEXT, // &mut ctx — ContextFlags must be set BEFORE this call
) -> Result<()>
```

`CONTEXT` must have `ContextFlags` set before calling. Use `CONTEXT_FULL` to capture all registers. `ctx.Rip` is the current instruction pointer — save it if you want to restore the thread later.

### Step 8 — Redirect RIP

```rust
ctx.Rip = remote_buf as u64;
```

`ctx.Rip` is a direct `u64` field on the x64 `CONTEXT` struct. Set it to the address of the remote shellcode allocation.

### Step 9 — Apply the modified context

```
SetThreadContext(
    hthread: HANDLE,           // h_thread — must still be suspended
    lpcontext: *const CONTEXT, // &ctx — the modified context with new Rip
) -> Result<()>
```

### Step 10 — Resume the thread

```
ResumeThread(
    hthread: HANDLE, // h_thread
) -> u32            // previous suspend count (1); 0xFFFFFFFF on failure
```

The thread resumes at `remote_buf`, executing your shellcode.

---

## Thread enumeration note

`TH32CS_SNAPTHREAD` with `th32processid = 0` snapshots **all** threads on the system. You must filter by `th32OwnerProcessID` to find threads belonging to your target. This is intentional — in a real scenario you wouldn't know which process spawned the target thread.

The loop pattern:
```rust
// pseudo-code only — implement this yourself
Thread32First(snap, &mut te).unwrap();
loop {
    if te.th32OwnerProcessID == target_pid {
        target_tid = te.th32ThreadID;
        break;
    }
    if Thread32Next(snap, &mut te).is_err() { break; }
}
```

---

## Acceptance Criteria

- [ ] `cargo build --target x86_64-pc-windows-gnu -p thread-hijacking` succeeds
- [ ] Running `thread-hijacking.exe` on the VM opens `calc.exe`
- [ ] No new thread appears in Process Explorer before calc pops (compare with module 02)
- [ ] `SuspendThread` is called before `GetThreadContext`
- [ ] `VirtualAllocEx` NULL return is checked
- [ ] `SuspendThread` failure (`0xFFFFFFFF`) is checked
- [ ] `ResumeThread` failure is checked
- [ ] `CloseHandle` is called on the snapshot, process, and thread handles

---

## Key Types

**`THREADENTRY32`** — represents one thread in the system. Set `dwSize = mem::size_of::<THREADENTRY32>() as u32` before `Thread32First`. Key fields: `th32ThreadID` (thread ID to pass to `OpenThread`), `th32OwnerProcessID` (use this to filter for your target process).

**`CONTEXT`** — x64 thread register state. Set `ContextFlags = CONTEXT_FULL` before calling `GetThreadContext`. `Rip` is the instruction pointer. `Rsp` is the stack pointer. All general-purpose registers are direct `u64` fields.

**`THREAD_ACCESS_RIGHTS`** — access mask for `OpenThread`. Use `THREAD_ALL_ACCESS` for this exercise. In production code you'd request only what you need (`THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT`).

---

## Hints

- Call `Sleep(200)` after spawning notepad, before enumerating threads. If you enumerate too early, notepad may not have initialized its threads yet.
- The snapshot from `CreateToolhelp32Snapshot` is a static snapshot taken at the moment of the call. Changes to threads after that point are not reflected. Close it with `CloseHandle` after you're done iterating.
- `SuspendThread` increments the suspend count; `ResumeThread` decrements it. A thread runs when its count reaches 0. If you call `SuspendThread` twice, you need two `ResumeThread` calls to actually wake it.
- **Context restoration**: the shellcode from this module (calc.exe) exits the process, so restoration doesn't matter here. But for shellcode that returns, you'd need to: (a) save `original_rip` before modification, (b) after shellcode returns, call `SuspendThread` again, read context, set `Rip` back to `original_rip`, call `SetThreadContext`, then `ResumeThread`. This lets the original thread continue as if nothing happened.
- The safe hijack point problem: `SuspendThread` can interrupt a thread mid-instruction or in a non-reentrant region. For calc shellcode that exits the process this doesn't matter, but for shellcode that returns, you should check that the thread is inside a syscall before hijacking (advanced: use `RtlWalkFrameChain` to inspect the call stack).
- Compare the thread list in Process Explorer before running this tool vs. module 02. Module 02 briefly shows a foreign thread; this module never creates one.

---

## Submission

Paste `15-thread-hijacking/src/main.rs` and ask for a review.
