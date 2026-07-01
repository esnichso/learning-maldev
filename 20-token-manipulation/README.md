# Module 20 — Token Manipulation

## Concept

Every process and thread in Windows runs under an **access token** — a kernel object that records the user identity, group memberships, integrity level, and set of privileges the subject is allowed to use. When a Win32 API call checks "is the caller allowed to do X?", it reads the token.

Token manipulation lets you **borrow** the identity of another process without knowing its password. The general flow:
1. Enable `SeDebugPrivilege` on your own token so you can open any process.
2. Open a high-privileged process (e.g., `winlogon.exe`, which always runs as SYSTEM).
3. Get a handle to its token.
4. Duplicate the token into a new primary token.
5. Use `CreateProcessWithTokenW` to spawn a process that runs under that identity.

The spawned process is fully independent and runs as SYSTEM — `whoami` inside it returns `nt authority\system`.

---

## Token Types

| Type | Purpose |
|---|---|
| **Primary token** | Assigned to a process at creation. Used by the OS to determine what the process can do. |
| **Impersonation token** | Attached temporarily to a thread. Lets a server thread act on behalf of a client. Comes in four levels: Anonymous, Identification, Impersonation, Delegation. |

`DuplicateTokenEx` can produce either type. To spawn a new process you need a **primary token**. To impersonate in-thread (e.g., for a single API call) you need an **impersonation token** passed to `ImpersonateLoggedOnUser`.

---

## Integrity Levels

Windows Vista+ added **mandatory integrity control**: every subject and object gets a level, and lower-integrity subjects cannot write to higher-integrity objects.

| Level | Typical subject |
|---|---|
| Low | Protected Mode IE, sandboxed browsers |
| Medium | Standard user processes |
| High | Elevated (admin, UAC-elevated) processes |
| System | Services, winlogon, lsass |
| Protected Process | Anticheat, PPL-protected processes |

When you steal a SYSTEM token, you inherit System integrity. This unlocks access to files, registry keys, and APIs gated at that level.

---

## SeDebugPrivilege

Windows grants `SeDebugPrivilege` to administrators by default but keeps it **disabled** in the token — the privilege is present but inactive. You must enable it with `AdjustTokenPrivileges` before it takes effect.

Once enabled, `SeDebugPrivilege` overrides the DACL check in `OpenProcess` — you can open any user-mode process, including SYSTEM processes, regardless of their security descriptor. This is why it's the master key for privilege escalation.

> **Detection note**: Enabling `SeDebugPrivilege` is logged in Security event logs (Event ID 4703) when auditing is configured. EDRs also watch for this pattern closely.

---

## Win32 APIs

### Token APIs

```
OpenProcessToken(
    processhandle: HANDLE,            // handle to the target process
    desiredaccess: TOKEN_ACCESS_MASK, // what you need: TOKEN_QUERY, TOKEN_DUPLICATE, TOKEN_ADJUST_PRIVILEGES
    tokenhandle: *mut HANDLE,         // out: handle to the token
) -> Result<()>
```

```
LookupPrivilegeValueA(
    lpsystemname: PCSTR,  // None — query the local system
    lpname: PCSTR,        // privilege name string, e.g. b"SeDebugPrivilege\0"
    lpluid: *mut LUID,    // out: the LUID for this privilege on this boot
) -> Result<()>           // LUIDs are not stable across reboots — always look them up
```

```
AdjustTokenPrivileges(
    tokenhandle: HANDLE,                       // handle from OpenProcessToken with TOKEN_ADJUST_PRIVILEGES
    disableallprivileges: BOOL,                // FALSE — we are adjusting, not disabling everything
    newstate: Option<*const TOKEN_PRIVILEGES>, // pointer to TOKEN_PRIVILEGES describing changes
    bufferlength: u32,                         // size of PreviousState buffer — 0 if not needed
    previousstate: Option<*mut TOKEN_PRIVILEGES>, // None — don't capture the previous state
    returnlength: Option<*mut u32>,            // None
) -> Result<()>
// IMPORTANT: returns Ok(()) even if the privilege was not assigned.
// Check GetLastError() == ERROR_SUCCESS (0) after the call to confirm.
```

```
DuplicateTokenEx(
    hexistingtoken: HANDLE,                              // source token (must have TOKEN_DUPLICATE)
    dwdesiredaccess: TOKEN_ACCESS_MASK,                  // TOKEN_ALL_ACCESS for a fully usable duplicate
    lptokenattributes: Option<*const SECURITY_ATTRIBUTES>, // None — default security
    impersonationlevel: SECURITY_IMPERSONATION_LEVEL,    // SecurityImpersonation (or SecurityDelegation)
    tokentype: TOKEN_TYPE,                               // TokenPrimary (for CreateProcessWithTokenW)
                                                         // or TokenImpersonation (for ImpersonateLoggedOnUser)
    phnewtoken: *mut HANDLE,                             // out: the duplicate token
) -> Result<()>
```

```
CreateProcessWithTokenW(
    htoken: HANDLE,                               // primary token — determines the new process's identity
    dwlogonflags: CREATE_PROCESS_WITH_TOKEN_FLAGS, // 0 — no special logon behavior
    lpapplicationname: PCWSTR,                    // None — derive from command line
    lpcommandline: PWSTR,                         // mutable wide-string command — Windows may modify it
    dwcreationflags: PROCESS_CREATION_FLAGS,      // 0 — no special creation flags
    lpenvironment: Option<*const c_void>,         // None — inherit environment
    lpcurrentdirectory: PCWSTR,                   // None — inherit working directory
    lpstartupinfo: *const STARTUPINFOW,           // &si — use the wide version (STARTUPINFOW, not A)
    lpprocessinformation: *mut PROCESS_INFORMATION, // &mut pi — receives handles for the new process
) -> Result<()>
// Requires SeAssignPrimaryTokenPrivilege or SeIncreaseQuotaPrivilege — both are held by SYSTEM
```

### Process enumeration

```
CreateToolhelp32Snapshot(
    dwflags: CREATE_TOOLHELP_SNAPSHOT_FLAGS, // TH32CS_SNAPPROCESS — snapshot the process list
    th32processid: u32,                      // 0 — all processes
) -> Result<HANDLE>                          // handle to the snapshot; close with CloseHandle
```

```
Process32First(
    hsnapshot: HANDLE,        // snapshot handle
    lppe: *mut PROCESSENTRY32, // out: first entry; dwSize MUST be set before calling
) -> Result<()>               // Err if snapshot is empty
```

```
Process32Next(
    hsnapshot: HANDLE,
    lppe: *mut PROCESSENTRY32, // out: next entry (reuse the same struct)
) -> Result<()>               // Err when there are no more entries — loop termination
```

`PROCESSENTRY32` fields you need:
- `dwSize: u32` — must be set to `mem::size_of::<PROCESSENTRY32>() as u32` before the first call
- `th32ProcessID: u32` — the PID
- `szExeFile: [i8; 260]` — the image name (not the full path), null-terminated

---

## Task

Implement `enable_sedebug`, `find_pid`, and `steal_token_and_spawn` in `src/main.rs`. Each function has `todo!()` stubs with hints.

### Phase 1 — Enable SeDebugPrivilege (in `enable_sedebug`)

**Step 1** — Call `OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut htoken)` to get a handle to your own process token.

**Step 2** — Call `LookupPrivilegeValueA` for `"SeDebugPrivilege"` to get its boot-specific LUID.

**Step 3** — Build a `TOKEN_PRIVILEGES` struct:
```rust
let tp = TOKEN_PRIVILEGES {
    PrivilegeCount: 1,
    Privileges: [LUID_AND_ATTRIBUTES {
        Luid: luid,
        Attributes: SE_PRIVILEGE_ENABLED,
    }],
};
```
Call `AdjustTokenPrivileges(htoken, FALSE, &tp, 0, None, None)`. Then check `GetLastError() == 0` — the function lies about success; only the error code is authoritative.

---

### Phase 2 — Find winlogon.exe (in `find_pid`)

**Step 4** — Call `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` to get a snapshot handle.

**Step 5** — Set `pe.dwSize = mem::size_of::<PROCESSENTRY32>() as u32`, then call `Process32First`. Loop with `Process32Next` until you find an entry whose `szExeFile` matches `target_name`. Store `pe.th32ProcessID` in `pid`. Close the snapshot handle.

To compare `szExeFile` (which is `[i8; 260]`): cast to `*const u8`, take a slice up to the null byte, and compare with the target bytes.

---

### Phase 3 — Steal the token and spawn (in `steal_token_and_spawn`)

**Step 6** — Call `OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, target_pid)` to get a handle to winlogon.exe.

**Step 7** — Call `OpenProcessToken(hproc, TOKEN_DUPLICATE, &mut htoken_src)` to get winlogon's token.

**Step 8** — Call `DuplicateTokenEx(htoken_src, TOKEN_ALL_ACCESS, None, SecurityImpersonation, TokenPrimary, &mut htoken_duped)` to clone it as a primary token.

**Step 9** — Build the wide command string: `"cmd.exe\0"` encoded as `Vec<u16>`. Call `CreateProcessWithTokenW` with the duplicated token. The spawned cmd.exe runs as SYSTEM.

---

## Acceptance Criteria

- [ ] `cargo build --target x86_64-pc-windows-gnu -p token-manipulation` succeeds
- [ ] Running as an administrator on the VM: a new `cmd.exe` window opens
- [ ] Inside that cmd.exe: `whoami` outputs `nt authority\system`
- [ ] `GetLastError()` checked after `AdjustTokenPrivileges` to confirm `ERROR_SUCCESS`
- [ ] All handles closed in correct order (inner handles before outer)
- [ ] `OpenProcess` failure (non-admin or SeDebugPrivilege not enabled) produces a meaningful error message rather than a panic with no context

---

## Hints

- `AdjustTokenPrivileges` always returns `Ok(())` even when the privilege was not granted. Call `GetLastError()` immediately after — `ERROR_SUCCESS` (0) means success; `ERROR_NOT_ALL_ASSIGNED` (1300) means the privilege isn't in the token at all (you're not running as admin).
- `szExeFile` is `[i8; 260]`. Cast to `*const u8` with `pe.szExeFile.as_ptr() as *const u8`, then slice up to the first `0i8` byte (null terminator) for comparison.
- `CreateProcessWithTokenW` requires **wide strings** (`PCWSTR`/`PWSTR`). Use `"cmd.exe\0".encode_utf16().collect::<Vec<u16>>()` and pass `PWSTR(cmd.as_mut_ptr())`.
- The `CreateProcessWithTokenW` call will fail with `ERROR_PRIVILEGE_NOT_HELD` if you don't also have `SeAssignPrimaryTokenPrivilege` or `SeIncreaseQuotaPrivilege`. These are held by SYSTEM — but since we are using winlogon's token (which is SYSTEM), the duplicated token carries them and the call succeeds.
- If `winlogon.exe` has multiple instances (multiple sessions), find the one in session 0. Check `pe.th32SessionID == 0` when iterating — though usually only one instance runs there.
- `TOKEN_ADJUST_PRIVILEGES` is an associated constant on `TOKEN_ACCESS_MASK`, so it's written as `TOKEN_ADJUST_PRIVILEGES` not `TOKEN_ACCESS_MASK::TOKEN_ADJUST_PRIVILEGES`. Same for `TOKEN_QUERY`, `TOKEN_DUPLICATE`, `TOKEN_ALL_ACCESS`.

---

## Submission

Paste `20-token-manipulation/src/main.rs` and ask for a review.
