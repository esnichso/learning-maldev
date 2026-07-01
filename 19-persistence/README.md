# Module 19 — Persistence

## Concept

Malware that only runs once is useless. **Persistence** is the set of techniques that make your payload survive across reboots, logouts, and process restarts. The central tension is **noise vs. stealth**: the easiest mechanisms are the first thing defenders check; the quietest require more setup and often specific conditions.

This module implements four persistence mechanisms, ordered from most to least detectable, so you can observe the spectrum directly.

---

## Mechanism Comparison

| Mechanism | Where it lives | Noise level | Requires admin | Detection |
|---|---|---|---|---|
| Run key | `HKCU\...\Run` | Very high | No | Checked by every AV and EDR on boot |
| Startup folder | `%APPDATA%\...\Startup` | High | No | Trivially visible; AV checks on write |
| Scheduled task | Task Scheduler | Medium | No (current user) | `schtasks /query` shows it; ETW logs creation |
| COM object hijack | `HKCU\Software\Classes\CLSID\...` | Low | No | Only detected when the hijacked class is loaded |
| WMI subscription | WMI repository | Very low | Yes | Rarely checked; fileless; survives reimaging |

This module covers the first four. WMI subscriptions are complex enough for their own exercise — see FUTURE_TOPICS.md if you want to go further.

---

## Win32 APIs

### Registry

```
RegCreateKeyExA(
    hkey: HKEY,                                    // root key — HKEY_CURRENT_USER or HKEY_LOCAL_MACHINE
    lpsubkey: PCSTR,                               // subkey path to create or open
    reserved: u32,                                 // must be 0
    lpclass: PCSTR,                                // PCSTR::null() — unused
    dwoptions: REG_OPEN_CREATE_OPTIONS,            // REG_OPTION_NON_VOLATILE — persists across reboots
    samdesired: REG_SAM_FLAGS,                     // access mask — KEY_SET_VALUE is enough for writing
    lpsecurityattributes: Option<*const SECURITY_ATTRIBUTES>, // None
    phkresult: *mut HKEY,                          // out: handle to the key
    lpdwdisposition: Option<*mut REG_CREATE_KEY_DISPOSITION>, // None — don't care if created vs. opened
) -> WIN32_ERROR                                   // 0 = ERROR_SUCCESS
```

```
RegSetValueExA(
    hkey: HKEY,             // handle from RegCreateKeyExA
    lpvaluename: PCSTR,     // name of the value; PCSTR::null() or empty string sets the (Default) value
    reserved: u32,          // must be 0
    dwtype: REG_VALUE_TYPE, // REG_SZ for a null-terminated string
    lpdata: *const u8,      // pointer to the data (e.g. a path string's bytes)
    cbdata: u32,            // byte length INCLUDING the null terminator
) -> WIN32_ERROR            // 0 = ERROR_SUCCESS
```

```
RegCloseKey(
    hkey: HKEY,  // handle to close
) -> WIN32_ERROR
```

### Shell (startup folder)

```
SHGetFolderPathA(
    hwnd: HWND,        // None — no window
    csidl: i32,        // CSIDL_STARTUP (0x0007) — current user's Startup folder
    htoken: HANDLE,    // None — current user
    dwflags: u32,      // 0 — return the verified path
    pszpath: PSTR,     // out: buffer of MAX_PATH bytes that receives the folder path
) -> HRESULT           // S_OK (0) on success
```

```
CopyFileA(
    lpexistingfilename: PCSTR, // path to the source file
    lpnewfilename: PCSTR,      // destination path (in the Startup folder)
    bfailifexists: BOOL,       // FALSE — overwrite if the file is already there
) -> BOOL                      // TRUE on success; FALSE + GetLastError() on failure
```

### Process creation (for scheduled task via schtasks.exe)

```
CreateProcessA(
    lpapplicationname: PCSTR,                   // None — derive from command line
    lpcommandline: PSTR,                        // mutable buffer — Windows may modify it
    lpprocessattributes: Option<...>,           // None
    lpthreadattributes: Option<...>,            // None
    binherithandles: BOOL,                      // FALSE
    dwcreationflags: PROCESS_CREATION_FLAGS,    // 0 — no special flags needed
    lpenvironment: Option<*const c_void>,       // None
    lpcurrentdirectory: PCSTR,                  // None — inherit parent's working directory
    lpstartupinfo: *const STARTUPINFOA,         // &si — cb field must be set to size_of::<STARTUPINFOA>()
    lpprocessinformation: *mut PROCESS_INFORMATION, // &mut pi — receives process and thread handles
) -> Result<()>
```

---

## Task

Implement four persistence methods in `src/main.rs`. The skeleton has a `todo!()` for each step. The payload used for testing is `C:\Windows\System32\calc.exe` (hardcoded constant `PAYLOAD_PATH`).

### Method 1 — Run key

**Step 1 — Open the Run key.**

Call `RegCreateKeyExA` with `HKEY_CURRENT_USER` and the path `Software\Microsoft\Windows\CurrentVersion\Run`. Use `REG_OPTION_NON_VOLATILE` and `KEY_SET_VALUE`. Store the resulting handle in `hkey`.

**Step 2 — Write the value.**

Call `RegSetValueExA` with the key handle, the value name `"MaldevTest"`, `REG_SZ`, and `PAYLOAD_PATH` as the data. The `cbdata` parameter is the byte length of `PAYLOAD_PATH` including the null terminator.

**Step 3 — Close the key.** Call `RegCloseKey(hkey)`.

After implementing: open `regedit.exe` on the VM, navigate to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, and confirm `MaldevTest` appears.

---

### Method 2 — Startup folder

**Step 4 — Get the Startup folder path.**

Call `SHGetFolderPathA` with `CSIDL_STARTUP` (integer `0x0007`) into a `[u8; 260]` buffer. The result is something like `C:\Users\<name>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`.

**Step 5 — Write a batch file into the folder.**

Two sub-steps:
1. Write a small `.bat` file somewhere writable (e.g. `C:\Temp\start.bat`) containing: `@echo off\r\nstart C:\Windows\System32\calc.exe\r\n`
2. Call `CopyFileA` to copy it to `<startup_path>\MaldevTest.bat`

Build the destination path by concatenating the startup folder path (as a string) with `\MaldevTest.bat`.

After implementing: log out and back in on the VM — `calc.exe` should launch.

---

### Method 3 — Scheduled task

**Step 6 — Spawn schtasks.exe with /create.**

Build the command string:
```
schtasks /create /tn "MaldevTest" /tr "C:\Windows\System32\calc.exe" /sc onlogon /f
```

Pass it as a `Vec<u8>` (mutable, null-terminated) to `CreateProcessA` as `lpcommandline`. After the call, wait for schtasks to finish with `WaitForSingleObject(pi.hProcess, INFINITE)`, then close both handles.

The `/f` flag forces overwrite if the task exists; `/sc onlogon` runs it at login.

> **README note on the COM API approach:** `schtasks.exe` is used here for simplicity. The production approach uses the `ITaskService` COM interface: `CoCreateInstance(CLSID_TaskScheduler, ...)` → `ITaskService::Connect(...)` → `ITaskService::GetFolder(...)` → `ITaskFolder::RegisterTaskDefinition(...)`. This gives full control over triggers, actions, and settings without spawning a subprocess. See [MS-TSCH] documentation.

After implementing: run `schtasks /query /tn MaldevTest` on the VM to confirm.

---

### Method 4 — COM object hijacking

**Step 7 — Create the CLSID key under HKCU.**

Call `RegCreateKeyExA` with `HKEY_CURRENT_USER` and:
```
Software\Classes\CLSID\{B54F3741-5B07-11CF-A4B0-00AA004A55E8}\InprocServer32
```

This is the VBScript engine CLSID — loaded by many Office macros and scripting hosts. Any process that instantiates `VBScript.RegExp` will now load your DLL instead.

**Step 8 — Set the (Default) value to the payload DLL path.**

Call `RegSetValueExA` with `PCSTR::null()` as the value name — this sets the key's `(Default)` entry. The data is your DLL path.

**Step 9 — Set ThreadingModel.**

Call `RegSetValueExA` again with value name `"ThreadingModel"` and data `"Both"`. Without this, COM may refuse to load the server in some contexts.

Close the key.

> **Why HKCU?** Windows COM resolution checks `HKCU\Software\Classes` before `HKLM\SOFTWARE\Classes`. Registering in HKCU requires no admin rights and does not affect other users. The hijack is active as long as the HKCU key exists.

After implementing: verify the key exists in regedit under `HKCU\Software\Classes\CLSID\{B54F3741...}\InprocServer32`.

---

## Acceptance Criteria

- [ ] `cargo build --target x86_64-pc-windows-gnu -p persistence` succeeds
- [ ] Method 1: `HKCU\...\Run\MaldevTest` exists in regedit after running
- [ ] Method 2: `MaldevTest.bat` appears in the Startup folder
- [ ] Method 3: `schtasks /query /tn MaldevTest` shows the task
- [ ] Method 4: `HKCU\Software\Classes\CLSID\{B54F3741...}\InprocServer32` key exists with correct default value
- [ ] All `WIN32_ERROR` returns from registry APIs checked (`!= 0` triggers a panic or error message)
- [ ] All `BOOL` returns from `CopyFileA` checked
- [ ] Handles closed after use (`RegCloseKey`, `CloseHandle` for `pi.hProcess`/`pi.hThread`)

---

## Key Concepts

**`HKEY_CURRENT_USER` vs `HKEY_LOCAL_MACHINE`**: HKCU writes require no admin and affect only the current user. HKLM writes affect all users but require admin. For stealth, prefer HKCU — you get equivalent effect for the current user, with less noise and no UAC prompt.

**`REG_SZ` vs `REG_EXPAND_SZ`**: `REG_SZ` is a plain string. `REG_EXPAND_SZ` allows environment variables like `%USERPROFILE%`. For compatibility, use `REG_EXPAND_SZ` for paths that contain env vars.

**COM hijacking requires a DLL**: the `InprocServer32` default value must point to a DLL with `DllGetClassObject` exported, not an EXE. For a real exercise, build a minimal DLL payload and point the key at it. Module 03 showed you how to build a DLL.

**Cleanup**: run `reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v MaldevTest /f` and similar commands on the VM to clean up between tests.

---

## Hints

- `RegCreateKeyExA` takes a `PCSTR` for the subkey — wrap a `b"...\0"` byte literal: `PCSTR(subkey.as_ptr())`.
- `cbdata` in `RegSetValueExA` is the byte count INCLUDING the null terminator. For `b"value\0"`, `cbdata` is 6.
- To build the startup folder destination path: convert the `[u8; 260]` buffer to a `&str` (trim at the first null byte), append `\\MaldevTest.bat`, then re-encode as a null-terminated byte string.
- The scheduled task approach (`schtasks.exe`) produces event log entries in `Microsoft-Windows-TaskScheduler/Operational`. For lower noise use the `ITaskService` COM interface directly.
- COM hijacking: to test without building a DLL, try pointing `InprocServer32` at a system DLL that already exists (e.g., `shell32.dll`). Observe that COM loads it without errors. Then swap for your own DLL.

---

## Submission

Paste `19-persistence/src/main.rs` and ask for a review.
