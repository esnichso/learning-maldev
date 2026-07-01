# Module 23 — SAM & Credential Dumping

## Concept

Windows stores local account credentials in the **Security Account Manager (SAM)** registry hive. The hashes it stores are NTLM hashes, encrypted with a **boot key** (also called SysKey) that lives in the **SYSTEM** hive. The **SECURITY** hive contains LSA secrets — service account passwords, domain cached credentials (DCC2 hashes), and machine account secrets.

To decrypt and use the credentials offline, you need all three:

| Hive | Registry path | What it contains |
|---|---|---|
| SAM | `HKLM\SAM` | NTLM hashes of local accounts, encrypted with the boot key |
| SYSTEM | `HKLM\SYSTEM` | Boot key (SysKey) — required to decrypt SAM |
| SECURITY | `HKLM\SECURITY` | LSA secrets, DCC2 domain cached hashes, machine account hash |

The OS keeps all three hive files locked and ACL-protected while running. Normal API calls return `ERROR_ACCESS_DENIED` even as a local Administrator.

### Why SeBackupPrivilege Works

`SeBackupPrivilege` is the "backup operator" privilege. It was designed to allow backup software to read files and registry keys regardless of their ACLs — because a backup operator needs to back up *everything*, not just what the current user has read access to.

When this privilege is enabled on your token **and** you open a registry key with the `REG_OPTION_BACKUP_RESTORE` flag, Windows bypasses the ACL check and grants access. Without that flag, the privilege is ignored even if it's present on your token — this is a common implementation mistake.

`RegSaveKeyA` then exports an entire hive subtree to a file, which you can carry offline and parse with tools like `secretsdump.py`.

### Detection

- `SeBackupPrivilege` is not held by most processes — enabling it on a regular process is a high-signal event for EDRs.
- `RegSaveKeyA` on SAM/SYSTEM/SECURITY generates Event ID **4663** (object access) and **4656** (handle request with backup privilege) in the Security log.
- A less-detectable alternative is Volume Shadow Copy Service (VSS): read the locked hive files through a shadow copy path without touching the live registry. The bonus section below covers the concept.

---

## Task

Implement a credential dumper that exports the three hives to `C:\Windows\Temp\`.

### Step 1 — Enable SeBackupPrivilege

Without this privilege your `RegOpenKeyExA` calls on SAM and SECURITY will fail with `ERROR_ACCESS_DENIED`, even running as a local Administrator. Administrator accounts hold the privilege but it is **disabled by default** — you must explicitly enable it.

The pattern is identical to the token privilege adjustment you did in Module 20:

```
OpenProcessToken(
    hProcess: HANDLE,         // GetCurrentProcess() — the current process's pseudo-handle
    dwDesiredAccess: TOKEN_ACCESS_RIGHTS,  // TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
    phToken: *mut HANDLE,     // out: receives the process token handle
) -> Result<()>

LookupPrivilegeValueA(
    lpsystemname: PCSTR,      // None — look up on the local system
    lpname: PCSTR,            // b"SeBackupPrivilege\0" — the privilege name
    lpluid: *mut LUID,        // out: receives the LUID for this privilege
) -> Result<()>

AdjustTokenPrivileges(
    tokenhandle: HANDLE,      // the token handle from OpenProcessToken
    disableallprivileges: BOOL, // FALSE — we want to adjust, not disable all
    nestate: Option<*const TOKEN_PRIVILEGES>, // pointer to TOKEN_PRIVILEGES with our privilege
    bufferlength: u32,        // 0 — we don't need the previous state
    previousstate: Option<*mut TOKEN_PRIVILEGES>, // None
    returnlength: Option<*mut u32>, // None
) -> Result<()>
```

`TOKEN_PRIVILEGES` holds a count and an array of `LUID_AND_ATTRIBUTES`. Set `Attributes` to `SE_PRIVILEGE_ENABLED`.

Important: `AdjustTokenPrivileges` returns `Ok(())` even if the privilege isn't present on the token — check `GetLastError()` afterward for `ERROR_NOT_ALL_ASSIGNED` to detect failure.

### Step 2 — Dump the SAM hive

`HKLM\SAM` is the hive to open. The `REG_OPTION_BACKUP_RESTORE` flag (value `4`) in the `ulOptions` parameter is what activates the backup privilege bypass.

```
RegOpenKeyExA(
    hKey: HKEY,                      // HKEY_LOCAL_MACHINE
    lpSubKey: PCSTR,                 // b"SAM\0"
    ulOptions: REG_OPEN_CREATE_OPTIONS, // REG_OPEN_CREATE_OPTIONS(4) — REG_OPTION_BACKUP_RESTORE
    samDesired: REG_SAM_FLAGS,       // KEY_READ
    phkResult: *mut HKEY,            // out: receives the open key handle
) -> WIN32_ERROR                     // ERROR_SUCCESS (0) on success; check it

RegSaveKeyA(
    hKey: HKEY,                      // the handle from RegOpenKeyExA
    lpFile: PCSTR,                   // b"C:\\Windows\\Temp\\sam.save\0" — must NOT already exist
    lpSecurityAttributes: Option<*const SECURITY_ATTRIBUTES>, // None
) -> WIN32_ERROR                     // ERROR_SUCCESS on success
```

Close the handle with `RegCloseKey` when done.

### Step 3 — Dump the SYSTEM hive

Same pattern as step 2, but opening `"SYSTEM"` and saving to `"C:\Windows\Temp\system.save"`.

The SYSTEM hive is not ACL-protected like SAM and SECURITY — you can often read it without `SeBackupPrivilege`. But using the backup flag consistently is cleaner.

### Step 4 — Dump the SECURITY hive

Same pattern, opening `"SECURITY"` and saving to `"C:\Windows\Temp\security.save"`.

### Step 5 — Report and clean up

Print the paths of the saved files. Close all handles. Optionally delete the files after exfiltration (or leave that to the caller).

Remind the operator of the offline parsing command:
```
secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
```

---

## Bonus — VSS (Volume Shadow Copy) Approach

The registry-based approach (steps 1–5) works but is noisy. The stealthier alternative reads the hive **files** directly from a Volume Shadow Copy, bypassing the live lock.

The sequence:

1. **Create a VSS snapshot**: Use the `IVssBackupComponents` COM interface to request a shadow copy of the system drive.
2. **Get the shadow copy device path**: The snapshot is exposed as a path like `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1`.
3. **Read hive files directly**: The SAM, SYSTEM, and SECURITY files are at `%WINDIR%\System32\config\SAM` etc. Through the shadow path: `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM`.
4. **Copy them out**: Use `CopyFileA` — no privilege or registry call needed.

This approach is harder to implement (VSS COM is verbose) but leaves a much smaller footprint: no registry handle on SAM, no backup privilege event.

Implement VSS if you want a challenge. The COM initialization pattern from Module 24 is a prerequisite.

---

## Acceptance Criteria

- [ ] Runs as a local Administrator and produces three `.save` files in `C:\Windows\Temp\`
- [ ] `SeBackupPrivilege` enabled before opening hives
- [ ] `REG_OPTION_BACKUP_RESTORE` passed to `RegOpenKeyExA` for SAM and SECURITY
- [ ] `GetLastError()` checked after `AdjustTokenPrivileges` for `ERROR_NOT_ALL_ASSIGNED`
- [ ] All `WIN32_ERROR` returns from `RegOpenKeyExA` and `RegSaveKeyA` checked
- [ ] All HKEY handles closed with `RegCloseKey`
- [ ] Output tells the operator what files were created and how to parse them offline
- [ ] (Bonus) VSS path printed or implemented

---

## Key Types

**`TOKEN_PRIVILEGES`** — `Win32_Security`. Fields: `PrivilegeCount: u32` and `Privileges: [LUID_AND_ATTRIBUTES; 1]`. `LUID_AND_ATTRIBUTES` has `Luid: LUID` and `Attributes: TOKEN_PRIVILEGES_ATTRIBUTES`. Set `Attributes` to `SE_PRIVILEGE_ENABLED`.

**`HKEY`** — `Win32_System_Registry`. A handle to an open registry key. Predefined roots like `HKEY_LOCAL_MACHINE` are constants of this type.

**`REG_OPEN_CREATE_OPTIONS`** — a newtype wrapper around `u32`. `REG_OPTION_BACKUP_RESTORE` is value `4`. If the named constant is not available in your feature set, use `REG_OPEN_CREATE_OPTIONS(4)` directly.

**`REG_SAM_FLAGS`** — a newtype wrapper around `u32` for the `samDesired` parameter. `KEY_READ` combines read and enumerate permissions.

**`WIN32_ERROR`** — returned by registry functions. `ERROR_SUCCESS` is `WIN32_ERROR(0)`. Compare: `if result != ERROR_SUCCESS { panic!(...) }`.

**`LUID`** — a locally unique identifier for a privilege. Obtained from `LookupPrivilegeValueA`. Opaque — don't construct it manually.

---

## Hints

- Delete `C:\Windows\Temp\sam.save` (and the others) before running again — `RegSaveKeyA` fails with `ERROR_ALREADY_EXISTS` if the file exists.
- `AdjustTokenPrivileges` with `Ok(())` does not mean the privilege was granted. Always call `GetLastError()` immediately after to check for `ERROR_NOT_ALL_ASSIGNED`.
- On Windows 11, the SECURITY hive may require `SeSecurityPrivilege` in addition to `SeBackupPrivilege`. If you get `ERROR_ACCESS_DENIED` on SECURITY, try enabling `SeSecurityPrivilege` as well.
- `RegSaveKeyA` requires the token to have `SeBackupPrivilege` **and** the key to have been opened with `REG_OPTION_BACKUP_RESTORE`. Missing either one gives `ERROR_PRIVILEGE_NOT_HELD`.
- The offline parsing step is where the real work happens — this module only handles the extraction. Impacket's `secretsdump.py` is the standard tool. You can also parse the hive format manually (it's the same as `.hiv` files).
- Module 20 implemented `enable_privilege` as a helper function. Copy or adapt that pattern here — the only difference is the privilege name (`SeBackupPrivilege` instead of `SeDebugPrivilege`).

---

## Submission

Paste `23-sam-dumping/src/main.rs` and ask for a review.
