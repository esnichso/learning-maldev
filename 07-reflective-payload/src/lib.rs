use std::ffi::c_void;
use windows::Win32::Foundation::BOOL;

const DLL_PROCESS_ATTACH: u32 = 1;

/// Called by the injector. Must be position-independent — no external calls
/// until imports are resolved. Finds the DLL base by walking backward from
/// its own address, then maps the PE manually into a new allocation.
/// Returns the new base address, or 0 on failure.
#[no_mangle]
pub unsafe extern "system" fn ReflectiveLoader() -> usize {
    // Step 1 — Find the MZ header by walking backward from this function's address.
    // Hint: start at ReflectiveLoader as usize, decrement, check for 0x5A4D at each alignment.

    // Step 2 — Parse NT headers to get ImageBase, SizeOfImage, entry point RVA.

    // Step 3 — VirtualAlloc a new region of SizeOfImage bytes (PAGE_EXECUTE_READWRITE).

    // Step 4 — Copy PE headers and each section to the new region.
    //   Headers: copy from offset 0, length = OptionalHeader.SizeOfHeaders
    //   Sections: for each IMAGE_SECTION_HEADER, copy SizeOfRawData bytes from
    //             PointerToRawData in the source to VirtualAddress in the destination.

    // Step 5 — Apply base relocations.
    //   delta = new_base - preferred_base (ImageBase from optional header)
    //   Walk IMAGE_BASE_RELOCATION blocks; apply DIR64 (type 10) entries.

    // Step 6 — Resolve imports.
    //   Walk IMAGE_IMPORT_DESCRIPTOR array (terminated by all-zero entry).
    //   For each descriptor: LoadLibraryA(name), then for each name in
    //   OriginalFirstThunk: GetProcAddress and write into FirstThunk slot.

    // Step 7 — Call DllMain with DLL_PROCESS_ATTACH.
    //   entry_point = new_base + AddressOfEntryPoint
    //   transmute and call.

    0 // replace with new_base
}

#[no_mangle]
pub extern "system" fn DllMain(
    _hinstance: *mut c_void,
    reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        // TODO: your payload (MessageBoxA, WinExec, etc.)
    }
    BOOL(1)
}
