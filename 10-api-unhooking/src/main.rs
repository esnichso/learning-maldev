use std::ffi::c_void;
use std::mem;
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
};
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::Win32::System::Memory::{
    CreateFileMappingA, MapViewOfFile, UnmapViewOfFile, VirtualProtect,
    FILE_MAP_READ, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};
use windows::core::PCSTR;

fn main() {
    unsafe {
        // Step 1 — Get the in-memory base address of ntdll.dll.
        // ntdll.dll is always loaded in every Windows process. GetModuleHandleA
        // returns a handle (which is actually the load address) without adding a
        // reference count — do NOT call FreeLibrary on it.
        //
        // Hint: GetModuleHandleA(
        //     lpmodulename: PCSTR,  // b"ntdll.dll\0" — the module to look up
        // ) -> Result<HMODULE>     // Err if not found; the HMODULE value IS the base address
        let ntdll_base: *mut c_void = todo!(
            "GetModuleHandleA(b\"ntdll.dll\\0\") and cast the HMODULE to *mut c_void"
        );
        println!("[*] ntdll.dll in-memory base: {:#x}", ntdll_base as usize);

        // Step 2 — Open ntdll.dll on disk and create a read-only file mapping.
        // This gives us the clean, unmodified bytes straight from the file system.
        // The path must use the standard Windows path.
        //
        // Step 2a — Open the file:
        // Hint: CreateFileA(
        //     lpfilename: PCSTR,                             // b"C:\\Windows\\System32\\ntdll.dll\0"
        //     dwdesiredaccess: FILE_ACCESS_RIGHTS,           // GENERIC_READ
        //     dwsharemode: FILE_SHARE_MODE,                  // FILE_SHARE_READ (others can read simultaneously)
        //     lpsecurityattributes: Option<*const _>,        // None
        //     dwcreationdisposition: FILE_CREATION_DISPOSITION, // OPEN_EXISTING
        //     dwflagsandattributes: FILE_FLAGS_AND_ATTRIBUTES,  // FILE_ATTRIBUTE_NORMAL
        //     htemplatefile: HANDLE,                         // HANDLE(0) — no template
        // ) -> Result<HANDLE>
        let hfile: HANDLE = todo!("CreateFileA to open ntdll.dll on disk");

        // Step 2b — Create a file mapping object (no actual memory mapped yet):
        // Hint: CreateFileMappingA(
        //     hfile: HANDLE,                        // hfile from above
        //     lpfilemappingattributes: Option<*const _>, // None
        //     flprotect: PAGE_PROTECTION_FLAGS,     // PAGE_READONLY
        //     dwmaximumsizehigh: u32,               // 0 — use file size
        //     dwmaximumsizelow: u32,                // 0 — use file size
        //     lpname: PCSTR,                        // PCSTR::null() — anonymous mapping
        // ) -> Result<HANDLE>
        let hmap: HANDLE = todo!("CreateFileMappingA(hfile, PAGE_READONLY, 0, 0, null)");

        // Step 2c — Map a view of the file into this process's address space:
        // Hint: MapViewOfFile(
        //     hfilemappingobject: HANDLE,           // hmap from above
        //     dwdesiredaccess: FILE_MAP_TYPE,       // FILE_MAP_READ
        //     dwfileoffsethigh: u32,                // 0
        //     dwfileoffsetlow: u32,                 // 0
        //     dwnumberofbytestomap: usize,          // 0 — map the whole file
        // ) -> *mut c_void                          // null on failure; check it
        let disk_base: *mut c_void = todo!("MapViewOfFile(hmap, FILE_MAP_READ, 0, 0, 0)");
        if disk_base.is_null() {
            panic!("[!] MapViewOfFile failed");
        }
        println!("[*] ntdll.dll on-disk mapping base: {:#x}", disk_base as usize);

        // Step 3 — Parse PE headers to locate the .text section in BOTH copies.
        // Both the in-memory and disk-mapped copies are valid PE images and share
        // the same section layout. IMAGE_DOS_HEADER → e_lfanew → IMAGE_NT_HEADERS64
        // → section headers immediately after.
        //
        // Do this twice: once with ntdll_base, once with disk_base.
        //
        // Hint: cast the base pointer to *const IMAGE_DOS_HEADER.
        //       nt_ptr = base.add((*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64
        //       sections start at nt_ptr.add(1) cast to *const IMAGE_SECTION_HEADER
        //       (i.e., immediately after the NT headers struct)
        //       Search sections for one whose Name bytes start with b".text"

        // In-memory copy:
        let mem_dos = ntdll_base as *const IMAGE_DOS_HEADER;
        let mem_nt  = todo!("parse IMAGE_NT_HEADERS64 from ntdll_base") as *const IMAGE_NT_HEADERS64;
        let mem_num_sections = todo!("(*mem_nt).FileHeader.NumberOfSections as usize");
        let mem_sections     = todo!("pointer to first IMAGE_SECTION_HEADER after mem_nt");

        // On-disk copy:
        let dsk_dos = disk_base as *const IMAGE_DOS_HEADER;
        let dsk_nt  = todo!("parse IMAGE_NT_HEADERS64 from disk_base") as *const IMAGE_NT_HEADERS64;
        let dsk_sections = todo!("pointer to first IMAGE_SECTION_HEADER after dsk_nt");

        // Find the .text section (same index in both — sections are in the same order):
        let mut text_rva:  u32 = 0;
        let mut text_size: u32 = 0;
        todo!(
            "iterate mem_num_sections sections, find one where Name starts with b\".text\", \
             record VirtualAddress as text_rva and VirtualSize (or SizeOfRawData) as text_size"
        );
        println!("[*] .text section RVA={:#x} size={:#x}", text_rva, text_size);

        // Step 4 — Compare .text sections byte by byte and count differences.
        // The in-memory RVA is the same in both copies (PE is mapped at the same layout).
        // Pointer arithmetic: base + text_rva gives you the start of .text.
        //
        // For the disk view the raw file layout is slightly different from the mapped
        // layout, but ntdll's .text section PointerToRawData == VirtualAddress in practice
        // (it starts at the beginning of the mapped image). To be safe, use VirtualAddress
        // for both (both are mapped views — the file mapping maps the raw file, so the
        // correct offset into the disk mapping is PointerToRawData from the section header).
        //
        // Hint: let mem_text = (ntdll_base as usize + text_rva as usize) as *const u8;
        //       let dsk_text = (disk_base as usize + dsk_section.PointerToRawData as usize) as *const u8;
        //       iterate 0..text_size, compare *mem_text.add(i) vs *dsk_text.add(i)
        let mut diff_count: usize = 0;
        todo!("compare .text bytes, print the address and values of each difference, count them");
        println!("[*] Found {} differing byte(s) before unhooking", diff_count);

        // Step 5 — Restore hooked bytes from the clean disk copy.
        // For each differing byte range, use VirtualProtect to unlock the page,
        // copy the clean bytes from the disk view, then restore the protection.
        //
        // A page-granular approach is fine for this exercise:
        //   - Call VirtualProtect on the entire .text section (or per-page)
        //   - std::ptr::copy_nonoverlapping from disk_text to mem_text for the changed bytes
        //   - Call VirtualProtect again to restore original protection
        //
        // Hint: VirtualProtect(
        //     lpaddress: *const c_void,         // mem_text as *const c_void
        //     dwsize: usize,                    // text_size as usize
        //     flnewprotect: PAGE_PROTECTION_FLAGS, // PAGE_EXECUTE_READWRITE
        //     lpfloldprotect: *mut PAGE_PROTECTION_FLAGS, // &mut old_protect
        // ) -> Result<()>
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        todo!("VirtualProtect(mem_text, text_size, PAGE_EXECUTE_READWRITE, &mut old_protect)");
        todo!("std::ptr::copy_nonoverlapping(dsk_text, mem_text as *mut u8, text_size as usize)");
        todo!("VirtualProtect(mem_text, text_size, old_protect, &mut old_protect) to restore");
        println!("[+] .text section restored from disk copy");

        // Step 6 — Verify: re-compare and confirm no differences remain.
        let mut remaining: usize = 0;
        todo!("repeat the comparison from step 4, count remaining differences into `remaining`");
        if remaining == 0 {
            println!("[+] Verification passed — no hooks detected after restore");
        } else {
            println!("[!] {} byte(s) still differ after restore", remaining);
        }

        // Cleanup
        UnmapViewOfFile(disk_base as *const c_void).unwrap();
        CloseHandle(hmap).unwrap();
        CloseHandle(hfile).unwrap();
    }
}
