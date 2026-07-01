// Module 08 — Custom Shellcode & PEB Walk
// Resolve Win32 APIs at runtime by walking the PEB loader list and kernel32's EAT.
// No import table entries — this is how position-independent shellcode finds functions.
//
// Build:
//   cargo build --target x86_64-pc-windows-gnu -p shellcode-peb-walk

use std::ffi::c_void;

// ROR13 hashing — rotate hash right 13 bits, add each byte (including null terminator).
// Used to identify function names without storing string literals in the binary.
//
// Hint: iterate bytes in `name`, for each: hash = hash.rotate_right(13).wrapping_add(b as u32)
fn ror13(name: &[u8]) -> u32 {
    todo!("implement ROR13: rotate_right(13) + wrapping_add each byte")
}

// Well-known ROR13 hashes — verify these match your ror13() implementation.
// Compute them at runtime in a debug build and println! the values if you're unsure.
const HASH_LOAD_LIBRARY_A:   u32 = 0xec0e4e8e; // ror13(b"LoadLibraryA\0")
const HASH_GET_PROC_ADDRESS: u32 = 0x7c0dfcaa; // ror13(b"GetProcAddress\0")

fn main() {
    unsafe {
        // Step 1 — Read the PEB address from the GS segment register.
        // On x64 Windows, gs:[0x60] always holds the PEB pointer for the current thread.
        // This is the only assembly instruction you need — everything else is pointer arithmetic.
        //
        // Hint: use core::arch::asm!
        //   let peb: *mut c_void;
        //   asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, pure, readonly));
        let peb: *mut c_void = todo!("read gs:[0x60] into a raw *mut c_void via asm!");

        // Step 2 — Get PEB.Ldr and the head of InMemoryOrderModuleList.
        //
        // PEB (x64 offsets):
        //   +0x018  Ldr  (*mut PEB_LDR_DATA)
        //
        // PEB_LDR_DATA (x64 offsets):
        //   +0x020  InMemoryOrderModuleList  (LIST_ENTRY — this is the list HEAD/sentinel)
        //
        // LIST_ENTRY:
        //   +0x000  Flink (*mut LIST_ENTRY)  → next entry
        //   +0x008  Blink (*mut LIST_ENTRY)  → previous entry
        //
        // Hint: let ldr = *((peb as usize + 0x18) as *const *mut c_void);
        //       let list_head = (ldr as usize + 0x20) as *mut c_void;   // sentinel node
        //       let mut current = *(list_head as *const *mut c_void);   // first real entry
        let ldr: *mut c_void = todo!("*(peb + 0x18) as *mut c_void — PEB.Ldr");
        let list_head: *mut c_void = todo!("(ldr + 0x20) as *mut c_void — InMemoryOrderModuleList head");
        let mut current: *mut c_void = todo!("*(list_head as *const *mut c_void) — Flink: first entry");

        // Step 3 — Walk InMemoryOrderModuleList to find kernel32.dll.
        //
        // Each pointer in the list points to LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks.
        // InMemoryOrderLinks is at offset 0x10 within LDR_DATA_TABLE_ENTRY,
        // so: entry_base = current - 0x10
        //
        // LDR_DATA_TABLE_ENTRY (x64 offsets, starting from entry_base):
        //   +0x030  DllBase        (*mut c_void)
        //   +0x058  BaseDllName.Length  (u16) — byte length of the wide string (not char count)
        //   +0x060  BaseDllName.Buffer  (*mut u16) — pointer to wide-char name (not null-terminated by Length)
        //
        // Loop: while current != list_head
        //   entry_base = (current as usize - 0x10) as *mut c_void
        //   dll_base   = *((entry_base as usize + 0x30) as *const *mut c_void)
        //   name_len   = *((entry_base as usize + 0x58) as *const u16)  // bytes, not chars
        //   name_buf   = *((entry_base as usize + 0x60) as *const *const u16)
        //   Build a &[u16] slice: std::slice::from_raw_parts(name_buf, name_len as usize / 2)
        //   Compare (case-insensitive) each char to "KERNEL32.DLL"
        //   Advance: current = *(current as *const *mut c_void)   // Flink of current LIST_ENTRY
        let mut kernel32_base: *mut c_void = std::ptr::null_mut();
        todo!("loop the InMemoryOrderModuleList; find the entry whose BaseDllName == 'KERNEL32.DLL' (case-insensitive)");
        assert!(!kernel32_base.is_null(), "kernel32.dll not found in loader list");

        // Step 4 — Walk kernel32's Export Address Table to find LoadLibraryA and GetProcAddress.
        //
        // PE format (same structures as Modules 04 and 07):
        //   kernel32_base → IMAGE_DOS_HEADER
        //     .e_lfanew → byte offset to IMAGE_NT_HEADERS64
        //       .OptionalHeader.DataDirectory[0] → IMAGE_DATA_DIRECTORY for exports
        //         .VirtualAddress → RVA of IMAGE_EXPORT_DIRECTORY
        //
        // IMAGE_EXPORT_DIRECTORY (offsets from its own base):
        //   +0x018  NumberOfNames      (u32)
        //   +0x020  AddressOfFunctions  (u32 RVA) → array of u32 function RVAs
        //   +0x024  AddressOfNames      (u32 RVA) → array of u32 name-string RVAs
        //   +0x028  AddressOfNameOrdinals (u32 RVA) → array of u16 ordinals
        //
        // For each i in 0..NumberOfNames:
        //   name_rva   = *(AddressOfNames_ptr + i)              // u32
        //   name_ptr   = (kernel32_base + name_rva) as *const u8 // null-terminated ASCII
        //   Build slice up to the null byte, then hash with ror13 (include null byte).
        //   ordinal    = *(AddressOfNameOrdinals_ptr + i)       // u16
        //   fn_rva     = *(AddressOfFunctions_ptr + ordinal)    // u32
        //   fn_ptr     = (kernel32_base + fn_rva) as *mut c_void
        //
        // Hint: Parse DOS/NT headers exactly as in Modules 04 and 07.
        //   Use raw pointer arithmetic: (base as usize + rva as usize) as *const T
        let mut load_library_a:   Option<unsafe extern "system" fn(*const u8) -> *mut c_void> = None;
        let mut get_proc_address: Option<unsafe extern "system" fn(*mut c_void, *const u8) -> *mut c_void> = None;
        todo!("walk kernel32 EAT; match HASH_LOAD_LIBRARY_A and HASH_GET_PROC_ADDRESS via ror13");
        assert!(load_library_a.is_some(),   "LoadLibraryA not found in kernel32 EAT");
        assert!(get_proc_address.is_some(), "GetProcAddress not found in kernel32 EAT");

        let load_library_a_fn   = load_library_a.unwrap();
        let get_proc_address_fn = get_proc_address.unwrap();

        // Step 5 — Use LoadLibraryA to get a handle to user32.dll.
        // user32 is almost always already loaded, but calling LoadLibraryA is safe (bumps ref count).
        //
        // Hint: load_library_a_fn(b"user32.dll\0".as_ptr())  returns *mut c_void (HMODULE)
        let user32_base: *mut c_void = todo!("call load_library_a_fn(b\"user32.dll\\0\".as_ptr())");
        assert!(!user32_base.is_null(), "LoadLibraryA(user32.dll) returned NULL");

        // Step 6 — Resolve MessageBoxA from user32 via GetProcAddress.
        //
        // Hint: get_proc_address_fn(user32_base, b"MessageBoxA\0".as_ptr())
        let msg_box_ptr: *mut c_void = todo!("call get_proc_address_fn(user32_base, b\"MessageBoxA\\0\".as_ptr())");
        assert!(!msg_box_ptr.is_null(), "GetProcAddress(MessageBoxA) returned NULL");

        // Step 7 — Call MessageBoxA through the resolved pointer.
        // Signature: (hwnd: *mut c_void, text: *const u8, caption: *const u8, utype: u32) -> i32
        //
        // Hint: std::mem::transmute the raw pointer to the function type, then call.
        type MessageBoxA = unsafe extern "system" fn(*mut c_void, *const u8, *const u8, u32) -> i32;
        let message_box_a: MessageBoxA = std::mem::transmute(msg_box_ptr);
        todo!("call message_box_a(null_mut(), b\"PEB walk succeeded!\\0\".as_ptr(), b\"Module 08\\0\".as_ptr(), 0)");
    }
}
