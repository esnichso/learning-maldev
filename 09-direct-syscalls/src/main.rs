// Module 09 — Direct Syscalls
// Extract the SSN for NtAllocateVirtualMemory at runtime using Hell's Gate,
// build a raw syscall stub in RWX memory, and call it directly — bypassing EDR hooks.
//
// Build:
//   cargo build --target x86_64-pc-windows-gnu -p direct-syscalls

use std::ffi::c_void;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
    VirtualAlloc, VirtualFree, MEM_RELEASE,
};
use windows::Win32::Foundation::HANDLE;

// The type signature of NtAllocateVirtualMemory — identical to what the kernel expects.
// We will cast our syscall stub to this type and call it like a normal function.
type NtAllocateVirtualMemory = unsafe extern "system" fn(
    ProcessHandle:   HANDLE,          // -1 (current process pseudo-handle) or a real handle
    BaseAddress:     *mut *mut c_void, // in: desired address (null = OS chooses); out: actual address
    ZeroBits:        usize,            // number of high address bits that must be zero — pass 0
    RegionSize:      *mut usize,       // in: requested size; out: actual size (rounded to page)
    AllocationType:  u32,              // MEM_COMMIT | MEM_RESERVE = 0x3000
    Protect:         u32,              // PAGE_READWRITE = 0x04
) -> i32; // NTSTATUS — 0 = STATUS_SUCCESS

// The syscall stub we will write into RWX memory (11 bytes, x64):
//   4C 8B D1        mov r10, rcx     — required by Windows syscall ABI
//   B8 xx xx 00 00  mov eax, SSN     — xx xx is the little-endian SSN
//   0F 05           syscall          — transfer to kernel
//   C3              ret              — return to caller
const STUB_TEMPLATE: [u8; 11] = [
    0x4C, 0x8B, 0xD1,        // mov r10, rcx
    0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, <SSN placeholder>
    0x0F, 0x05,              // syscall
    0xC3,                    // ret
];
// Bytes [4] and [5] of the stub hold the SSN (u16, little-endian). Bytes [6] and [7] are 0x00.

fn main() {
    unsafe {
        // Step 1 — Get ntdll.dll base address from the PEB.
        // Reuse the PEB walk technique from Module 08.
        // ntdll.dll is always the second entry in InLoadOrderModuleList
        // (first is the main executable, second is ntdll).
        // Or walk InMemoryOrderModuleList and match the name "ntdll.dll".
        //
        // Hint: same gs:[0x60] → PEB → Ldr → InLoadOrderModuleList walk as Module 08.
        //   Match BaseDllName == "ntdll.dll" (case-insensitive).
        let ntdll_base: *mut c_void = todo!("PEB walk to find ntdll.dll base address");
        assert!(!ntdll_base.is_null(), "ntdll.dll not found in loader list");

        // Step 2 — Find NtAllocateVirtualMemory in ntdll's EAT.
        // Walk ntdll's Export Address Table exactly as in Module 08 (kernel32 EAT walk).
        // This time look for the function pointer of "NtAllocateVirtualMemory" by name.
        // You need the function's RVA within ntdll so you can scan its bytes.
        //
        // Hint: parse IMAGE_DOS_HEADER → IMAGE_NT_HEADERS64 → DataDirectory[0] →
        //   IMAGE_EXPORT_DIRECTORY → walk AddressOfNames for "NtAllocateVirtualMemory".
        //   Save the resolved *const u8 pointer (the first byte of the stub) for Step 3.
        let nt_alloc_stub: *const u8 = todo!("find &NtAllocateVirtualMemory[0] in ntdll EAT");
        assert!(!nt_alloc_stub.is_null(), "NtAllocateVirtualMemory not found in ntdll");

        // Step 3 — Extract the SSN using Hell's Gate.
        // An unhooked ntdll stub on Windows 10/11 starts with these bytes:
        //   4C 8B D1        mov r10, rcx
        //   B8 xx xx 00 00  mov eax, <SSN>
        //
        // The SSN is a u16 stored at byte offsets [4] and [5] of the stub (little-endian).
        // "Hell's Gate" = scan for the pattern 0x4C 0x8B 0xD1 0xB8 at the stub start.
        //
        // If the stub is hooked (first bytes are 0xE9 / JMP), use Halo's Gate:
        //   look at the stub immediately above or below in the EAT (ordinal ± 1) and
        //   use its SSN ± 1 to infer the hooked function's SSN.
        //
        // Hint:
        //   let b = std::slice::from_raw_parts(nt_alloc_stub, 8);
        //   if b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8 {
        //       // unhooked — SSN is at bytes [4] and [5]
        //       let ssn = u16::from_le_bytes([b[4], b[5]]);
        //   } else {
        //       // hooked — implement Halo's Gate or panic for now
        //       panic!("stub is hooked: {:02x?}", &b[..4]);
        //   }
        let ssn: u16 = todo!("scan nt_alloc_stub bytes for 4C 8B D1 B8 pattern; extract SSN from bytes [4..6]");
        println!("NtAllocateVirtualMemory SSN: {:#x}", ssn);

        // Step 4 — Build the syscall stub in RWX memory.
        // Allocate a small RWX region using the normal windows crate VirtualAlloc (not the stub).
        // Copy STUB_TEMPLATE into it, then patch bytes [4] and [5] with the real SSN.
        //
        // Hint: VirtualAlloc(None, STUB_TEMPLATE.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        //   returns *mut c_void. Cast to *mut u8, copy STUB_TEMPLATE with ptr::copy_nonoverlapping,
        //   then write the SSN bytes: stub_ptr.add(4).write(ssn_bytes[0]); stub_ptr.add(5).write(ssn_bytes[1]);
        let stub_mem: *mut c_void = VirtualAlloc(
            None,
            STUB_TEMPLATE.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        assert!(!stub_mem.is_null(), "VirtualAlloc for stub failed");

        let stub_ptr = stub_mem as *mut u8;
        todo!("copy STUB_TEMPLATE into stub_ptr with ptr::copy_nonoverlapping");
        todo!("patch stub_ptr.add(4) and stub_ptr.add(5) with the SSN bytes (little-endian u16)");

        // Step 5 — Call the stub as NtAllocateVirtualMemory.
        // Transmute stub_mem to the NtAllocateVirtualMemory function type and call it
        // to allocate a page in the current process. Verify the return is STATUS_SUCCESS (0).
        //
        // Hint: std::mem::transmute::<*mut c_void, NtAllocateVirtualMemory>(stub_mem)
        //   Process handle for current process: HANDLE(-1isize as *mut c_void)  (or use GetCurrentProcess())
        let direct_alloc: NtAllocateVirtualMemory = std::mem::transmute(stub_mem);
        let mut alloc_base: *mut c_void = std::ptr::null_mut();
        let mut region_size: usize = 0x1000; // 4 KB

        let status: i32 = todo!(
            "call direct_alloc(current_process_handle, &mut alloc_base, 0, &mut region_size, MEM_COMMIT|MEM_RESERVE as u32, PAGE_READWRITE as u32)"
        );
        assert_eq!(status, 0, "NtAllocateVirtualMemory returned NTSTATUS {:#x}", status);
        assert!(!alloc_base.is_null(), "NtAllocateVirtualMemory returned null base address");
        println!(
            "Direct syscall succeeded: allocated {:#x} bytes at {:p}",
            region_size, alloc_base
        );

        // Clean up — free the allocation and the stub.
        // (In real shellcode you would skip cleanup, but good practice here.)
        VirtualFree(alloc_base, 0, MEM_RELEASE).ok();
        VirtualFree(stub_mem, 0, MEM_RELEASE).ok();
    }
}
