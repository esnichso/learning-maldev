// Module 31 — Binary Hardening
//
// This is module 01's shellcode runner, used as the hardening baseline.
// The task is NOT to change the code — it is to change Cargo.toml and
// build configuration to shrink the binary as much as possible.
//
// Workflow:
//   1. cargo build --target x86_64-pc-windows-gnu -p binary-hardening
//      Note the size of target/.../debug/binary-hardening.exe
//   2. cargo build --target x86_64-pc-windows-gnu -p binary-hardening --release
//      Note the size of target/.../release/binary-hardening.exe
//   3. Add settings to [profile.release] in Cargo.toml ONE AT A TIME,
//      rebuilding and noting the size after each addition.
//   4. Run `cargo bloat` to identify what's contributing to binary size.
//   5. Optionally: add linker flags via .cargo/config.toml for further reduction.
//
// Fill in the size table in the README as you go.

use std::ffi::c_void;
use std::mem;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
    VirtualAlloc, VirtualFree, VirtualProtect,
    MEM_RELEASE,
};
use windows::Win32::Foundation::GetLastError;

// Placeholder shellcode — NOPs ending in a RET so it's safe to call locally.
// In a real scenario this would be meaningful shellcode.
const SHELLCODE: &[u8] = &[
    0x90, 0x90, 0x90, 0x90, // NOP sled
    0x90, 0x90, 0x90, 0x90,
    0xC3,                   // RET
];

fn main() {
    unsafe {
        // Allocate RW memory for the shellcode.
        let alloc = VirtualAlloc(
            None,
            SHELLCODE.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if alloc.is_null() {
            panic!("VirtualAlloc failed: {:?}", GetLastError());
        }

        // Copy shellcode into the allocation.
        std::ptr::copy_nonoverlapping(
            SHELLCODE.as_ptr(),
            alloc as *mut u8,
            SHELLCODE.len(),
        );

        // Change protection to RX.
        let mut old_protect = PAGE_READWRITE;
        VirtualProtect(
            alloc,
            SHELLCODE.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect,
        ).expect("VirtualProtect failed");

        // Execute.
        let f: unsafe extern "system" fn() = mem::transmute(alloc);
        f();

        // Free.
        VirtualFree(alloc, 0, MEM_RELEASE).expect("VirtualFree failed");
    }

    println!("done — check binary size with `ls -lh target/.../binary-hardening.exe`");
}
