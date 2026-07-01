# Module 08 — Custom Shellcode & PEB Walk

## Concept

Every function call in a normal Windows binary goes through the **import table** — a list of DLL names and function names baked into the PE headers. AV/EDR tools scan this table at load time (and continuously in memory) to identify what APIs a binary uses. A binary that imports `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread` is trivially fingerprinted.

**Position-independent code** (shellcode) solves this by carrying no import table. Instead, it finds the APIs it needs at runtime by walking a data structure the Windows loader maintains in every process: the **Process Environment Block (PEB)**. The PEB's loader list (`PEB.Ldr`) records every DLL currently mapped in the process, including their base addresses and export tables. By walking this list and searching export tables, shellcode can resolve any function pointer without declaring a single import.

This module teaches the primitive that underlies most serious offensive tooling: **PEB → kernel32 base → EAT walk → `GetProcAddress` → everything else**.

### Why this matters beyond module 08

Once you can resolve `LoadLibraryA` and `GetProcAddress` via PEB walk, you can reach any function in any DLL with zero import table entries. Modules 09 (direct syscalls), 10 (API unhooking), 12 (reverse shell), and 13 (payload staging) all build on this foundation. Module 29 (no_std) takes it further — a `no_std` binary with no CRT has *no* standard imports at all.

---

## The PEB walk sequence

The seven steps in this module:

1. Read `gs:[0x60]` → PEB pointer
2. Dereference `PEB.Ldr` → PEB_LDR_DATA pointer
3. Walk `PEB_LDR_DATA.InMemoryOrderModuleList` → find kernel32.dll entry
4. Get `LDR_DATA_TABLE_ENTRY.DllBase` → kernel32 base address
5. Walk kernel32's `IMAGE_EXPORT_DIRECTORY` → find `LoadLibraryA` and `GetProcAddress` by ROR13 hash
6. Call `LoadLibraryA("user32.dll")` → get user32 base
7. Call `GetProcAddress(user32, "MessageBoxA")` → call `MessageBoxA("PEB walk succeeded!")`

---

## Key data structures

### PEB (x64 offsets)

| Offset | Type | Field |
|---|---|---|
| 0x000 | u8 | InheritedAddressSpace |
| 0x002 | u8 | BeingDebugged |
| 0x008 | *mut c_void | Mutant |
| 0x010 | *mut c_void | ImageBaseAddress |
| **0x018** | **\*mut PEB_LDR_DATA** | **Ldr** |

`gs:[0x60]` gives the PEB address. `PEB.Ldr` at offset `0x18` gives the loader data.

### PEB_LDR_DATA (x64 offsets)

| Offset | Type | Field |
|---|---|---|
| 0x000 | u32 | Length |
| 0x010 | LIST_ENTRY | InLoadOrderModuleList |
| **0x020** | **LIST_ENTRY** | **InMemoryOrderModuleList** |
| 0x030 | LIST_ENTRY | InInitializationOrderModuleList |

`InMemoryOrderModuleList` at offset `0x20` is the **sentinel head** of a circular doubly-linked list. Its `Flink` points to the first real entry. Walk `Flink` pointers until you circle back to the head.

### LIST_ENTRY (x64)

| Offset | Type | Field |
|---|---|---|
| 0x000 | *mut LIST_ENTRY | Flink (next) |
| 0x008 | *mut LIST_ENTRY | Blink (prev) |

### LDR_DATA_TABLE_ENTRY (x64 offsets from entry base)

Each pointer from `InMemoryOrderModuleList` points to `LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks`, which is at offset **0x10** inside the entry. To get the entry base: `current_ptr - 0x10`.

| Offset | Type | Field |
|---|---|---|
| 0x000 | LIST_ENTRY | InLoadOrderLinks |
| 0x010 | LIST_ENTRY | **InMemoryOrderLinks** ← list iterator points here |
| 0x020 | LIST_ENTRY | InInitializationOrderLinks |
| **0x030** | **\*mut c_void** | **DllBase** |
| 0x038 | *mut c_void | EntryPoint |
| 0x040 | u32 | SizeOfImage |
| 0x048 | UNICODE_STRING | FullDllName |
| **0x058** | **UNICODE_STRING** | **BaseDllName** |

### UNICODE_STRING (x64)

| Offset | Type | Field |
|---|---|---|
| 0x000 | u16 | Length — byte length of the string (not char count) |
| 0x002 | u16 | MaximumLength |
| 0x008 | *mut u16 | Buffer — wide-char string, NOT null-terminated by Length |

To compare: `std::slice::from_raw_parts(buffer, length as usize / 2)` gives a `&[u16]`. Compare each element to the corresponding ASCII char cast to `u16`, case-insensitively.

### IMAGE_EXPORT_DIRECTORY

After parsing the DOS/NT headers (same as Modules 04 and 07):
`DataDirectory[0]` (index 0 = `IMAGE_DIRECTORY_ENTRY_EXPORT`) gives `VirtualAddress` and `Size` of the export directory.

| Offset | Type | Field |
|---|---|---|
| 0x010 | u32 | NumberOfFunctions |
| 0x014 | u32 | NumberOfNames |
| 0x018 | u32 | AddressOfFunctions — RVA → array of u32 function RVAs |
| 0x01C | u32 | AddressOfNames — RVA → array of u32 name-string RVAs |
| 0x020 | u32 | AddressOfNameOrdinals — RVA → array of u16 |

For each `i` in `0..NumberOfNames`:
```
name_rva   = AddressOfNames[i]
name_str   = (dll_base + name_rva) as *const u8   // null-terminated ASCII
ordinal    = AddressOfNameOrdinals[i]
fn_rva     = AddressOfFunctions[ordinal]
fn_ptr     = (dll_base + fn_rva) as *mut c_void
```

---

## The ROR13 algorithm

ROR13 hashes a byte string so you can identify function names without storing them. Rotate the running hash right by 13 bits, then add the current byte:

```
hash = 0
for each byte b in name (including the null terminator):
    hash = ror(hash, 13) + b
```

In Rust: `hash = hash.rotate_right(13).wrapping_add(b as u32)`

**Why 13?** Arbitrary — Metasploit chose it; the value doesn't matter as long as you're consistent. Real shellcode pre-computes constants for every function it needs.

**Module name comparison note**: `BaseDllName.Buffer` contains wide chars (u16). The module names in the list are `KERNEL32.DLL`, `ntdll.dll`, `KERNELBASE.dll` etc. (case varies by Windows version). For reliability, compare case-insensitively by calling `.to_ascii_uppercase()` on each char's low byte.

---

## Task — PEB walker (`08-shellcode-peb-walk/src/main.rs`)

Implement the seven steps. Each `todo!()` is one logical operation. Work through them in order.

### Step 1 — Read the PEB address

On x64 Windows, the CPU's `gs` segment register always points to the Thread Environment Block (TEB). The PEB pointer lives at a fixed offset within the TEB: `gs:[0x60]`.

```
// Hint — inline assembly to read gs:[0x60]:
let peb: *mut c_void;
asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, pure, readonly));
```

`asm!` is in `core::arch::asm` (stable since Rust 1.59). The `out(reg)` constraint says "write the result to any general-purpose register and give me that register's value".

### Step 2 — Get the list head

```
PEB.Ldr               = *(peb + 0x18) as *mut c_void
list_head             = (ldr + 0x20) as *mut c_void   // InMemoryOrderModuleList sentinel
current (first entry) = *(list_head as *const *mut c_void)  // Flink of sentinel
```

The sentinel's `Flink` points to the first real `LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks`.

### Step 3 — Walk the list and find kernel32.dll

Loop: `while current != list_head` — when `Flink` returns to the sentinel, you've seen every loaded module.

For each entry:
```
entry_base = (current as usize - 0x10) as *mut c_void
dll_base   = *((entry_base as usize + 0x30) as *const *mut c_void)
name_len   = *((entry_base as usize + 0x58) as *const u16)   // byte length
name_buf   = *((entry_base as usize + 0x60) as *const *const u16)
name_slice = std::slice::from_raw_parts(name_buf, name_len as usize / 2)
// compare name_slice to "KERNEL32.DLL" case-insensitively
// advance: current = *(current as *const *mut c_void)   // Flink
```

### Step 4 — Walk kernel32's EAT

Parse the PE headers exactly as in Module 04:
1. `dos = kernel32_base as *const IMAGE_DOS_HEADER`
2. `nt  = (kernel32_base as usize + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64`
3. `export_dir_rva = (*nt).OptionalHeader.DataDirectory[0].VirtualAddress`
4. `export_dir = (kernel32_base as usize + export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY`

```
// IMAGE_EXPORT_DIRECTORY offsets:
NumberOfNames        = *((export_dir as usize + 0x18) as *const u32)
AddressOfFunctions   = *((export_dir as usize + 0x1C) as *const u32)  // RVA
AddressOfNames       = *((export_dir as usize + 0x20) as *const u32)  // RVA
AddressOfNameOrdinals= *((export_dir as usize + 0x24) as *const u32)  // RVA
```

For each `i` in `0..NumberOfNames`:
- Get the null-terminated name string
- Build a byte slice up to (and including) the `\0`
- Call `ror13()` on it
- Compare to `HASH_LOAD_LIBRARY_A` and `HASH_GET_PROC_ADDRESS`
- If matched, look up the function pointer via the ordinal

### Step 5 — Load user32.dll

```rust
let user32_base = load_library_a_fn(b"user32.dll\0".as_ptr());
```

`LoadLibraryA` returns an `HMODULE` (alias for `*mut c_void`). `NULL` means failure.

### Step 6 — Resolve MessageBoxA

```rust
let msg_box_ptr = get_proc_address_fn(user32_base, b"MessageBoxA\0".as_ptr());
```

### Step 7 — Call MessageBoxA

`MessageBoxA` signature:
```
MessageBoxA(
    hWnd:    *mut c_void,   // parent window — null for a standalone dialog
    lpText:  *const u8,     // message body (null-terminated ASCII)
    lpCaption: *const u8,   // window title (null-terminated ASCII)
    uType:   u32,           // button style — 0 = MB_OK
) -> i32                    // which button was clicked; ignored here
```

Use `std::mem::transmute` to turn the raw `*mut c_void` into the typed function pointer.

---

## Acceptance Criteria

- [ ] `cargo build --target x86_64-pc-windows-gnu -p shellcode-peb-walk` succeeds
- [ ] `ror13()` correctly hashes at least `LoadLibraryA\0` and `GetProcAddress\0`; verify against the constants
- [ ] PEB pointer is obtained via inline `asm!` (not via ntapi's `NtCurrentPeb()`)
- [ ] `kernel32_base` is found by walking `InMemoryOrderModuleList`, not by calling `GetModuleHandleA`
- [ ] `LoadLibraryA` and `GetProcAddress` are resolved by ROR13 hash match, not by name string comparison
- [ ] Running on the VM pops a `MessageBoxA` dialog reading "PEB walk succeeded!"
- [ ] No function from kernel32 or user32 is listed in the binary's import table (check with `objdump -p` or `dumpbin /imports`)

---

## Hints

- The `asm!` syntax for reading a segment-register offset is `"mov {}, gs:[0x60]"`. The `pure` and `readonly` options tell the compiler this has no side effects and reads memory.
- All RVAs (Relative Virtual Addresses) from PE headers are byte offsets from the DLL's base address, not from the start of the file. Add them directly to `dll_base as usize`.
- A `UNICODE_STRING.Length` of 24 means 12 wide chars (12 × 2 bytes). The buffer is NOT null-terminated up to `Length`.
- For the null-terminated ASCII name in the EAT: iterate forward from the pointer until you hit `0u8`, then build the slice including the null byte for hashing. Or: `std::ffi::CStr::from_ptr(ptr as *const i8).to_bytes_with_nul()`.
- `InMemoryOrderModuleList` does not include an entry for the main executable at index 0 — that's in `InLoadOrderModuleList`. kernel32 is typically the 3rd entry in memory order, but don't hard-code the index; always walk the full list.
- If `ror13` returns wrong values for the known constants, add a `dbg!(ror13(b"LoadLibraryA\0"))` before the walk and compare to `0xec0e4e8e`. Adjust your null-terminator handling if it doesn't match.
- `IMAGE_EXPORT_DIRECTORY` is also in `windows::Win32::System::Diagnostics::Debug` if you prefer the typed approach over raw offsets.
- The ntapi crate (`ntapi::ntpebteb::PEB`, `ntapi::ntldr::LDR_DATA_TABLE_ENTRY`) provides typed structs for the PEB and LDR structures if you prefer struct field access over manual offsets. Both approaches are valid — the raw-offset approach is closer to real shellcode.

---

## Submission

Paste `08-shellcode-peb-walk/src/main.rs` and ask for a review.
