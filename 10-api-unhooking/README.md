# Module 10 — API Unhooking

## Concept

EDR (Endpoint Detection and Response) products intercept Win32 API calls by **patching the first few bytes** of stub functions inside `ntdll.dll`. When your process calls `NtAllocateVirtualMemory`, it jumps into the EDR's monitoring code instead of directly into the kernel. The EDR logs the call, checks it against policy, and (if allowed) forwards to the real syscall.

The patch looks like this in memory:

```
; original ntdll stub
mov eax, 0x18        ; system service number
syscall
ret

; after EDR hook
jmp 0x7fff12340000  ; JMP to EDR monitoring code
nop
nop
```

**API unhooking** defeats this by reading `ntdll.dll` clean from disk — before the EDR can touch it — mapping it into memory, comparing its `.text` section byte-for-byte with the in-memory (hooked) copy, and overwriting any modified bytes back to their original values.

### Why this works

The file on disk is never touched by the EDR. It hooks the in-memory image during process startup (typically via a DLL injected via `AppInit_DLLs` or a kernel callback). By the time your code runs, the hooks are already in place — but the disk file is still clean.

### Comparison with Module 09 (Direct Syscalls)

| | API Unhooking (this module) | Direct Syscalls (module 09) |
|---|---|---|
| What it bypasses | In-memory EDR hooks in ntdll | In-memory EDR hooks in ntdll |
| Mechanism | Overwrite hooks with clean bytes | Issue syscall instruction directly, skip ntdll entirely |
| After applying | Normal ntdll calls work unhooked | Ntdll not used at all for those calls |
| Detection surface | File read from `System32` | Unusual `syscall` origin not in ntdll |
| Complexity | Medium — PE parsing + file mapping | Medium — SSN extraction + asm stubs |

Both techniques address the same detection layer. In practice, loaders combine both.

---

## The unhooking sequence

1. Get the in-memory base of `ntdll.dll` from the PEB (or via `GetModuleHandleA`).
2. Open `C:\Windows\System32\ntdll.dll` from disk with `CreateFileA`.
3. Map it read-only into this process with `CreateFileMappingA` + `MapViewOfFile`.
4. Parse PE headers of both copies to find the `.text` section boundaries.
5. Compare `.text` byte by byte — differences are potential hooks.
6. `VirtualProtect` the in-memory `.text` to `PAGE_EXECUTE_READWRITE`, copy the clean bytes from the disk view, restore protection.
7. Re-compare to confirm no differences remain.

---

## Task

Implement the unhooker in `src/main.rs`. The skeleton has `todo!()` stubs for each step with hint comments.

### Step 1 — Get ntdll's in-memory base

```
GetModuleHandleA(
    lpmodulename: PCSTR,   // b"ntdll.dll\0" — name of the already-loaded module
) -> Result<HMODULE>       // the HMODULE value is the base address; cast to *mut c_void
```

`GetModuleHandleA` does **not** increment the module's reference count. Do not call `FreeLibrary` on the result. The returned `HMODULE` is numerically equal to the module's load address in the current process.

### Step 2 — Map ntdll from disk

Three API calls in sequence:

**`CreateFileA`** — opens the file:
```
CreateFileA(
    lpfilename: PCSTR,                                 // b"C:\\Windows\\System32\\ntdll.dll\0"
    dwdesiredaccess: FILE_ACCESS_RIGHTS,               // GENERIC_READ
    dwsharemode: FILE_SHARE_MODE,                      // FILE_SHARE_READ — others may read the file simultaneously
    lpsecurityattributes: Option<*const SECURITY_ATTRIBUTES>, // None — default security
    dwcreationdisposition: FILE_CREATION_DISPOSITION,  // OPEN_EXISTING — fail if not found
    dwflagsandattributes: FILE_FLAGS_AND_ATTRIBUTES,   // FILE_ATTRIBUTE_NORMAL
    htemplatefile: HANDLE,                             // HANDLE(0) — no template
) -> Result<HANDLE>                                    // Err if the path is wrong or access denied
```

**`CreateFileMappingA`** — creates the mapping object (no memory committed yet):
```
CreateFileMappingA(
    hfile: HANDLE,                                     // handle from CreateFileA
    lpfilemappingattributes: Option<*const SECURITY_ATTRIBUTES>, // None
    flprotect: PAGE_PROTECTION_FLAGS,                  // PAGE_READONLY — we only need to read
    dwmaximumsizehigh: u32,                            // 0 — use the file's actual size
    dwmaximumsizelow: u32,                             // 0 — use the file's actual size
    lpname: PCSTR,                                     // PCSTR::null() — anonymous, not shared
) -> Result<HANDLE>                                    // mapping object handle
```

**`MapViewOfFile`** — maps the file into virtual address space:
```
MapViewOfFile(
    hfilemappingobject: HANDLE,   // mapping handle from CreateFileMappingA
    dwdesiredaccess: FILE_MAP_TYPE, // FILE_MAP_READ
    dwfileoffsethigh: u32,        // 0 — start from the beginning
    dwfileoffsetlow: u32,         // 0
    dwnumberofbytestomap: usize,  // 0 — map the entire file
) -> *mut c_void                  // base of the mapped region; null on failure
```

### Step 3 — Find the .text section in both copies

Parse both images with the same PE walking code:

```
IMAGE_DOS_HEADER at base → e_lfanew → IMAGE_NT_HEADERS64
IMAGE_NT_HEADERS64 → FileHeader.NumberOfSections
Section headers begin immediately after IMAGE_NT_HEADERS64 in memory.
```

To cast to the section header array:
```rust
let sections = (nt_ptr as usize + mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;
```

Each `IMAGE_SECTION_HEADER.Name` is an 8-byte array. The `.text` section's name is `b".text\0\0\0"`. Compare with `starts_with(b".text")`.

You need from the section header:
- `VirtualAddress` — RVA of the section in the mapped image (use for the in-memory copy)
- `PointerToRawData` — byte offset in the raw file (use for the disk-mapped copy)
- `VirtualSize` or `SizeOfRawData` — how many bytes to compare

### Step 4 — Compare byte by byte

```rust
let mem_text = (ntdll_base as usize + section.VirtualAddress as usize) as *const u8;
let dsk_text = (disk_base  as usize + section.PointerToRawData as usize) as *const u8;

for i in 0..text_size {
    let mb = *mem_text.add(i);
    let db = *dsk_text.add(i);
    if mb != db {
        // print address and both byte values
    }
}
```

Even on a machine with no EDR, you may see a few differences — Windows itself patches some stubs at boot time (e.g., `KiUserApcDispatcher`). Print each difference so you can verify the output.

### Step 5 — Restore clean bytes

```
VirtualProtect(
    lpaddress: *const c_void,              // start of .text in memory (mem_text as *const c_void)
    dwsize: usize,                         // text_size as usize
    flnewprotect: PAGE_PROTECTION_FLAGS,   // PAGE_EXECUTE_READWRITE — allow writes
    lpfloldprotect: *mut PAGE_PROTECTION_FLAGS, // out: previous protection, saved for restore
) -> Result<()>
```

After `VirtualProtect`, copy the clean bytes:
```rust
std::ptr::copy_nonoverlapping(dsk_text, mem_text as *mut u8, text_size as usize);
```

Restore original protection:
```rust
VirtualProtect(mem_text as *const c_void, text_size as usize, old_protect, &mut old_protect)?;
```

### Step 6 — Verify

Repeat the comparison loop from step 4. On success, `diff_count` should be 0.

### Cleanup

Always unmap and close in reverse order:
```rust
UnmapViewOfFile(disk_base as *const c_void)?;
CloseHandle(hmap)?;
CloseHandle(hfile)?;
```

---

## PE section layout note

A file mapping maps the raw file bytes, not a fully-loaded PE image. In `ntdll.dll` the `.text` section's `PointerToRawData` and `VirtualAddress` are almost always identical (the section starts at the same offset in the file and in the mapped image). But to be correct, use `VirtualAddress` for the in-memory copy and `PointerToRawData` for the disk-mapped copy.

If you see the values differ significantly (e.g., `VirtualAddress = 0x1000` vs `PointerToRawData = 0x400`), the section is at a different offset on disk versus in memory, and you must use the appropriate field for each view.

---

## Acceptance Criteria

- [ ] `cargo build --target x86_64-pc-windows-gnu -p api-unhooking` succeeds
- [ ] On the VM, the binary prints the in-memory base and disk mapping base
- [ ] `.text` section RVA and size are printed and plausible (size should be in the MB range for ntdll)
- [ ] Any pre-existing byte differences are printed with address, memory byte, and disk byte
- [ ] After restore, the verification pass reports 0 differences (or explains any remaining ones)
- [ ] `VirtualProtect` return value is checked before writing
- [ ] File handle and mapping are closed on exit
- [ ] `MapViewOfFile` null return is checked

---

## Hints

- `HMODULE` in the `windows` crate is a newtype wrapper around `isize`. To get the raw pointer: `let base = hmod.0 as *mut c_void;`
- `PAGE_READONLY` for the file mapping and `PAGE_EXECUTE_READWRITE` for the VirtualProtect patch — don't confuse them.
- The `.text` section in `ntdll.dll` is large (several MB). Iterating it byte by byte is fine for this exercise but slow — you'll see it pause briefly.
- Section name comparison: `section.Name` is `[u8; 8]`. Use `section.Name.starts_with(b".text")` — the name may not be null-terminated if all 8 bytes are used.
- If you get an `Access Denied` error from `VirtualProtect`, check that `lpaddress` points to the actual in-memory copy (based on `ntdll_base`), not the disk-mapped copy.
- This module builds directly on the PE parsing skills from modules 04, 06, and 07. If the IMAGE_DOS_HEADER / IMAGE_NT_HEADERS64 casting is unfamiliar, revisit module 04's step 5.

---

## Submission

Paste `10-api-unhooking/src/main.rs` and ask for a review.
