# Module 07 — Reflective DLL Loading

## Concept

Module 03 injected a DLL using `LoadLibraryA`. That works, but it has two problems:

1. **Disk touch** — the DLL must exist as a file before `LoadLibraryA` can load it
2. **Module list registration** — `LoadLibraryA` adds the DLL to the process's `PEB.Ldr` module list, where any memory scanner can enumerate it

**Reflective loading** eliminates both. The DLL carries its own loader — a function called `ReflectiveLoader` — that manually maps the DLL from wherever its bytes happen to be in memory. No `LoadLibraryA`, no file, no module list entry.

The injector's job becomes simpler: copy the raw DLL bytes into the target and jump to `ReflectiveLoader`. The loader stub does everything else.

### Comparison

| Technique | File on disk | Module list | Detectable by |
|---|---|---|---|
| Module 03 DLL injection | Yes (briefly) | Yes | File scan + module enumeration |
| Module 07 reflective loading | Never | No (unless DllMain adds it) | Memory scan for PE headers (mitigated by Module 06's header stomping) |

---

## How ReflectiveLoader works

The loader stub is position-independent code embedded in the DLL as an export. When called, it:

1. **Finds its own location in memory** — it doesn't know where it was copied to. It uses a `call/pop` trick or reads the instruction pointer to find itself, then walks backward through memory to find the MZ header.

2. **Parses the PE headers** — reads `IMAGE_NT_HEADERS`, calculates `SizeOfImage`, reads `ImageBase`, finds the section headers.

3. **Allocates a new region** — `VirtualAlloc(NULL, SizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)`. This is the DLL's permanent home.

4. **Copies sections** — for each `IMAGE_SECTION_HEADER`, copies `SizeOfRawData` bytes from `PointerToRawData` in the source buffer to `VirtualAddress` in the new allocation.

5. **Applies base relocations** — if the new allocation isn't at `ImageBase` (it won't be), fixup every absolute address. Walk `IMAGE_BASE_RELOCATION` blocks in the `.reloc` section and add the delta (`new_base - preferred_base`) to each address.

6. **Resolves imports** — walk `IMAGE_IMPORT_DESCRIPTOR` entries. For each imported DLL, call `LoadLibraryA`. For each imported function, call `GetProcAddress` and write the result into the import address table (IAT).

7. **Calls DllMain** — compute `new_base + AddressOfEntryPoint`, cast to `fn(HINSTANCE, u32, *mut c_void) -> BOOL`, call it with `DLL_PROCESS_ATTACH`.

Steps 5 and 6 are the hardest. They require careful pointer arithmetic and a solid understanding of the PE format from Module 06.

---

## This module has two crates

| Crate | Output | Role |
|---|---|---|
| `07-reflective-payload` | `reflective_payload.dll` | DLL with `ReflectiveLoader` export + payload |
| `07-reflective-loader` | `reflective-loader.exe` | Copies DLL bytes into target, calls `ReflectiveLoader` |

Build order: payload first, then loader (loader embeds the DLL via `include_bytes!`).

---

## Task A — Payload DLL (`07-reflective-payload/src/lib.rs`)

Export two things:

**`ReflectiveLoader`** — the loader stub (see below). Must be position-independent.

**`DllMain`** — your actual payload. Pop a MessageBox or spawn calc, same as Module 03.

### The loader stub

This is the hard part. Implement `ReflectiveLoader` as a `#[no_mangle] pub unsafe extern "system" fn ReflectiveLoader() -> usize`.

It returns the base address of the newly mapped DLL — the injector can use this to locate `DllMain` and call it, or you can call `DllMain` from within the loader itself.

#### Finding your own base address

The loader is called at some arbitrary address inside the raw DLL bytes. You need to find where the bytes start (the MZ header). Walk backward from the current function's address, checking each page boundary for `0x5A4D` (MZ magic):

```rust
// Get the current instruction pointer (approximate — function entry is close enough)
let mut ptr = ReflectiveLoader as usize;
loop {
    if *(ptr as *const u16) == 0x5A4D { break; }
    ptr -= 1;
}
// ptr is now the base of the DLL bytes in memory
```

#### Base relocation format

The `.reloc` section is a sequence of `IMAGE_BASE_RELOCATION` blocks:

```
IMAGE_BASE_RELOCATION {
    VirtualAddress: u32,   // page RVA this block covers
    SizeOfBlock: u32,      // total size of this block in bytes
    // followed by (SizeOfBlock - 8) / 2 u16 type/offset entries
}
```

Each `u16` entry: top 4 bits = type (`3` = HIGHLOW 32-bit, `10` = DIR64 64-bit, `0` = skip), bottom 12 bits = offset within the page. For x64 you only care about type `10` (DIR64).

For each DIR64 entry: `*(page_rva + offset) += delta` where delta = `new_base - preferred_base`.

#### Import table format

`IMAGE_IMPORT_DESCRIPTOR` array, terminated by an all-zero entry:

```
IMAGE_IMPORT_DESCRIPTOR {
    OriginalFirstThunk: u32,  // RVA of INT (import name table) — names/ordinals
    TimeDateStamp: u32,
    ForwarderChain: u32,
    Name: u32,                // RVA of DLL name string
    FirstThunk: u32,          // RVA of IAT — where you write function pointers
}
```

For each descriptor: call `LoadLibraryA(base + Name)`. Walk the `OriginalFirstThunk` array; for each entry that isn't an ordinal (bit 63 clear), the value is an RVA to `IMAGE_IMPORT_BY_NAME { Hint: u16, Name: [u8] }` — call `GetProcAddress` and write the result into the corresponding `FirstThunk` slot.

---

## Task B — Injector (`07-reflective-loader/src/main.rs`)

Simpler than Module 03 because there's no `LoadLibraryA` dance.

### Step 1 — Find notepad.exe PID

Same Toolhelp32 code as before.

### Step 2 — Open the target

Same as Module 03: `PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD`.

### Step 3 — Copy raw DLL bytes into the target

```
VirtualAllocEx(
    hprocess: HANDLE,                          // target process handle
    lpaddress: Option<*const c_void>,          // None — OS picks the address
    dwsize: usize,                             // DLL_BYTES.len()
    flallocationtype: VIRTUAL_ALLOCATION_TYPE, // MEM_COMMIT | MEM_RESERVE
    flprotect: PAGE_PROTECTION_FLAGS,          // PAGE_EXECUTE_READWRITE — loader needs RWX during mapping
) -> *mut c_void                               // base of remote allocation; NULL on failure
```

Note: `PAGE_EXECUTE_READWRITE` here, not `PAGE_READWRITE`. The loader will be executing from this region while it sets up the real mapping. You'd normally clean this up afterward.

Write the DLL bytes:
```
WriteProcessMemory(
    hprocess: HANDLE,
    lpbaseaddress: *const c_void,               // remote_base as *const c_void
    lpbuffer: *const c_void,                    // DLL_BYTES.as_ptr() cast
    nsize: usize,                               // DLL_BYTES.len()
    lpnumberofbyteswritten: Option<*mut usize>, // None
) -> BOOL
```

### Step 4 — Find the ReflectiveLoader offset

You need to call `ReflectiveLoader` in the remote process. Its address there is `remote_base + offset_within_dll`.

Find the offset within the local DLL bytes by parsing the export directory:

```
IMAGE_EXPORT_DIRECTORY {
    ...
    NumberOfFunctions: u32,      // total number of exported functions
    NumberOfNames: u32,          // number of named exports
    AddressOfFunctions: u32,     // RVA of function address array
    AddressOfNames: u32,         // RVA of name pointer array
    AddressOfNameOrdinals: u32,  // RVA of ordinal array (u16)
}
```

Walk `AddressOfNames` to find the index of `"ReflectiveLoader"`, use `AddressOfNameOrdinals[index]` as an index into `AddressOfFunctions` to get the RVA, then `remote_base as usize + rva` is the callable address in the target.

Hint: `IMAGE_EXPORT_DIRECTORY` is in the data directory at index 0 (`IMAGE_DIRECTORY_ENTRY_EXPORT`).

### Step 5 — Create a remote thread at ReflectiveLoader

```
CreateRemoteThread(
    hprocess: HANDLE,
    lpthreadattributes: Option<*const SECURITY_ATTRIBUTES>,
    dwstacksize: usize,
    lpstartaddress: LPTHREAD_START_ROUTINE,  // remote_base + reflective_loader_rva
    lpparameter: Option<*const c_void>,      // None — ReflectiveLoader takes no argument
    dwcreationflags: u32,
    lpthreadid: Option<*mut u32>,
) -> Result<HANDLE>
```

`lpparameter` is `None` this time — unlike Module 03 where you passed the DLL path. `ReflectiveLoader` finds the DLL bytes by walking backward from its own address.

---

## Acceptance Criteria

- [ ] Both crates build
- [ ] Only `reflective-loader.exe` goes to the VM — the DLL is embedded
- [ ] Payload executes inside `notepad.exe` with no file ever created on disk
- [ ] `ReflectiveLoader` correctly applies relocations (test by examining the mapped region — it should be functional, not just copied)
- [ ] `ReflectiveLoader` correctly resolves imports (if payload calls anything from user32 or kernel32)
- [ ] All Win32 errors checked

---

## Key Types (new in this module)

**`IMAGE_DATA_DIRECTORY`** — a `{VirtualAddress: u32, Size: u32}` pair. `OptionalHeader.DataDirectory[0]` is the export directory; `DataDirectory[5]` is the base relocation table; `DataDirectory[1]` is the import table.

**`IMAGE_EXPORT_DIRECTORY`** — describes all exported symbols. RVAs are relative to the DLL's preferred `ImageBase`, not to the raw bytes — add the buffer base to navigate.

**`IMAGE_BASE_RELOCATION`** — header of one relocation block. Entries are packed `u16` values immediately following the header.

**`IMAGE_IMPORT_DESCRIPTOR`** — one entry per imported DLL. Terminated by an all-zero struct.

**`IMAGE_IMPORT_BY_NAME`** — `{Hint: u16, Name: [u8]}`. The `Name` field is a variable-length null-terminated string. Cast and `CStr::from_ptr` to read it.

---

## Hints

- In the loader stub, avoid calling any external functions before imports are resolved. You can call `LoadLibraryA` and `GetProcAddress` by finding them via PEB walking instead of relying on the import table — but for simplicity, resolve your own imports first, then call DllMain.
- All RVAs in the PE format are offsets from `ImageBase` (the base of the *mapped* image), not from the raw file start. When navigating the raw bytes (before mapping), use the `PointerToRawData` fields instead.
- The `IMAGE_BASE_RELOCATION` entries are right after the struct header — `(block_ptr as *const u8).add(8)` gets you the first `u16`.
- If the DLL has no `.reloc` section (which can happen if it was compiled without `/FIXED:NO`), the relocation data directory will have `Size = 0` — skip the relocation step.
- Test `ReflectiveLoader` locally first: map the DLL bytes into your own process and call the loader directly before attempting remote injection.

---

## Submission

Paste both `07-reflective-payload/src/lib.rs` and `07-reflective-loader/src/main.rs` and ask for a review.
