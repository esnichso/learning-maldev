# Module 06 — PE Disguise

## Concept

Every Windows executable is a **Portable Executable (PE)** file. The PE format contains far more than just code — it carries metadata that forensic tools, AV engines, and analysts use to identify and classify binaries. This module teaches you to manipulate that metadata so your binary looks like something it isn't.

There are two contexts where disguise matters:

| Context | Goal |
|---|---|
| **On-disk** | Fool static analysis, AV scanners, and human analysts who inspect the file |
| **In-memory** | Defeat memory forensics tools that walk loaded module lists and scan mapped PE headers |

This module covers both.

---

## PE Format Crash Course

A PE file is laid out like this (offsets are approximate):

```
Offset 0x00  IMAGE_DOS_HEADER        ← "MZ" magic, e_lfanew points to NT headers
Offset 0x3C  e_lfanew (u32)          ← offset of IMAGE_NT_HEADERS
Offset ?     IMAGE_NT_HEADERS64
               Signature (0x50450000 = "PE\0\0")
               IMAGE_FILE_HEADER      ← machine type, section count, TimeDateStamp
               IMAGE_OPTIONAL_HEADER64 ← entry point, image base, CheckSum, etc.
Offset ?     IMAGE_SECTION_HEADER[]  ← one per section (.text, .data, .rsrc, ...)
...          Section data
...          .rsrc section            ← resources: version info, icons, manifests
```

The structs you'll need are in `windows::Win32::System::Diagnostics::Debug`:
`IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS64`, `IMAGE_FILE_HEADER`, `IMAGE_OPTIONAL_HEADER64`, `IMAGE_SECTION_HEADER`

To navigate from bytes to structs, you'll cast raw pointers:

```rust
let dos = bytes.as_ptr() as *const IMAGE_DOS_HEADER;
let nt_offset = (*dos).e_lfanew as usize;
let nt = bytes.as_ptr().add(nt_offset) as *const IMAGE_NT_HEADERS64;
```

This is all `unsafe`. You're treating a byte array as structured data — if the file is malformed or you calculate the wrong offset, you'll read garbage or crash.

---

## Techniques

### 1. Timestomping

`IMAGE_FILE_HEADER.TimeDateStamp` is a Unix timestamp of when the PE was linked. Security tools use it for correlation ("this binary was compiled at 3am on a Sunday, suspicious"). You can set it to anything — typically the timestamp of a legitimate system binary.

Field: `(*nt).FileHeader.TimeDateStamp: u32`

Realistic values: grab `TimeDateStamp` from `kernel32.dll` or `ntdll.dll` using a hex editor or the `dumpbin /headers` tool, then write that value into your binary.

### 2. Section name normalization

Section names are 8-byte null-padded ASCII strings in `IMAGE_SECTION_HEADER.Name`. Rust compilers often produce unusual names like `.rdata`, `_TEXT`, or packer-specific names. Legitimate MSVC binaries have predictable names: `.text`, `.data`, `.rdata`, `.rsrc`, `.reloc`.

Field: `(*section).Name: [u8; 8]`

Walk the section array (count from `FileHeader.NumberOfSections`) and overwrite the names.

### 3. Checksum recalculation

`IMAGE_OPTIONAL_HEADER64.CheckSum` is a CRC-like sum of the PE. Most user-mode loaders ignore it, but `%WINDIR%\system32\*.dll` files are required to have a valid checksum, and some security tools flag binaries where the checksum is zero or wrong.

Windows provides `CheckSumMappedFile` in `imagehlp.dll`:

```
CheckSumMappedFile(
    baseaddress: *mut c_void,  // pointer to the mapped file bytes in memory
    filelength: u32,           // total file size in bytes
    headersum: *mut u32,       // out: the checksum stored in the header (before you overwrite it)
    checksum: *mut u32,        // out: the correct computed checksum
) -> *mut IMAGE_NT_HEADERS     // pointer to the NT headers in your buffer (or null on failure)
```

Feature flag: `Win32_System_Diagnostics_Debug` (CheckSumMappedFile lives there)

After calling it, write `checksum` into `OptionalHeader.CheckSum`.

### 4. Version info resource spoofing

The `.rsrc` section holds **resources**: icons, dialogs, manifests, and `VS_VERSION_INFO`. This is the metadata visible in the Details tab of Windows Explorer — Company Name, Product Name, File Description, Original Filename, Copyright.

The resource format is complex (nested `IMAGE_RESOURCE_DIRECTORY` trees), but you have two practical options:

**Option A — Binary patch in place**: The strings in VS_VERSION_INFO are UTF-16LE. If your replacement string is shorter than the original, you can overwrite in place and zero-pad. Simple, but brittle — doesn't handle different lengths.

**Option B — Resource compiler**: Build your binary with the right version info baked in from the start, sourced from a real binary you want to impersonate. This is the production approach. Create a `.rc` file, compile with `windres`, link it in.

For this exercise, implement Option A: find the VS_VERSION_INFO block by scanning for the `VS_VERSION_INFO\0` UTF-16LE signature (`56 00 53 00 5F 00 ...`) and patch strings in place.

### 5. PE header stomping (in-memory)

After your loader maps a PE into memory and calls `DllMain`, the MZ/PE headers at the base of the allocation serve no further purpose. Zeroing them defeats memory scanners that walk allocations looking for the `MZ` signature:

```rust
// Inside your loader, after DllMain returns:
std::ptr::write_bytes(remote_base as *mut u8, 0, 0x1000); // zero first page
```

This is only meaningful in the context of a loader (Modules 03, 07) — you do it *after* mapping, not to a file on disk.

---

## Task

Write `pe-disguise.exe`, a command-line tool that takes a PE file and modifies it in place (or writes a new file):

```
pe-disguise.exe <input.exe> [output.exe]
```

If `output.exe` is omitted, overwrite the input.

### Step 1 — Read and parse

Read the file into a `Vec<u8>`. Parse and validate:
- Check the MZ magic (`0x5A4D`) at offset 0
- Follow `e_lfanew` to the NT headers
- Check the PE signature (`0x00004550`)
- Read `FileHeader.NumberOfSections`

If anything is wrong, bail out with a clear error message.

### Step 2 — Stomp the timestamp

Hint: `(*nt_mut).FileHeader.TimeDateStamp = your_value;`

Use `0x5B36C2F5` (a plausible 2018 timestamp) or look up the real timestamp from a system DLL.

### Step 3 — Normalize section names

Walk the section header array. Rename any section whose name doesn't start with `.` to a neutral name (e.g. unnamed sections to `.data`). Leave `.text`, `.rdata`, `.data`, `.rsrc`, `.reloc` alone.

Hint: section headers start immediately after the NT headers. The offset is:
```
nt_offset + size_of::<u32>() + size_of::<IMAGE_FILE_HEADER>() + FileHeader.SizeOfOptionalHeader as usize
```

### Step 4 — Recalculate the checksum

Call `CheckSumMappedFile` on your (modified) buffer, then write the result into `OptionalHeader.CheckSum`.

### Step 5 — Write the output

`std::fs::write(output_path, &bytes)`

---

## Acceptance Criteria

- [ ] Compiles for `x86_64-pc-windows-gnu`
- [ ] Correctly parses MZ and PE headers; rejects non-PE input
- [ ] Timestamp is changed to a plausible value
- [ ] Section names are normalized
- [ ] Checksum in the output is valid (verify with `dumpbin /headers output.exe`)
- [ ] Tool does not corrupt the binary — `output.exe` still runs

---

## Key Types

**`IMAGE_DOS_HEADER`** — the first 64 bytes of every PE. `e_lfanew` (offset 0x3C) is the byte offset of `IMAGE_NT_HEADERS` from the file start.

**`IMAGE_FILE_HEADER`** — machine type, section count, `TimeDateStamp`, `SizeOfOptionalHeader`. Sits inside `IMAGE_NT_HEADERS64` at `NtHeaders.FileHeader`.

**`IMAGE_OPTIONAL_HEADER64`** — entry point, preferred base address, section alignment, `CheckSum`. Sits inside `IMAGE_NT_HEADERS64` at `NtHeaders.OptionalHeader`.

**`IMAGE_SECTION_HEADER`** — one entry per section: `Name [u8; 8]`, `VirtualAddress`, `SizeOfRawData`, `PointerToRawData`. Array starts immediately after the optional header.

---

## Hints

- Cast with `as *mut` (not `as *const`) so you can write through the pointer. The Vec gives you `&mut [u8]` — you need `as_mut_ptr()` for the base.
- `size_of::<IMAGE_DOS_HEADER>()` is 64 bytes, but `e_lfanew` is the authoritative offset — don't hardcode 64.
- `dumpbin /headers yourfile.exe` on Windows shows all fields including TimeDateStamp and CheckSum. Use it to verify your output.
- `CheckSumMappedFile` requires the `imagehlp` link library. Add `#[link(name = "imagehlp")]` above your `extern` block, or use the `windows` crate which handles this.

---

## Submission

Paste `src/main.rs` and ask for a review.
