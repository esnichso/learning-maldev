# Module 04 — Process Hollowing

## Concept

**Process hollowing** (also called *process replacement*) is a technique where you:

1. Create a legitimate process — something innocent like `notepad.exe` — in a suspended state, so its main thread hasn't run a single instruction yet.
2. Tear out its loaded image by unmapping it from the process's virtual address space.
3. Map your own PE binary into the now-empty space.
4. Redirect the suspended thread's instruction pointer to your payload's entry point.
5. Resume the thread — the process wakes up running your code.

From the outside, the process still shows up as `notepad.exe` in Task Manager, Process Explorer, or `tasklist`. The parent/child relationship looks normal. There is no DLL on disk, no shellcode written into a running process, and no remote thread created. The process runs under a legitimate identity from birth.

### Why it's stealthier than Modules 02 and 03

| Property | Module 02 (shellcode injection) | Module 03 (DLL injection) | Module 04 (process hollowing) |
|---|---|---|---|
| Target process | existing, running | existing, running | we create it ourselves |
| What we write | raw shellcode | a file path string | a full mapped PE image |
| Payload on disk | never | briefly in `%TEMP%` | never |
| Process name in task list | target's (notepad) | target's (notepad) | our chosen decoy (notepad) |
| How execution starts | `CreateRemoteThread` at shellcode | `CreateRemoteThread` at `LoadLibraryA` | resume the process's own main thread |
| PE format knowledge needed | none | none | deep — headers, sections, relocations |

The last row is why this module exists: hollowing forces you to understand the PE format in a way that directly previews Modules 06 (PE disguise) and 07 (reflective loading).

---

## The hollowing sequence

1. `CreateProcessA` — launch `notepad.exe` suspended; get back `hProcess` and `hThread`.
2. `NtQueryInformationProcess` — query class 0 (`ProcessBasicInformation`) to get `PebBaseAddress`.
3. `ReadProcessMemory` — read 8 bytes at `peb_address + 0x10` to get the loaded image base.
4. `NtUnmapViewOfSection` — tear the existing image out of the remote address space.
5. Parse the embedded payload PE — read `ImageBase`, `SizeOfImage`, `SizeOfHeaders`, sections, reloc directory, `AddressOfEntryPoint` from the raw bytes.
6. `VirtualAllocEx` — allocate at the payload's preferred `ImageBase` with `PAGE_EXECUTE_READWRITE`.
7. `WriteProcessMemory` — write PE headers, then each section's raw data to its virtual address.
8. Apply base relocations — if `new_base != preferred_base`, walk `.reloc` blocks and apply DIR64 fixups.
9. `WriteProcessMemory` — update `PEB.ImageBaseAddress` to `new_base`.
10. `GetThreadContext` — read the suspended thread's register state (`ContextFlags = CONTEXT_FULL`).
11. Set `ctx.Rcx = new_base + AddressOfEntryPoint`, then `SetThreadContext` + `ResumeThread`.

---

## This module has two crates

| Crate | Output | Role |
|---|---|---|
| `04-hollow-payload` | `hollow_payload.exe` | Payload — the code that will run inside notepad's process slot |
| `04-process-hollowing` | `process-hollowing.exe` | Hollower — creates, unmaps, maps, and resumes |

**Build order matters.** The hollower embeds the payload via `include_bytes!`:

```
cargo build --target x86_64-pc-windows-gnu -p hollow-payload    # first
cargo build --target x86_64-pc-windows-gnu -p process-hollowing # second
```

Only `process-hollowing.exe` needs to go to the VM.

---

## Task — Hollower (`04-process-hollowing/src/main.rs`)

Implement the hollower in eleven steps. The skeleton in `src/main.rs` has a `todo!()` for each step. Work through them in order — each step's output is needed by the next.

### Step 1 — Launch the host process suspended

```
CreateProcessA(
    lpapplicationname: PCSTR,                        // full path to the exe to launch, OR
    lpcommandline: PSTR,                             // command line — Windows may modify this buffer,
                                                     //   so it must be mutable; pass None if you used
                                                     //   lpapplicationname
    lpprocessattributes: Option<*const SECURITY_ATTRIBUTES>, // security for the process object — None for default
    lpthreadattributes: Option<*const SECURITY_ATTRIBUTES>,  // security for the initial thread — None for default
    binherithandles: BOOL,                           // whether the new process inherits open handles — false
    dwcreationflags: PROCESS_CREATION_FLAGS,         // CREATE_SUSPENDED — start paused, thread hasn't run
    lpenvironment: Option<*const c_void>,            // environment block — None to inherit parent's
    lpcurrentdirectory: PCSTR,                       // working directory — None to inherit parent's
    lpstartupinfo: *const STARTUPINFOA,              // window/stdio config — cb field must be set to size_of::<STARTUPINFOA>()
    lpprocessinformation: *mut PROCESS_INFORMATION,  // out: hProcess, hThread, dwProcessId, dwThreadId
) -> Result<()>                                      // Err if the exe was not found or access denied
```

`PROCESS_INFORMATION` gives you two handles you'll use in every remaining step: `hProcess` (to read/write the process's memory) and `hThread` (to redirect execution).

### Step 2 — Get the remote PEB address

The Process Environment Block (PEB) is a per-process structure in the target's address space. Its address is not a fixed offset — you query it via `NtQueryInformationProcess`.

```
NtQueryInformationProcess(
    ProcessHandle: HANDLE,          // hProcess from PROCESS_INFORMATION
    ProcessInformationClass: u32,   // 0 = ProcessBasicInformation
    ProcessInformation: *mut c_void, // pointer to a PROCESS_BASIC_INFORMATION you allocate locally
    ProcessInformationLength: u32,  // mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32
    ReturnLength: *mut u32,         // out: actual bytes written — can pass a local u32 or null
) -> i32 (NTSTATUS)                 // 0 = STATUS_SUCCESS; negative = error
```

After the call, `pbi.PebBaseAddress` holds a pointer valid in the **remote** address space. You can't dereference it locally — use `ReadProcessMemory` to read through it.

### Step 3 — Read PEB.ImageBaseAddress

On x64 Windows, `PEB.ImageBaseAddress` is at offset `0x10` from the PEB base. This is the base address of whichever image is currently loaded in the process — right now that's `notepad.exe`.

```
ReadProcessMemory(
    hprocess: HANDLE,                       // hProcess from PROCESS_INFORMATION
    lpbaseaddress: *const c_void,           // peb_base + 0x10 — where ImageBaseAddress lives
    lpbuffer: *mut c_void,                  // pointer to a local usize to receive the value
    nsize: usize,                           // 8 (size of a pointer on x64)
    lpnumberofbytesread: Option<*mut usize>, // None
) -> Result<()>
```

Save this value — it's what you'll pass to `NtUnmapViewOfSection`.

### Step 4 — Unmap the existing image

```
NtUnmapViewOfSection(
    ProcessHandle: HANDLE,   // hProcess from PROCESS_INFORMATION
    BaseAddress: *mut c_void, // the image base you read from the PEB in step 3
) -> i32 (NTSTATUS)          // 0 = STATUS_SUCCESS
```

After this call, the memory range that held `notepad.exe`'s image is freed and ready to be replaced. The process is still running (suspended) — it just has no image mapped anymore.

### Step 5 — Parse the embedded payload PE

Before allocating anything in the remote process, parse the payload bytes (`PAYLOAD`) locally to extract what you need:

- `IMAGE_DOS_HEADER.e_lfanew` — byte offset to the NT headers
- `IMAGE_NT_HEADERS64.OptionalHeader.ImageBase` — preferred load address
- `IMAGE_NT_HEADERS64.OptionalHeader.SizeOfImage` — total mapped size to allocate
- `IMAGE_NT_HEADERS64.OptionalHeader.SizeOfHeaders` — how many bytes to write as the header region
- `IMAGE_NT_HEADERS64.FileHeader.NumberOfSections` — how many section headers follow
- `IMAGE_NT_HEADERS64.OptionalHeader.AddressOfEntryPoint` — RVA of the entry point (needed in step 11)
- `IMAGE_NT_HEADERS64.OptionalHeader.DataDirectory[5]` — base relocation directory (needed in step 8)

Section headers begin immediately after `IMAGE_NT_HEADERS64` in memory. Each `IMAGE_SECTION_HEADER` has `VirtualAddress` (RVA in the mapped image) and `PointerToRawData` / `SizeOfRawData` (location in the file bytes).

All of this is raw pointer arithmetic into the `PAYLOAD` byte slice. This is PE format work — the same structures appear in Modules 06 and 07.

### Step 6 — Allocate space in the remote process

```
VirtualAllocEx(
    hprocess: HANDLE,                          // hProcess from PROCESS_INFORMATION
    lpaddress: Option<*const c_void>,          // preferred_base as *const c_void — try the ImageBase
    dwsize: usize,                             // SizeOfImage from the payload's OptionalHeader
    flallocationtype: VIRTUAL_ALLOCATION_TYPE, // MEM_COMMIT | MEM_RESERVE
    flprotect: PAGE_PROTECTION_FLAGS,          // PAGE_EXECUTE_READWRITE — image needs RWX while you build it
) -> *mut c_void                               // actual base in the remote process; NULL on failure
```

The returned `new_base` may differ from `preferred_base` — the OS doesn't guarantee the preferred address. If they differ, you must apply relocations (step 8).

### Step 7 — Write the payload image into remote memory

Two writes: headers first, then each section.

**Headers:**
```
WriteProcessMemory(
    hprocess: HANDLE,                           // hProcess
    lpbaseaddress: *const c_void,               // new_base — start of the remote allocation
    lpbuffer: *const c_void,                    // PAYLOAD.as_ptr() cast — start of raw file bytes
    nsize: usize,                               // SizeOfHeaders from OptionalHeader
    lpnumberofbyteswritten: Option<*mut usize>, // None
) -> Result<()>
```

**Sections** (one `WriteProcessMemory` call per section):
```
WriteProcessMemory(
    hprocess: HANDLE,
    lpbaseaddress: *const c_void,  // new_base + section.VirtualAddress
    lpbuffer: *const c_void,       // PAYLOAD.as_ptr() + section.PointerToRawData
    nsize: usize,                  // section.SizeOfRawData
    lpnumberofbyteswritten: Option<*mut usize>, // None
) -> Result<()>
```

### Step 8 — Apply base relocations (if needed)

If `new_base as usize != preferred_base`, every hardcoded absolute address in the payload is wrong by a delta of `new_base as isize - preferred_base as isize`. The `.reloc` section records every location that needs fixing.

`DataDirectory[5]` (index 5 = `IMAGE_DIRECTORY_ENTRY_BASERELOC`) gives you `VirtualAddress` and `Size` of the relocation data. The data is a sequence of `IMAGE_BASE_RELOCATION` blocks:

```
IMAGE_BASE_RELOCATION {
    VirtualAddress: u32,  // RVA of the 4 KB page this block covers
    SizeOfBlock:    u32,  // total byte size of this block, including this 8-byte header
    // followed by (SizeOfBlock - 8) / 2  entries of type u16
}
```

Each `u16` entry packs two fields:
- **top 4 bits** — relocation type: `10` (0xA) = DIR64 (x64 pointer), `0` = padding (skip)
- **bottom 12 bits** — byte offset within the page

For each DIR64 entry, the address to fix up is `new_base + block.VirtualAddress + entry_offset`. Read the 8-byte value there, add `delta`, write it back. You are working on bytes you just wrote into the **remote** process, so use `ReadProcessMemory` + `WriteProcessMemory` for each fixup — or collect the entire reloc section locally, apply fixups to a local buffer, and write it back in one shot.

### Step 9 — Update PEB.ImageBaseAddress

The PEB still records the old image base. Update it to `new_base` so the runtime and any debugger see the correct value:

```
WriteProcessMemory(
    hprocess: HANDLE,
    lpbaseaddress: *const c_void,  // peb_base + 0x10 — same address you read in step 3
    lpbuffer: *const c_void,       // pointer to new_base (a local usize)
    nsize: usize,                  // 8
    lpnumberofbyteswritten: Option<*mut usize>, // None
) -> Result<()>
```

### Step 10 — Read the suspended thread's context

```
GetThreadContext(
    hthread: HANDLE,         // hThread from PROCESS_INFORMATION — the suspended main thread
    lpcontext: *mut CONTEXT, // pointer to a CONTEXT you allocate — set ContextFlags first
) -> Result<()>
```

`CONTEXT` must have `ContextFlags` set **before** the call. Use `CONTEXT_FULL` to capture all registers including the general-purpose ones.

```rust
let mut ctx = CONTEXT { ContextFlags: CONTEXT_FULL, ..Default::default() };
```

### Step 11 — Redirect and resume

On x64, when the OS creates the main thread, it starts execution at the entry point with `Rcx` pointing to the entry point address (Windows calling convention: first argument = Rcx). Setting `Rcx` here is what directs the CRT startup code to the right place.

```
// Modify the context:
ctx.Rcx = new_base as u64 + payload_entry_point_rva as u64;
```

Apply the modified context:
```
SetThreadContext(
    hthread: HANDLE,          // hThread from PROCESS_INFORMATION
    lpcontext: *const CONTEXT, // the modified CONTEXT
) -> Result<()>
```

Resume the thread:
```
ResumeThread(
    hthread: HANDLE,  // hThread from PROCESS_INFORMATION
) -> u32              // previous suspend count (1 = was suspended once); 0xFFFFFFFF on error
```

---

## ntapi crate note

`NtQueryInformationProcess` and `NtUnmapViewOfSection` are NT-level APIs that the `windows` crate does not wrap. The `ntapi` crate exposes them directly. Import them like this:

```rust
use ntapi::ntpsapi::{
    NtQueryInformationProcess,
    NtUnmapViewOfSection,
    PROCESS_BASIC_INFORMATION,
    ProcessBasicInformation,   // the u32 constant 0 — the class you pass to NtQueryInformationProcess
};
```

Both functions return an `i32` (`NTSTATUS`). Check for success with `== 0`. There is no `?` operator for NTSTATUS — check it manually and call `panic!` (or return an error) if it isn't zero.

---

## PEB structure note

The Process Environment Block (PEB) is an undocumented (but stable) Windows structure. On x64:

| Offset | Size | Field |
|---|---|---|
| 0x00 | 1 | InheritedAddressSpace |
| 0x02 | 1 | BeingDebugged |
| 0x08 | 8 | Mutant (HANDLE) |
| **0x10** | **8** | **ImageBaseAddress** |
| 0x18 | 8 | Ldr (PEB_LDR_DATA*) |
| ... | | ... |

`ImageBaseAddress` at offset `0x10` is what you read in step 3 and update in step 9. Use `ReadProcessMemory` / `WriteProcessMemory` with `peb_base as usize + 0x10` as the address. Cast `pbi.PebBaseAddress` (a `*mut PEB` from ntapi) to `usize` for the arithmetic:

```rust
let image_base_addr = pbi.PebBaseAddress as usize + 0x10;
```

---

## Acceptance Criteria

- [ ] `cargo build --target x86_64-pc-windows-gnu -p hollow-payload` builds first
- [ ] `cargo build --target x86_64-pc-windows-gnu -p process-hollowing` succeeds
- [ ] Only `process-hollowing.exe` goes to the VM
- [ ] Running `process-hollowing.exe` on the VM opens `calc.exe` (payload's visible effect)
- [ ] The process that executed the payload appears as `notepad.exe` in Task Manager
- [ ] All NT status codes checked (`!= 0` triggers a panic or error path)
- [ ] All Win32 `Result<()>` returns unwrapped or handled (no silent failures)
- [ ] `VirtualAllocEx` NULL return detected and handled
- [ ] Relocations are applied if `new_base != preferred_base` (don't assume the OS honors the preferred address)
- [ ] `PEB.ImageBaseAddress` is updated to `new_base` before resuming

---

## Key Types

**`PROCESS_INFORMATION`** — returned by `CreateProcessA`. Contains `hProcess` (process handle), `hThread` (initial thread handle), `dwProcessId`, `dwThreadId`. Both handles must be closed when you are done.

**`STARTUPINFOA`** — passed to `CreateProcessA`. The `cb` field must be set to `mem::size_of::<STARTUPINFOA>() as u32` before the call; all other fields can be zeroed with `..Default::default()`.

**`PROCESS_BASIC_INFORMATION`** — from `ntapi::ntpsapi`. Key field: `PebBaseAddress: *mut PEB` — the address of the remote process's PEB. Cast to `usize` for pointer arithmetic.

**`CONTEXT`** — from `Win32_System_Diagnostics_Debug`. On x64, general-purpose registers are direct fields (`Rax`, `Rcx`, `Rdx`, ...). Set `ContextFlags = CONTEXT_FULL` before calling `GetThreadContext`. Modify `Rcx` to point to the new entry point, then call `SetThreadContext`.

**`NTSTATUS`** — `i32` returned by NT functions. `0` (`STATUS_SUCCESS`) means success. Negative values are error codes. The `ntapi` crate does not use `Result<()>` — check the return value manually.

**`IMAGE_DOS_HEADER`**, **`IMAGE_NT_HEADERS64`**, **`IMAGE_SECTION_HEADER`**, **`IMAGE_BASE_RELOCATION`** — all in `Win32_System_Diagnostics_Debug`. These are the PE format structures you'll navigate with raw pointer arithmetic. All RVAs (relative virtual addresses) in these headers are offsets from the image base in the mapped image, not from the start of the raw file bytes — use `PointerToRawData` for file offsets and `VirtualAddress` for mapped offsets.

---

## Hints

- Build `hollow-payload` before `process-hollowing` every time you change the payload. The `include_bytes!` path only updates when you rebuild the hollower.
- `NtQueryInformationProcess` and `NtUnmapViewOfSection` are not in the `windows` crate — they're in `ntapi`. See the ntapi crate note above for the import path.
- The section headers start immediately after `IMAGE_NT_HEADERS64` in the file. Cast `(nt_ptr as usize + mem::size_of::<IMAGE_NT_HEADERS64>())` to `*const IMAGE_SECTION_HEADER` and index into it with `.add(i)`.
- `DataDirectory` is an array of 16 `IMAGE_DATA_DIRECTORY` structs. Index 5 is the base relocation table. Check that `DataDirectory[5].Size > 0` before walking relocation blocks — a payload compiled with ASLR disabled has no `.reloc` section.
- For the relocation loop, the next block starts at `block_ptr + block.SizeOfBlock`. The loop ends when you've consumed `DataDirectory[5].Size` bytes.
- `ctx.Rcx` is not inside a nested anonymous struct in windows-rs 0.58 on x64 — it is a direct field. `CONTEXT_FULL` is sufficient to capture it.
- `ResumeThread` decrement the suspend count and returns the **previous** count. `0xFFFFFFFF` (`u32::MAX`) means it failed — check it.
- This module introduces PE header parsing and base relocation walking. The same skills come back in Modules 06 (PE disguise) and 07 (reflective loading). Module 07's README has a detailed breakdown of base relocation blocks — read it now as a reference if you want more context before implementing step 8.

---

## Submission

Paste `04-process-hollowing/src/main.rs` and ask for a review.
