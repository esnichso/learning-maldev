# Module 09 — Direct Syscalls

## Concept

EDR products (CrowdStrike, SentinelOne, Carbon Black, etc.) intercept API calls by **hooking ntdll.dll**. When Windows loads ntdll into a process, the EDR's kernel driver patches the first few bytes of sensitive stub functions — `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`, etc. — with a `JMP` instruction that redirects execution into the EDR's monitoring code before the real kernel call happens.

This is called **user-mode hooking**. It is the most common detection mechanism against injection techniques. Every module in this curriculum so far goes through ntdll and is therefore visible to any EDR that hooks it.

**Direct syscalls** bypass this entirely: instead of calling the ntdll stub (which may be hooked), you issue the `syscall` instruction yourself with the correct **System Service Number (SSN)** — the integer the Windows kernel uses to dispatch the call internally. The kernel receives the call exactly as if ntdll had made it, but your code never touched ntdll's stub.

### Detection profile comparison

| Technique | Goes through ntdll? | EDR hook visible? |
|---|---|---|
| Module 02 (CreateRemoteThread) | Yes | Yes |
| Module 04 (hollow) via VirtualAllocEx | Yes | Yes |
| Module 09 (direct syscall) | No | No (at user-mode hook layer) |

---

## How EDR hooks work

On an unhooked system, `NtAllocateVirtualMemory` in ntdll.dll starts with:
```
4C 8B D1        mov r10, rcx         ; copy first arg to r10 (syscall ABI)
B8 18 00 00 00  mov eax, 0x18        ; SSN for NtAllocateVirtualMemory (varies by Windows version)
F6 04 25 08 03  test [SharedUserData], ...
...
0F 05           syscall
C3              ret
```

An EDR overwrites the first bytes with a `JMP`:
```
E9 xx xx xx xx  jmp <EDR hook handler>
```

The EDR's handler logs the call, checks arguments, and either blocks or allows the real syscall.

---

## Hell's Gate — extracting the SSN

**Hell's Gate** (by am0nsec and RtlMateusz, 2021): scan the ntdll stub bytes at runtime. If the stub starts with `4C 8B D1 B8`, it is unhooked and bytes `[4]` and `[5]` are the SSN (little-endian `u16`):

```
stub[0] = 0x4C  \
stub[1] = 0x8B   } mov r10, rcx
stub[2] = 0xD1  /
stub[3] = 0xB8  \
stub[4] = SSN_LO  } mov eax, SSN
stub[5] = SSN_HI  /
stub[6] = 0x00  |
stub[7] = 0x00  /
```

**Halo's Gate**: if the stub is hooked (`stub[0] == 0xE9`), look at the function immediately above or below it in the EAT (sorted by ordinal). Their SSNs differ by exactly 1. Use their SSN ± 1 to recover the hooked function's SSN.

SSNs are **not stable across Windows versions**. The SSN for `NtAllocateVirtualMemory` is `0x18` on Windows 10 22H2 but different on other versions. Always extract at runtime — never hard-code.

---

## The Windows syscall ABI (x64)

The x64 Windows syscall convention differs slightly from the standard calling convention:

| Register | Role |
|---|---|
| `rax` | SSN (in), return value (out) |
| `r10` | First argument (copy of `rcx`) |
| `rdx` | Second argument |
| `r8` | Third argument |
| `r9` | Fourth argument |
| Stack | Fifth+ arguments (with 0x20 shadow space) |

The stub's `mov r10, rcx` is required: the kernel reads arg1 from `r10`, not `rcx` (because `rcx` is overwritten by the `syscall` instruction itself with the return address).

---

## The stub

The syscall stub you'll write into RWX memory is 11 bytes:

```
4C 8B D1           mov r10, rcx     ; move first argument into r10
B8 xx xx 00 00     mov eax, <SSN>   ; load SSN
0F 05              syscall          ; enter kernel
C3                 ret              ; return to caller
```

This is identical to what an unhooked ntdll stub does — the only difference is that you wrote it yourself into your own memory.

---

## Task — Direct syscall caller (`09-direct-syscalls/src/main.rs`)

Implement the five steps. Each `todo!()` is one logical operation.

### Step 1 — Get ntdll.dll base from PEB

Reuse the PEB walk from Module 08. Walk `InLoadOrderModuleList` (or `InMemoryOrderModuleList`) and find the entry whose `BaseDllName` is `"ntdll.dll"`. Return its `DllBase`.

`ntdll.dll` is always the **second** entry in `InLoadOrderModuleList` (after the main executable), but walk the list properly rather than hard-coding the index.

### Step 2 — Find NtAllocateVirtualMemory in ntdll's EAT

Walk ntdll's `IMAGE_EXPORT_DIRECTORY` (same as Module 08's kernel32 EAT walk). This time, instead of hashing, compare the name string directly to `"NtAllocateVirtualMemory"`.

You need the **pointer to the first byte of the function** (not just the function pointer — the first byte is what you scan for the SSN).

```
fn_rva  = AddressOfFunctions[ordinal]
stub_ptr = (ntdll_base as usize + fn_rva as usize) as *const u8
```

### Step 3 — Extract the SSN (Hell's Gate)

```
let bytes = std::slice::from_raw_parts(stub_ptr, 8);
```

Check `bytes[0..4] == [0x4C, 0x8B, 0xD1, 0xB8]`. If yes, the SSN is:
```rust
let ssn = u16::from_le_bytes([bytes[4], bytes[5]]);
```

If `bytes[0] == 0xE9` (JMP — hooked), the bonus task is to implement Halo's Gate. For the base exercise, `panic!` with a message indicating the stub is hooked.

### Step 4 — Build the stub in RWX memory

```
VirtualAlloc(
    lpaddress:      Option<*const c_void>,          // None — let OS choose
    dwsize:         usize,                           // STUB_TEMPLATE.len() = 11
    flallocationtype: VIRTUAL_ALLOCATION_TYPE,       // MEM_COMMIT | MEM_RESERVE
    flprotect:      PAGE_PROTECTION_FLAGS,           // PAGE_EXECUTE_READWRITE
) -> *mut c_void                                     // NULL on failure
```

Copy `STUB_TEMPLATE` into the allocation, then patch bytes `[4]` and `[5]` with the SSN:

```rust
let ssn_bytes = ssn.to_le_bytes();
stub_ptr.add(4).write(ssn_bytes[0]);
stub_ptr.add(5).write(ssn_bytes[1]);
```

### Step 5 — Call the stub

Transmute the stub memory pointer to `NtAllocateVirtualMemory` and call it:

```
NtAllocateVirtualMemory(
    ProcessHandle:   HANDLE,           // pseudo-handle for current process: HANDLE(-1isize as *mut c_void)
    BaseAddress:     *mut *mut c_void,  // &mut alloc_base — out: actual allocated address
    ZeroBits:        usize,             // 0 — no address space restriction
    RegionSize:      *mut usize,        // &mut region_size — in: requested size; out: actual size
    AllocationType:  u32,               // MEM_COMMIT | MEM_RESERVE = 0x3000
    Protect:         u32,               // PAGE_READWRITE = 0x04
) -> i32 (NTSTATUS)                    // 0x00000000 = STATUS_SUCCESS
```

Assert the returned `NTSTATUS == 0` and that `alloc_base` is non-null.

---

## Key structures

**`NTSTATUS` return values**: NT functions return `i32`. `0` = `STATUS_SUCCESS`. Negative values are errors. Unlike Win32 `BOOL`, there is no `.ok()` adapter — check manually with `assert_eq!(status, 0, ...)`.

**Current-process pseudo-handle**: `HANDLE(-1isize as *mut c_void)` or `GetCurrentProcess()`. The value `-1` is special — the kernel interprets it as "the calling process". No `OpenProcess` needed for self-operations.

**`MEM_COMMIT | MEM_RESERVE` as u32**: The windows crate constants are `VIRTUAL_ALLOCATION_TYPE` bitflags. For passing to a raw NT function: `(MEM_COMMIT | MEM_RESERVE).0` extracts the `u32` value.

**`PAGE_READWRITE` as u32**: Similarly, `PAGE_READWRITE.0`.

---

## Acceptance Criteria

- [ ] `cargo build --target x86_64-pc-windows-gnu -p direct-syscalls` succeeds
- [ ] ntdll base is found via PEB walk, not via `GetModuleHandleA("ntdll.dll")`
- [ ] `NtAllocateVirtualMemory` stub pointer is found via ntdll EAT walk, not imported
- [ ] SSN is printed and matches the expected value for your Windows version (check with Sysmon or Windbg: `u ntdll!NtAllocateVirtualMemory`)
- [ ] The 11-byte stub is correctly patched with the real SSN
- [ ] Calling the stub returns `NTSTATUS 0` (STATUS_SUCCESS)
- [ ] `alloc_base` is non-null after the call, confirming memory was allocated
- [ ] The binary's import table does NOT contain `NtAllocateVirtualMemory` (it only imports `VirtualAlloc` for the stub buffer, which is expected)

---

## Hints

- `HANDLE(-1isize as *mut c_void)` is the current-process pseudo-handle. The NT API doesn't require you to call `OpenProcess` on yourself.
- The SSN for `NtAllocateVirtualMemory` on a clean Windows 10 22H2 system is typically `0x18`, but this varies. Always extract it at runtime.
- `ptr::copy_nonoverlapping(STUB_TEMPLATE.as_ptr(), stub_ptr, STUB_TEMPLATE.len())` copies the template bytes. Then patch [4] and [5].
- The `MEM_COMMIT | MEM_RESERVE` flag value as a plain `u32` is `0x3000`. `PAGE_READWRITE` is `0x04`. You can pass these directly to avoid `.0` extraction from the windows crate types.
- If you get `NTSTATUS 0xC0000005` (ACCESS_VIOLATION), the stub RWX allocation may have failed silently — check `VirtualAlloc`'s return value.
- `println!("stub bytes: {:02x?}", std::slice::from_raw_parts(stub_ptr as *const u8, 11))` is useful for debugging your stub construction.
- For the bonus Halo's Gate: you need the ordinal of `NtAllocateVirtualMemory` in the EAT. Look at the adjacent function at ordinal ± 1, check if it is unhooked, extract its SSN, and infer the target's SSN = adjacent_SSN ∓ 1.
- After step 5, verify with Process Hacker that a 4 KB `RW` allocation appeared in the process's memory map at `alloc_base`.

---

## Submission

Paste `09-direct-syscalls/src/main.rs` and ask for a review.
