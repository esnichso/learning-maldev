# Module 05 — Evasion Basics

## Concept

Antivirus and EDR tools detect malware at three different moments:

| Detection phase | When it happens | What gets scanned |
|---|---|---|
| **Static** | Before execution — on disk or in transit | File bytes, strings, PE structure |
| **In-memory / dynamic** | While the process is running | Contents of memory allocations |
| **Behavioral** | During execution | API call patterns, system calls, network traffic |

This module focuses on the first two. You take Module 01's shellcode runner and add three hardening layers on top of it, one at a time. Each layer defeats a specific detection mechanism.

---

## Detection Model

| Technique | Defeats |
|---|---|
| XOR string obfuscation | Static string scanning (`strings.exe`, YARA rules, AV signatures that match on literal text) |
| Shellcode encryption at rest | Static byte signature scanning of the binary on disk |
| Sleep obfuscation (PAGE_NOACCESS) | In-memory scanning during the sleep window |

None of these make you undetectable. They raise the cost of detection. Understanding *what* each technique defeats — and what it doesn't — matters as much as implementing it.

---

## Starting Point

**Do not start from scratch.** Open `01-shellcode-runner/src/main.rs` and copy it into `05-evasion-basics/src/main.rs`. Then add each technique as described below. The skeleton in this module's `src/main.rs` shows where the new pieces fit.

---

## Technique 1 — XOR String Obfuscation

### The problem

Open a compiled binary in any hex editor or run:

```
strings.exe evasion-basics.exe
```

String literals — API names, process names, URLs, file paths — appear verbatim. AV signature databases contain lists of strings known to appear in malware. If your binary contains `"notepad.exe"` or `"calc.exe"` in plaintext, that's a match.

### The solution

XOR each string with a key byte **at compile time**. Only the ciphertext is stored in the binary. At runtime, XOR it back to recover the original string.

Rust's `const fn` makes compile-time computation possible. A `const fn`:
- is evaluated by the compiler at build time
- its result is baked into the binary as a constant
- no runtime computation happens at all

The pattern:

```rust
const fn xor_bytes<const N: usize>(data: &[u8; N], key: u8) -> [u8; N] {
    // iterate over `data`, XOR each byte with `key`, return the result
    // use `while`, not `for` — const fn cannot use iterators
}
```

Note the `<const N: usize>` generic parameter. This is a **const generic** — it captures the array length at compile time so the function can return `[u8; N]` (a fixed-size array). You can't use `for` loops in `const fn` because iterator methods aren't const — use a `while` loop with an index instead.

### Key selection

`KEY = 0x4b` is used in the skeleton. Any non-zero byte works. In practice, keys are derived from host fingerprinting (username hash, volume serial number) so the sample only decrypts on the intended target. That's Module 06+ territory.

---

## Technique 2 — Shellcode Encryption at Rest

### The problem

AV/EDR vendors capture shellcode samples. Meterpreter's `x64/exec` payload starts with:

```
0xfc 0x48 0x83 0xe4 0xf0 ...
```

That byte sequence is a signature. A scanner reading your binary on disk finds it in the `SHELLCODE` constant and flags it immediately, before execution.

### The solution

Apply the same `xor_bytes` const fn from Technique 1 to the shellcode bytes themselves. The binary stores only ciphertext. No scanner scanning the file on disk will see the real shellcode bytes.

The runtime flow changes slightly:

1. `VirtualAlloc` — RW region (same as Module 01)
2. Copy `SHELLCODE_ENC` into the allocation
3. Decrypt **in place**: walk the allocation byte by byte and XOR with `KEY`
4. Only now flip to `PAGE_EXECUTE_READ`

The decrypted shellcode only ever exists in memory (in the `VirtualAlloc`'d region), never on disk.

To generate `SHELLCODE_ENC` from your Module 01 bytes:

```
# Python one-liner to XOR every byte
python3 -c "
data = bytes([0xfc,0x48,...])  # paste your shellcode here
key = 0x4b
print(list(b ^ key for b in data))
"
```

Or use the `xor_bytes` const fn directly if you have the bytes as a Rust `const`.

---

## Technique 3 — Sleep Obfuscation with PAGE_NOACCESS

### The problem

Windows Defender and many EDR products run a periodic **memory scanner** inside each process. The scanner walks all memory allocations, reads their contents, and checks for shellcode signatures. This scan can happen **while your thread is sleeping**.

Module 01's runner allocates, writes shellcode, flips to `PAGE_EXECUTE_READ`, then executes. If the scanner runs between the flip and the execute, it reads the decrypted shellcode at that RX address and flags it.

### The solution

After flipping to `PAGE_EXECUTE_READ`, immediately flip the region to `PAGE_NOACCESS` before sleeping. `PAGE_NOACCESS` means no read, no write, no execute. Any attempt to touch the page raises an access violation.

The flow:

```
VirtualAlloc (RW)
  ↓
copy + decrypt shellcode
  ↓
VirtualProtect → PAGE_EXECUTE_READ   (brief — we change it immediately)
  ↓
VirtualProtect → PAGE_NOACCESS       ← page is now invisible to scanners
  ↓
Sleep(N)                             ← scanners can't read the page here
  ↓
VirtualProtect → PAGE_EXECUTE_READ   ← restore before executing
  ↓
CreateThread + WaitForSingleObject
```

During the `Sleep` window, any process that tries to read the page — including a memory scanner — receives an access violation and cannot see the shellcode bytes.

### Limitations

This only protects during the sleep window. Once the shellcode is executing, the page must be `PAGE_EXECUTE_READ`. More sophisticated approaches encrypt the shellcode in place before sleeping (re-encrypting it so the decrypted form never sits on a readable/executable page), but that requires the shellcode to cooperate. The NOACCESS trick is simpler and still meaningfully reduces the scan window.

Also: if any other thread in your process accesses the protected region while it's `PAGE_NOACCESS`, it will crash. Don't use this in multithreaded loaders without coordination.

Page protection transitions (`RW → RX`, `RX → NOACCESS`, `NOACCESS → RX`) are themselves suspicious. EDRs log `VirtualProtect` calls with certain permission patterns. That's a behavioral signal — addressed in later modules via direct syscalls.

---

## Task

Starting from Module 01's `main.rs`, implement all three techniques:

1. Write the `xor_bytes` const fn and use it to encrypt `SHELLCODE_ENC` at compile time
2. Decrypt the shellcode in place after copying it into the `VirtualAlloc`'d region
3. Add the `PAGE_NOACCESS` sleep obfuscation sequence around a 5-second sleep

Everything in `src/main.rs` is marked with `todo!()`. Fill in each step. The structure mirrors Module 01 — you are hardening it, not rewriting it.

---

## API Reference

### VirtualProtect

```
VirtualProtect(
    lpaddress: *mut c_void,                     // base address of the region to change (from VirtualAlloc)
    dwsize: usize,                              // number of bytes to change protection on
    flnewprotect: PAGE_PROTECTION_FLAGS,        // the new protection to apply (e.g. PAGE_NOACCESS)
    lpfloldprotect: *mut PAGE_PROTECTION_FLAGS, // out-param: receives the previous protection value
) -> Result<()>                                 // returns Err on failure; check with .ok().expect(...)
```

Feature flag: `Win32_System_Memory`

You call `VirtualProtect` three times in this module:
- once to go `RW → PAGE_EXECUTE_READ`
- once to go `PAGE_EXECUTE_READ → PAGE_NOACCESS`
- once to go `PAGE_NOACCESS → PAGE_EXECUTE_READ`

The `lpfloldprotect` out-parameter is mandatory — pass `&mut old` where `old` is declared as `PAGE_PROTECTION_FLAGS::default()`. Reuse the same `old` variable for all three calls.

### Sleep

```
Sleep(
    dwmilliseconds: u32,  // how long to pause this thread, in milliseconds (5000 = 5 seconds)
)                         // no return value
```

Feature flag: `Win32_System_Threading`

`Sleep` is in the same feature flag as `CreateThread` and `WaitForSingleObject`. You already have that feature enabled.

---

## Acceptance Criteria

- [ ] `cargo build --target x86_64-pc-windows-gnu -p evasion-basics` compiles without errors
- [ ] `strings.exe evasion-basics.exe` does not reveal the shellcode bytes in plaintext
- [ ] The raw Meterpreter header bytes (`0xfc 0x48 0x83 0xe4 0xf0`) do not appear in the compiled binary
- [ ] The shellcode is decrypted in memory (not stored as plaintext in any `const`)
- [ ] During the `Sleep` call, the shellcode allocation is `PAGE_NOACCESS`
- [ ] All `VirtualProtect` calls check the return value
- [ ] `xor_bytes` is a `const fn` — decryption of constants happens at compile time, not runtime
- [ ] Running the `.exe` in the Windows VM executes the shellcode (calc.exe pops or equivalent)

---

## Key Types

**`PAGE_NOACCESS`** — `PAGE_PROTECTION_FLAGS(0x01)`. No read, no write, no execute. Any access raises an access violation (`STATUS_ACCESS_VIOLATION`). Import from `windows::Win32::System::Memory`.

**`PAGE_EXECUTE_READ`** — `PAGE_PROTECTION_FLAGS(0x20)`. Execute and read, but no write. Import from `windows::Win32::System::Memory`.

**`PAGE_PROTECTION_FLAGS`** — a newtype wrapping `u32`. Defined in `windows::Win32::System::Memory`. Initialize the out-parameter as `PAGE_PROTECTION_FLAGS::default()` (which is `PAGE_PROTECTION_FLAGS(0)`).

---

## Hints

- `const fn` cannot use `for` loops — `for` desugars to iterator methods which aren't `const`. Use `while i < N { ... i += 1; }` instead.
- To decrypt in place after `ptr::copy_nonoverlapping`: iterate over the allocation using a raw pointer. A raw `*mut u8` offset by index works: `*(base as *mut u8).add(i) ^= KEY`. Do this before the first `VirtualProtect` call.
- `Sleep` lives in `windows::Win32::System::Threading` — same import block as `CreateThread`. Add it to the `use` statement.
- `PAGE_NOACCESS` and `PAGE_EXECUTE_READ` are in `windows::Win32::System::Memory`.
- The `xor_bytes` const fn takes a reference to a fixed-size array (`&[u8; N]`), not a slice. Make sure your shellcode constant is written as `&[u8; N]` or cast appropriately when calling the function.
- You need three `VirtualProtect` calls total. The first two happen before `Sleep`, the third after. Reuse `&mut old` for all three.

---

## What's Still Missing

**XOR is a toy cipher.** XOR with a fixed key is trivially broken if the attacker knows any plaintext (which they do — Meterpreter headers are public). Production obfuscation uses RC4 or AES-128, often with a key derived at runtime from host characteristics (volume serial number, username hash). The deferred key derivation means the sample only decrypts on the intended target. That's beyond this module.

**Permission transitions are behavioral signals.** `VirtualProtect` calls that follow the pattern `RW → RX → NOACCESS → RX` are logged by EDRs. Some products flag this exact sequence. Bypassing behavioral monitoring requires direct syscalls (bypassing the `ntdll` hook layer) — that's a later module.

**The sleep window is still finite.** A sufficiently fast in-memory scanner can catch the page in the brief `RX` window between decryption and the `NOACCESS` flip. The fix is to never have a simultaneous decrypted + readable + executable state at all, which requires cooperation from the shellcode itself.

Module 06 adds PE-level disguise on top of these runtime techniques — modifying PE metadata, section names, and timestamps so the binary looks less suspicious to static analyzers before it even runs.

---

## Submission

Paste `05-evasion-basics/src/main.rs` and ask for a review.
