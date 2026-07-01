# Future Topics

This document maps the path from Module 07 to the point where you can write modern, hard-to-detect malware in Rust. Topics are grouped by theme and annotated with why they matter. A suggested progression order is at the bottom.

---

## What "modern, hard to detect" actually requires

Current detection pipelines have several independent layers. Bypassing one is not enough — you need to address all of them:

| Detection layer | What it looks at | Defeated by |
|---|---|---|
| Static file scanning | Byte signatures, strings, PE metadata | Modules 05-06 (encryption, PE disguise) |
| Import table analysis | Which APIs does the binary import | Dynamic resolution, direct syscalls |
| User-mode API hooks | EDR hooks in ntdll.dll stub functions | Direct syscalls, unhooking |
| In-memory scanning | Contents of RWX allocations, PE headers | Module 07 (header stomping), sleep masking |
| ETW telemetry | API call events reported to the kernel | ETW patching |
| AMSI | Script content scanning | AMSI bypass |
| Behavioral analysis | Sequences of API calls, anomalous patterns | Indirect calls, PPID spoofing, blending |
| Call stack inspection | Who called the suspicious function | Stack spoofing |
| Network inspection | Traffic patterns, TLS fingerprints | C2 traffic blending, domain fronting |

Modules 01-07 address the first two rows and partially address the third. Everything below addresses the rest.

---

## Theme A — Bypassing EDR Hooks

This is the single most important area after Module 07. Most EDR products instrument the user-mode layer by overwriting the first few bytes of ntdll.dll stub functions with jumps into their own code. Every `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, etc. call is intercepted. Direct syscalls bypass this entirely.

### 08 — Direct Syscalls

**What**: Instead of calling the ntdll stub (`NtAllocateVirtualMemory`), issue the `syscall` instruction yourself with the correct system service number (SSN) in `eax`. The kernel doesn't care who called it.

**Why**: This is the most common EDR bypass today. Every injection technique you've learned goes through ntdll — once you have direct syscalls, all of them become EDR-invisible at the API layer.

**Key concepts**:
- Hell's Gate: extract SSNs by reading ntdll's `.text` section at runtime, looking for the `mov eax, imm32` pattern in each Nt function stub
- Halo's Gate: when a stub is hooked (bytes overwritten), find the SSN from an adjacent unhooked function ± the ordinal distance
- Tartarus Gate / FreshyCalls: alternative SSN extraction methods
- `asm!` macro in Rust for the actual `syscall` instruction — nightly or stable depending on Rust version
- Defining your own `NTSTATUS` return type and calling conventions

**Rust note**: The `asm!` macro (`core::arch::asm!`) is stable since Rust 1.59. You can issue raw `syscall` from Rust without any C glue code. This is a clean Rust skill to develop.

---

### 09 — API Unhooking

**What**: Read ntdll.dll fresh from disk, compare `.text` section bytes with the loaded (potentially hooked) version, and overwrite any modified bytes with the clean originals.

**Why**: An alternative to direct syscalls. Also useful for cleaning up hooks placed by your own process (e.g., security software that injects into you). Requires PE parsing skills from Modules 06-07.

**Key concepts**:
- `CreateFileA` + `CreateFileMappingA` + `MapViewOfFile` to read ntdll from `%WINDIR%\System32`
- Compare mapped `.text` sections byte by byte with the in-memory version
- `VirtualProtect` → overwrite → restore on the live copy
- Handling cases where ntdll itself is patched in memory (kernel32 hooks, etc.)

---

### 10 — ETW and AMSI Patching

**What**: Patch two telemetry sources in memory to blind them.

- **ETW** (Event Tracing for Windows): `EtwEventWrite` in ntdll reports API events to the kernel. Overwrite its first bytes with `ret` to make it a no-op.
- **AMSI** (Antimalware Scan Interface): `AmsiScanBuffer` in `amsi.dll` is called by PowerShell and .NET before executing script content. Same `ret` patch, or change the return value to `AMSI_RESULT_CLEAN`.

**Why**: Disabling ETW cuts off a major data source for kernel-mode EDR callbacks. AMSI bypass is essential for running PowerShell or .NET payloads without triggering script-based detection.

**Key concepts**:
- `GetProcAddress` to find the target functions
- `VirtualProtect` + `WriteProcessMemory` (or direct write in-process) for the patch
- ETW patching only needs to happen in your own process (or the injected process)
- AMSI patch must happen before the script engine initializes — timing matters

---

## Theme B — Advanced Execution Primitives

You know three execution primitives: shellcode injection, DLL injection, process hollowing. Modern loaders use several more — each with different detection profiles.

### 11 — APC Injection / Early Bird

**What**: Asynchronous Procedure Calls (APCs) are queued to threads and execute when the thread enters an alertable wait state. Early Bird queues an APC to the main thread of a newly created (suspended) process before it calls `NtTestAlert` — making APC execution nearly guaranteed.

**Why**: APC execution happens inside the target thread's natural execution context, making call stack inspection much harder. Early Bird is one of the cleanest injection primitives available.

**Key concepts**:
- `QueueUserAPC(lpApcFunc, hThread, dwData)` — queue shellcode address as an APC
- `CreateProcessA` with `CREATE_SUSPENDED` + `QueueUserAPC` + `ResumeThread`
- `NtQueueApcThread` (ntapi) for a direct-syscall variant
- The alertable wait requirement and why Early Bird sidesteps it

---

### 12 — Thread Hijacking

**What**: Suspend a running thread in a target process, redirect its `RIP` register to your shellcode, resume it.

**Why**: No new threads created — avoids `CreateRemoteThread` detections entirely. The shellcode appears to execute as part of a legitimate thread.

**Key concepts**:
- `SuspendThread` / `ResumeThread`
- `GetThreadContext` / `SetThreadContext` — same as Module 04, applied to a running thread
- Choosing a safe hijack point (thread must be in a system call, not mid-instruction)
- Context restoration after shellcode execution (so the hijacked thread continues normally)

---

### 13 — Module Stomping

**What**: Load a legitimate, signed DLL into the target process (e.g., `netfxcfg.dll`, an unused system DLL). Then overwrite its `.text` section with your shellcode. A thread executing your shellcode appears — to memory scanners — to be executing inside a signed module.

**Why**: Defeats memory scanners that check whether executable regions are backed by signed images. The shellcode sits inside a legitimate DLL's mapped region. Combines well with Module 07's reflective loading.

**Key concepts**:
- `LoadLibraryExA` with `DONT_RESOLVE_DLL_REFERENCES` to load without running DllMain
- Identifying a suitable DLL to stomp (unused, large `.text` section, signed)
- Calculating the stomp offset within `.text`
- Writing shellcode that fits within the section size

---

### 14 — Process Doppelgänging and Herpaderping

Two techniques that exploit the gap between what the file system sees and what gets mapped into memory.

**Process Doppelgänging** (more complex):
- Open a legitimate file in an NTFS transaction (`CreateTransaction`, `CreateFileTransacted`)
- Overwrite it with your payload within the transaction
- Create a section from the transacted file (`NtCreateSection`)
- Roll back the transaction — the file reverts on disk, but the section is already mapped
- Create a process from the section

**Process Herpaderping** (simpler):
- Create a process from a payload written to disk
- Before the loader finishes, overwrite the file on disk with something benign
- EDR opens the file to scan it and sees the benign version; the malicious image is already mapped

**Why**: Both defeat file-based scanning because what's on disk doesn't match what runs. Doppelgänging is very difficult to detect at the file layer.

**Key concepts**:
- NTFS Transacted File I/O (`CreateTransaction`, `CreateFileTransacted`, `RollbackTransaction`)
- `NtCreateSection`, `NtCreateProcessEx`, `NtCreateThreadEx` — NT-level process creation
- Timing sensitivity in Herpaderping
- `ntapi` crate for most of the NT functions

---

## Theme C — Memory Stealth

### 15 — Sleep Masking (Heap + Stack Encryption)

**What**: A proper sleep masking implementation encrypts not just the shellcode page but all heap allocations, the stack, and any other writable regions associated with your implant before sleeping. Decrypts after waking.

Techniques: **Ekko** (uses `SetTimer` + `CreateTimerQueueTimer` with ROP chain to do the encrypt/sleep/decrypt without calling `VirtualProtect` during the sensitive window), **Foliage** (stack-based), **Cronos**.

**Why**: The Module 05 `PAGE_NOACCESS` trick only hides one page. A serious memory scanner will also find your heap allocations, global variables, and stack. Full sleep masking hides all of it.

**Key concepts**:
- Enumerating your own heap regions (`HeapWalk`, `VirtualQuery` loop)
- `SystemFunction032` (RC4 in ntdll) for fast in-place encryption
- Timer-based execution to avoid calling `VirtualProtect` from within the shellcode
- Stack walking to find and encrypt your own stack frames

---

### 16 — Call Stack Spoofing

**What**: When EDR sees a suspicious API call (e.g., `NtWriteVirtualMemory`), it walks the thread's call stack to find the call origin. If the call appears to come from `ntdll.dll!RtlUserThreadStart` rather than anonymous shellcode, it looks legitimate. Stack spoofing plants a fake return address chain on the stack before making the call.

**Why**: Increasingly used by EDR to identify injected code even when direct syscalls are used. Stack spoofing closes this gap.

**Key concepts**:
- How the x64 call stack is laid out (return addresses, frame pointers, shadow space)
- Synthetic stack frames: building a convincing return chain from scratch
- `RtlCaptureContext` / `RtlRestoreContext` for context switching tricks
- Requires inline assembly (`asm!`) in Rust

---

## Theme D — Persistence

For malware that survives reboots and user logoffs.

### 17 — Persistence Mechanisms

Cover several, ordered from noisy to quiet:

| Mechanism | Where | Noise level | Requires admin |
|---|---|---|---|
| Run key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | High (well-known) | No |
| Startup folder | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` | High | No |
| Scheduled task | Task Scheduler | Medium | No (current user) |
| COM object hijacking | `HKCU\Software\Classes\CLSID\...` | Low | No |
| DLL search order hijacking | Application directory | Low | No (usually) |
| WMI event subscription | WMI repository | Very low | Yes |
| Service installation | SCM | High | Yes |

**Key concepts**:
- Registry API: `RegCreateKeyExA`, `RegSetValueExA`
- Task Scheduler COM interface: `ITaskService`, `ITaskFolder`, `ITaskDefinition`
- COM hijacking: finding CLSIDs loaded by high-value processes, redirecting via HKCU
- WMI subscriptions: `__EventFilter`, `ActiveScriptEventConsumer`, `__FilterToConsumerBinding` — fileless, survives reboots
- `windows` crate COM support for Task Scheduler

---

## Theme E — Privilege Escalation

### 18 — Token Manipulation

**What**: Windows access tokens control what a thread can do. Duplicating and impersonating a token from a higher-privileged process grants those privileges.

**Key concepts**:
- `OpenProcessToken`, `DuplicateTokenEx`, `ImpersonateLoggedOnUser`, `CreateProcessWithTokenW`
- `SeDebugPrivilege`: enables opening any process regardless of DACL (needed to steal tokens from SYSTEM processes)
- `SeImpersonatePrivilege`: enables impersonation (held by service accounts — basis of potato exploits)
- `AdjustTokenPrivileges` to enable privileges that are present but disabled
- Token stealing from SYSTEM processes (`winlogon.exe`, `lsass.exe`)

---

### 19 — UAC Bypass

**What**: Many users run as standard users in a split-token admin account. UAC bypass elevates from medium integrity to high integrity without a UAC prompt.

Common modern techniques:
- **CMSTPLUA COM elevation**: invoke a COM object that auto-elevates and pass it a command
- **fodhelper.exe**: reads a registry key under HKCU before auto-elevating — hijack it
- **DiskCleanup / other auto-elevate binaries**: similar hijacking via environment variable or registry

**Key concepts**:
- Integrity levels: low / medium / high / system
- Auto-elevate COM objects and how to find them (`Elevation:Administrator!new:` manifest)
- Environment variable hijacking (`%windir%`, `%systemroot%` abuse)
- Each technique is fragile — tied to specific Windows versions; study the detection surface

---

## Theme F — Credential Access

### 20 — LSASS Dumping

**What**: `lsass.exe` holds credentials (hashes, Kerberos tickets, plaintext passwords in some configs) in memory. Dump its memory and parse it offline with Mimikatz or pypykatz.

**Key concepts**:
- `MiniDumpWriteDump` (dbghelp.dll) — the classic approach, heavily detected
- `NtReadVirtualMemory` loop — avoid the suspicious API
- Silentprocessexit / `ProcDump` abuse
- Handle duplication from another process that already has a handle to LSASS
- Writing the dump to memory (not disk) to avoid file-based detection
- `SeDebugPrivilege` required

---

### 21 — SAM / SHADOW Copy Dumping

**What**: The SAM hive contains local account NTLM hashes. Normally locked by the SYSTEM account, but accessible via VSS (Volume Shadow Copy) or registry export with `SeBackupPrivilege`.

**Key concepts**:
- `RegSaveKeyA` with `SeBackupPrivilege` to dump SAM/SYSTEM/SECURITY
- VSS (Volume Shadow Copy Service): `IVssBackupComponents`, snapshot creation, reading locked files through the shadow path
- Offline hash extraction from the hive dump

---

## Theme G — Lateral Movement

### 22 — Pass-the-Hash and Token Impersonation

**What**: Use a stolen NTLM hash to authenticate to remote services without knowing the plaintext password.

**Key concepts**:
- `LogonUserA` with `LOGON32_LOGON_NEW_CREDENTIALS` for network-only impersonation
- `ImpersonateLoggedOnUser` + `CreateProcessWithTokenW` to spawn processes under the stolen identity
- NTLM authentication internals (Challenge-Response, NTLMv2)
- SMB named pipe connection with impersonated credentials

---

### 23 — WMI / DCOM Lateral Movement

**What**: Execute code on a remote host using Windows' built-in management interfaces — no file transfer required.

**Key concepts**:
- WMI: `IWbemServices::ExecMethod` → `Win32_Process::Create` on a remote host
- DCOM: `CoCreateInstanceEx` with `COSERVERINFO` to instantiate a COM object on a remote machine (`MMC20.Application`, `ShellBrowserWindow`, etc.)
- Authentication via explicit credentials: `CoInitializeSecurity`, `CoSetProxyBlanket`
- These techniques leave WMI/DCOM event logs — know what you're leaving behind

---

## Theme H — C2 Framework

This is where all the previous techniques come together into a usable tool.

### 24 — HTTP/HTTPS Beacon

**What**: A minimal command-and-control agent that checks in to a server on a schedule, receives tasks, executes them, and returns output.

**Key concepts**:
- Check-in loop: `WinHttpOpen` / `WinHttpConnect` / `WinHttpSendRequest` / `WinHttpReceiveResponse`
- Sleep with jitter: `rand` crate or custom PRNG + `Sleep(base ± jitter%)`
- Task encoding: simple JSON, msgpack, or binary protocol
- Output collection: `CreatePipe` + `CreateProcess` with redirected stdio for shell commands
- Minimal implant: keep the binary small, no unnecessary imports

---

### 25 — Staged Payloads

**What**: Split the implant into a small first-stage (stager) and a larger second-stage (the full agent). The stager downloads and reflectively loads the second stage — nothing but the stager ever touches disk.

**Key concepts**:
- Stager downloads second stage via HTTP to a heap allocation
- Reflectively loads it (Module 07 skills applied)
- No file on disk for the full implant at any point
- Second stage can be updated without replacing the stager

---

### 26 — Traffic Obfuscation

**What**: Make C2 traffic look like legitimate application traffic to defeat network-based detection.

**Key concepts**:
- **Domain fronting**: route HTTPS traffic through a CDN (Cloudfront, Azure CDN) with a legitimate `Host` header — the SNI shows the CDN, the actual request goes to your server
- **Malleable C2 profiles**: customize HTTP request/response format, headers, URIs to match a specific application (e.g., Microsoft Teams, Slack)
- **JA3 fingerprinting**: every TLS client has a fingerprint derived from the ClientHello. Use `rustls` with custom cipher suites to match a known-good fingerprint
- **DNS C2**: encode commands in DNS TXT/A queries to your controlled domain — works through most firewalls

---

## Theme I — Rust Mastery for Malware

These are Rust-specific skills that run in parallel with the techniques above and make everything smaller, faster, and harder to analyze.

### A — `no_std` Malware

**What**: Remove the Rust standard library entirely. The resulting binary has no `main` CRT startup, no allocator, no panicking infrastructure — just your code and direct system calls.

**Why**: Smaller binaries (no std overhead), fewer imports in the PE import table, harder to identify as Rust, no Rust-specific signatures.

**Key concepts**:
- `#![no_std]`, `#![no_main]`, custom panic handler
- Custom global allocator using `HeapCreate` / `HeapAlloc`
- `core` and `alloc` crates as replacements for std
- Writing a `_start` or `WinMain` entry point manually

---

### B — Procedural Macros for Obfuscation

**What**: Go beyond `const fn` for compile-time obfuscation. A proc macro runs arbitrary code during compilation — it can encrypt strings, generate random keys, transform ASTs.

**Key concepts**:
- Writing a `#[derive]` or attribute macro that encrypts string literals at compile time
- `proc-macro2`, `syn`, `quote` crates
- Obfuscating API names (hash-based resolution instead of string lookup)
- Compile-time shellcode encryption with a randomly-generated key per build

---

### C — Inline Assembly for Syscalls and Shellcode

**What**: The `asm!` macro for writing raw assembly inline in Rust functions. Essential for direct syscalls, stack spoofing, and writing position-independent shellcode.

**Key concepts**:
- `core::arch::asm!` syntax and constraints
- Register clobbering and the `lateout` / `inout` constraint syntax
- Writing a direct syscall wrapper that takes SSN + arguments
- Building shellcode that bootstraps a Rust heap (for calling into normal Rust code from shellcode)

---

### D — Binary Hardening

**What**: Make the compiled binary as small and unremarkable as possible.

**Cargo.toml profile settings**:
```toml
[profile.release]
opt-level = "z"       # optimize for size
lto = true            # link-time optimization removes dead code
codegen-units = 1     # single codegen unit for better optimization
panic = "abort"       # no unwinding machinery
strip = true          # strip symbols and debug info
```

**Key concepts**:
- `cargo bloat` to find what's making the binary large
- Feature flags to disable unused crate functionality
- Custom linker scripts to control section layout
- Removing Rust's default allocator in favor of a minimal one
- `upx` or custom packing for further size reduction (trade-off: packing itself is a detection signal)

---

### E — Hash-Based API Resolution

**What**: Instead of importing functions by name (leaving strings in the binary), walk the PEB's loaded module list at runtime, hash exported function names, and resolve function pointers by hash match.

**Why**: No API name strings in the binary. No entries in the import table. The binary imports nothing — all Win32 calls are resolved dynamically via PEB walking.

**Key concepts**:
- PEB structure (`gs:[0x60]` → `PEB.Ldr` → `InMemoryOrderModuleList`)
- Iterating the module list to find `kernel32.dll` by hash of its name
- Iterating kernel32's export table to find `GetProcAddress` by hash
- From there, resolve everything else via `GetProcAddress`
- Choosing a fast, collision-resistant hash (djb2, FNV-1a)
- This is position-independent code — no relocations needed

---

## Suggested Progression Order

After completing Module 07:

```
08 — Direct syscalls              (unlocks EDR-invisible injection; do this first)
09 — API unhooking                (alternative/complement to direct syscalls)
17 — Persistence mechanisms       (low complexity, high practical value)
10 — ETW + AMSI patching          (short module, high impact)
11 — APC injection / Early Bird   (new execution primitive, builds on 04)
18 — Token manipulation           (opens up privilege escalation and pivoting)
15 — Sleep masking                (builds on 05, closes the memory scanning gap)
12 — Thread hijacking             (execution primitive, builds on 04/11)
13 — Module stomping              (builds on 07, hides shellcode in signed memory)
24 — HTTP beacon                  (ties everything together into a usable tool)
16 — Call stack spoofing          (advanced, requires asm! — do after 08)
19 — UAC bypass                   (completes the privilege escalation picture)
20 — LSASS dumping                (credential access)
25 — Staged payloads              (builds on 07 and 24)
26 — Traffic obfuscation          (C2 hardening)
22 — Pass-the-hash                (lateral movement)
14 — Doppelgänging / Herpaderping (advanced loader techniques)
23 — WMI/DCOM lateral movement    (lateral movement)
21 — SAM dumping                  (credential access)

Rust skills — develop in parallel:
  A — no_std              (attempt after Module 08 when you understand direct syscalls)
  E — Hash-based API resolution  (implement as part of or after Module 08)
  B — Proc macro obfuscation     (after Module 05, when const fn feels limiting)
  C — Inline assembly            (required for Module 08)
  D — Binary hardening           (apply to every module's release build)
```

---

## References to Keep Handy

These are the primary resources for the topics above (read, don't copy):

- **Windows Internals (7th ed.)** — Mark Russinovich et al. — process/memory/token architecture
- **The Rust Reference** — `asm!` syntax, const generics, proc macros
- **VX-Underground** — real-world malware samples and technique writeups
- **ired.team** — technique breakdowns with working code in C (translate to Rust)
- **MDSec / Sektor7 / Outflank blogs** — EDR evasion, sleep masking, stack spoofing
- **NtDoc** (https://ntdoc.m417z.com) — undocumented NT function signatures
- **Process Hacker source** — best reference for PEB/TEB structure offsets and NT internals
